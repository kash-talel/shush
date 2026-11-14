//! Vault container, data model and in-memory state (spec §4, §5, roadmap Step 3).
//!
//! Payload pipeline (inside the AEAD):
//!
//! ```text
//! VaultData ─ JSON ─ zstd ─ frame: u32 len || compressed || zero padding (PADMÉ) ─ AEAD
//! ```
//!
//! Padding hides the exact vault size (issue #4). Decompression is bounded by
//! the size recorded in the zstd frame, which must be ≤ [`MAX_DECOMPRESSED`]
//! (issue #5).

pub mod attachments;
pub mod backup;
pub mod container;
pub mod importer;
pub mod items;
pub mod lock;
pub mod models;
pub mod registry;
pub mod siblings;
pub mod slots;
pub mod state;

use std::io::ErrorKind;
use std::path::Path;

use zeroize::Zeroizing;

use crate::crypto::{
    derive_master_key, kdf, CipherSuite, CryptoError, KdfParams, KeyfileDigest, SecretBytes,
    VaultKeys,
};
use container::{FileKind, Header, FORMAT_VERSION, HEADER_LEN};
pub use models::VaultData;

/// Largest decompressed JSON payload accepted (256 MiB).
pub const MAX_DECOMPRESSED: u64 = 256 * 1024 * 1024;
/// Smallest padded plaintext, so tiny vaults are indistinguishable.
const MIN_PADDED: usize = 4096;
const ZSTD_LEVEL: i32 = 3;

/// Everything that can go wrong reading or writing a vault.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VaultError {
    /// No file at the given path.
    #[error("vault file not found")]
    NotFound,
    /// Refusing to overwrite an existing vault.
    #[error("a vault already exists at this location")]
    AlreadyExists,
    /// Filesystem error.
    #[error("I/O error: {0}")]
    Io(ErrorKind),
    /// MAGIC is not a shush envelope.
    #[error("not a shush vault file")]
    NotAVault,
    /// A `.shushbackup` was given where a vault was expected (or vice versa).
    #[error("this file is a {0:?}, not the expected kind")]
    WrongKind(FileKind),
    /// Written by a newer (or unknown) format version.
    #[error("unsupported vault format version {0}")]
    UnsupportedVersion(u16),
    /// File ends early.
    #[error("vault file is truncated")]
    Truncated,
    /// Structurally invalid.
    #[error("malformed vault file: {0}")]
    Malformed(&'static str),
    /// Exceeds size limits.
    #[error("vault is too large")]
    TooLarge,
    /// Header says a keyfile is required but none was supplied.
    #[error("this vault requires its keyfile")]
    KeyfileRequired,
    /// A keyfile was supplied for a vault that does not use one.
    #[error("this vault does not use a keyfile")]
    KeyfileNotExpected,
    /// Decrypted fine but the contents are unusable (format bug).
    #[error("vault contents are corrupt: {0}")]
    CorruptPayload(&'static str),
    /// The bytes read back after writing did not verify.
    #[error("written vault failed verification; the previous vault was kept")]
    WriteVerifyFailed,
    /// Another process holds this vault open (issue #9).
    #[error("this vault is open in another shush process")]
    InUse,
    /// The file on disk is no longer the one this vault was loaded from
    /// (another writer replaced it); saving would discard its changes (issue #9).
    #[error("the vault file was changed by another program since it was opened")]
    ChangedOnDisk,
    /// Reloading the vault from disk requires the password because credentials or KDF parameters changed (issue #49).
    #[error("the master password is required to reload because credentials changed on disk")]
    PasswordRequired,
    /// Attachments are sidecar files a decoy could count (issue #8).
    #[error("remove all attachments before setting a duress password")]
    DuressWithAttachments,
    /// Adding attachments would reveal the duress vault (issue #8).
    #[error("attachments are turned off while a duress password is set")]
    AttachmentsDisabled,
    /// The duress password must differ from the master password.
    #[error("the duress password must differ from the master password")]
    DuressSameAsMaster,
    /// Underlying cryptographic failure.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        match e.kind() {
            ErrorKind::NotFound => Self::NotFound,
            ErrorKind::AlreadyExists => Self::AlreadyExists,
            k => Self::Io(k),
        }
    }
}

/// Settings chosen when a vault is created.
#[derive(Debug, Clone, Copy, Default)]
pub struct CreateOptions {
    /// AEAD suite.
    pub suite: CipherSuite,
    /// Argon2id parameters.
    pub kdf: KdfParams,
}

/// A decrypted vault held in memory. Dropping it wipes keys and data.
pub struct OpenVault {
    header: Header,
    keys: VaultKeys,
    data: VaultData,
    /// Fingerprint of the file image this vault was loaded from or last
    /// wrote; `None` until it exists on disk. A save only replaces exactly
    /// that file (optimistic concurrency, issue #9).
    disk_id: Option<DiskId>,
    /// Where this vault lives in the two-slot file (format v3, issue #8).
    slot: SlotState,
}

/// This vault's slot and the opaque bytes of the other slot.
struct SlotState {
    /// The slot these credentials open.
    index: usize,
    /// The other slot, copied verbatim on every save (it cannot be read).
    /// Empty when there is none yet: it is then written as random bytes.
    other: Vec<u8>,
    /// Current slot size; 0 before the first v3 write.
    len: usize,
}

impl SlotState {
    /// A random slot for a vault that has no v3 file yet, so the position of
    /// the first vault reveals nothing about whether a second one exists.
    fn fresh() -> Result<Self, VaultError> {
        let mut b = [0u8; 1];
        crate::crypto::fill_random(&mut b)?;
        Ok(Self {
            index: usize::from(b[0] & 1),
            other: Vec::new(),
            len: 0,
        })
    }
}

/// Identifies one written file image: SHA-256 of the whole file, which holds
/// the random nonces and `SAVE_ID` drawn on every save, so two saves never
/// share it. Not a secret and not an integrity check (the AEAD is).
type DiskId = [u8; 32];

fn disk_id(bytes: &[u8]) -> DiskId {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
}

/// The [`DiskId`] of the file currently at `path`, or `None` if there is none.
fn disk_id_at(path: &Path) -> Result<Option<DiskId>, VaultError> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(disk_id(&bytes))),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

impl std::fmt::Debug for OpenVault {
    /// Redacted: shows only non-secret header fields and counts.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenVault")
            .field("header", &self.header)
            .field("items", &self.data.items.len())
            .finish_non_exhaustive()
    }
}

impl OpenVault {
    /// Creates a new, empty vault in memory (runs Argon2id once).
    pub fn create(
        password: &[u8],
        keyfile: Option<&KeyfileDigest>,
        options: CreateOptions,
    ) -> Result<Self, VaultError> {
        let header = Header {
            kind: FileKind::Vault,
            suite: options.suite,
            keyfile_required: keyfile.is_some(),
            kdf: options.kdf,
            salt: kdf::generate_salt()?,
        };
        let master = derive_master_key(password, keyfile, &header.salt, &header.kdf)?;
        Ok(Self {
            keys: VaultKeys::derive(&master),
            header,
            data: VaultData::new(),
            disk_id: None,
            slot: SlotState::fresh()?,
        })
    }

    /// Decrypts a vault file image (format v3, or legacy v1 / v2).
    ///
    /// A v3 file runs Argon2id once and then tries the credentials on every
    /// slot, so it costs the same whichever slot they open (issue #8).
    pub fn unlock(
        bytes: &[u8],
        password: &[u8],
        keyfile: Option<&KeyfileDigest>,
    ) -> Result<Self, VaultError> {
        let header = Header::parse(bytes)?;
        if header.kind != FileKind::Vault {
            return Err(VaultError::WrongKind(header.kind));
        }
        // Structure is checked before the expensive KDF runs.
        enum Parsed<'a> {
            Slots(slots::SlotFile<'a>),
            Single(container::Sealed<'a>),
        }
        let parsed = if container::read_version(bytes) == FORMAT_VERSION {
            Parsed::Slots(slots::parse(bytes)?)
        } else {
            Parsed::Single(container::parse(bytes)?)
        };
        match (header.keyfile_required, keyfile.is_some()) {
            (true, false) => return Err(VaultError::KeyfileRequired),
            (false, true) => return Err(VaultError::KeyfileNotExpected),
            _ => {}
        }
        let master = derive_master_key(password, keyfile, &header.salt, &header.kdf)?;
        let keys = VaultKeys::derive(&master);
        let (plaintext, slot) = match parsed {
            Parsed::Slots(f) => {
                let (index, h) = f.find_slot(&keys)?;
                let plaintext = f.open_payload(index, &h, &keys)?;
                let slot = SlotState {
                    index,
                    other: f.slot(1 - index).to_vec(),
                    len: f.slot_len(),
                };
                (plaintext, slot)
            }
            Parsed::Single(s) => {
                s.verify_canary(&keys)?;
                // The next save upgrades the file to v3 (`.bak` keeps the old one).
                (s.open_payload(&keys)?, SlotState::fresh()?)
            }
        };
        let data: VaultData = decode_json(&plaintext)?;
        Ok(Self {
            header,
            keys,
            data,
            disk_id: Some(disk_id(bytes)),
            slot,
        })
    }

    /// Reloads the vault from disk after a concurrent change (issue #49).
    ///
    /// If the on-disk file has the same salt and KDF parameters as the in-memory
    /// vault and can be opened with the existing keys, it is decrypted directly
    /// without re-running Argon2id.
    ///
    /// If credentials or KDF parameters changed on disk:
    /// - If `password` is `None`, returns [`VaultError::PasswordRequired`].
    /// - If `password` is provided, derives the new keys and reloads.
    pub fn reload(
        &mut self,
        path: &Path,
        password: Option<&[u8]>,
        keyfile: Option<&KeyfileDigest>,
    ) -> Result<(), VaultError> {
        let bytes = read_vault_file(path)?;
        let header = Header::parse(&bytes)?;
        if header.kind != FileKind::Vault {
            return Err(VaultError::WrongKind(header.kind));
        }

        enum Parsed<'a> {
            Slots(slots::SlotFile<'a>),
            Single(container::Sealed<'a>),
        }
        let parsed = if container::read_version(&bytes) == FORMAT_VERSION {
            Parsed::Slots(slots::parse(&bytes)?)
        } else {
            Parsed::Single(container::parse(&bytes)?)
        };

        let decrypt_with_keys = |keys: &VaultKeys| -> Result<(SecretBytes, SlotState), VaultError> {
            match &parsed {
                Parsed::Slots(f) => {
                    let (index, h) = f.find_slot(keys)?;
                    let plaintext = f.open_payload(index, &h, keys)?;
                    let slot = SlotState {
                        index,
                        other: f.slot(1 - index).to_vec(),
                        len: f.slot_len(),
                    };
                    Ok((plaintext, slot))
                }
                Parsed::Single(s) => {
                    s.verify_canary(keys)?;
                    Ok((s.open_payload(keys)?, SlotState::fresh()?))
                }
            }
        };

        let (new_keys, plaintext, slot) = match password {
            None => {
                if header.salt != self.header.salt || header.kdf != self.header.kdf {
                    return Err(VaultError::PasswordRequired);
                }
                match decrypt_with_keys(&self.keys) {
                    Ok((pt, slot)) => (None, pt, slot),
                    Err(_) => return Err(VaultError::PasswordRequired),
                }
            }
            Some(pw) => {
                match (header.keyfile_required, keyfile.is_some()) {
                    (true, false) => return Err(VaultError::KeyfileRequired),
                    (false, true) => return Err(VaultError::KeyfileNotExpected),
                    _ => {}
                }
                let master = derive_master_key(pw, keyfile, &header.salt, &header.kdf)?;
                let keys = VaultKeys::derive(&master);
                let (pt, slot) = decrypt_with_keys(&keys)?;
                (Some(keys), pt, slot)
            }
        };

        let data: VaultData = decode_json(&plaintext)?;
        if let Some(keys) = new_keys {
            self.keys = keys;
        }
        self.header = header;
        self.data = data;
        self.slot = slot;
        self.disk_id = Some(disk_id(&bytes));
        Ok(())
    }

    /// Serializes and seals the vault into a complete (format v3) file image.
    pub fn to_bytes(&self) -> Result<Vec<u8>, VaultError> {
        let plaintext = encode_json(&self.data)?;
        let own = slots::seal_slot(&self.header, &self.keys, self.slot.index, &plaintext)?;
        slots::assemble(
            &self.header,
            self.slot.index,
            &own,
            &self.slot.other,
            self.slot.len,
        )
    }

    /// Writes the vault crash-safely, verifying the written bytes decrypt
    /// back to the same data before the old file is replaced.
    ///
    /// Refuses with [`VaultError::ChangedOnDisk`] if the file at `path` is not
    /// the one this vault was loaded from or last wrote, so a concurrent
    /// writer's changes are never silently overwritten (issue #9).
    pub fn save(&mut self, path: &Path) -> Result<(), VaultError> {
        self.save_checked(path, None)
    }

    /// [`Self::save`], additionally requiring that `other_keys` open the other
    /// slot of the written file (used right after sealing a duress slot).
    fn save_checked(
        &mut self,
        path: &Path,
        other_keys: Option<&VaultKeys>,
    ) -> Result<(), VaultError> {
        let bytes = self.to_bytes()?;
        let expected = self.disk_id;
        let index = self.slot.index;
        container::write_atomic(path, &bytes, |written| {
            // Checked as late as possible: right before the old file is replaced.
            if disk_id_at(path)? != expected {
                return Err(VaultError::ChangedOnDisk);
            }
            let f = slots::parse(written)?;
            let h = f.open_header(index, &self.keys)?;
            let data: VaultData = decode_json(&f.open_payload(index, &h, &self.keys)?)?;
            if data != self.data || !f.slot(1 - index).starts_with(&self.slot.other) {
                return Err(VaultError::WriteVerifyFailed);
            }
            if let Some(k) = other_keys {
                let h = f.open_header(1 - index, k)?;
                decode_json::<VaultData>(&f.open_payload(1 - index, &h, k)?)?;
            }
            Ok(())
        })?;
        let f = slots::parse(&bytes)?;
        self.slot.other = f.slot(1 - index).to_vec();
        self.slot.len = f.slot_len();
        self.disk_id = Some(disk_id(&bytes));
        Ok(())
    }

    /// Re-seals the vault without changing its contents.
    ///
    /// Called after every unlock, so `vault.shush.bak` and the current file
    /// always differ only in the slot that was opened last. Otherwise
    /// comparing them after a decoy unlock could show that the *other* slot
    /// changed most recently, revealing a second vault (issue #8).
    pub fn refresh(&mut self, path: &Path) -> Result<(), VaultError> {
        self.save(path)
    }

    /// Whether the file on disk is already format v3 (legacy files are only
    /// upgraded by an actual change, not by unlocking).
    pub fn is_current_format(&self) -> bool {
        self.slot.len != 0
    }

    /// Whether this vault has set a duress password. Only the vault that set
    /// it knows: the decoy cannot tell that it is one.
    pub fn duress_enabled(&self) -> bool {
        self.data.settings.duress_pin_enabled
    }

    /// Seals a new, empty decoy vault into the other slot under a duress
    /// password (same keyfile, salt and KDF parameters), replacing whatever
    /// was there. Refused while the vault has attachments, whose sidecar
    /// files the decoy could not account for (issue #8).
    pub fn set_duress(
        &mut self,
        path: &Path,
        current_password: &[u8],
        password: &[u8],
        keyfile: Option<&KeyfileDigest>,
    ) -> Result<(), VaultError> {
        if attachments::has_attachments(&self.data) {
            return Err(VaultError::DuressWithAttachments);
        }
        match (self.header.keyfile_required, keyfile.is_some()) {
            (true, false) => return Err(VaultError::KeyfileRequired),
            (false, true) => return Err(VaultError::KeyfileNotExpected),
            _ => {}
        }
        // Re-authenticate: the vault cannot tell whether it is the real one or
        // a decoy, so overwriting the other slot must never be a one-click
        // action (issue #68). The keyfile is shared by both slots.
        let current = derive_master_key(
            current_password,
            keyfile,
            &self.header.salt,
            &self.header.kdf,
        )?;
        if !VaultKeys::derive(&current)
            .canary_key()
            .ct_eq(self.keys.canary_key())
        {
            return Err(VaultError::Crypto(CryptoError::WrongCredentials));
        }
        let master = derive_master_key(password, keyfile, &self.header.salt, &self.header.kdf)?;
        let keys = VaultKeys::derive(&master);
        if keys.canary_key().ct_eq(self.keys.canary_key()) {
            return Err(VaultError::DuressSameAsMaster);
        }
        let other_index = 1 - self.slot.index;
        let decoy = slots::seal_slot(
            &self.header,
            &keys,
            other_index,
            &encode_json(&VaultData::new())?,
        )?;
        self.replace_other(path, decoy, true, Some(&keys))?;
        // A second write, so `.bak` holds the duress state too and a diff of
        // the two files shows only this slot changing (see [`Self::refresh`]).
        let _ = self.refresh(path);
        Ok(())
    }

    /// Overwrites the other slot with random bytes, destroying the decoy.
    pub fn clear_duress(&mut self, path: &Path) -> Result<(), VaultError> {
        self.replace_other(path, Vec::new(), false, None)?;
        let _ = self.refresh(path);
        Ok(())
    }

    fn replace_other(
        &mut self,
        path: &Path,
        other: Vec<u8>,
        enabled: bool,
        check: Option<&VaultKeys>,
    ) -> Result<(), VaultError> {
        let prev_other = std::mem::replace(&mut self.slot.other, other);
        let prev_enabled = std::mem::replace(&mut self.data.settings.duress_pin_enabled, enabled);
        let result = self.save_checked(path, check);
        if result.is_err() {
            self.slot.other = prev_other;
            self.data.settings.duress_pin_enabled = prev_enabled;
        }
        result
    }

    /// Applies `f` to a copy of the data, saves it, and only then commits it in
    /// memory. If `f` or the save fails, memory and disk stay unchanged.
    pub fn modify<R, E: From<VaultError>>(
        &mut self,
        path: &Path,
        f: impl FnOnce(&mut VaultData) -> Result<R, E>,
    ) -> Result<R, E> {
        let mut next = self.data.clone();
        let result = f(&mut next)?;
        let previous = std::mem::replace(&mut self.data, next);
        if let Err(e) = self.save(path) {
            self.data = previous;
            return Err(e.into());
        }
        Ok(result)
    }

    /// Derived keys (crate-internal: used to seal backups with the vault's credentials).
    pub(crate) fn keys(&self) -> &VaultKeys {
        &self.keys
    }

    /// Authenticated header fields.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Decrypted contents.
    pub fn data(&self) -> &VaultData {
        &self.data
    }

    /// Mutable decrypted contents. Call [`Self::save`] to persist.
    pub fn data_mut(&mut self) -> &mut VaultData {
        &mut self.data
    }
}

/// Reads just the header of the vault at `path` (no credentials needed).
pub fn read_header(path: &Path) -> Result<Header, VaultError> {
    use std::io::Read;
    let mut buf = Vec::with_capacity(HEADER_LEN);
    std::fs::File::open(path)?
        .take(HEADER_LEN as u64)
        .read_to_end(&mut buf)?;
    Header::parse(&buf)
}

/// Reads a vault file, refusing anything larger than the format allows
/// before loading it into memory.
pub fn read_vault_file(path: &Path) -> Result<Vec<u8>, VaultError> {
    let len = std::fs::metadata(path)?.len();
    if len > slots::MAX_FILE_LEN {
        return Err(VaultError::TooLarge);
    }
    Ok(std::fs::read(path)?)
}

/// Creates a new vault file at `path`. Never overwrites an existing file.
pub fn create_vault_file(
    path: &Path,
    password: &[u8],
    keyfile: Option<&KeyfileDigest>,
    options: CreateOptions,
) -> Result<OpenVault, VaultError> {
    if path.exists() {
        return Err(VaultError::AlreadyExists);
    }
    let mut vault = OpenVault::create(password, keyfile, options)?;
    vault.save(path)?;
    Ok(vault)
}

/// PADMÉ padding (Nikitin et al., 2019): pads `len` so that at most
/// O(log log len) bits of the length leak, with ≤ 12% overhead.
pub fn padme(len: usize) -> usize {
    if len < 2 {
        return len;
    }
    let e = usize::BITS - 1 - len.leading_zeros(); // floor(log2 len)
    let s = u32::BITS - e.leading_zeros(); // floor(log2 e) + 1
    let low_bits = e - s;
    let mask = (1usize << low_bits) - 1;
    (len + mask) & !mask
}

/// JSON → zstd → length-prefixed, PADMÉ-padded plaintext (shared by vault and backup).
pub(crate) fn encode_json<T: serde::Serialize>(data: &T) -> Result<SecretBytes, VaultError> {
    // serde_json would grow a Vec while writing, leaving unwiped fragments of
    // the plaintext in freed memory (issue #6). Measure first, then write into
    // a buffer allocated at its final size so it never reallocates.
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 += buf.len();
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let ser_err = |_| VaultError::CorruptPayload("serialization failed");
    let mut count = Count(0);
    serde_json::to_writer(&mut count, data).map_err(ser_err)?;
    let mut json = SecretBytes::with_capacity(count.0);
    let cap = json.capacity();
    serde_json::to_writer(&mut json, data).map_err(ser_err)?;
    debug_assert_eq!(json.capacity(), cap, "JSON buffer reallocated");
    let compressed = Zeroizing::new(
        zstd::bulk::compress(&json, ZSTD_LEVEL)
            .map_err(|_| VaultError::CorruptPayload("compression failed"))?,
    );
    let framed_len = 4 + compressed.len();
    let total = padme(framed_len).max(MIN_PADDED);
    let mut out = SecretBytes::with_capacity(total);
    out.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
    out.extend_from_slice(&compressed);
    out.resize(total, 0);
    Ok(out)
}

/// Inverse of [`encode_json`], with the decompression-bomb guard.
pub(crate) fn decode_json<T: serde::de::DeserializeOwned>(
    plaintext: &[u8],
) -> Result<T, VaultError> {
    let header: [u8; 4] = plaintext
        .get(..4)
        .and_then(|b| b.try_into().ok())
        .ok_or(VaultError::CorruptPayload("missing length prefix"))?;
    let n = u32::from_le_bytes(header) as usize;
    let compressed = plaintext
        .get(4..4 + n)
        .ok_or(VaultError::CorruptPayload("length prefix out of range"))?;
    let size = zstd::zstd_safe::get_frame_content_size(compressed)
        .ok()
        .flatten()
        .ok_or(VaultError::CorruptPayload(
            "zstd frame without content size",
        ))?;
    if size > MAX_DECOMPRESSED {
        return Err(VaultError::TooLarge);
    }
    // Exact capacity in page-locked memory: no reallocation, no stale copies (issue #59).
    let mut json = SecretBytes::with_capacity(size as usize);
    json.resize(size as usize, 0);
    let written = zstd::bulk::decompress_to_buffer(compressed, json.as_mut_slice())
        .map_err(|_| VaultError::CorruptPayload("decompression failed"))?;
    if written != size as usize {
        json.truncate(written);
    }
    serde_json::from_slice(&json).map_err(|_| VaultError::CorruptPayload("invalid JSON"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keyfile;
    use models::{BaseItem, SecureNoteItem, VaultItem};

    const FAST: CreateOptions = CreateOptions {
        suite: CipherSuite::Aes256Gcm,
        kdf: KdfParams {
            mem_kib: 1024,
            iterations: 1,
            parallelism: 1,
        },
    };

    fn note(title: &str, body: &str) -> VaultItem {
        VaultItem::SecureNote(SecureNoteItem {
            base: BaseItem {
                id: title.into(),
                title: title.into(),
                folder_id: None,
                tags: vec![],
                favorite: false,
                notes: String::new(),
                attachments: vec![],
                created_at: models::now_rfc3339(),
                updated_at: models::now_rfc3339(),
                last_used_at: None,
            },
            content: body.into(),
        })
    }

    #[test]
    fn create_save_unlock_roundtrip_both_suites() {
        let dir = tempfile::tempdir().unwrap();
        for suite in CipherSuite::ALL {
            let path = dir.path().join(format!("{suite:?}.shush"));
            let mut v = create_vault_file(
                &path,
                b"correct horse",
                None,
                CreateOptions { suite, ..FAST },
            )
            .unwrap();
            v.data_mut().items.push(note("n1", "secret body"));
            v.save(&path).unwrap();

            let bytes = read_vault_file(&path).unwrap();
            assert!(
                !bytes.windows(11).any(|w| w == b"secret body"),
                "plaintext leaked to disk"
            );
            let reopened = OpenVault::unlock(&bytes, b"correct horse", None).unwrap();
            assert_eq!(reopened.data(), v.data());
            assert_eq!(reopened.header().suite, suite);
        }
    }

    #[test]
    fn create_refuses_to_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.shush");
        create_vault_file(&path, b"pw", None, FAST).unwrap();
        assert_eq!(
            create_vault_file(&path, b"other", None, FAST).err(),
            Some(VaultError::AlreadyExists)
        );
        assert!(OpenVault::unlock(&read_vault_file(&path).unwrap(), b"pw", None).is_ok());
    }

    #[test]
    fn credential_errors_are_specific() {
        let kf = keyfile::digest_bytes(b"usb key").unwrap();
        let wrong_kf = keyfile::digest_bytes(b"other key").unwrap();
        let with_kf = OpenVault::create(b"pw", Some(&kf), FAST)
            .unwrap()
            .to_bytes()
            .unwrap();
        let without_kf = OpenVault::create(b"pw", None, FAST)
            .unwrap()
            .to_bytes()
            .unwrap();

        assert!(OpenVault::unlock(&with_kf, b"pw", Some(&kf)).is_ok());
        assert_eq!(
            OpenVault::unlock(&with_kf, b"pw", None).err(),
            Some(VaultError::KeyfileRequired)
        );
        assert_eq!(
            OpenVault::unlock(&with_kf, b"pw", Some(&wrong_kf)).err(),
            Some(VaultError::Crypto(CryptoError::WrongCredentials))
        );
        assert_eq!(
            OpenVault::unlock(&with_kf, b"pX", Some(&kf)).err(),
            Some(VaultError::Crypto(CryptoError::WrongCredentials))
        );
        assert_eq!(
            OpenVault::unlock(&without_kf, b"pw", Some(&kf)).err(),
            Some(VaultError::KeyfileNotExpected)
        );
    }

    #[test]
    fn header_and_size_reveal_little() {
        // Empty vault and a vault with a few items pad to the same size.
        let mut v = OpenVault::create(b"pw", None, FAST).unwrap();
        let empty = v.to_bytes().unwrap().len();
        for i in 0..5 {
            v.data_mut().items.push(note(&format!("n{i}"), "short"));
        }
        assert_eq!(v.to_bytes().unwrap().len(), empty);
    }

    #[test]
    fn stale_snapshot_cannot_overwrite_a_newer_save() {
        // Two writers load generation N (issue #9).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.shush");
        create_vault_file(&path, b"pw", None, FAST).unwrap();
        let bytes = read_vault_file(&path).unwrap();
        let mut a = OpenVault::unlock(&bytes, b"pw", None).unwrap();
        let mut b = OpenVault::unlock(&bytes, b"pw", None).unwrap();

        // A saves N+1; A can keep saving on top of its own writes.
        for t in ["a1", "a2"] {
            a.modify::<_, VaultError>(&path, |d| {
                d.items.push(note(t, "x"));
                Ok(())
            })
            .unwrap();
        }

        // B's save from the stale snapshot is refused and rolled back.
        let r = b.modify::<_, VaultError>(&path, |d| {
            d.items.push(note("b", "x"));
            Ok(())
        });
        assert_eq!(r, Err(VaultError::ChangedOnDisk));
        assert!(b.data().items.is_empty());
        let on_disk = OpenVault::unlock(&read_vault_file(&path).unwrap(), b"pw", None).unwrap();
        assert_eq!(on_disk.data().items.len(), 2, "A's items survive");
        assert!(!sibling_exists(&path, "tmp"));
    }

    #[test]
    fn reload_recovers_from_changed_on_disk_and_allows_reapply() {
        // Issue #49: recover from VAULT_CHANGED_ON_DISK without locking
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.shush");
        create_vault_file(&path, b"pw", None, FAST).unwrap();
        let bytes = read_vault_file(&path).unwrap();
        let mut a = OpenVault::unlock(&bytes, b"pw", None).unwrap();
        let mut b = OpenVault::unlock(&bytes, b"pw", None).unwrap();

        // A writes an item to disk
        a.modify::<_, VaultError>(&path, |d| {
            d.items.push(note("from-a", "content-a"));
            Ok(())
        })
        .unwrap();

        // B tries to save, gets ChangedOnDisk
        let err = b.modify::<_, VaultError>(&path, |d| {
            d.items.push(note("from-b", "content-b"));
            Ok(())
        });
        assert_eq!(err, Err(VaultError::ChangedOnDisk));

        // B reloads with keys in memory (no password needed because salt/KDF unchanged)
        b.reload(&path, None, None).unwrap();
        assert_eq!(b.data().items.len(), 1);
        fn item_title(item: &VaultItem) -> &str {
            match item {
                VaultItem::Login(l) => &l.base.title,
                VaultItem::SecureNote(n) => &n.base.title,
            }
        }
        assert_eq!(item_title(&b.data().items[0]), "from-a");

        // B re-applies its edit on top of the reloaded vault
        b.modify::<_, VaultError>(&path, |d| {
            d.items.push(note("from-b", "content-b"));
            Ok(())
        })
        .unwrap();

        // File on disk now contains both edits
        let final_disk = OpenVault::unlock(&read_vault_file(&path).unwrap(), b"pw", None).unwrap();
        assert_eq!(final_disk.data().items.len(), 2);
        assert_eq!(item_title(&final_disk.data().items[0]), "from-a");
        assert_eq!(item_title(&final_disk.data().items[1]), "from-b");
    }

    #[test]
    fn reload_requires_password_when_credentials_change_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.shush");
        create_vault_file(&path, b"old-pw", None, FAST).unwrap();
        let bytes = read_vault_file(&path).unwrap();
        let mut client = OpenVault::unlock(&bytes, b"old-pw", None).unwrap();

        // Another program writes a new vault file with a different password
        std::fs::remove_file(&path).unwrap();
        create_vault_file(&path, b"new-pw", None, FAST).unwrap();

        // Reload without password fails asking for password
        assert_eq!(
            client.reload(&path, None, None),
            Err(VaultError::PasswordRequired)
        );

        // Reload with wrong password fails
        assert!(matches!(
            client.reload(&path, Some(b"wrong-pw"), None),
            Err(VaultError::Crypto(CryptoError::WrongCredentials))
        ));

        // Reload with correct new password succeeds
        client.reload(&path, Some(b"new-pw"), None).unwrap();
        assert!(client.save(&path).is_ok());
    }

    #[test]
    fn save_refuses_missing_or_unexpected_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.shush");
        let mut v = create_vault_file(&path, b"pw", None, FAST).unwrap();

        // The file was removed or moved away by someone else.
        std::fs::remove_file(&path).unwrap();
        assert_eq!(v.save(&path), Err(VaultError::ChangedOnDisk));
        assert!(!path.exists(), "not silently recreated");

        // A brand-new vault must not replace a file that appeared meanwhile.
        let mut fresh = OpenVault::create(b"pw", None, FAST).unwrap();
        std::fs::write(&path, b"someone else's file").unwrap();
        assert_eq!(fresh.save(&path), Err(VaultError::ChangedOnDisk));
        assert_eq!(std::fs::read(&path).unwrap(), b"someone else's file");
    }

    fn sibling_exists(path: &Path, suffix: &str) -> bool {
        container::sibling(path, suffix).exists()
    }

    #[test]
    fn modify_is_transactional() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.shush");
        let mut v = create_vault_file(&path, b"pw", None, FAST).unwrap();

        v.modify::<_, VaultError>(&path, |d| {
            d.items.push(note("kept", "x"));
            Ok(())
        })
        .unwrap();
        let on_disk = OpenVault::unlock(&read_vault_file(&path).unwrap(), b"pw", None).unwrap();
        assert_eq!(on_disk.data().items.len(), 1);

        // A failing closure leaves memory untouched.
        let r: Result<(), VaultError> = v.modify(&path, |d| {
            d.items.clear();
            Err(VaultError::Malformed("nope"))
        });
        assert!(r.is_err());
        assert_eq!(v.data().items.len(), 1);

        // A failing save (target is a directory) rolls memory back.
        let r: Result<(), VaultError> = v.modify(dir.path(), |d| {
            d.items.clear();
            Ok(())
        });
        assert!(r.is_err());
        assert_eq!(v.data().items.len(), 1);
    }

    #[test]
    fn padme_properties() {
        for len in [
            0usize,
            1,
            2,
            3,
            100,
            4096,
            4097,
            9999,
            1 << 20,
            (1 << 20) + 1,
        ] {
            let p = padme(len);
            assert!(p >= len);
            assert!(
                p as f64 <= (len as f64) * 1.12 + 1.0,
                "overhead too large for {len}: {p}"
            );
        }
        assert_eq!(padme(9), 10);
        // L=1000: E=9, S=4 -> round up to a multiple of 2^(9-4)=32.
        assert_eq!(padme(1000), 1024);
    }

    #[test]
    fn decompression_bomb_is_rejected_by_frame_size() {
        // Hand-built zstd frame header (RFC 8878 §3.1.1): magic, then a frame
        // header descriptor with Single_Segment=1 and an 8-byte content size
        // declaring MAX_DECOMPRESSED + 1. No allocation may be attempted.
        let mut frame = vec![0x28, 0xB5, 0x2F, 0xFD, 0xE0];
        frame.extend_from_slice(&(MAX_DECOMPRESSED + 1).to_le_bytes());
        let mut plaintext = (frame.len() as u32).to_le_bytes().to_vec();
        plaintext.extend_from_slice(&frame);
        assert_eq!(
            decode_json::<VaultData>(&plaintext).err(),
            Some(VaultError::TooLarge)
        );
    }

    #[test]
    fn decode_rejects_garbage() {
        assert_eq!(
            decode_json::<VaultData>(b"").err(),
            Some(VaultError::CorruptPayload("missing length prefix"))
        );
        assert_eq!(
            decode_json::<VaultData>(&[255, 255, 0, 0, 1]).err(),
            Some(VaultError::CorruptPayload("length prefix out of range"))
        );
    }

    #[test]
    fn backup_kind_cannot_be_unlocked_as_vault() {
        let v = OpenVault::create(b"pw", None, FAST).unwrap();
        let mut h = v.header().clone();
        h.kind = FileKind::Backup;
        let bytes = container::seal(&h, &v.keys, &encode_json(v.data()).unwrap()).unwrap();
        assert_eq!(
            OpenVault::unlock(&bytes, b"pw", None).err(),
            Some(VaultError::WrongKind(FileKind::Backup))
        );
    }

    fn unlock_file(path: &Path, pw: &[u8]) -> Result<OpenVault, VaultError> {
        OpenVault::unlock(&read_vault_file(path).unwrap(), pw, None)
    }

    #[test]
    fn duress_password_opens_an_empty_decoy_and_saves_never_touch_the_other_slot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.shush");
        let mut real = create_vault_file(&path, b"real pw", None, FAST).unwrap();
        real.modify::<_, VaultError>(&path, |d| {
            d.items.push(note("bank", "real secret"));
            Ok(())
        })
        .unwrap();
        let size_without = std::fs::metadata(&path).unwrap().len();

        assert_eq!(
            real.set_duress(&path, b"real pw", b"real pw", None),
            Err(VaultError::DuressSameAsMaster)
        );
        assert_eq!(
            real.set_duress(&path, b"wrong", b"duress pw", None),
            Err(VaultError::Crypto(CryptoError::WrongCredentials)),
            "overwriting the other slot needs the current password"
        );
        assert!(!real.duress_enabled());
        real.set_duress(&path, b"real pw", b"duress pw", None)
            .unwrap();
        assert!(real.duress_enabled());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), size_without);

        let mut decoy = unlock_file(&path, b"duress pw").unwrap();
        assert!(decoy.data().items.is_empty(), "decoy starts empty");
        assert!(!decoy.duress_enabled(), "decoy cannot tell it is one");
        assert_ne!(decoy.slot.index, real.slot.index);

        // Saving from the decoy leaves the real slot bit-identical, and back.
        let real_slot = |bytes: &[u8], i| slots::parse(bytes).unwrap().slot(i).to_vec();
        let before = read_vault_file(&path).unwrap();
        decoy
            .modify::<_, VaultError>(&path, |d| {
                d.items.push(note("netflix", "decoy"));
                Ok(())
            })
            .unwrap();
        let after = read_vault_file(&path).unwrap();
        assert_eq!(
            real_slot(&before, real.slot.index),
            real_slot(&after, real.slot.index)
        );
        assert_ne!(
            real_slot(&before, decoy.slot.index),
            real_slot(&after, decoy.slot.index)
        );

        let mut real = unlock_file(&path, b"real pw").unwrap();
        assert_eq!(real.data().items.len(), 1);
        assert!(real.duress_enabled());
        real.modify::<_, VaultError>(&path, |d| {
            d.items.push(note("mail", "x"));
            Ok(())
        })
        .unwrap();
        assert_eq!(
            unlock_file(&path, b"duress pw").unwrap().data().items.len(),
            1,
            "decoy edits survive real saves"
        );
        assert_eq!(
            unlock_file(&path, b"wrong").err(),
            Some(VaultError::Crypto(CryptoError::WrongCredentials))
        );

        // Removing the duress password destroys the decoy.
        real.clear_duress(&path).unwrap();
        assert!(!real.duress_enabled());
        assert_eq!(
            unlock_file(&path, b"duress pw").err(),
            Some(VaultError::Crypto(CryptoError::WrongCredentials))
        );
        assert_eq!(
            unlock_file(&path, b"real pw").unwrap().data().items.len(),
            2
        );
    }

    #[test]
    fn duress_needs_the_vault_keyfile() {
        let kf = keyfile::digest_bytes(b"usb").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.shush");
        let mut v = create_vault_file(&path, b"pw", Some(&kf), FAST).unwrap();
        assert_eq!(
            v.set_duress(&path, b"pw", b"duress", None),
            Err(VaultError::KeyfileRequired)
        );
        v.set_duress(&path, b"pw", b"duress", Some(&kf)).unwrap();
        let bytes = read_vault_file(&path).unwrap();
        assert!(OpenVault::unlock(&bytes, b"duress", Some(&kf)).is_ok());
    }

    #[test]
    fn legacy_v2_vault_is_upgraded_to_v3_on_save() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.shush");
        let v = OpenVault::create(b"pw", None, FAST).unwrap();
        let v2 = container::seal(&v.header, &v.keys, &encode_json(v.data()).unwrap()).unwrap();
        std::fs::write(&path, &v2).unwrap();
        let mut opened = unlock_file(&path, b"pw").unwrap();
        opened.refresh(&path).unwrap();
        let bytes = read_vault_file(&path).unwrap();
        assert_eq!(container::read_version(&bytes), FORMAT_VERSION);
        assert!(unlock_file(&path, b"pw").is_ok());
        assert_eq!(
            std::fs::read(container::sibling(&path, "bak")).unwrap(),
            v2,
            "the v2 file is kept as .bak"
        );
    }

    /// Acceptance check for issue #8: unlock time does not depend on which
    /// slot the password opens. Timing-sensitive, so run on demand:
    /// `cargo test --release -- --ignored unlock_timing`.
    #[test]
    #[ignore]
    fn unlock_timing_is_independent_of_the_slot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.shush");
        let opts = CreateOptions {
            kdf: KdfParams {
                mem_kib: 64 * 1024,
                iterations: 2,
                parallelism: 1,
            },
            ..FAST
        };
        let mut v = create_vault_file(&path, b"real", None, opts).unwrap();
        v.set_duress(&path, b"real", b"decoy", None).unwrap();
        let bytes = read_vault_file(&path).unwrap();
        let once = |pw: &[u8]| {
            let s = std::time::Instant::now();
            let _ = OpenVault::unlock(&bytes, pw, None);
            s.elapsed().as_secs_f64()
        };
        // Interleaved, so machine load drifts affect both series alike.
        let (mut real, mut decoy) = (Vec::new(), Vec::new());
        for _ in 0..41 {
            real.push(once(b"real"));
            decoy.push(once(b"decoy"));
        }
        let median = |mut t: Vec<f64>| {
            t.sort_by(f64::total_cmp);
            t[t.len() / 2]
        };
        // Real vs decoy is what matters: a wrong password is a little faster
        // (no payload to decrypt) but reveals nothing about a second slot.
        let (real, decoy) = (median(real), median(decoy));
        assert!(
            (real - decoy).abs() / real.min(decoy) < 0.05,
            "median unlock times differ: real {real:.4}s, decoy {decoy:.4}s"
        );
    }

    #[test]
    fn read_header_without_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.shush");
        let kf = keyfile::digest_bytes(b"k").unwrap();
        create_vault_file(&path, b"pw", Some(&kf), FAST).unwrap();
        let h = read_header(&path).unwrap();
        assert!(h.keyfile_required);
        assert_eq!(h.kdf, FAST.kdf);
        assert_eq!(
            read_header(&dir.path().join("missing")).err(),
            Some(VaultError::NotFound)
        );
    }
}
