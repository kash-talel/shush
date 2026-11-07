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
pub mod models;
pub mod state;

use std::io::ErrorKind;
use std::path::Path;

use zeroize::Zeroizing;

use crate::crypto::{
    derive_master_key, kdf, CipherSuite, CryptoError, KdfParams, KeyfileDigest, SecretBytes,
    VaultKeys,
};
use container::{FileKind, Header, HEADER_LEN, MAX_PAYLOAD_LEN};
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
        })
    }

    /// Decrypts a vault file image.
    pub fn unlock(
        bytes: &[u8],
        password: &[u8],
        keyfile: Option<&KeyfileDigest>,
    ) -> Result<Self, VaultError> {
        let sealed = container::parse(bytes)?;
        let header = sealed.header.clone();
        if header.kind != FileKind::Vault {
            return Err(VaultError::WrongKind(header.kind));
        }
        match (header.keyfile_required, keyfile.is_some()) {
            (true, false) => return Err(VaultError::KeyfileRequired),
            (false, true) => return Err(VaultError::KeyfileNotExpected),
            _ => {}
        }
        let master = derive_master_key(password, keyfile, &header.salt, &header.kdf)?;
        let keys = VaultKeys::derive(&master);
        sealed.verify_canary(&keys)?;
        let plaintext = sealed.open_payload(&keys)?;
        let data: VaultData = decode_json(&plaintext)?;
        Ok(Self { header, keys, data })
    }

    /// Serializes and seals the vault into a complete file image.
    pub fn to_bytes(&self) -> Result<Vec<u8>, VaultError> {
        let plaintext = encode_json(&self.data)?;
        container::seal(&self.header, &self.keys, &plaintext)
    }

    /// Writes the vault crash-safely, verifying the written bytes decrypt
    /// back to the same data before the old file is replaced.
    pub fn save(&self, path: &Path) -> Result<(), VaultError> {
        let bytes = self.to_bytes()?;
        container::write_atomic(path, &bytes, |written| {
            let sealed = container::parse(written)?;
            sealed.verify_canary(&self.keys)?;
            let data: VaultData = decode_json(&sealed.open_payload(&self.keys)?)?;
            if data == self.data {
                Ok(())
            } else {
                Err(VaultError::WriteVerifyFailed)
            }
        })
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
    if len > HEADER_LEN as u64 + u64::from(MAX_PAYLOAD_LEN) {
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
    let vault = OpenVault::create(password, keyfile, options)?;
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
    // Limitation (issue #6): serde_json grows its Vec while writing, which can
    // leave unwiped fragments in freed memory.
    let json = Zeroizing::new(
        serde_json::to_vec(data).map_err(|_| VaultError::CorruptPayload("serialization failed"))?,
    );
    let compressed = Zeroizing::new(
        zstd::bulk::compress(&json, ZSTD_LEVEL)
            .map_err(|_| VaultError::CorruptPayload("compression failed"))?,
    );
    let framed_len = 4 + compressed.len();
    let total = padme(framed_len).max(MIN_PADDED);
    let mut out = SecretBytes::new(Vec::with_capacity(total));
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
    // Exact capacity from the frame header: no reallocation, no stale copies.
    let json = Zeroizing::new(
        zstd::bulk::decompress(compressed, size as usize)
            .map_err(|_| VaultError::CorruptPayload("decompression failed"))?,
    );
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
