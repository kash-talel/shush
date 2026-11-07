//! `vault.shush` binary container (spec §4) and crash-safe disk writer.
//!
//! Layout (all integers little-endian):
//!
//! | Offset | Len | Field              |
//! |-------:|----:|--------------------|
//! | 0x00   |   5 | MAGIC `SHUSH` / `SHBKP` |
//! | 0x05   |   2 | FORMAT_VERSION (1) |
//! | 0x07   |   1 | CIPHER_SUITE_ID    |
//! | 0x08   |   1 | FLAGS (bit 0: keyfile) |
//! | 0x09   |   4 | ARGON2_MEM_KIB     |
//! | 0x0D   |   4 | ARGON2_ITERATIONS  |
//! | 0x11   |   4 | ARGON2_PARALLELISM |
//! | 0x15   |  32 | KDF_SALT           |
//! | 0x35   |  24 | CANARY_NONCE (zero-padded) |
//! | 0x4D   |  33 | CANARY_CIPHERTEXT  |
//! | 0x6E   |  24 | PAYLOAD_NONCE (zero-padded) |
//! | 0x86   |   4 | PAYLOAD_LENGTH     |
//! | 0x8A   |   N | PAYLOAD_CIPHERTEXT |
//!
//! Header authentication (issue #1): every header byte is bound into an AEAD
//! tag. The canary's AAD is `[0x00, 0x35)`; the payload's AAD is
//! `[0x00, 0x6E) || PAYLOAD_LENGTH`. Each nonce is authenticated by its own
//! AEAD, and nonce padding must be zero, so no byte can change undetected.

use std::fs::{self, File};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::crypto::cipher::{self, CANARY_CIPHERTEXT_LEN, MAX_NONCE_LEN, TAG_LEN};
use crate::crypto::{CipherSuite, KdfParams, SecretBytes, VaultKeys, SALT_LEN};

use super::VaultError;

/// Magic for the primary vault file.
pub const MAGIC_VAULT: [u8; 5] = *b"SHUSH";
/// Magic for `.shushbackup` files (spec §9.1).
pub const MAGIC_BACKUP: [u8; 5] = *b"SHBKP";
/// The only format version this build reads and writes.
pub const FORMAT_VERSION: u16 = 1;
/// FLAGS bit 0: a keyfile is part of the credentials.
pub const FLAG_KEYFILE: u8 = 0x01;
const KNOWN_FLAGS: u8 = FLAG_KEYFILE;

const OFF_VERSION: usize = 0x05;
const OFF_CIPHER: usize = 0x07;
const OFF_FLAGS: usize = 0x08;
const OFF_MEM: usize = 0x09;
const OFF_ITER: usize = 0x0D;
const OFF_PAR: usize = 0x11;
const OFF_SALT: usize = 0x15;
const OFF_CANARY_NONCE: usize = 0x35;
const OFF_CANARY_CT: usize = 0x4D;
const OFF_PAYLOAD_NONCE: usize = 0x6E;
const OFF_PAYLOAD_LEN: usize = 0x86;
/// Total header length; the payload ciphertext starts here.
pub const HEADER_LEN: usize = 0x8A;

// The spec's offsets must agree with the field sizes.
const _: () = assert!(OFF_SALT + SALT_LEN == OFF_CANARY_NONCE);
const _: () = assert!(OFF_CANARY_NONCE + MAX_NONCE_LEN == OFF_CANARY_CT);
const _: () = assert!(OFF_CANARY_CT + CANARY_CIPHERTEXT_LEN == OFF_PAYLOAD_NONCE);
const _: () = assert!(OFF_PAYLOAD_NONCE + MAX_NONCE_LEN == OFF_PAYLOAD_LEN);
const _: () = assert!(OFF_PAYLOAD_LEN + 4 == HEADER_LEN);

/// Largest payload ciphertext accepted (512 MiB). Bounds memory use when
/// reading untrusted files (issue #5).
pub const MAX_PAYLOAD_LEN: u32 = 512 * 1024 * 1024;

/// Which kind of envelope a file is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    /// `vault.shush`.
    Vault,
    /// `.shushbackup`.
    Backup,
}

impl FileKind {
    fn magic(self) -> [u8; 5] {
        match self {
            Self::Vault => MAGIC_VAULT,
            Self::Backup => MAGIC_BACKUP,
        }
    }
}

/// Plaintext (but authenticated) header fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Envelope kind (from MAGIC).
    pub kind: FileKind,
    /// AEAD suite.
    pub suite: CipherSuite,
    /// Whether a keyfile is required.
    pub keyfile_required: bool,
    /// Argon2id parameters.
    pub kdf: KdfParams,
    /// Argon2id salt.
    pub salt: [u8; SALT_LEN],
}

impl Header {
    /// Serializes the fixed fields `[0x00, 0x35)`; this is also the canary's AAD.
    fn fixed_bytes(&self) -> [u8; OFF_CANARY_NONCE] {
        let mut b = [0u8; OFF_CANARY_NONCE];
        b[..OFF_VERSION].copy_from_slice(&self.kind.magic());
        b[OFF_VERSION..OFF_CIPHER].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        b[OFF_CIPHER] = self.suite.id();
        b[OFF_FLAGS] = if self.keyfile_required {
            FLAG_KEYFILE
        } else {
            0
        };
        b[OFF_MEM..OFF_ITER].copy_from_slice(&self.kdf.mem_kib.to_le_bytes());
        b[OFF_ITER..OFF_PAR].copy_from_slice(&self.kdf.iterations.to_le_bytes());
        b[OFF_PAR..OFF_SALT].copy_from_slice(&self.kdf.parallelism.to_le_bytes());
        b[OFF_SALT..OFF_CANARY_NONCE].copy_from_slice(&self.salt);
        b
    }

    /// Parses and validates the fixed header fields. Cheap, and needs no key,
    /// so the UI can learn e.g. whether a keyfile is required before unlocking.
    /// KDF parameters are bounds-checked here, before any KDF can run.
    pub fn parse(bytes: &[u8]) -> Result<Self, VaultError> {
        if bytes.len() < OFF_CANARY_NONCE {
            return Err(if bytes.len() >= 5 && is_known_magic(&bytes[..5]) {
                VaultError::Truncated
            } else {
                VaultError::NotAVault
            });
        }
        let kind = match &bytes[..OFF_VERSION] {
            m if m == MAGIC_VAULT => FileKind::Vault,
            m if m == MAGIC_BACKUP => FileKind::Backup,
            _ => return Err(VaultError::NotAVault),
        };
        let version = u16::from_le_bytes([bytes[OFF_VERSION], bytes[OFF_VERSION + 1]]);
        if version != FORMAT_VERSION {
            return Err(VaultError::UnsupportedVersion(version));
        }
        let suite = CipherSuite::from_id(bytes[OFF_CIPHER])?;
        let flags = bytes[OFF_FLAGS];
        if flags & !KNOWN_FLAGS != 0 {
            return Err(VaultError::Malformed("unknown flag bits set"));
        }
        let kdf = KdfParams {
            mem_kib: read_u32(bytes, OFF_MEM),
            iterations: read_u32(bytes, OFF_ITER),
            parallelism: read_u32(bytes, OFF_PAR),
        };
        kdf.validate()?;
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&bytes[OFF_SALT..OFF_CANARY_NONCE]);
        Ok(Self {
            kind,
            suite,
            keyfile_required: flags & FLAG_KEYFILE != 0,
            kdf,
            salt,
        })
    }
}

fn is_known_magic(m: &[u8]) -> bool {
    m == MAGIC_VAULT || m == MAGIC_BACKUP
}

fn read_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn padded_nonce(nonce: &[u8]) -> [u8; MAX_NONCE_LEN] {
    let mut out = [0u8; MAX_NONCE_LEN];
    out[..nonce.len()].copy_from_slice(nonce);
    out
}

/// Seals `plaintext` into a complete container file image under `keys`.
/// A fresh canary nonce and payload nonce are drawn on every call (issue #2).
pub fn seal(header: &Header, keys: &VaultKeys, plaintext: &[u8]) -> Result<Vec<u8>, VaultError> {
    let payload_len = plaintext
        .len()
        .checked_add(TAG_LEN)
        .filter(|&n| n <= MAX_PAYLOAD_LEN as usize)
        .ok_or(VaultError::TooLarge)? as u32;

    let fixed = header.fixed_bytes();
    let canary = cipher::seal_canary(header.suite, keys, &fixed)?;

    let mut out = Vec::with_capacity(HEADER_LEN + payload_len as usize);
    out.extend_from_slice(&fixed);
    out.extend_from_slice(&padded_nonce(&canary.nonce));
    out.extend_from_slice(&canary.ciphertext);

    let mut aad = Vec::with_capacity(OFF_PAYLOAD_NONCE + 4);
    aad.extend_from_slice(&out);
    aad.extend_from_slice(&payload_len.to_le_bytes());
    let payload = cipher::seal_payload(header.suite, keys, &aad, plaintext)?;
    debug_assert_eq!(payload.ciphertext.len(), payload_len as usize);

    out.extend_from_slice(&padded_nonce(&payload.nonce));
    out.extend_from_slice(&payload_len.to_le_bytes());
    out.extend_from_slice(&payload.ciphertext);
    Ok(out)
}

/// A parsed, structurally valid container that has not been decrypted yet.
#[derive(Debug)]
pub struct Sealed<'a> {
    /// Authenticated header fields.
    pub header: Header,
    bytes: &'a [u8],
}

/// Parses a complete container file image, validating every structural rule
/// before any cryptography runs.
pub fn parse(bytes: &[u8]) -> Result<Sealed<'_>, VaultError> {
    let header = Header::parse(bytes)?;
    if bytes.len() < HEADER_LEN {
        return Err(VaultError::Truncated);
    }
    let nl = header.suite.nonce_len();
    for off in [OFF_CANARY_NONCE, OFF_PAYLOAD_NONCE] {
        if bytes[off + nl..off + MAX_NONCE_LEN].iter().any(|&b| b != 0) {
            return Err(VaultError::Malformed("nonzero nonce padding"));
        }
    }
    let payload_len = read_u32(bytes, OFF_PAYLOAD_LEN);
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(VaultError::TooLarge);
    }
    if (payload_len as usize) < TAG_LEN {
        return Err(VaultError::Malformed("payload shorter than tag"));
    }
    match (bytes.len() - HEADER_LEN).cmp(&(payload_len as usize)) {
        std::cmp::Ordering::Less => return Err(VaultError::Truncated),
        std::cmp::Ordering::Greater => return Err(VaultError::Malformed("trailing bytes")),
        std::cmp::Ordering::Equal => {}
    }
    Ok(Sealed { header, bytes })
}

impl Sealed<'_> {
    /// Verifies the credentials against the canary. Fast after the KDF;
    /// distinguishes "wrong password/keyfile" from "corrupt payload".
    pub fn verify_canary(&self, keys: &VaultKeys) -> Result<(), VaultError> {
        let nl = self.header.suite.nonce_len();
        cipher::verify_canary(
            self.header.suite,
            keys,
            &self.bytes[OFF_CANARY_NONCE..OFF_CANARY_NONCE + nl],
            &self.bytes[..OFF_CANARY_NONCE],
            &self.bytes[OFF_CANARY_CT..OFF_PAYLOAD_NONCE],
        )?;
        Ok(())
    }

    /// Decrypts the payload. Call [`Self::verify_canary`] first.
    pub fn open_payload(&self, keys: &VaultKeys) -> Result<SecretBytes, VaultError> {
        let nl = self.header.suite.nonce_len();
        let mut aad = Vec::with_capacity(OFF_PAYLOAD_NONCE + 4);
        aad.extend_from_slice(&self.bytes[..OFF_PAYLOAD_NONCE]);
        aad.extend_from_slice(&self.bytes[OFF_PAYLOAD_LEN..HEADER_LEN]);
        Ok(cipher::open_payload(
            self.header.suite,
            keys,
            &self.bytes[OFF_PAYLOAD_NONCE..OFF_PAYLOAD_NONCE + nl],
            &aad,
            &self.bytes[HEADER_LEN..],
        )?)
    }
}

/// `vault.shush` -> `vault.shush.<suffix>`.
pub fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".");
    name.push(suffix);
    path.with_file_name(name)
}

/// Crash-safe replacement of `path` with `bytes` (issue #11):
///
/// 1. write `path.tmp` and `fsync` it;
/// 2. read it back, require byte equality, and run `verify` (decrypt check);
/// 3. copy the current file to `path.bak` (previous generation);
/// 4. rename `path.tmp` over `path`, retrying briefly on the sharing
///    violations antivirus / indexers / sync clients commonly cause.
///
/// At every step either the old or the new vault is intact on disk.
pub fn write_atomic(
    path: &Path,
    bytes: &[u8],
    verify: impl FnOnce(&[u8]) -> Result<(), VaultError>,
) -> Result<(), VaultError> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let tmp = sibling(path, "tmp");
    let result = (|| {
        {
            let mut f = File::create(&tmp)?;
            f.write_all(bytes)?;
            f.sync_all()?;
        }
        let readback = fs::read(&tmp)?;
        if readback != bytes {
            return Err(VaultError::WriteVerifyFailed);
        }
        verify(&readback)?;

        if path.exists() {
            let bak = sibling(path, "bak");
            fs::copy(path, &bak)?;
            // FlushFileBuffers requires a handle with write access on Windows.
            fs::OpenOptions::new().write(true).open(&bak)?.sync_all()?;
        }
        rename_with_retry(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn rename_with_retry(from: &Path, to: &Path) -> Result<(), VaultError> {
    const ATTEMPTS: u32 = 10;
    let mut attempt = 0;
    loop {
        match fs::rename(from, to) {
            Ok(()) => return Ok(()),
            Err(e) if attempt + 1 < ATTEMPTS && is_transient(&e) => {
                attempt += 1;
                std::thread::sleep(Duration::from_millis(25 * u64::from(attempt)));
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// Access-denied / sharing-violation errors that usually clear within
/// milliseconds when another process briefly holds the file.
fn is_transient(e: &std::io::Error) -> bool {
    const ERROR_SHARING_VIOLATION: i32 = 32;
    const ERROR_LOCK_VIOLATION: i32 = 33;
    e.kind() == ErrorKind::PermissionDenied
        || matches!(
            e.raw_os_error(),
            Some(ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION)
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{CryptoError, SecretKey};

    fn keys(b: u8) -> VaultKeys {
        // Derive from a deterministic, non-zero master key without running Argon2.
        let mut mk = SecretKey::zeroed();
        mk.as_mut_bytes().fill(b);
        VaultKeys::derive(&mk)
    }

    fn header(suite: CipherSuite) -> Header {
        Header {
            kind: FileKind::Vault,
            suite,
            keyfile_required: true,
            kdf: KdfParams::INTERACTIVE,
            salt: [9u8; SALT_LEN],
        }
    }

    #[test]
    fn layout_matches_spec_offsets() {
        let k = keys(1);
        let file = seal(&header(CipherSuite::Aes256Gcm), &k, b"hello").unwrap();
        assert_eq!(&file[..5], b"SHUSH");
        assert_eq!(&file[5..7], &[1, 0]);
        assert_eq!(file[7], 0x01);
        assert_eq!(file[8], FLAG_KEYFILE);
        assert_eq!(read_u32(&file, 0x09), 65536);
        assert_eq!(read_u32(&file, 0x0D), 3);
        assert_eq!(read_u32(&file, 0x11), 4);
        assert_eq!(&file[0x15..0x35], &[9u8; 32]);
        assert_eq!(
            &file[0x35 + 12..0x4D],
            &[0u8; 12],
            "AES nonce zero-padded to 24"
        );
        assert_eq!(read_u32(&file, 0x86) as usize, 5 + TAG_LEN);
        assert_eq!(file.len(), HEADER_LEN + 5 + TAG_LEN);
    }

    #[test]
    fn roundtrip_both_suites() {
        let k = keys(2);
        for suite in CipherSuite::ALL {
            let h = header(suite);
            let file = seal(&h, &k, b"payload").unwrap();
            let sealed = parse(&file).unwrap();
            assert_eq!(sealed.header, h);
            sealed.verify_canary(&k).unwrap();
            assert_eq!(&*sealed.open_payload(&k).unwrap(), b"payload");
        }
    }

    #[test]
    fn every_single_byte_tamper_is_detected() {
        let k = keys(3);
        for suite in CipherSuite::ALL {
            let file = seal(&header(suite), &k, b"secret payload").unwrap();
            for i in 0..file.len() {
                let mut t = file.clone();
                t[i] ^= 0x01;
                let opened = parse(&t)
                    .and_then(|s| s.verify_canary(&k).map(|()| s))
                    .and_then(|s| s.open_payload(&k));
                assert!(
                    opened.is_err(),
                    "{suite:?}: flipping byte 0x{i:02x} went undetected"
                );
            }
        }
    }

    #[test]
    fn header_tamper_is_reported_as_wrong_credentials_not_success() {
        // Flags / KDF params / salt live in the canary AAD.
        let k = keys(4);
        let file = seal(&header(CipherSuite::Aes256Gcm), &k, b"x").unwrap();
        for off in [OFF_FLAGS, OFF_ITER, OFF_SALT + 5] {
            let mut t = file.clone();
            t[off] ^= if off == OFF_FLAGS { FLAG_KEYFILE } else { 0x01 };
            let s = parse(&t).unwrap();
            assert_eq!(
                s.verify_canary(&k).unwrap_err(),
                VaultError::Crypto(CryptoError::WrongCredentials),
                "offset {off:#x}"
            );
        }
    }

    #[test]
    fn canary_length_and_payload_length_tamper_detected() {
        let k = keys(5);
        let file = seal(&header(CipherSuite::XChaCha20Poly1305), &k, b"x").unwrap();
        // Payload ciphertext byte: canary OK, payload fails.
        let mut t = file.clone();
        *t.last_mut().unwrap() ^= 1;
        let s = parse(&t).unwrap();
        s.verify_canary(&k).unwrap();
        assert_eq!(
            s.open_payload(&k).unwrap_err(),
            VaultError::Crypto(CryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn structural_validation() {
        let k = keys(6);
        let file = seal(&header(CipherSuite::Aes256Gcm), &k, b"abc").unwrap();

        assert_eq!(parse(b"").unwrap_err(), VaultError::NotAVault);
        assert_eq!(
            parse(b"MZ\x90\x00 not a vault at all, just some bytes....................")
                .unwrap_err(),
            VaultError::NotAVault
        );
        assert_eq!(parse(&file[..20]).unwrap_err(), VaultError::Truncated);
        assert_eq!(
            parse(&file[..HEADER_LEN + 3]).unwrap_err(),
            VaultError::Truncated
        );

        let mut extra = file.clone();
        extra.push(0);
        assert_eq!(
            parse(&extra).unwrap_err(),
            VaultError::Malformed("trailing bytes")
        );

        let mut v2 = file.clone();
        v2[OFF_VERSION] = 2;
        assert_eq!(parse(&v2).unwrap_err(), VaultError::UnsupportedVersion(2));

        let mut bad_suite = file.clone();
        bad_suite[OFF_CIPHER] = 0x7F;
        assert_eq!(
            parse(&bad_suite).unwrap_err(),
            VaultError::Crypto(CryptoError::UnsupportedCipherSuite(0x7F))
        );

        let mut flags = file.clone();
        flags[OFF_FLAGS] = 0x80;
        assert_eq!(
            parse(&flags).unwrap_err(),
            VaultError::Malformed("unknown flag bits set")
        );

        let mut pad = file.clone();
        pad[OFF_CANARY_NONCE + 20] = 1;
        assert_eq!(
            parse(&pad).unwrap_err(),
            VaultError::Malformed("nonzero nonce padding")
        );

        let mut huge = file.clone();
        huge[OFF_PAYLOAD_LEN..HEADER_LEN].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(parse(&huge).unwrap_err(), VaultError::TooLarge);
    }

    #[test]
    fn hostile_kdf_params_rejected_at_parse() {
        let k = keys(7);
        let mut file = seal(&header(CipherSuite::Aes256Gcm), &k, b"x").unwrap();
        file[OFF_MEM..OFF_ITER].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            Header::parse(&file).unwrap_err(),
            VaultError::Crypto(CryptoError::InvalidKdfParams(_))
        ));
    }

    #[test]
    fn backup_magic_is_a_distinct_kind() {
        let k = keys(8);
        let mut h = header(CipherSuite::Aes256Gcm);
        h.kind = FileKind::Backup;
        let file = seal(&h, &k, b"x").unwrap();
        assert_eq!(&file[..5], b"SHBKP");
        assert_eq!(parse(&file).unwrap().header.kind, FileKind::Backup);

        // Relabelling a backup as a vault breaks authentication.
        let mut relabelled = file.clone();
        relabelled[..5].copy_from_slice(b"SHUSH");
        assert!(parse(&relabelled).unwrap().verify_canary(&k).is_err());
    }

    #[test]
    fn every_seal_uses_fresh_nonces() {
        let k = keys(9);
        let h = header(CipherSuite::Aes256Gcm);
        let a = seal(&h, &k, b"same").unwrap();
        let b = seal(&h, &k, b"same").unwrap();
        assert_ne!(
            a[OFF_CANARY_NONCE..OFF_CANARY_CT],
            b[OFF_CANARY_NONCE..OFF_CANARY_CT]
        );
        assert_ne!(
            a[OFF_PAYLOAD_NONCE..OFF_PAYLOAD_LEN],
            b[OFF_PAYLOAD_NONCE..OFF_PAYLOAD_LEN]
        );
    }

    #[test]
    fn atomic_write_creates_backup_and_leaves_no_tmp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("vault.shush");

        write_atomic(&path, b"generation-1", |_| Ok(())).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"generation-1");
        assert!(!sibling(&path, "bak").exists(), "no backup on first write");

        write_atomic(&path, b"generation-2", |_| Ok(())).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"generation-2");
        assert_eq!(fs::read(sibling(&path, "bak")).unwrap(), b"generation-1");
        assert!(!sibling(&path, "tmp").exists());
    }

    #[test]
    fn failed_verification_keeps_the_old_vault() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.shush");
        write_atomic(&path, b"good", |_| Ok(())).unwrap();

        let err = write_atomic(&path, b"bad", |_| Err(VaultError::WriteVerifyFailed)).unwrap_err();
        assert_eq!(err, VaultError::WriteVerifyFailed);
        assert_eq!(fs::read(&path).unwrap(), b"good");
        assert!(!sibling(&path, "tmp").exists());
    }

    #[test]
    fn sibling_names() {
        let p = Path::new(r"C:\data\vault.shush");
        assert_eq!(sibling(p, "tmp"), Path::new(r"C:\data\vault.shush.tmp"));
        assert_eq!(sibling(p, "bak"), Path::new(r"C:\data\vault.shush.bak"));
    }
}
