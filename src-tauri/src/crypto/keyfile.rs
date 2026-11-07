//! Keyfile generation and digesting (security model §3.1).
//!
//! A keyfile is either 32 CSPRNG bytes that shush generates, or any existing
//! file the user picks. Either way, only `SHA-256(file bytes)` enters the KDF.
//! The file is hashed in streaming fashion, so a huge file cannot exhaust
//! memory (issue #22).

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::Path;

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::zeroize_guard::KEY_LEN;
use super::{fill_random, CryptoError};

/// Size of a generated keyfile in bytes (256 bits).
pub const KEYFILE_LEN: usize = 32;

const READ_CHUNK: usize = 64 * 1024;

/// `SHA-256(keyfile bytes)`, wiped on drop and redacted in `Debug`.
///
/// Limitation: `sha2` 0.10 does not zeroize its internal block buffer, so up
/// to 64 bytes of the keyfile's tail can remain in freed stack memory.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KeyfileDigest([u8; KEY_LEN]);

impl KeyfileDigest {
    /// Borrows the digest bytes.
    pub fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    fn from_hasher(hasher: Sha256) -> Self {
        let mut out = Self([0u8; KEY_LEN]);
        hasher.finalize_into((&mut out.0).into());
        out
    }
}

impl core::fmt::Debug for KeyfileDigest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KeyfileDigest([REDACTED])")
    }
}

/// Generates fresh keyfile contents: 32 bytes from the OS CSPRNG.
pub fn generate() -> Result<Zeroizing<[u8; KEYFILE_LEN]>, CryptoError> {
    let mut bytes = Zeroizing::new([0u8; KEYFILE_LEN]);
    fill_random(bytes.as_mut())?;
    Ok(bytes)
}

/// Generates a new keyfile at `path` and returns its digest.
///
/// The file is created with `create_new`, so an existing file (perhaps an
/// existing keyfile!) is **never** overwritten. Data is flushed to disk before
/// returning.
pub fn create_keyfile(path: &Path) -> Result<KeyfileDigest, CryptoError> {
    let bytes = generate()?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| CryptoError::KeyfileIo(e.kind()))?;
    let written = file
        .write_all(bytes.as_ref())
        .and_then(|()| file.sync_all());
    if let Err(e) = written {
        drop(file);
        // Best effort: do not leave a partial keyfile that looks valid.
        let _ = std::fs::remove_file(path);
        return Err(CryptoError::KeyfileIo(e.kind()));
    }
    digest_bytes(bytes.as_ref())
}

/// Digests in-memory keyfile contents.
pub fn digest_bytes(bytes: &[u8]) -> Result<KeyfileDigest, CryptoError> {
    if bytes.is_empty() {
        return Err(CryptoError::EmptyKeyfile);
    }
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(KeyfileDigest::from_hasher(hasher))
}

/// Digests a keyfile from any reader, in chunks of 64 KiB.
pub fn digest_reader<R: Read>(mut reader: R) -> Result<KeyfileDigest, CryptoError> {
    let mut hasher = Sha256::new();
    let mut buf = Zeroizing::new(vec![0u8; READ_CHUNK]);
    let mut total: u64 = 0;
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(CryptoError::KeyfileIo(e.kind())),
        };
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    if total == 0 {
        return Err(CryptoError::EmptyKeyfile);
    }
    Ok(KeyfileDigest::from_hasher(hasher))
}

/// Opens and digests the keyfile at `path`.
pub fn digest_file(path: &Path) -> Result<KeyfileDigest, CryptoError> {
    let file = std::fs::File::open(path).map_err(|e| CryptoError::KeyfileIo(e.kind()))?;
    digest_reader(std::io::BufReader::with_capacity(READ_CHUNK, file))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;

    #[test]
    fn sha256_known_answer() {
        // FIPS 180-2 test vector "abc".
        let d = digest_bytes(b"abc").unwrap();
        assert_eq!(
            hex::encode(d.expose()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn generated_keyfiles_are_32_random_bytes() {
        let a = generate().unwrap();
        let b = generate().unwrap();
        assert_eq!(a.len(), KEYFILE_LEN);
        assert_ne!(*a, *b);
        assert_ne!(*a, [0u8; KEYFILE_LEN]);
    }

    #[test]
    fn streaming_digest_matches_one_shot_across_chunk_boundaries() {
        let data: Vec<u8> = (0..(3 * READ_CHUNK + 17))
            .map(|i| (i * 31 % 251) as u8)
            .collect();
        let streamed = digest_reader(std::io::Cursor::new(&data)).unwrap();
        assert_eq!(streamed.expose(), digest_bytes(&data).unwrap().expose());
    }

    #[test]
    fn empty_keyfile_is_rejected() {
        assert_eq!(digest_bytes(b"").unwrap_err(), CryptoError::EmptyKeyfile);
        assert_eq!(
            digest_reader(std::io::empty()).unwrap_err(),
            CryptoError::EmptyKeyfile
        );
    }

    #[test]
    fn create_then_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.key");
        let created = create_keyfile(&path).unwrap();

        assert_eq!(std::fs::metadata(&path).unwrap().len(), KEYFILE_LEN as u64);
        assert_eq!(digest_file(&path).unwrap().expose(), created.expose());
    }

    #[test]
    fn create_never_overwrites_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.key");
        std::fs::write(&path, b"precious existing keyfile").unwrap();

        assert_eq!(
            create_keyfile(&path).unwrap_err(),
            CryptoError::KeyfileIo(ErrorKind::AlreadyExists)
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"precious existing keyfile");
    }

    #[test]
    fn missing_keyfile_reports_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let err = digest_file(&dir.path().join("absent.key")).unwrap_err();
        assert_eq!(err, CryptoError::KeyfileIo(ErrorKind::NotFound));
    }

    #[test]
    fn single_bit_change_changes_digest() {
        let mut data = vec![0u8; 32];
        let a = digest_bytes(&data).unwrap();
        data[31] ^= 1;
        assert_ne!(a.expose(), digest_bytes(&data).unwrap().expose());
    }

    #[test]
    fn debug_output_is_redacted() {
        assert_eq!(
            format!("{:?}", digest_bytes(b"x").unwrap()),
            "KeyfileDigest([REDACTED])"
        );
    }
}
