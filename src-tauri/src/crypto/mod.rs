//! Cryptographic engine (spec §3).
//!
//! Pipeline:
//!
//! ```text
//! password ─┐
//!           ├─ composite ─ Argon2id(salt, params) ─ MasterKey ─ HKDF-SHA256 ─┬─ VEK         (payload AEAD)
//! keyfile ──┘  (SHA-256)                                                      └─ canary key  (credential check)
//! ```
//!
//! Design invariants enforced here:
//! - Every key type is wiped on drop and never prints its bytes in `Debug`.
//! - Encryption always draws a fresh nonce from the OS CSPRNG; callers cannot
//!   supply one (issue #2).
//! - KDF parameters are bounds-checked *before* Argon2 runs, because a hostile
//!   header must not be able to make us allocate unbounded memory (issue #1).
//! - The AEAD layer takes AAD from the caller; which header bytes are bound is
//!   a container-format decision (issue #1, Phase 3).

#![forbid(unsafe_code)]

pub mod cipher;
pub mod kdf;
pub mod keyfile;
pub mod zeroize_guard;

pub use cipher::{CipherSuite, SealedBox, VaultKeys};
pub use kdf::{derive_master_key, KdfParams, SALT_LEN};
pub use keyfile::KeyfileDigest;
pub use zeroize_guard::{SecretBytes, SecretKey, KEY_LEN};

/// Every failure the crypto engine can report.
///
/// Variants are deliberately coarse where finer detail would help an
/// attacker: any AEAD failure on the canary is [`CryptoError::WrongCredentials`],
/// and any AEAD failure on the payload is [`CryptoError::AuthenticationFailed`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    /// KDF parameters are outside the hard safety bounds.
    #[error("invalid KDF parameters: {0}")]
    InvalidKdfParams(&'static str),
    /// The master password bytes are not valid UTF-8.
    #[error("master password is not valid UTF-8")]
    InvalidPasswordEncoding,
    /// Neither a password nor a keyfile was supplied.
    #[error("no credentials supplied: a password and/or keyfile is required")]
    EmptyCredentials,
    /// Argon2 rejected its inputs (should be unreachable after validation).
    #[error("key derivation failed")]
    KeyDerivation,
    /// The cipher suite byte does not name a supported suite.
    #[error("unsupported cipher suite id 0x{0:02x}")]
    UnsupportedCipherSuite(u8),
    /// A nonce had the wrong length for its cipher suite.
    #[error("invalid nonce length: expected {expected} bytes, got {actual}")]
    InvalidNonceLength {
        /// Length required by the suite.
        expected: usize,
        /// Length supplied.
        actual: usize,
    },
    /// Ciphertext is structurally invalid (e.g. shorter than the tag).
    #[error("malformed ciphertext")]
    MalformedCiphertext,
    /// The canary failed to authenticate: wrong password and/or keyfile
    /// (or the header was tampered with).
    #[error("wrong password or keyfile")]
    WrongCredentials,
    /// The payload failed to authenticate: corrupt or tampered data.
    #[error("authentication failed: data is corrupt or has been tampered with")]
    AuthenticationFailed,
    /// The keyfile contains no bytes.
    #[error("keyfile is empty")]
    EmptyKeyfile,
    /// The keyfile could not be read or written.
    #[error("keyfile I/O error: {0}")]
    KeyfileIo(std::io::ErrorKind),
    /// The operating system CSPRNG failed.
    #[error("operating system random number generator failure")]
    Rng,
}

/// Fills `buf` from the OS CSPRNG, mapping failure to [`CryptoError::Rng`]
/// instead of panicking.
pub(crate) fn fill_random(buf: &mut [u8]) -> Result<(), CryptoError> {
    use rand::RngCore;
    rand::rngs::OsRng
        .try_fill_bytes(buf)
        .map_err(|_| CryptoError::Rng)
}

/// End-to-end tests of the spec §3 pipeline across modules.
#[cfg(test)]
mod tests {
    use super::*;

    /// Cheap parameters so the suite stays fast; production presets are
    /// exercised separately in `kdf::tests`.
    const FAST: KdfParams = KdfParams {
        mem_kib: 1024,
        iterations: 1,
        parallelism: 1,
    };
    const AAD: &[u8] = b"SHUSH\x01\x00\x01";

    struct Vault {
        salt: [u8; SALT_LEN],
        suite: CipherSuite,
        canary: SealedBox,
        payload: SealedBox,
    }

    fn create(password: &str, kf: Option<&KeyfileDigest>, suite: CipherSuite) -> Vault {
        let salt = kdf::generate_salt().unwrap();
        let mk = derive_master_key(password.as_bytes(), kf, &salt, &FAST).unwrap();
        let keys = VaultKeys::derive(&mk);
        Vault {
            salt,
            suite,
            canary: cipher::seal_canary(suite, &keys, AAD).unwrap(),
            payload: cipher::seal_payload(suite, &keys, AAD, b"{\"items\":[]}").unwrap(),
        }
    }

    fn unlock(
        v: &Vault,
        password: &str,
        kf: Option<&KeyfileDigest>,
    ) -> Result<SecretBytes, CryptoError> {
        let mk = derive_master_key(password.as_bytes(), kf, &v.salt, &FAST)?;
        let keys = VaultKeys::derive(&mk);
        cipher::verify_canary(v.suite, &keys, &v.canary.nonce, AAD, &v.canary.ciphertext)?;
        cipher::open_payload(v.suite, &keys, &v.payload.nonce, AAD, &v.payload.ciphertext)
    }

    #[test]
    fn full_roundtrip_both_suites_with_and_without_keyfile() {
        let kf = keyfile::digest_bytes(b"physical key material").unwrap();
        for suite in CipherSuite::ALL {
            for kf in [None, Some(&kf)] {
                let v = create("correct horse", kf, suite);
                assert_eq!(
                    &*unlock(&v, "correct horse", kf).unwrap(),
                    b"{\"items\":[]}"
                );
            }
        }
    }

    #[test]
    fn wrong_password_is_reported_as_wrong_credentials() {
        for suite in CipherSuite::ALL {
            let v = create("correct horse", None, suite);
            assert_eq!(
                unlock(&v, "correct horsf", None).unwrap_err(),
                CryptoError::WrongCredentials
            );
            assert_eq!(
                unlock(&v, "", None).unwrap_err(),
                CryptoError::EmptyCredentials
            );
        }
    }

    #[test]
    fn missing_or_corrupt_keyfile_is_reported_as_wrong_credentials() {
        let original = vec![0x5a_u8; 32];
        let kf = keyfile::digest_bytes(&original).unwrap();
        let v = create("pw", Some(&kf), CipherSuite::Aes256Gcm);

        // Missing USB key.
        assert_eq!(
            unlock(&v, "pw", None).unwrap_err(),
            CryptoError::WrongCredentials
        );

        // Single-bit corruption of the keyfile.
        let mut corrupt = original.clone();
        corrupt[17] ^= 0x01;
        let bad = keyfile::digest_bytes(&corrupt).unwrap();
        assert_eq!(
            unlock(&v, "pw", Some(&bad)).unwrap_err(),
            CryptoError::WrongCredentials
        );

        // Truncated keyfile.
        let short = keyfile::digest_bytes(&original[..31]).unwrap();
        assert_eq!(
            unlock(&v, "pw", Some(&short)).unwrap_err(),
            CryptoError::WrongCredentials
        );
    }

    #[test]
    fn payload_tamper_is_distinguished_from_wrong_credentials() {
        for suite in CipherSuite::ALL {
            let mut v = create("pw", None, suite);
            v.payload.ciphertext[3] ^= 0x80;
            // Canary still verifies, so the user is told the *data* is bad,
            // not that they mistyped their password.
            assert_eq!(
                unlock(&v, "pw", None).unwrap_err(),
                CryptoError::AuthenticationFailed
            );
        }
    }

    #[test]
    fn salt_tamper_is_reported_as_wrong_credentials() {
        let mut v = create("pw", None, CipherSuite::XChaCha20Poly1305);
        v.salt[0] ^= 0x01;
        assert_eq!(
            unlock(&v, "pw", None).unwrap_err(),
            CryptoError::WrongCredentials
        );
    }
}
