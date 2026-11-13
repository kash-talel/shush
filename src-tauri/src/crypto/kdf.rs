//! Argon2id key derivation (spec §3.1, as amended by issue #3).
//!
//! Inputs to Argon2id (RFC 9106 §3.1):
//! - `P` (password): `UTF-8(NFC(master password))`
//! - `S` (salt):     32-byte per-vault random salt
//! - `K` (secret):   `SHA-256(keyfile)` when a keyfile is used, else empty
//!
//! Feeding the keyfile digest through Argon2's dedicated secret input gives
//! unambiguous domain separation (no `password || digest` concatenation), and
//! NFC normalization means the same visible password always yields the same
//! bytes regardless of keyboard layout / IME.

use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

use super::keyfile::KeyfileDigest;
use super::zeroize_guard::{SecretKey, KEY_LEN};
use super::{fill_random, CryptoError};
use zeroize::Zeroizing;

/// Length of the per-vault Argon2 salt in bytes.
pub const SALT_LEN: usize = 32;

/// Argon2id cost parameters, stored in the vault header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub mem_kib: u32,
    /// Number of passes (time cost).
    pub iterations: u32,
    /// Number of lanes. `argon2` 0.5 runs lanes sequentially on one thread, so
    /// this changes the key but gives no speedup (issue #21).
    pub parallelism: u32,
}

impl KdfParams {
    /// Spec default "Interactive" preset: 64 MiB, 3 passes, 4 lanes.
    pub const INTERACTIVE: Self = Self {
        mem_kib: 64 * 1024,
        iterations: 3,
        parallelism: 4,
    };
    /// Spec "Hardened / Paranoid" preset: 256 MiB, 8 passes, 4 lanes.
    pub const HARDENED: Self = Self {
        mem_kib: 256 * 1024,
        iterations: 8,
        parallelism: 4,
    };

    /// Hard upper bound on memory (2 GiB). Above this a hostile header is a DoS.
    pub const MAX_MEM_KIB: u32 = 2 * 1024 * 1024;
    /// Hard upper bound on passes.
    pub const MAX_ITERATIONS: u32 = 64;
    /// Hard upper bound on lanes.
    pub const MAX_PARALLELISM: u32 = 16;

    /// Policy floor for *new* vaults (OWASP: m ≥ 19 MiB, t ≥ 2).
    pub const POLICY_MIN_MEM_KIB: u32 = 19 * 1024;
    /// Policy floor for passes on new vaults.
    pub const POLICY_MIN_ITERATIONS: u32 = 2;

    /// Checks the hard safety bounds. This runs **before** any memory is
    /// allocated, because the parameters come from an untrusted file header
    /// (issue #1).
    pub fn validate(&self) -> Result<(), CryptoError> {
        if self.parallelism == 0 || self.parallelism > Self::MAX_PARALLELISM {
            return Err(CryptoError::InvalidKdfParams(
                "parallelism out of range 1..=16",
            ));
        }
        if self.iterations == 0 || self.iterations > Self::MAX_ITERATIONS {
            return Err(CryptoError::InvalidKdfParams(
                "iterations out of range 1..=64",
            ));
        }
        if self.mem_kib > Self::MAX_MEM_KIB {
            return Err(CryptoError::InvalidKdfParams("memory exceeds 2 GiB limit"));
        }
        if self.mem_kib < 8 * self.parallelism {
            return Err(CryptoError::InvalidKdfParams(
                "memory must be at least 8 KiB per lane",
            ));
        }
        Ok(())
    }

    /// True if these parameters are strong enough to *create* a vault with.
    /// Weaker parameters may still be opened (they were valid when written).
    pub fn meets_policy(&self) -> bool {
        self.validate().is_ok()
            && self.mem_kib >= Self::POLICY_MIN_MEM_KIB
            && self.iterations >= Self::POLICY_MIN_ITERATIONS
    }

    fn to_argon2(self, secret: &[u8]) -> Result<Argon2<'_>, CryptoError> {
        self.validate()?;
        let params = Params::new(
            self.mem_kib,
            self.iterations,
            self.parallelism,
            Some(KEY_LEN),
        )
        .map_err(|_| CryptoError::InvalidKdfParams("rejected by argon2"))?;
        if secret.is_empty() {
            return Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params));
        }
        Argon2::new_with_secret(secret, Algorithm::Argon2id, Version::V0x13, params)
            .map_err(|_| CryptoError::KeyDerivation)
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::INTERACTIVE
    }
}

/// Generates a fresh random per-vault salt.
pub fn generate_salt() -> Result<[u8; SALT_LEN], CryptoError> {
    let mut salt = [0u8; SALT_LEN];
    fill_random(&mut salt)?;
    Ok(salt)
}

/// Normalizes a master password to Unicode NFC and returns its UTF-8 bytes
/// in a wiped buffer.
///
/// The output buffer is pre-sized (NFC never expands by more than 3x), so it
/// is not reallocated and no unwiped copy is left behind.
pub fn normalize_password(password: &[u8]) -> Result<Zeroizing<String>, CryptoError> {
    let text = core::str::from_utf8(password).map_err(|_| CryptoError::InvalidPasswordEncoding)?;
    let mut out = Zeroizing::new(String::with_capacity(text.len() * 3));
    out.extend(text.nfc());
    Ok(out)
}

/// Derives the 256-bit master key with Argon2id (RFC 9106, v1.3).
///
/// `password` must be UTF-8; it is NFC-normalized here. A keyfile-only vault
/// (empty password + keyfile) is allowed; no credentials at all is not.
///
/// This is CPU- and memory-heavy (~100 ms to seconds). Call it from a blocking
/// thread (`tauri::async_runtime::spawn_blocking`), never from the UI or async
/// executor (issue #21).
pub fn derive_master_key(
    password: &[u8],
    keyfile: Option<&KeyfileDigest>,
    salt: &[u8; SALT_LEN],
    params: &KdfParams,
) -> Result<SecretKey, CryptoError> {
    // Validate (cheap, bounds-only) before touching anything else.
    params.validate()?;
    let password = normalize_password(password)?;
    if password.is_empty() && keyfile.is_none() {
        return Err(CryptoError::EmptyCredentials);
    }
    let secret: &[u8] = keyfile.map_or(&[], |kf| kf.expose().as_slice());
    let argon2 = params.to_argon2(secret)?;
    let mut key = SecretKey::zeroed();
    argon2
        .hash_password_into(password.as_bytes(), salt, key.as_mut_bytes())
        .map_err(|_| CryptoError::KeyDerivation)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keyfile;

    const FAST: KdfParams = KdfParams {
        mem_kib: 256,
        iterations: 1,
        parallelism: 1,
    };
    const SALT: [u8; SALT_LEN] = [7u8; SALT_LEN];

    fn derive(pw: &str, kf: Option<&KeyfileDigest>, salt: &[u8; SALT_LEN]) -> [u8; KEY_LEN] {
        *derive_master_key(pw.as_bytes(), kf, salt, &FAST)
            .unwrap()
            .expose()
    }

    #[test]
    fn spec_defaults() {
        assert_eq!(
            KdfParams::default(),
            KdfParams {
                mem_kib: 65536,
                iterations: 3,
                parallelism: 4
            }
        );
        for p in [KdfParams::INTERACTIVE, KdfParams::HARDENED] {
            assert!(p.validate().is_ok());
            assert!(p.meets_policy());
        }
        assert!(!FAST.meets_policy());
    }

    #[test]
    fn validate_rejects_out_of_bounds_params() {
        let ok = KdfParams::INTERACTIVE;
        let cases = [
            KdfParams {
                parallelism: 0,
                ..ok
            },
            KdfParams {
                parallelism: 17,
                ..ok
            },
            KdfParams {
                iterations: 0,
                ..ok
            },
            KdfParams {
                iterations: 65,
                ..ok
            },
            KdfParams { mem_kib: 0, ..ok },
            KdfParams {
                mem_kib: KdfParams::MAX_MEM_KIB + 1,
                ..ok
            },
            KdfParams {
                mem_kib: u32::MAX,
                ..ok
            },
            KdfParams {
                mem_kib: 31,
                parallelism: 4,
                ..ok
            }, // < 8 KiB per lane
        ];
        for p in cases {
            assert!(
                matches!(p.validate(), Err(CryptoError::InvalidKdfParams(_))),
                "{p:?}"
            );
        }
    }

    #[test]
    fn hostile_header_params_fail_before_allocation() {
        // ~4 TiB request from a tampered header must be refused, not attempted.
        let hostile = KdfParams {
            mem_kib: u32::MAX,
            iterations: u32::MAX,
            parallelism: 4,
        };
        let started = std::time::Instant::now();
        let err = derive_master_key(b"pw", None, &SALT, &hostile).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidKdfParams(_)));
        assert!(started.elapsed() < std::time::Duration::from_millis(50));
    }

    #[test]
    fn derivation_is_deterministic_and_input_sensitive() {
        let kf = keyfile::digest_bytes(b"keyfile-a").unwrap();
        let kf2 = keyfile::digest_bytes(b"keyfile-b").unwrap();
        let base = derive("hunter2", None, &SALT);

        assert_eq!(base, derive("hunter2", None, &SALT));
        assert_ne!(base, derive("hunter3", None, &SALT));
        assert_ne!(base, derive("hunter2", None, &[8u8; SALT_LEN]));
        assert_ne!(base, derive("hunter2", Some(&kf), &SALT));
        assert_ne!(
            derive("hunter2", Some(&kf), &SALT),
            derive("hunter2", Some(&kf2), &SALT)
        );
        assert_ne!(base, [0u8; KEY_LEN]);
    }

    #[test]
    fn params_change_the_key() {
        let a = derive_master_key(b"pw", None, &SALT, &FAST).unwrap();
        let b = derive_master_key(
            b"pw",
            None,
            &SALT,
            &KdfParams {
                iterations: 2,
                ..FAST
            },
        )
        .unwrap();
        let c = derive_master_key(
            b"pw",
            None,
            &SALT,
            &KdfParams {
                parallelism: 2,
                ..FAST
            },
        )
        .unwrap();
        assert_ne!(a.expose(), b.expose());
        assert_ne!(a.expose(), c.expose());
    }

    #[test]
    fn nfc_equivalent_passwords_derive_the_same_key() {
        // "café" with precomposed é (U+00E9) vs e + combining acute (U+0301).
        let composed = "caf\u{e9}";
        let decomposed = "cafe\u{301}";
        assert_ne!(composed.as_bytes(), decomposed.as_bytes());
        assert_eq!(
            derive(composed, None, &SALT),
            derive(decomposed, None, &SALT)
        );
        assert_eq!(
            &**normalize_password(decomposed.as_bytes()).unwrap(),
            composed
        );
    }

    #[test]
    fn keyfile_changes_the_key_through_the_secret_input() {
        let kf = keyfile::digest_bytes(b"kf").unwrap();
        let without = derive_master_key(b"pw", None, &SALT, &FAST).unwrap();
        let with = derive_master_key(b"pw", Some(&kf), &SALT, &FAST).unwrap();
        assert_ne!(without.expose(), with.expose());
    }

    #[test]
    fn credential_validation() {
        let kf = keyfile::digest_bytes(b"kf").unwrap();
        assert_eq!(
            derive_master_key(b"", None, &SALT, &FAST).unwrap_err(),
            CryptoError::EmptyCredentials
        );
        // Keyfile-only vaults are allowed.
        assert!(derive_master_key(b"", Some(&kf), &SALT, &FAST).is_ok());
        assert_eq!(
            derive_master_key(&[0xff, 0xfe], None, &SALT, &FAST).unwrap_err(),
            CryptoError::InvalidPasswordEncoding
        );
        // Non-ASCII UTF-8 is fine.
        assert!(derive_master_key("pässwörd🔑".as_bytes(), None, &SALT, &FAST).is_ok());
    }

    #[test]
    fn salts_are_random() {
        assert_ne!(generate_salt().unwrap(), generate_salt().unwrap());
    }

    /// Known-answer test with the production Argon2id configuration.
    ///
    /// Inputs: P = NFC("shush-kat-pässword"), K = SHA-256("shush-kat-keyfile").
    /// The password is passed *decomposed* (a + U+0308) so this also proves NFC
    /// normalization. The expected value was computed independently with
    /// hash-wasm (the reference Argon2 C code compiled to WASM).
    /// If this test fails, existing vaults would no longer open.
    #[test]
    fn argon2id_known_answer() {
        let params = KdfParams {
            mem_kib: 1024,
            iterations: 2,
            parallelism: 4,
        };
        let salt: [u8; SALT_LEN] = core::array::from_fn(|i| i as u8);
        let kf = keyfile::digest_bytes(b"shush-kat-keyfile").unwrap();
        let key = derive_master_key(
            "shush-kat-pa\u{308}ssword".as_bytes(),
            Some(&kf),
            &salt,
            &params,
        )
        .unwrap();
        assert_eq!(hex::encode(key.expose()), KAT_ARGON2ID);
    }
    const KAT_ARGON2ID: &str = "0360e61af742f41fa2cd3948086d6ae6fcf4b5495c97a1a4a30ca95e526d0cb8";

    /// Production preset under real cost. Slower (~0.3–1 s with optimised argon2).
    #[test]
    fn interactive_preset_derives() {
        let key = derive_master_key(b"pw", None, &SALT, &KdfParams::INTERACTIVE).unwrap();
        assert!(!key.is_all_zero());
    }
}
