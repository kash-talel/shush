//! Argon2id key derivation and composite-secret construction (spec §3.1).

use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};

use super::keyfile::KeyfileDigest;
use super::zeroize_guard::{SecretBytes, SecretKey, KEY_LEN};
use super::{fill_random, CryptoError};

/// Length of the per-vault Argon2 salt in bytes.
pub const SALT_LEN: usize = 32;

/// Argon2id cost parameters, stored in the vault header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub mem_kib: u32,
    /// Number of passes (time cost).
    pub iterations: u32,
    /// Number of lanes.
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

    fn to_argon2(self) -> Result<Argon2<'static>, CryptoError> {
        self.validate()?;
        let params = Params::new(
            self.mem_kib,
            self.iterations,
            self.parallelism,
            Some(KEY_LEN),
        )
        .map_err(|_| CryptoError::InvalidKdfParams("rejected by argon2"))?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
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

/// Builds the KDF input exactly as spec §3.1 defines it:
///
/// - without keyfile: `UTF-8(password)`
/// - with keyfile:    `UTF-8(password) || SHA-256(keyfile)`
///
/// Issue #3 tracks replacing this with a domain-separated construction plus
/// NFC normalization; keeping it in one function makes that a local change.
pub fn composite_secret(
    password: &[u8],
    keyfile: Option<&KeyfileDigest>,
) -> Result<SecretBytes, CryptoError> {
    if core::str::from_utf8(password).is_err() {
        return Err(CryptoError::InvalidPasswordEncoding);
    }
    if password.is_empty() && keyfile.is_none() {
        return Err(CryptoError::EmptyCredentials);
    }
    // Exact capacity: no reallocation, so no unwiped stale copy.
    let extra = keyfile.map_or(0, |_| KEY_LEN);
    let mut out = SecretBytes::new(Vec::with_capacity(password.len() + extra));
    out.extend_from_slice(password);
    if let Some(kf) = keyfile {
        out.extend_from_slice(kf.expose());
    }
    Ok(out)
}

/// Derives the 256-bit master key with Argon2id (RFC 9106, v1.3).
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
    let argon2 = params.to_argon2()?;
    let composite = composite_secret(password, keyfile)?;
    let mut key = SecretKey::zeroed();
    argon2
        .hash_password_into(&composite, salt, key.as_mut_bytes())
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
    fn composite_layout_matches_spec() {
        let kf = keyfile::digest_bytes(b"kf").unwrap();
        assert_eq!(&**composite_secret(b"pw", None).unwrap(), b"pw");

        let c = composite_secret(b"pw", Some(&kf)).unwrap();
        assert_eq!(c.len(), 2 + KEY_LEN);
        assert_eq!(&c[..2], b"pw");
        assert_eq!(&c[2..], kf.expose());
    }

    #[test]
    fn credential_validation() {
        let kf = keyfile::digest_bytes(b"kf").unwrap();
        assert_eq!(
            composite_secret(b"", None).unwrap_err(),
            CryptoError::EmptyCredentials
        );
        // Keyfile-only vaults are allowed.
        assert_eq!(composite_secret(b"", Some(&kf)).unwrap().len(), KEY_LEN);
        assert_eq!(
            composite_secret(&[0xff, 0xfe], None).unwrap_err(),
            CryptoError::InvalidPasswordEncoding
        );
        // Non-ASCII UTF-8 is fine.
        assert!(composite_secret("pässwörd🔑".as_bytes(), None).is_ok());
    }

    #[test]
    fn salts_are_random() {
        assert_ne!(generate_salt().unwrap(), generate_salt().unwrap());
    }

    /// Known-answer test with the production Argon2id configuration.
    ///
    /// The expected value was cross-checked against an independent Argon2
    /// implementation (hash-wasm, the reference C code compiled to WASM).
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
        let key = derive_master_key(b"shush-kat-password", Some(&kf), &salt, &params).unwrap();
        assert_eq!(hex::encode(key.expose()), KAT_ARGON2ID);
    }
    const KAT_ARGON2ID: &str = "53cc979c950e90ac91fb89704eb1c5e9e1144d8b41acd46733132ac272fbbdd6";

    /// Production preset under real cost. Slower (~0.3–1 s with optimised argon2).
    #[test]
    fn interactive_preset_derives() {
        let key = derive_master_key(b"pw", None, &SALT, &KdfParams::INTERACTIVE).unwrap();
        assert!(!key.is_all_zero());
    }
}
