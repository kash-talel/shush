//! Curated AEAD suite, HKDF key schedule and canary block (spec §3.2).

use aes_gcm::Aes256Gcm;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use super::zeroize_guard::{SecretBytes, SecretKey};
use super::{fill_random, CryptoError};

/// AEAD authentication tag length (both suites).
pub const TAG_LEN: usize = 16;
/// Largest nonce of any suite; the vault header reserves this many bytes.
pub const MAX_NONCE_LEN: usize = 24;

/// HKDF `info` labels. Changing either breaks every existing vault.
const INFO_VEK: &[u8] = b"shush/v1/vault-encryption-key";
const INFO_CANARY: &[u8] = b"shush/v1/canary-verification-key";
const INFO_ATTACHMENT: &[u8] = b"shush/v1/attachment-key";

/// Known canary plaintext. 17 bytes, so the sealed canary is 33 bytes,
/// matching the `CANARY_CIPHERTEXT` field in spec §4.
pub const CANARY_PLAINTEXT: &[u8; 17] = b"SHUSH_CANARY_V001";
/// Sealed canary length on disk.
pub const CANARY_CIPHERTEXT_LEN: usize = CANARY_PLAINTEXT.len() + TAG_LEN;

/// The curated cipher suites. The discriminant is the on-disk `CIPHER_SUITE_ID`.
#[repr(u8)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CipherSuite {
    /// AES-256-GCM, 96-bit nonce (default).
    #[default]
    Aes256Gcm = 0x01,
    /// XChaCha20-Poly1305, 192-bit nonce.
    XChaCha20Poly1305 = 0x02,
}

impl CipherSuite {
    /// Every supported suite.
    pub const ALL: [Self; 2] = [Self::Aes256Gcm, Self::XChaCha20Poly1305];

    /// On-disk identifier byte.
    pub const fn id(self) -> u8 {
        self as u8
    }

    /// Parses an on-disk identifier, rejecting anything not in the suite.
    pub const fn from_id(id: u8) -> Result<Self, CryptoError> {
        match id {
            0x01 => Ok(Self::Aes256Gcm),
            0x02 => Ok(Self::XChaCha20Poly1305),
            other => Err(CryptoError::UnsupportedCipherSuite(other)),
        }
    }

    /// Nonce length in bytes for this suite.
    pub const fn nonce_len(self) -> usize {
        match self {
            Self::Aes256Gcm => 12,
            Self::XChaCha20Poly1305 => 24,
        }
    }

    /// Human-readable name for the status bar.
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Aes256Gcm => "AES-256-GCM",
            Self::XChaCha20Poly1305 => "XChaCha20-Poly1305",
        }
    }
}

impl TryFrom<u8> for CipherSuite {
    type Error = CryptoError;
    fn try_from(id: u8) -> Result<Self, Self::Error> {
        Self::from_id(id)
    }
}

/// Output of [`seal`]: the nonce actually used and `ciphertext || tag`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedBox {
    /// Suite that produced this box.
    pub suite: CipherSuite,
    /// Nonce of exactly `suite.nonce_len()` bytes.
    pub nonce: Vec<u8>,
    /// Ciphertext with the 16-byte tag appended.
    pub ciphertext: Vec<u8>,
}

/// Sub-keys expanded from the master key with HKDF-SHA256.
#[derive(Debug)]
pub struct VaultKeys {
    vek: SecretKey,
    canary: SecretKey,
    attachment: SecretKey,
}

impl VaultKeys {
    /// Expands the Argon2id master key into independent sub-keys.
    pub fn derive(master: &SecretKey) -> Self {
        // The master key is already uniformly random, so no HKDF salt is needed.
        let hk = Hkdf::<Sha256>::new(None, master.expose());
        let mut vek = SecretKey::zeroed();
        let mut canary = SecretKey::zeroed();
        let mut attachment = SecretKey::zeroed();
        // 32 bytes is far below HKDF-SHA256's 8160-byte limit; cannot fail.
        hk.expand(INFO_VEK, vek.as_mut_bytes())
            .expect("valid HKDF length");
        hk.expand(INFO_CANARY, canary.as_mut_bytes())
            .expect("valid HKDF length");
        hk.expand(INFO_ATTACHMENT, attachment.as_mut_bytes())
            .expect("valid HKDF length");
        Self {
            vek,
            canary,
            attachment,
        }
    }

    /// Key that encrypts the vault payload.
    pub fn vault_encryption_key(&self) -> &SecretKey {
        &self.vek
    }

    /// Key that encrypts the canary block.
    pub fn canary_key(&self) -> &SecretKey {
        &self.canary
    }

    /// Key that encrypts attachment sidecar blobs.
    pub fn attachment_key(&self) -> &SecretKey {
        &self.attachment
    }
}

/// Encrypts `plaintext` under `key`, binding `aad`, with a **fresh random
/// nonce**. There is deliberately no way to supply your own nonce (issue #2).
pub fn seal(
    suite: CipherSuite,
    key: &SecretKey,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<SealedBox, CryptoError> {
    let mut nonce = vec![0u8; suite.nonce_len()];
    fill_random(&mut nonce)?;
    seal_with_nonce(suite, key, nonce, aad, plaintext)
}

fn seal_with_nonce(
    suite: CipherSuite,
    key: &SecretKey,
    nonce: Vec<u8>,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<SealedBox, CryptoError> {
    // Sealing under a wiped / never-derived key would silently produce a
    // vault anyone can open (issue #10). Refuse in all builds.
    if key.is_all_zero() {
        return Err(CryptoError::KeyDerivation);
    }
    check_nonce(suite, &nonce)?;
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    let ciphertext = match suite {
        CipherSuite::Aes256Gcm => {
            Aes256Gcm::new(key.expose().into()).encrypt(nonce.as_slice().into(), payload)
        }
        CipherSuite::XChaCha20Poly1305 => {
            XChaCha20Poly1305::new(key.expose().into()).encrypt(nonce.as_slice().into(), payload)
        }
    }
    // Encryption only fails for plaintexts beyond the AEAD length limit (~64 GiB).
    .map_err(|_| CryptoError::MalformedCiphertext)?;
    Ok(SealedBox {
        suite,
        nonce,
        ciphertext,
    })
}

/// Decrypts and authenticates `ciphertext` (with tag). Any tampering with the
/// ciphertext, tag, nonce or AAD, or a wrong key, yields
/// [`CryptoError::AuthenticationFailed`]. The plaintext is wiped on drop.
pub fn open(
    suite: CipherSuite,
    key: &SecretKey,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<SecretBytes, CryptoError> {
    check_nonce(suite, nonce)?;
    if ciphertext.len() < TAG_LEN {
        return Err(CryptoError::MalformedCiphertext);
    }
    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    match suite {
        CipherSuite::Aes256Gcm => {
            Aes256Gcm::new(key.expose().into()).decrypt(nonce.into(), payload)
        }
        CipherSuite::XChaCha20Poly1305 => {
            XChaCha20Poly1305::new(key.expose().into()).decrypt(nonce.into(), payload)
        }
    }
    .map(SecretBytes::new)
    .map_err(|_| CryptoError::AuthenticationFailed)
}

fn check_nonce(suite: CipherSuite, nonce: &[u8]) -> Result<(), CryptoError> {
    // GenericArray conversion panics on a length mismatch; check first.
    if nonce.len() != suite.nonce_len() {
        return Err(CryptoError::InvalidNonceLength {
            expected: suite.nonce_len(),
            actual: nonce.len(),
        });
    }
    Ok(())
}

/// Seals the known canary token under the canary key.
pub fn seal_canary(
    suite: CipherSuite,
    keys: &VaultKeys,
    aad: &[u8],
) -> Result<SealedBox, CryptoError> {
    seal(suite, keys.canary_key(), aad, CANARY_PLAINTEXT)
}

/// Checks the credentials against the canary block without touching the payload.
///
/// Any authentication failure is reported as [`CryptoError::WrongCredentials`].
pub fn verify_canary(
    suite: CipherSuite,
    keys: &VaultKeys,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<(), CryptoError> {
    if ciphertext.len() != CANARY_CIPHERTEXT_LEN {
        return Err(CryptoError::MalformedCiphertext);
    }
    let plain = open(suite, keys.canary_key(), nonce, aad, ciphertext).map_err(|e| match e {
        CryptoError::AuthenticationFailed => CryptoError::WrongCredentials,
        other => other,
    })?;
    // Authenticated, so a mismatch here means a format/version bug, not an attack.
    if plain.as_slice() != CANARY_PLAINTEXT {
        return Err(CryptoError::WrongCredentials);
    }
    Ok(())
}

/// Seals the (already compressed) vault payload under the vault encryption key.
pub fn seal_payload(
    suite: CipherSuite,
    keys: &VaultKeys,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<SealedBox, CryptoError> {
    seal(suite, keys.vault_encryption_key(), aad, plaintext)
}

/// Opens the vault payload. Call [`verify_canary`] first so the user can be told
/// "wrong password" rather than "corrupt vault".
pub fn open_payload(
    suite: CipherSuite,
    keys: &VaultKeys,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<SecretBytes, CryptoError> {
    open(suite, keys.vault_encryption_key(), nonce, aad, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn key(byte: u8) -> SecretKey {
        let mut k = SecretKey::zeroed();
        k.as_mut_bytes().fill(byte);
        k
    }

    /// Spec §3.2 AAD: MAGIC || VERSION (u16 LE) || CIPHER_ID.
    fn spec_aad(suite_id: u8) -> Vec<u8> {
        let mut aad = b"SHUSH".to_vec();
        aad.extend_from_slice(&1u16.to_le_bytes());
        aad.push(suite_id);
        aad
    }

    #[test]
    fn suite_ids_and_nonce_lengths() {
        assert_eq!(CipherSuite::Aes256Gcm.id(), 0x01);
        assert_eq!(CipherSuite::XChaCha20Poly1305.id(), 0x02);
        assert_eq!(CipherSuite::default(), CipherSuite::Aes256Gcm);
        for s in CipherSuite::ALL {
            assert_eq!(CipherSuite::from_id(s.id()).unwrap(), s);
            assert!(s.nonce_len() <= MAX_NONCE_LEN);
        }
        for bad in [0x00, 0x03, 0x7f, 0xff] {
            assert_eq!(
                CipherSuite::try_from(bad).unwrap_err(),
                CryptoError::UnsupportedCipherSuite(bad)
            );
        }
    }

    #[test]
    fn roundtrip_various_sizes() {
        let k = key(1);
        for suite in CipherSuite::ALL {
            for len in [0usize, 1, 15, 16, 17, 4096, 1 << 20] {
                let pt: Vec<u8> = (0..len).map(|i| i as u8).collect();
                let b = seal(suite, &k, b"aad", &pt).unwrap();
                assert_eq!(b.nonce.len(), suite.nonce_len());
                assert_eq!(b.ciphertext.len(), len + TAG_LEN);
                assert_eq!(
                    &*open(suite, &k, &b.nonce, b"aad", &b.ciphertext).unwrap(),
                    &pt[..]
                );
            }
        }
    }

    #[test]
    fn every_seal_uses_a_fresh_nonce() {
        let k = key(2);
        for suite in CipherSuite::ALL {
            let mut nonces = HashSet::new();
            let mut cts = HashSet::new();
            for _ in 0..256 {
                let b = seal(suite, &k, b"", b"same plaintext").unwrap();
                assert!(nonces.insert(b.nonce));
                assert!(cts.insert(b.ciphertext));
            }
        }
    }

    #[test]
    fn every_single_bit_flip_in_ciphertext_or_tag_is_detected() {
        let k = key(3);
        for suite in CipherSuite::ALL {
            let b = seal(suite, &k, b"hdr", b"credentials: hunter2").unwrap();
            for bit in 0..b.ciphertext.len() * 8 {
                let mut ct = b.ciphertext.clone();
                ct[bit / 8] ^= 1 << (bit % 8);
                assert_eq!(
                    open(suite, &k, &b.nonce, b"hdr", &ct).unwrap_err(),
                    CryptoError::AuthenticationFailed,
                    "{suite:?} bit {bit}"
                );
            }
        }
    }

    #[test]
    fn nonce_aad_and_key_tamper_is_detected() {
        let k = key(4);
        for suite in CipherSuite::ALL {
            let b = seal(suite, &k, b"hdr", b"secret").unwrap();
            for bit in 0..b.nonce.len() * 8 {
                let mut n = b.nonce.clone();
                n[bit / 8] ^= 1 << (bit % 8);
                assert_eq!(
                    open(suite, &k, &n, b"hdr", &b.ciphertext).unwrap_err(),
                    CryptoError::AuthenticationFailed
                );
            }
            assert_eq!(
                open(suite, &k, &b.nonce, b"hdS", &b.ciphertext).unwrap_err(),
                CryptoError::AuthenticationFailed
            );
            assert_eq!(
                open(suite, &k, &b.nonce, b"", &b.ciphertext).unwrap_err(),
                CryptoError::AuthenticationFailed
            );
            assert_eq!(
                open(suite, &key(5), &b.nonce, b"hdr", &b.ciphertext).unwrap_err(),
                CryptoError::AuthenticationFailed
            );
        }
    }

    #[test]
    fn truncated_ciphertext_and_bad_nonce_length_are_clean_errors() {
        let k = key(6);
        let b = seal(CipherSuite::Aes256Gcm, &k, b"", b"x").unwrap();
        assert_eq!(
            open(
                CipherSuite::Aes256Gcm,
                &k,
                &b.nonce,
                b"",
                &b.ciphertext[..TAG_LEN - 1]
            )
            .unwrap_err(),
            CryptoError::MalformedCiphertext
        );
        assert_eq!(
            open(
                CipherSuite::Aes256Gcm,
                &k,
                &b.nonce,
                b"",
                &b.ciphertext[..TAG_LEN]
            )
            .unwrap_err(),
            CryptoError::AuthenticationFailed
        );
        assert_eq!(
            open(CipherSuite::Aes256Gcm, &k, &[0u8; 24], b"", &b.ciphertext).unwrap_err(),
            CryptoError::InvalidNonceLength {
                expected: 12,
                actual: 24
            }
        );
    }

    /// Header downgrade: an attacker flips CIPHER_SUITE_ID from XChaCha (0x02)
    /// to AES (0x01). The container would read the first 12 bytes of the
    /// 24-byte nonce field and rebuild AAD with 0x01. Decryption must fail.
    #[test]
    fn cipher_suite_downgrade_is_rejected() {
        let k = key(7);
        let real = CipherSuite::XChaCha20Poly1305;
        let b = seal(real, &k, &spec_aad(real.id()), b"vault").unwrap();

        let forged = CipherSuite::from_id(0x01).unwrap();
        let err = open(
            forged,
            &k,
            &b.nonce[..forged.nonce_len()],
            &spec_aad(forged.id()),
            &b.ciphertext,
        )
        .unwrap_err();
        assert_eq!(err, CryptoError::AuthenticationFailed);

        // Same suite, but tampered id inside the AAD only.
        let err = open(real, &k, &b.nonce, &spec_aad(0x01), &b.ciphertext).unwrap_err();
        assert_eq!(err, CryptoError::AuthenticationFailed);
    }

    #[test]
    fn refuses_to_seal_with_zero_key() {
        for suite in CipherSuite::ALL {
            assert_eq!(
                seal(suite, &SecretKey::zeroed(), b"", b"x").unwrap_err(),
                CryptoError::KeyDerivation
            );
        }
    }

    #[test]
    fn hkdf_subkeys_are_distinct_and_deterministic() {
        let a = VaultKeys::derive(&key(9));
        let b = VaultKeys::derive(&key(9));
        let c = VaultKeys::derive(&key(10));
        assert_ne!(a.vault_encryption_key().expose(), a.canary_key().expose());
        assert_eq!(
            a.vault_encryption_key().expose(),
            b.vault_encryption_key().expose()
        );
        assert_eq!(a.canary_key().expose(), b.canary_key().expose());
        assert_ne!(
            a.vault_encryption_key().expose(),
            c.vault_encryption_key().expose()
        );
        assert!(!format!("{a:?}").contains("09"));
    }

    #[test]
    fn canary_matches_spec_size_and_verifies() {
        let keys = VaultKeys::derive(&key(11));
        for suite in CipherSuite::ALL {
            let aad = spec_aad(suite.id());
            let c = seal_canary(suite, &keys, &aad).unwrap();
            assert_eq!(
                c.ciphertext.len(),
                33,
                "spec §4 CANARY_CIPHERTEXT is 33 bytes"
            );
            verify_canary(suite, &keys, &c.nonce, &aad, &c.ciphertext).unwrap();

            let wrong = VaultKeys::derive(&key(12));
            assert_eq!(
                verify_canary(suite, &wrong, &c.nonce, &aad, &c.ciphertext).unwrap_err(),
                CryptoError::WrongCredentials
            );

            let mut t = c.ciphertext.clone();
            t[0] ^= 1;
            assert_eq!(
                verify_canary(suite, &keys, &c.nonce, &aad, &t).unwrap_err(),
                CryptoError::WrongCredentials
            );
            assert_eq!(
                verify_canary(suite, &keys, &c.nonce, &aad, &t[..32]).unwrap_err(),
                CryptoError::MalformedCiphertext
            );
        }
    }

    #[test]
    fn payload_key_cannot_open_canary_and_vice_versa() {
        let keys = VaultKeys::derive(&key(13));
        let c = seal_canary(CipherSuite::Aes256Gcm, &keys, b"").unwrap();
        assert_eq!(
            open_payload(CipherSuite::Aes256Gcm, &keys, &c.nonce, b"", &c.ciphertext).unwrap_err(),
            CryptoError::AuthenticationFailed
        );
    }

    /// Known-answer vectors for the whole key schedule + AEAD, cross-checked
    /// against independent implementations (Node.js crypto for HKDF and
    /// AES-GCM, @noble/ciphers for XChaCha20-Poly1305).
    #[test]
    fn known_answer_vectors() {
        let master = key(0x42);
        let keys = VaultKeys::derive(&master);
        assert_eq!(hex::encode(keys.vault_encryption_key().expose()), KAT_VEK);
        assert_eq!(hex::encode(keys.canary_key().expose()), KAT_CANARY_KEY);
        assert_eq!(
            hex::encode(keys.attachment_key().expose()),
            KAT_ATTACHMENT_KEY
        );

        let aes = seal_with_nonce(
            CipherSuite::Aes256Gcm,
            keys.vault_encryption_key(),
            vec![0x11; 12],
            b"SHUSH\x01\x00\x01",
            b"shush-kat",
        )
        .unwrap();
        assert_eq!(hex::encode(&aes.ciphertext), KAT_AES_GCM);

        let xc = seal_with_nonce(
            CipherSuite::XChaCha20Poly1305,
            keys.vault_encryption_key(),
            vec![0x22; 24],
            b"SHUSH\x01\x00\x02",
            b"shush-kat",
        )
        .unwrap();
        assert_eq!(hex::encode(&xc.ciphertext), KAT_XCHACHA);
    }
    const KAT_ATTACHMENT_KEY: &str =
        "6f15f26ac3f35a68aaa6dfeeb6cfb1cc86ea130eebdd320b4eed091152bd72bb";
    const KAT_VEK: &str = "9ebcb7380c3f97f55dda404254d62e33cdc04d87c37c30904a729d9bfdbf3d1c";
    const KAT_CANARY_KEY: &str = "ccdbf1f1e85b9dff53b86e22278669061e18ecaf2a76063e7cfe9d4360b52c65";
    const KAT_AES_GCM: &str = "dc82094e5b7fbe54db65c5be6ed3d49a02b3a9b80b957b7118";
    const KAT_XCHACHA: &str = "f32984d857bb3368268222841a75a46a427e1bbedc172f8a26";
}
