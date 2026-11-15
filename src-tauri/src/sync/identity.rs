//! Sync identity (`lan-sync.md` §2): one X25519 static key pair per vault
//! payload, created the first time that vault pairs a device. The secret lives
//! in the encrypted payload and, in memory, only in zeroizing buffers.

use base64::Engine;
use blake2::{Blake2s256, Digest};
use snow::params::DHChoice;
use snow::resolvers::{CryptoResolver, DefaultResolver};
use zeroize::Zeroizing;

use crate::crypto::{fill_random, CryptoError};
use crate::vault::models::{now_rfc3339, SyncIdentityRecord};

/// Domain separation for the device fingerprint.
const FP_TAG: &[u8] = b"shush-sync-fp-v1";
/// RFC 4648 Base32 alphabet (the pairing-code alphabet).
pub(crate) const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// An unlocked sync identity. The secret is wiped on drop.
pub struct Identity {
    secret: Zeroizing<[u8; 32]>,
    public: [u8; 32],
}

impl Identity {
    /// A fresh key pair from the OS RNG.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut secret = Zeroizing::new([0u8; 32]);
        fill_random(&mut *secret)?;
        Ok(Self::from_secret(secret))
    }

    /// The key pair for a stored secret (the public half is derived).
    pub fn from_secret(secret: Zeroizing<[u8; 32]>) -> Self {
        let mut dh = DefaultResolver
            .resolve_dh(&DHChoice::Curve25519)
            .expect("the default resolver has X25519");
        dh.set(&secret[..]);
        let mut public = [0u8; 32];
        public.copy_from_slice(dh.pubkey());
        Self { secret, public }
    }

    /// Loads the identity stored in a vault payload. `None` if it is malformed.
    pub fn from_record(rec: &SyncIdentityRecord) -> Option<Self> {
        let bytes = Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(rec.secret.as_bytes())
                .ok()?,
        );
        let mut secret = Zeroizing::new([0u8; 32]);
        if bytes.len() != secret.len() {
            return None;
        }
        secret.copy_from_slice(&bytes);
        Some(Self::from_secret(secret))
    }

    /// The record to store in the vault payload.
    pub fn to_record(&self) -> SyncIdentityRecord {
        SyncIdentityRecord {
            secret: base64::engine::general_purpose::STANDARD.encode(&self.secret[..]),
            created_at: now_rfc3339(),
        }
    }

    /// The static public key.
    pub fn public(&self) -> &[u8; 32] {
        &self.public
    }

    /// The static secret key, for the Noise builder only.
    pub(crate) fn secret(&self) -> &[u8] {
        &self.secret[..]
    }

    /// This identity's fingerprint.
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.public)
    }
}

/// Device fingerprint (§2): the first 10 bytes of
/// `BLAKE2s-256("shush-sync-fp-v1" ‖ static_public)` as 4 groups of 4 Base32
/// characters, e.g. `ABCD-EFGH-IJKL-MNOP`.
pub fn fingerprint(public: &[u8; 32]) -> String {
    let mut h = Blake2s256::new();
    h.update(FP_TAG);
    h.update(public);
    let digest = h.finalize();
    let chars = base32_80(&digest[..10]);
    let mut out = String::with_capacity(19);
    for (i, c) in chars.chunks(4).enumerate() {
        if i > 0 {
            out.push('-');
        }
        out.extend(c.iter().map(|&b| char::from(b)));
    }
    out
}

/// Base32 of exactly 10 bytes (80 bits, 16 characters, no padding).
fn base32_80(bytes: &[u8]) -> [u8; 16] {
    let mut acc: u128 = 0;
    for &b in bytes {
        acc = (acc << 8) | u128::from(b);
    }
    let mut out = [0u8; 16];
    for (i, o) in out.iter_mut().enumerate() {
        let shift = 75 - 5 * i;
        *o = BASE32[((acc >> shift) & 31) as usize];
    }
    out
}

/// Random Base32 characters from the OS RNG (codes and window names).
pub(crate) fn random_base32(n: usize) -> Result<Zeroizing<String>, CryptoError> {
    let mut raw = Zeroizing::new(vec![0u8; n]);
    fill_random(&mut raw)?;
    Ok(Zeroizing::new(
        raw.iter()
            .map(|r| char::from(BASE32[usize::from(r & 31)]))
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_key_matches_rfc7748() {
        // RFC 7748 §6.1, Alice's key pair.
        let sk: [u8; 32] =
            hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
                .unwrap()
                .try_into()
                .unwrap();
        let id = Identity::from_secret(Zeroizing::new(sk));
        assert_eq!(
            hex::encode(id.public()),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        );
    }

    #[test]
    fn record_round_trip() {
        let id = Identity::generate().unwrap();
        let back = Identity::from_record(&id.to_record()).unwrap();
        assert_eq!(back.public(), id.public());
        let bad = SyncIdentityRecord {
            secret: "AAAA".into(),
            created_at: String::new(),
        };
        assert!(Identity::from_record(&bad).is_none());
    }

    #[test]
    fn fingerprint_format() {
        let fp = fingerprint(&[0u8; 32]);
        assert_eq!(fp.len(), 19);
        let groups: Vec<&str> = fp.split('-').collect();
        assert_eq!(groups.len(), 4);
        assert!(groups
            .iter()
            .all(|g| g.len() == 4 && g.bytes().all(|b| BASE32.contains(&b))));
        assert_ne!(fp, fingerprint(&[1u8; 32]));
        // Known answer: BLAKE2s-256("shush-sync-fp-v1" ‖ 0^32), first 10 bytes in Base32.
        let mut h = Blake2s256::new();
        h.update(FP_TAG);
        h.update([0u8; 32]);
        let d = h.finalize();
        assert_eq!(fp.replace('-', ""), base32_ref(&d[..10]));
    }

    /// Straightforward bit-by-bit Base32 to check `base32_80`.
    fn base32_ref(bytes: &[u8]) -> String {
        let bits: Vec<u8> = bytes
            .iter()
            .flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1))
            .collect();
        bits.chunks(5)
            .map(|c| char::from(BASE32[c.iter().fold(0usize, |a, &b| a * 2 + usize::from(b))]))
            .collect()
    }

    #[test]
    fn base32_known_value() {
        // RFC 4648 §10: BASE32("fooba") = "MZXW6YTB"; two blocks of 5 bytes.
        assert_eq!(&base32_80(b"foobafooba"), b"MZXW6YTBMZXW6YTB");
    }
}
