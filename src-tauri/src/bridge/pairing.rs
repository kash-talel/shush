//! Extension pairing and request authentication (issue #16).
//!
//! 1. The user clicks *Pair browser* in shush. A [`PairingOffer`] is created
//!    and its 8-character code shown, valid for 2 minutes, 3 attempts, one use.
//! 2. `hello` gives the extension the offer's `host_nonce`. The user types the
//!    code into the extension, which sends `pair { ext_nonce, proof }` with
//!    `proof = HMAC-SHA256(code, ext_nonce ‖ host_nonce)`.
//! 3. Both sides derive `pair_key = HKDF-SHA256(ikm = code,
//!    salt = ext_nonce ‖ host_nonce, info = "shush-pair-v1")`.
//! 4. Every later request carries `mac = HMAC-SHA256(pair_key, counter_le ‖
//!    body)` with a counter that must strictly increase ([`Pairing::verify`]).
//!
//! Limitation: the code has 40 bits, so anyone who records a pairing
//! transcript (the browser, the relay, or same-user malware on the pipe) can
//! brute-force it offline. Only the local, same-user channel carries it;
//! switching to a PAKE (as planned for LAN sync, #18) removes this.

use std::time::{Duration, Instant};

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::{fill_random, CryptoError};

type HmacSha256 = Hmac<Sha256>;

/// How long a pairing code is valid.
pub const CODE_TTL: Duration = Duration::from_secs(120);
/// Wrong codes allowed before the offer is void.
pub const CODE_ATTEMPTS: u8 = 3;
/// Characters in a pairing code (Base32, 5 bits each).
pub const CODE_LEN: usize = 8;
/// Length of both pairing nonces.
pub const NONCE_LEN: usize = 32;
const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const PAIR_INFO: &[u8] = b"shush-pair-v1";

/// Why a pairing or an authenticated request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    /// No pairing is in progress, or it expired, was used, or ran out of attempts.
    #[error("no pairing code is active")]
    NoOffer,
    /// Wrong code (attempts remain).
    #[error("wrong pairing code")]
    WrongCode,
    /// Unknown or revoked pairing.
    #[error("this browser is not paired")]
    NotPaired,
    /// Bad MAC or a counter that did not increase (replay).
    #[error("request authentication failed")]
    BadMac,
    /// The OS random number generator failed.
    #[error("random number generator failed")]
    Rng,
}

impl From<CryptoError> for AuthError {
    fn from(_: CryptoError) -> Self {
        Self::Rng
    }
}

/// A pairing code on screen, waiting for the extension.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PairingOffer {
    code: [u8; CODE_LEN],
    host_nonce: [u8; NONCE_LEN],
    #[zeroize(skip)]
    expires: Instant,
    attempts_left: u8,
}

impl PairingOffer {
    /// Creates an offer with a fresh random code and nonce.
    pub fn new(now: Instant) -> Result<Self, AuthError> {
        let mut raw = Zeroizing::new([0u8; CODE_LEN]);
        fill_random(&mut *raw)?;
        let mut code = [0u8; CODE_LEN];
        for (c, r) in code.iter_mut().zip(raw.iter()) {
            *c = BASE32[usize::from(r & 31)];
        }
        let mut host_nonce = [0u8; NONCE_LEN];
        fill_random(&mut host_nonce)?;
        Ok(Self {
            code,
            host_nonce,
            expires: now + CODE_TTL,
            attempts_left: CODE_ATTEMPTS,
        })
    }

    /// The code to show the user.
    pub fn code(&self) -> &str {
        std::str::from_utf8(&self.code).expect("Base32 alphabet is ASCII")
    }

    /// Sent to the extension in `hello` while the offer is live.
    pub fn host_nonce(&self) -> &[u8; NONCE_LEN] {
        &self.host_nonce
    }

    /// Whether the code can still be redeemed.
    pub fn is_live(&self, now: Instant) -> bool {
        self.attempts_left > 0 && now < self.expires
    }

    /// Checks the extension's proof. On success the offer is used up (the
    /// caller drops it) and the new pairing is returned. Each failure costs
    /// an attempt; the offer is void after [`CODE_ATTEMPTS`] failures.
    pub fn redeem(
        &mut self,
        ext_nonce: &[u8; NONCE_LEN],
        proof: &[u8],
        now: Instant,
    ) -> Result<Pairing, AuthError> {
        if !self.is_live(now) {
            return Err(AuthError::NoOffer);
        }
        let mut mac = HmacSha256::new_from_slice(&self.code).expect("HMAC takes any key length");
        mac.update(ext_nonce);
        mac.update(&self.host_nonce);
        if mac.verify_slice(proof).is_err() {
            self.attempts_left -= 1;
            return Err(if self.attempts_left == 0 {
                AuthError::NoOffer
            } else {
                AuthError::WrongCode
            });
        }
        self.attempts_left = 0; // one use
        let mut salt = [0u8; 2 * NONCE_LEN];
        salt[..NONCE_LEN].copy_from_slice(ext_nonce);
        salt[NONCE_LEN..].copy_from_slice(&self.host_nonce);
        let mut key = [0u8; 32];
        Hkdf::<Sha256>::new(Some(&salt), &self.code)
            .expand(PAIR_INFO, &mut key)
            .expect("32 bytes is a valid HKDF length");
        let mut id = [0u8; 16];
        fill_random(&mut id)?;
        Ok(Pairing {
            id: id.iter().map(|b| format!("{b:02x}")).collect(),
            key,
            last_counter: 0,
        })
    }
}

/// A paired extension: its id, shared key and replay counter.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Pairing {
    id: String,
    key: [u8; 32],
    last_counter: u64,
}

impl Pairing {
    /// Public pairing id (sent with every request).
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Authenticates a request: `mac` must be `HMAC(pair_key, counter_le ‖
    /// body)` and `counter` must exceed every counter accepted before.
    /// State changes only on success, so a forged request cannot burn counters.
    pub fn verify(&mut self, counter: u64, body: &[u8], mac: &[u8]) -> Result<(), AuthError> {
        if counter <= self.last_counter {
            return Err(AuthError::BadMac);
        }
        self.mac(counter, body)
            .verify_slice(mac)
            .map_err(|_| AuthError::BadMac)?;
        self.last_counter = counter;
        Ok(())
    }

    /// MAC for a response to the request with `counter`, so the extension can
    /// tell answers really come from shush.
    pub fn sign(&self, counter: u64, body: &[u8]) -> [u8; 32] {
        self.mac(counter, body).finalize().into_bytes().into()
    }

    fn mac(&self, counter: u64, body: &[u8]) -> HmacSha256 {
        let mut m = HmacSha256::new_from_slice(&self.key).expect("HMAC takes any key length");
        m.update(&counter.to_le_bytes());
        m.update(body);
        m
    }

    #[cfg(test)]
    pub(crate) fn key_for_tests(&self) -> [u8; 32] {
        self.key
    }
}

/// What the extension computes; shared with tests and the future host tests.
pub fn extension_proof(code: &str, ext_nonce: &[u8], host_nonce: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(code.as_bytes()).expect("any key length");
    mac.update(ext_nonce);
    mac.update(host_nonce);
    mac.finalize().into_bytes().into()
}

/// What the extension sends as `mac` for a request.
pub fn request_mac(key: &[u8; 32], counter: u64, body: &[u8]) -> [u8; 32] {
    let mut m = HmacSha256::new_from_slice(key).expect("any key length");
    m.update(&counter.to_le_bytes());
    m.update(body);
    m.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(now: Instant) -> (PairingOffer, Pairing) {
        let mut offer = PairingOffer::new(now).unwrap();
        let ext = [7u8; NONCE_LEN];
        let proof = extension_proof(offer.code(), &ext, offer.host_nonce());
        let p = offer.redeem(&ext, &proof, now).unwrap();
        (offer, p)
    }

    #[test]
    fn code_shape() {
        let o = PairingOffer::new(Instant::now()).unwrap();
        assert_eq!(o.code().len(), CODE_LEN);
        assert!(o.code().bytes().all(|b| BASE32.contains(&b)));
    }

    #[test]
    fn correct_code_pairs_once() {
        let now = Instant::now();
        let (mut offer, p) = pair(now);
        assert_eq!(p.id().len(), 32);
        let ext = [7u8; NONCE_LEN];
        let proof = extension_proof(offer.code(), &ext, offer.host_nonce());
        assert_eq!(
            offer.redeem(&ext, &proof, now).err(),
            Some(AuthError::NoOffer)
        );
    }

    #[test]
    fn three_wrong_codes_void_the_offer() {
        let now = Instant::now();
        let mut offer = PairingOffer::new(now).unwrap();
        let ext = [1u8; NONCE_LEN];
        let wrong = extension_proof("AAAAAAAA", &ext, offer.host_nonce());
        assert_eq!(
            offer.redeem(&ext, &wrong, now).err(),
            Some(AuthError::WrongCode)
        );
        assert_eq!(
            offer.redeem(&ext, &wrong, now).err(),
            Some(AuthError::WrongCode)
        );
        assert_eq!(
            offer.redeem(&ext, &wrong, now).err(),
            Some(AuthError::NoOffer)
        );
        let right = extension_proof(offer.code(), &ext, offer.host_nonce());
        assert_eq!(
            offer.redeem(&ext, &right, now).err(),
            Some(AuthError::NoOffer)
        );
    }

    #[test]
    fn code_expires() {
        let now = Instant::now();
        let mut offer = PairingOffer::new(now).unwrap();
        let ext = [1u8; NONCE_LEN];
        let right = extension_proof(offer.code(), &ext, offer.host_nonce());
        let late = now + CODE_TTL;
        assert_eq!(
            offer.redeem(&ext, &right, late).err(),
            Some(AuthError::NoOffer)
        );
    }

    #[test]
    fn requests_need_mac_and_rising_counter() {
        let (_, mut p) = pair(Instant::now());
        let key = p.key_for_tests();
        let body = br#"{"type":"match","tab_origin":"https://a.test"}"#;
        assert!(p.verify(1, body, &request_mac(&key, 1, body)).is_ok());
        // Replay of the same counter, and an older one.
        assert_eq!(
            p.verify(1, body, &request_mac(&key, 1, body)),
            Err(AuthError::BadMac)
        );
        // Tampered body.
        assert_eq!(
            p.verify(2, b"{}", &request_mac(&key, 2, body)),
            Err(AuthError::BadMac)
        );
        // A forged high counter is refused and does not burn counter 2.
        assert_eq!(p.verify(99, body, &[0u8; 32]), Err(AuthError::BadMac));
        assert!(p.verify(2, body, &request_mac(&key, 2, body)).is_ok());
        // Wrong key.
        assert_eq!(
            p.verify(3, body, &request_mac(&[0u8; 32], 3, body)),
            Err(AuthError::BadMac)
        );
    }
}
