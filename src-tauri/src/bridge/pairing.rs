//! Extension pairing and request authentication (issues #16, #54).
//!
//! 1. The user clicks *Pair browser* in shush. A [`PairingOffer`] is created
//!    and its 8-character code shown, valid for 2 minutes, 3 attempts, one use.
//! 2. `hello` gives the extension the offer's `pairing_nonce` (SPAKE2 `host_msg`).
//!    The user types the code into the extension.
//! 3. The extension runs SPAKE2 role A (`start_a`), computes `ext_msg`, consumes
//!    `host_msg` via `.finish()`, and derives shared secret `K`.
//! 4. The extension computes `confirm_key` and `pair_key` via HKDF from `K`
//!    keyed by the transcript `ext_msg ‖ host_msg`, and sends
//!    `pair { ext_nonce: ext_msg, proof: HMAC(confirm_key, transcript) }`.
//! 5. Shush consumes `ext_msg` via `state_b.finish()`, derives `confirm_key` and
//!    `pair_key`, and verifies the HMAC proof. On success, `Pairing` is established.
//!    Each failure voids the attempt and regenerates a fresh ephemeral state for
//!    any remaining attempts (up to [`CODE_ATTEMPTS`]).
//! 6. Every later request carries `mac = HMAC-SHA256(pair_key, counter_le ‖
//!    body)` with a counter that must strictly increase ([`Pairing::verify`]).
//!
//! Offline brute-force resistance: SPAKE2 (RFC 9382 / Ed25519) ensures that
//! an eavesdropper recording `host_msg`, `ext_msg`, and `proof` cannot verify
//! candidate codes offline without solving the Computational Diffie-Hellman
//! problem (issue #54). An attacker is strictly limited to online guessing,
//! which is capped at 3 attempts per offer.

use std::time::{Duration, Instant};

use base64::Engine;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use spake2::{Ed25519Group, Identity, Password, Spake2};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::{fill_random, CryptoError};
use crate::vault::models::StoredPairing;

type HmacSha256 = Hmac<Sha256>;

/// How long a pairing code is valid.
pub const CODE_TTL: Duration = Duration::from_secs(120);
/// Wrong codes allowed before the offer is void.
pub const CODE_ATTEMPTS: u8 = 3;
/// Characters in a pairing code (Base32, 5 bits each).
pub const CODE_LEN: usize = 8;
/// Length of SPAKE2 Ed25519 outbound message in bytes.
pub const MSG_LEN: usize = 33;
/// Length of legacy pairing nonces for backwards compatibility.
pub const NONCE_LEN: usize = 32;

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const ID_EXTENSION: &[u8] = b"shush-bridge-v1/extension";
const ID_SHUSH: &[u8] = b"shush-bridge-v1/shush";
const PAIR_INFO: &[u8] = b"shush-pair-v2";
const CONFIRM_INFO: &[u8] = b"shush-pair-v2-confirm";

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

/// Normalizes a pairing code per docs/spec/lan-sync.md §3:
/// - Strips whitespace and all ASCII punctuation (hyphens, spaces, dots, colons, etc.)
/// - Converts lowercase to uppercase
/// - Maps visual lookalikes ('0' -> 'O', '1' -> 'I', '8' -> 'B')
/// - Truncates to at most [`CODE_LEN`] characters
pub fn normalize_code(raw: &str) -> String {
    raw.chars()
        .filter(|c| !c.is_whitespace() && !c.is_ascii_punctuation())
        .map(|c| match c.to_ascii_uppercase() {
            '0' => 'O',
            '1' => 'I',
            '8' => 'B',
            other => other,
        })
        .take(CODE_LEN)
        .collect()
}

/// Formats a pairing code dynamically as `XXXX-XXXX` (issue #114):
/// Normalizes the code (stripping whitespace and punctuation, mapping lookalikes),
/// and inserts a hyphen after 4 characters.
pub fn format_code(raw: &str) -> String {
    let norm = normalize_code(raw);
    if norm.len() <= 4 {
        norm
    } else {
        format!("{}-{}", &norm[..4], &norm[4..])
    }
}

fn derive_keys(k: &[u8], transcript: &[u8]) -> (Zeroizing<[u8; 32]>, [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(transcript), k);
    let mut confirm_key = Zeroizing::new([0u8; 32]);
    let mut pair_key = [0u8; 32];
    hk.expand(CONFIRM_INFO, &mut *confirm_key)
        .expect("32 bytes is a valid HKDF length");
    hk.expand(PAIR_INFO, &mut pair_key)
        .expect("32 bytes is a valid HKDF length");
    (confirm_key, pair_key)
}

fn compute_proof(confirm_key: &[u8], transcript: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(confirm_key).expect("HMAC takes any key length");
    mac.update(transcript);
    mac.finalize().into_bytes().into()
}

/// A pairing code on screen, waiting for the extension.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PairingOffer {
    code: [u8; CODE_LEN],
    #[zeroize(skip)]
    state_b: Option<Spake2<Ed25519Group>>,
    host_msg: [u8; MSG_LEN],
    #[zeroize(skip)]
    expires: Instant,
    attempts_left: u8,
}

impl PairingOffer {
    /// Creates an offer with a fresh random code and SPAKE2 state.
    pub fn new(now: Instant) -> Result<Self, AuthError> {
        let mut raw = Zeroizing::new([0u8; CODE_LEN]);
        fill_random(&mut *raw)?;
        let mut code = [0u8; CODE_LEN];
        for (c, r) in code.iter_mut().zip(raw.iter()) {
            *c = BASE32[usize::from(r & 31)];
        }
        let (state_b, host_msg) = Self::init_spake2(&code)?;
        Ok(Self {
            code,
            state_b: Some(state_b),
            host_msg,
            expires: now + CODE_TTL,
            attempts_left: CODE_ATTEMPTS,
        })
    }

    fn init_spake2(
        code: &[u8; CODE_LEN],
    ) -> Result<(Spake2<Ed25519Group>, [u8; MSG_LEN]), AuthError> {
        let pw = Password::new(code);
        let id_a = Identity::new(ID_EXTENSION);
        let id_b = Identity::new(ID_SHUSH);
        let (state_b, outbound) = Spake2::<Ed25519Group>::start_b(&pw, &id_a, &id_b);
        let host_msg: [u8; MSG_LEN] = outbound.try_into().map_err(|_| AuthError::Rng)?;
        Ok((state_b, host_msg))
    }

    /// The unformatted 8-character code.
    pub fn code(&self) -> &str {
        std::str::from_utf8(&self.code).expect("Base32 alphabet is ASCII")
    }

    /// The formatted code to show the user on screen (`XXXX-XXXX`).
    pub fn formatted_code(&self) -> String {
        format_code(self.code())
    }

    /// Sent to the extension in `hello` while the offer is live (SPAKE2 msgB).
    pub fn host_msg(&self) -> &[u8; MSG_LEN] {
        &self.host_msg
    }

    /// Backwards compatibility alias for `host_msg`.
    pub fn host_nonce(&self) -> &[u8] {
        &self.host_msg
    }

    /// Whether the code can still be redeemed.
    pub fn is_live(&self, now: Instant) -> bool {
        self.attempts_left > 0 && now < self.expires
    }

    /// Whole seconds until the code expires (rounded up; 0 once expired).
    pub fn seconds_left(&self, now: Instant) -> u64 {
        self.expires
            .saturating_duration_since(now)
            .as_secs_f64()
            .ceil() as u64
    }

    /// Checks the extension's SPAKE2 message and proof. On success the offer is
    /// used up (the caller drops it) and the new pairing is returned. Each failure
    /// costs an attempt; on failure, a fresh SPAKE2 ephemeral is generated if attempts
    /// remain. The offer is void after [`CODE_ATTEMPTS`] failures.
    pub fn redeem(
        &mut self,
        ext_msg: &[u8],
        proof: &[u8],
        now: Instant,
    ) -> Result<Pairing, AuthError> {
        if !self.is_live(now) {
            return Err(AuthError::NoOffer);
        }

        let state = match self.state_b.take() {
            Some(s) => s,
            None => return Err(AuthError::NoOffer),
        };

        let mut success = false;
        let mut final_pair_key = [0u8; 32];

        if let Ok(k) = state.finish(ext_msg) {
            let mut transcript = Vec::with_capacity(ext_msg.len() + self.host_msg.len());
            transcript.extend_from_slice(ext_msg);
            transcript.extend_from_slice(&self.host_msg);
            let (confirm_key, pair_key) = derive_keys(&k, &transcript);
            let mut mac =
                HmacSha256::new_from_slice(&*confirm_key).expect("HMAC takes any key length");
            mac.update(&transcript);
            if mac.verify_slice(proof).is_ok() {
                success = true;
                final_pair_key = pair_key;
            }
        }

        if success {
            self.attempts_left = 0;
            let mut id = [0u8; 16];
            fill_random(&mut id)?;
            Ok(Pairing {
                id: id.iter().map(|b| format!("{b:02x}")).collect(),
                key: final_pair_key,
                last_counter: 0,
            })
        } else {
            self.attempts_left -= 1;
            if self.attempts_left == 0 {
                self.state_b = None;
                Err(AuthError::NoOffer)
            } else {
                let (new_state, new_host_msg) = Self::init_spake2(&self.code)?;
                self.state_b = Some(new_state);
                self.host_msg = new_host_msg;
                Err(AuthError::WrongCode)
            }
        }
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

    /// The persisted form (stored inside the encrypted vault).
    pub fn to_stored(&self) -> StoredPairing {
        StoredPairing {
            id: self.id.clone(),
            key: base64::engine::general_purpose::STANDARD.encode(self.key),
            last_counter: self.last_counter,
        }
    }

    /// Restores a pairing from the vault; `None` if the record is malformed.
    pub fn from_stored(s: &StoredPairing) -> Option<Self> {
        let raw = zeroize::Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(&s.key)
                .ok()?,
        );
        let key: [u8; 32] = raw.as_slice().try_into().ok()?;
        Some(Self {
            id: s.id.clone(),
            key,
            last_counter: s.last_counter,
        })
    }

    #[cfg(test)]
    pub(crate) fn key_for_tests(&self) -> [u8; 32] {
        self.key
    }
}

/// What the companion extension computes during pairing.
/// Runs SPAKE2 role A (`start_a`), completes key exchange with `host_msg`,
/// and derives `(ext_msg, proof, pair_key)`.
#[allow(clippy::type_complexity)]
pub fn extension_pair(
    code: &str,
    host_msg: &[u8],
) -> Result<([u8; MSG_LEN], [u8; 32], [u8; 32]), AuthError> {
    let norm = normalize_code(code);
    let pw = Password::new(norm.as_bytes());
    let id_a = Identity::new(ID_EXTENSION);
    let id_b = Identity::new(ID_SHUSH);
    let (state_a, ext_msg_vec) = Spake2::<Ed25519Group>::start_a(&pw, &id_a, &id_b);
    let ext_msg: [u8; MSG_LEN] = ext_msg_vec.try_into().map_err(|_| AuthError::WrongCode)?;
    let k = state_a.finish(host_msg).map_err(|_| AuthError::WrongCode)?;
    let mut transcript = Vec::with_capacity(ext_msg.len() + host_msg.len());
    transcript.extend_from_slice(&ext_msg);
    transcript.extend_from_slice(host_msg);
    let (confirm_key, pair_key) = derive_keys(&k, &transcript);
    let proof = compute_proof(&*confirm_key, &transcript);
    Ok((ext_msg, proof, pair_key))
}

/// Compatibility helper: returns the proof generated by `extension_pair`.
pub fn extension_proof(code: &str, _ext_nonce: &[u8], host_msg: &[u8]) -> [u8; 32] {
    if let Ok((_, proof, _)) = extension_pair(code, host_msg) {
        proof
    } else {
        [0u8; 32]
    }
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
        let (ext_msg, proof, ext_key) = extension_pair(offer.code(), offer.host_msg()).unwrap();
        let p = offer.redeem(&ext_msg, &proof, now).unwrap();
        assert_eq!(p.key_for_tests(), ext_key);
        (offer, p)
    }

    #[test]
    fn code_shape() {
        let o = PairingOffer::new(Instant::now()).unwrap();
        assert_eq!(o.code().len(), CODE_LEN);
        assert!(o.code().bytes().all(|b| BASE32.contains(&b)));
        assert_eq!(o.host_msg().len(), MSG_LEN);
    }

    #[test]
    fn correct_code_pairs_once() {
        let now = Instant::now();
        let (mut offer, p) = pair(now);
        assert_eq!(p.id().len(), 32);
        let (ext_msg, proof, _) = extension_pair(offer.code(), offer.host_msg()).unwrap();
        assert_eq!(
            offer.redeem(&ext_msg, &proof, now).err(),
            Some(AuthError::NoOffer)
        );
    }

    #[test]
    fn three_wrong_codes_void_the_offer() {
        let now = Instant::now();
        let mut offer = PairingOffer::new(now).unwrap();

        // Attempt 1 with wrong code
        let (ext1, wrong1, _) = extension_pair("AAAAAAAA", offer.host_msg()).unwrap();
        assert_eq!(
            offer.redeem(&ext1, &wrong1, now).err(),
            Some(AuthError::WrongCode)
        );

        // Attempt 2 with wrong code (host_msg was refreshed)
        let (ext2, wrong2, _) = extension_pair("BBBBBBBB", offer.host_msg()).unwrap();
        assert_eq!(
            offer.redeem(&ext2, &wrong2, now).err(),
            Some(AuthError::WrongCode)
        );

        // Attempt 3 with wrong code voids the offer
        let (ext3, wrong3, _) = extension_pair("CCCCCCCC", offer.host_msg()).unwrap();
        assert_eq!(
            offer.redeem(&ext3, &wrong3, now).err(),
            Some(AuthError::NoOffer)
        );

        // Even the right code now fails
        let (right_msg, right_proof, _) = extension_pair(offer.code(), offer.host_msg()).unwrap();
        assert_eq!(
            offer.redeem(&right_msg, &right_proof, now).err(),
            Some(AuthError::NoOffer)
        );
    }

    #[test]
    fn wrong_code_then_correct_code_succeeds() {
        let now = Instant::now();
        let mut offer = PairingOffer::new(now).unwrap();

        // First attempt with wrong code
        let (ext1, wrong1, _) = extension_pair("AAAAAAAA", offer.host_msg()).unwrap();
        assert_eq!(
            offer.redeem(&ext1, &wrong1, now).err(),
            Some(AuthError::WrongCode)
        );

        // Second attempt with the correct code succeeds using the refreshed host_msg
        let (right_msg, right_proof, ext_key) =
            extension_pair(offer.code(), offer.host_msg()).unwrap();
        let pairing = offer.redeem(&right_msg, &right_proof, now).unwrap();
        assert_eq!(pairing.key_for_tests(), ext_key);
    }

    #[test]
    fn code_expires() {
        let now = Instant::now();
        let mut offer = PairingOffer::new(now).unwrap();
        let (right_msg, right_proof, _) = extension_pair(offer.code(), offer.host_msg()).unwrap();
        let late = now + CODE_TTL;
        assert_eq!(
            offer.redeem(&right_msg, &right_proof, late).err(),
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

    #[test]
    fn code_normalization_handles_spaces_dashes_and_lookalikes() {
        assert_eq!(normalize_code("ABCD-EFGH"), "ABCDEFGH");
        assert_eq!(normalize_code("abcd efgh"), "ABCDEFGH");
        assert_eq!(normalize_code("018X_yz"), "OIBXYZ");
        assert_eq!(normalize_code("a.b:c/d,e!f?g"), "ABCDEFG");
        assert_eq!(normalize_code("018x.yz23extra"), "OIBXYZ23");
        assert_eq!(normalize_code(""), "");

        // format_code tests
        assert_eq!(format_code(""), "");
        assert_eq!(format_code("a"), "A");
        assert_eq!(format_code("abcd"), "ABCD");
        assert_eq!(format_code("abcde"), "ABCD-E");
        assert_eq!(format_code("abcd efgh"), "ABCD-EFGH");
        assert_eq!(format_code("018x yz23"), "OIBX-YZ23");
        assert_eq!(format_code("a.b:c-d/e_f!g?h"), "ABCD-EFGH");
        assert_eq!(format_code("ABCD-EFGH"), "ABCD-EFGH");

        let now = Instant::now();
        let mut offer = PairingOffer::new(now).unwrap();
        assert_eq!(offer.formatted_code(), format_code(offer.code()));
        assert_eq!(offer.formatted_code().len(), 9);
        assert_eq!(&offer.formatted_code()[4..5], "-");

        let user_typed = format!("{}-{}", &offer.code()[..4], &offer.code()[4..])
            .to_lowercase()
            .replace('O', "0")
            .replace('I', "1")
            .replace('B', "8");
        let (ext_msg, proof, key) = extension_pair(&user_typed, offer.host_msg()).unwrap();
        let pairing = offer.redeem(&ext_msg, &proof, now).unwrap();
        assert_eq!(pairing.key_for_tests(), key);
    }

    #[test]
    fn tampered_or_invalid_point_rejected() {
        let now = Instant::now();
        let mut offer = PairingOffer::new(now).unwrap();
        let (right_msg, mut right_proof, _) =
            extension_pair(offer.code(), offer.host_msg()).unwrap();
        right_proof[0] ^= 0xff;
        assert_eq!(
            offer.redeem(&right_msg, &right_proof, now).err(),
            Some(AuthError::WrongCode)
        );

        // Invalid ext_msg length
        assert_eq!(
            offer.redeem(&[0u8; 10], &right_proof, now).err(),
            Some(AuthError::WrongCode)
        );
    }

    #[test]
    fn offline_bruteforce_transcript_protection() {
        // Record a genuine pairing transcript
        let now = Instant::now();
        let offer = PairingOffer::new(now).unwrap();
        let host_msg = *offer.host_msg();
        let (ext_msg, proof, _) = extension_pair(offer.code(), &host_msg).unwrap();

        // An attacker sniffing the pipe records: (host_msg, ext_msg, proof).
        // Since SPAKE2 is used, ext_msg and host_msg are ephemeral points:
        // T = G*x + M*pw, S = G*y + N*pw.
        // To verify candidate passwords against proof, an offline attacker would need
        // to compute K = G*x*y, which requires solving the Computational Diffie-Hellman
        // problem because the attacker does not have ephemeral secrets x or y.
        //
        // If an attacker attempts to run role A or B with candidate passwords:
        // Any fresh run generates a new random ephemeral (x' != x), producing a different
        // outbound point that cannot be matched against the recorded transcript.
        let pw_guess = "ZZZZZZZZ";
        let norm = normalize_code(pw_guess);
        let pw = Password::new(norm.as_bytes());
        let id_a = Identity::new(ID_EXTENSION);
        let id_b = Identity::new(ID_SHUSH);

        let (attacker_state_a, attacker_ext_msg) =
            Spake2::<Ed25519Group>::start_a(&pw, &id_a, &id_b);
        assert_ne!(&attacker_ext_msg[..], &ext_msg[..]);

        // Attempting to finish with recorded host_msg derives a key based on attacker's x',
        // which produces an invalid confirmation proof that does not match the recorded proof.
        let attacker_k = attacker_state_a.finish(&host_msg).unwrap();
        let mut transcript = Vec::with_capacity(ext_msg.len() + host_msg.len());
        transcript.extend_from_slice(&ext_msg);
        transcript.extend_from_slice(&host_msg);
        let (attacker_confirm, _) = derive_keys(&attacker_k, &transcript);
        let attacker_proof = compute_proof(&*attacker_confirm, &transcript);
        assert_ne!(attacker_proof, proof);
    }
}
