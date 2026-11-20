//! In-memory Windows Hello session (docs/spec/windows-hello.md, issue #66).
//!
//! After a password unlock, one Hello prompt produces a signature over a fresh
//! random challenge; HKDF turns it into a key-encryption key that wraps the
//! vault sub-keys. Only `{challenge, nonce, blob, vault_id, header_hash,
//! armed_at}` is kept, in process memory, never on disk. Locking wipes the
//! plaintext sub-keys as always; a Hello unlock needs a new user gesture to
//! rebuild the KEK and open the blob.
//!
//! The Windows API sits behind [`HelloSigner`] and the time source behind
//! [`Clock`], so every arming, unlock and eviction rule is tested here with a
//! mocked signer and an injected clock.

use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Instant;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::VaultKeys;

/// Hard cap on a session, and the default (spec section 7).
pub const MAX_SESSION_HOURS: u32 = 8;
/// Shortest session the setting allows.
pub const MIN_SESSION_HOURS: u32 = 1;
/// Failed or cancelled Hello prompts in a row before the session is wiped.
pub const MAX_PROMPT_FAILURES: u8 = 3;

/// Clamps the `hello_session_max_hours` setting to 1..=8.
pub fn clamp_hours(hours: u32) -> u32 {
    hours.clamp(MIN_SESSION_HOURS, MAX_SESSION_HOURS)
}

const MSG_PREFIX: &[u8] = b"shush-hello-v1";
const KEK_INFO: &[u8] = b"shush-hello-kek-v1";

/// Why a Hello prompt produced no signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignError {
    /// The user dismissed the prompt or Hello declined.
    Cancelled,
    /// The Hello key is gone or `KeyCredentialStatus` is not `Success`.
    KeyMissing,
    /// Any other failure.
    Failed,
}

/// The Hello key pair: signs a message after a user gesture.
pub trait HelloSigner {
    /// RSASSA-PKCS1-v1_5 / SHA-256 signature over `msg` (prompts for Hello).
    fn sign(&self, msg: &[u8]) -> Result<Zeroizing<Vec<u8>>, SignError>;
    /// Checks `sig` over `msg` against the credential's public key.
    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool;
}

/// Monotonic seconds, injectable so the 8 h cap is testable.
pub trait Clock {
    /// Seconds since an arbitrary fixed origin.
    fn now_secs(&self) -> u64;
}

/// The real clock: a monotonic `Instant`, so changing the wall clock cannot
/// extend a session.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_secs(&self) -> u64 {
        static ORIGIN: OnceLock<Instant> = OnceLock::new();
        ORIGIN.get_or_init(Instant::now).elapsed().as_secs()
    }
}

/// Why a Hello operation failed. All of them fall back to the password.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HelloError {
    /// No armed session (never armed, evicted, or for another vault).
    NoSession,
    /// The user cancelled or Hello failed; the session survives until the third in a row.
    Prompt,
    /// Third failed or cancelled prompt in a row; the session was wiped.
    TooManyFailures,
    /// The Hello key is missing; the session was wiped.
    KeyMissing,
    /// The signature did not verify against the public key.
    BadSignature,
    /// A valid signature did not open the blob: signatures are not deterministic. Wiped.
    NonDeterministic,
    /// The vault header changed on disk. Wiped.
    HeaderChanged,
    /// The session reached its time limit. Wiped.
    Expired,
    /// Randomness or cipher failure.
    Crypto,
}

/// Why a session was wiped (spec section 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvictReason {
    /// Reached the 8 h cap or the shorter setting.
    Expired,
    /// Suspend, hibernate or log-off.
    Suspend,
    /// "Lock & forget".
    LockAndForget,
    /// Another vault was selected, or this one was removed or deleted.
    VaultChanged,
    /// Sub-keys changed (password, keyfile, rekey, cipher, migration).
    KeysChanged,
    /// `header_hash` mismatch.
    HeaderChanged,
    /// Three failed or cancelled prompts in a row.
    TooManyFailures,
    /// Hello key missing or not `Success`.
    KeyMissing,
    /// Signature verified but did not open the blob.
    NonDeterministic,
    /// The user turned Hello off.
    HelloOff,
}

/// SHA-256 of the vault's fixed header: MAGIC, version, cipher suite, flags,
/// Argon2 parameters and KDF salt (the file's first `FIXED_LEN` bytes, the
/// same in every format version).
///
/// Only these bytes identify the credentials and format the session was armed
/// for. The bytes after them (slot nonce and sealed slot header in v3, nonces,
/// `SAVE_ID` and payload length in v1/v2) change on every save, including the
/// re-seal after each unlock, so hashing them would end the session on the
/// first save. The canary and AEAD tags still prove the keys fit the file.
pub fn header_hash(file: &[u8]) -> [u8; 32] {
    let n = file.len().min(super::container::FIXED_LEN);
    Sha256::digest(&file[..n]).into()
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct Session {
    challenge: [u8; 32],
    nonce: [u8; 24],
    blob: Vec<u8>,
    vault_id: String,
    header_hash: [u8; 32],
    #[zeroize(skip)]
    armed_at: u64,
    #[zeroize(skip)]
    max_secs: u64,
    #[zeroize(skip)]
    failures: u8,
    #[zeroize(skip)]
    generation: u64,
}

impl Session {
    fn expired(&self, now: u64) -> bool {
        now.saturating_sub(self.armed_at) >= self.max_secs
    }
}

#[derive(Default)]
struct Inner {
    session: Option<Session>,
    /// Bumped on every arm and eviction, so a prompt that was open while the
    /// session changed cannot install or open stale state.
    generation: u64,
    last_eviction: Option<EvictReason>,
}

/// The Hello session, managed by Tauri next to `VaultState`.
#[derive(Default)]
pub struct HelloState {
    inner: Mutex<Inner>,
}

/// What the unlock screen may show about an armed session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct HelloInfo {
    /// Whole seconds until the session expires.
    pub seconds_left: u64,
}

/// The signed message. It contains the secret challenge, so it is wiped on drop.
fn message(vault_id: &str, challenge: &[u8; 32]) -> Zeroizing<Vec<u8>> {
    let mut m = Zeroizing::new(Vec::with_capacity(MSG_PREFIX.len() + vault_id.len() + 32));
    m.extend_from_slice(MSG_PREFIX);
    m.extend_from_slice(vault_id.as_bytes());
    m.extend_from_slice(challenge);
    m
}

fn aad(vault_id: &str, header_hash: &[u8; 32]) -> Vec<u8> {
    let mut a = Vec::with_capacity(vault_id.len() + 32);
    a.extend_from_slice(vault_id.as_bytes());
    a.extend_from_slice(header_hash);
    a
}

fn kek(sig: &[u8], challenge: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(challenge), sig);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(KEK_INFO, &mut *out).expect("valid HKDF length");
    out
}

impl HelloState {
    fn guard(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn evict_locked(g: &mut Inner, reason: EvictReason) {
        g.generation += 1;
        if g.session.take().is_some() {
            g.last_eviction = Some(reason);
        }
    }

    /// Wipes the session (every eviction path goes through here).
    pub fn evict(&self, reason: EvictReason) {
        Self::evict_locked(&mut self.guard(), reason);
    }

    /// Wipes the session unless it belongs to `vault_id` (vault switch).
    /// Also cancels an arming prompt that is open right now.
    pub fn evict_unless_vault(&self, vault_id: &str) {
        let mut g = self.guard();
        if g.session.as_ref().is_some_and(|s| s.vault_id != vault_id) {
            Self::evict_locked(&mut g, EvictReason::VaultChanged);
        } else {
            // No session to wipe, but an `arm` in progress must not install one.
            g.generation += 1;
        }
    }

    /// Wipes the session if it belongs to `vault_id` (vault removed or deleted).
    /// Also cancels an arming prompt that is open right now.
    pub fn evict_vault(&self, vault_id: &str) {
        let mut g = self.guard();
        if g.session.as_ref().is_some_and(|s| s.vault_id == vault_id) {
            Self::evict_locked(&mut g, EvictReason::VaultChanged);
        } else {
            g.generation += 1;
        }
    }

    /// Applies a shorter `hello_session_max_hours` to the armed session right
    /// away (the setting can shorten a session, never lengthen it).
    pub fn limit_hours(&self, clock: &dyn Clock, hours: u32) {
        let mut g = self.guard();
        if let Some(s) = g.session.as_mut() {
            s.max_secs = s.max_secs.min(u64::from(clamp_hours(hours)) * 3600);
        }
        drop(g);
        self.sweep(clock);
    }

    /// Wipes the session if it reached its time limit. Cheap; call it often.
    pub fn sweep(&self, clock: &dyn Clock) {
        let mut g = self.guard();
        if g.session
            .as_ref()
            .is_some_and(|s| s.expired(clock.now_secs()))
        {
            Self::evict_locked(&mut g, EvictReason::Expired);
        }
    }

    /// Why the last session was wiped, if one was (for tests and the UI notice).
    pub fn last_eviction(&self) -> Option<EvictReason> {
        self.guard().last_eviction
    }

    /// Time left on an armed session for `vault_id`, or `None` (spec section 8:
    /// the unlock screen shows the button only then).
    pub fn info(&self, clock: &dyn Clock, vault_id: &str) -> Option<HelloInfo> {
        self.sweep(clock);
        let g = self.guard();
        let s = g.session.as_ref().filter(|s| s.vault_id == vault_id)?;
        let used = clock.now_secs().saturating_sub(s.armed_at);
        Some(HelloInfo {
            seconds_left: s.max_secs.saturating_sub(used),
        })
    }

    /// Whether any session is armed (any vault).
    pub fn is_armed(&self) -> bool {
        self.guard().session.is_some()
    }

    /// Arms a session after a successful **password** unlock: one Hello prompt,
    /// then wraps `sub_keys` (from [`VaultKeys::export`]). A cancelled prompt
    /// leaves no session. Replaces any earlier session.
    pub fn arm(
        &self,
        signer: &dyn HelloSigner,
        clock: &dyn Clock,
        vault_id: &str,
        header_hash: [u8; 32],
        sub_keys: &[u8],
        max_hours: u32,
    ) -> Result<(), HelloError> {
        let generation = {
            let mut g = self.guard();
            Self::evict_locked(&mut g, EvictReason::KeysChanged);
            g.last_eviction = None;
            g.generation
        };
        let mut challenge = [0u8; 32];
        crate::crypto::fill_random(&mut challenge).map_err(|_| HelloError::Crypto)?;
        let mut nonce = [0u8; 24];
        crate::crypto::fill_random(&mut nonce).map_err(|_| HelloError::Crypto)?;

        let msg = message(vault_id, &challenge);
        // The prompt runs with no lock held.
        let sig = signer.sign(&msg).map_err(|e| match e {
            SignError::KeyMissing => HelloError::KeyMissing,
            _ => HelloError::Prompt,
        });
        let sig = match sig {
            Ok(s) => s,
            Err(e) => {
                challenge.zeroize();
                return Err(e);
            }
        };
        if !signer.verify(&msg, &sig) {
            challenge.zeroize();
            return Err(HelloError::BadSignature);
        }
        let key = kek(&sig, &challenge);
        drop(sig);
        let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&*key));
        let blob = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: sub_keys,
                    aad: &aad(vault_id, &header_hash),
                },
            )
            .map_err(|_| HelloError::Crypto);
        drop(key);
        let blob = match blob {
            Ok(b) => b,
            Err(e) => {
                challenge.zeroize();
                return Err(e);
            }
        };

        let mut g = self.guard();
        if g.generation != generation {
            // Lock & forget, suspend or a vault change happened during the prompt.
            challenge.zeroize();
            return Err(HelloError::NoSession);
        }
        g.generation += 1;
        let generation = g.generation;
        g.session = Some(Session {
            challenge,
            nonce,
            blob,
            vault_id: vault_id.to_owned(),
            header_hash,
            armed_at: clock.now_secs(),
            max_secs: u64::from(clamp_hours(max_hours)) * 3600,
            failures: 0,
            generation,
        });
        Ok(())
    }

    /// Hello unlock: prompts, rebuilds the KEK, opens the blob and returns the
    /// sub-keys. The caller re-reads the vault file and installs it through
    /// `begin_unlock` / `finish_unlock`. Does not extend the session.
    pub fn unlock_keys(
        &self,
        signer: &dyn HelloSigner,
        clock: &dyn Clock,
        vault_id: &str,
        current_header_hash: &[u8; 32],
    ) -> Result<VaultKeys, HelloError> {
        let (msg, challenge, nonce, blob, expected_aad, generation) = {
            let mut g = self.guard();
            let Some(s) = g.session.as_ref() else {
                return Err(HelloError::NoSession);
            };
            if s.expired(clock.now_secs()) {
                Self::evict_locked(&mut g, EvictReason::Expired);
                return Err(HelloError::Expired);
            }
            if s.vault_id != vault_id {
                return Err(HelloError::NoSession);
            }
            if s.header_hash != *current_header_hash {
                Self::evict_locked(&mut g, EvictReason::HeaderChanged);
                return Err(HelloError::HeaderChanged);
            }
            (
                message(&s.vault_id, &s.challenge),
                Zeroizing::new(s.challenge),
                s.nonce,
                Zeroizing::new(s.blob.clone()),
                aad(&s.vault_id, &s.header_hash),
                s.generation,
            )
        };

        // The prompt runs with no lock held.
        let signed = signer.sign(&msg);
        let sig = match signed {
            Ok(s) => s,
            Err(SignError::KeyMissing) => {
                self.evict_if_current(generation, EvictReason::KeyMissing);
                return Err(HelloError::KeyMissing);
            }
            Err(_) => return self.prompt_failed(generation),
        };
        if !signer.verify(&msg, &sig) {
            return match self.prompt_failed(generation) {
                Err(HelloError::TooManyFailures) => Err(HelloError::TooManyFailures),
                _ => Err(HelloError::BadSignature),
            };
        }
        let key = kek(&sig, &challenge);
        drop(sig);
        let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&*key));
        let plain = cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &blob,
                    aad: &expected_aad,
                },
            )
            .map(Zeroizing::new);
        drop(key);
        let Ok(plain) = plain else {
            // A valid signature that does not open the blob: not deterministic.
            self.evict_if_current(generation, EvictReason::NonDeterministic);
            return Err(HelloError::NonDeterministic);
        };

        let mut g = self.guard();
        match g.session.as_mut() {
            Some(s) if s.generation == generation => s.failures = 0,
            _ => return Err(HelloError::NoSession),
        }
        drop(g);
        VaultKeys::from_export(&plain).ok_or(HelloError::Crypto)
    }

    fn evict_if_current(&self, generation: u64, reason: EvictReason) {
        let mut g = self.guard();
        if g.session
            .as_ref()
            .is_some_and(|s| s.generation == generation)
        {
            Self::evict_locked(&mut g, reason);
        }
    }

    fn prompt_failed(&self, generation: u64) -> Result<VaultKeys, HelloError> {
        let mut g = self.guard();
        let wipe = match g.session.as_mut() {
            Some(s) if s.generation == generation => {
                s.failures += 1;
                s.failures >= MAX_PROMPT_FAILURES
            }
            _ => return Err(HelloError::NoSession),
        };
        if wipe {
            Self::evict_locked(&mut g, EvictReason::TooManyFailures);
            Err(HelloError::TooManyFailures)
        } else {
            Err(HelloError::Prompt)
        }
    }
}

/// A clock tests move by hand.
#[cfg(test)]
pub struct TestClock(pub std::sync::atomic::AtomicU64);

#[cfg(test)]
impl Clock for TestClock {
    fn now_secs(&self) -> u64 {
        self.0.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KdfParams;
    use crate::vault::{CreateOptions, OpenVault};
    use std::cell::Cell;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A deterministic fake "Hello key": the signature is a hash of the message.
    #[derive(Default)]
    struct Mock {
        cancel: Cell<bool>,
        missing: Cell<bool>,
        /// Make every signature differ (a randomizing Hello).
        random: Cell<bool>,
        prompts: Cell<u32>,
    }

    impl Mock {
        fn sig_for(&self, msg: &[u8]) -> Vec<u8> {
            let mut h = Sha256::new();
            h.update(b"mock-key");
            h.update(msg);
            if self.random.get() {
                h.update(self.prompts.get().to_le_bytes());
            }
            h.finalize().to_vec()
        }
    }

    impl HelloSigner for Mock {
        fn sign(&self, msg: &[u8]) -> Result<Zeroizing<Vec<u8>>, SignError> {
            self.prompts.set(self.prompts.get() + 1);
            if self.missing.get() {
                return Err(SignError::KeyMissing);
            }
            if self.cancel.get() {
                return Err(SignError::Cancelled);
            }
            Ok(Zeroizing::new(self.sig_for(msg)))
        }
        fn verify(&self, _msg: &[u8], sig: &[u8]) -> bool {
            // The randomizing signer still produces well-formed signatures.
            sig.len() == 32
        }
    }

    fn clock(t: u64) -> TestClock {
        TestClock(AtomicU64::new(t))
    }

    fn vault() -> (OpenVault, Vec<u8>) {
        let v = OpenVault::create(
            b"pw",
            None,
            CreateOptions {
                kdf: KdfParams {
                    mem_kib: 256,
                    iterations: 1,
                    parallelism: 1,
                },
                ..CreateOptions::default()
            },
        )
        .unwrap();
        let bytes = v.to_bytes().unwrap();
        (v, bytes)
    }

    const ID: &str = "vault-a";

    fn armed(state: &HelloState, mock: &Mock, c: &TestClock) -> (OpenVault, Vec<u8>, [u8; 32]) {
        let (v, bytes) = vault();
        let hh = header_hash(&bytes);
        state
            .arm(mock, c, ID, hh, &v.keys().export(), 8)
            .expect("arm");
        (v, bytes, hh)
    }

    #[test]
    fn arming_then_hello_unlock_reopens_the_same_vault() {
        let (state, mock, c) = (HelloState::default(), Mock::default(), clock(100));
        let (v, bytes, hh) = armed(&state, &mock, &c);
        assert!(state.is_armed());
        assert_eq!(state.info(&c, ID).unwrap().seconds_left, 8 * 3600);
        let keys = state.unlock_keys(&mock, &c, ID, &hh).unwrap();
        let reopened = OpenVault::unlock_with_keys(&bytes, keys).unwrap();
        assert_eq!(reopened.data().items.len(), v.data().items.len());
        // The session survives an unlock and is not extended.
        c.0.store(100 + 3600, Ordering::Relaxed);
        state.unlock_keys(&mock, &c, ID, &hh).unwrap();
        assert_eq!(state.info(&c, ID).unwrap().seconds_left, 7 * 3600);
    }

    #[test]
    fn cancelled_arming_prompt_leaves_no_session() {
        let (state, mock, c) = (HelloState::default(), Mock::default(), clock(0));
        mock.cancel.set(true);
        let (v, bytes) = vault();
        let r = state.arm(&mock, &c, ID, header_hash(&bytes), &v.keys().export(), 8);
        assert_eq!(r, Err(HelloError::Prompt));
        assert!(!state.is_armed());
    }

    #[test]
    fn info_is_none_for_another_vault() {
        let (state, mock, c) = (HelloState::default(), Mock::default(), clock(0));
        armed(&state, &mock, &c);
        assert!(state.info(&c, "other").is_none());
        assert!(state.is_armed());
    }

    #[test]
    fn eight_hour_cap_with_injected_clock() {
        let (state, mock, c) = (HelloState::default(), Mock::default(), clock(5));
        let (_v, _b, hh) = armed(&state, &mock, &c);
        c.0.store(5 + 8 * 3600 - 1, Ordering::Relaxed);
        assert_eq!(state.info(&c, ID).unwrap().seconds_left, 1);
        c.0.store(5 + 8 * 3600, Ordering::Relaxed);
        assert_eq!(
            state.unlock_keys(&mock, &c, ID, &hh).unwrap_err(),
            HelloError::Expired
        );
        assert!(!state.is_armed());
        assert_eq!(state.last_eviction(), Some(EvictReason::Expired));
    }

    #[test]
    fn setting_can_shorten_but_not_lengthen() {
        let (v, bytes) = vault();
        let (mock, c) = (Mock::default(), clock(0));
        for (set, secs) in [(1, 3600), (3, 3 * 3600), (99, 8 * 3600), (0, 3600)] {
            let state = HelloState::default();
            state
                .arm(&mock, &c, ID, header_hash(&bytes), &v.keys().export(), set)
                .unwrap();
            assert_eq!(state.info(&c, ID).unwrap().seconds_left, secs);
        }
    }

    #[test]
    fn sweep_wipes_an_expired_session() {
        let (state, mock, c) = (HelloState::default(), Mock::default(), clock(0));
        armed(&state, &mock, &c);
        state.sweep(&c);
        assert!(state.is_armed());
        c.0.store(8 * 3600, Ordering::Relaxed);
        state.sweep(&c);
        assert!(!state.is_armed());
    }

    #[test]
    fn explicit_evictions_wipe() {
        for reason in [
            EvictReason::Suspend,
            EvictReason::LockAndForget,
            EvictReason::KeysChanged,
            EvictReason::HelloOff,
        ] {
            let (state, mock, c) = (HelloState::default(), Mock::default(), clock(0));
            let (_v, _b, hh) = armed(&state, &mock, &c);
            state.evict(reason);
            assert!(!state.is_armed());
            assert_eq!(state.last_eviction(), Some(reason));
            assert_eq!(
                state.unlock_keys(&mock, &c, ID, &hh).unwrap_err(),
                HelloError::NoSession
            );
        }
    }

    #[test]
    fn vault_switch_and_removal() {
        let (state, mock, c) = (HelloState::default(), Mock::default(), clock(0));
        armed(&state, &mock, &c);
        state.evict_unless_vault(ID);
        assert!(state.is_armed());
        state.evict_vault("other");
        assert!(state.is_armed());
        state.evict_unless_vault("other");
        assert!(!state.is_armed());
        assert_eq!(state.last_eviction(), Some(EvictReason::VaultChanged));

        armed(&state, &mock, &c);
        state.evict_vault(ID);
        assert!(!state.is_armed());
    }

    #[test]
    fn unlock_for_another_vault_does_not_use_or_wipe_the_session() {
        let (state, mock, c) = (HelloState::default(), Mock::default(), clock(0));
        let (_v, _b, hh) = armed(&state, &mock, &c);
        assert_eq!(
            state.unlock_keys(&mock, &c, "other", &hh).unwrap_err(),
            HelloError::NoSession
        );
        assert!(state.is_armed());
    }

    #[test]
    fn header_mismatch_wipes() {
        let (state, mock, c) = (HelloState::default(), Mock::default(), clock(0));
        armed(&state, &mock, &c);
        let before = mock.prompts.get();
        assert_eq!(
            state.unlock_keys(&mock, &c, ID, &[9u8; 32]).unwrap_err(),
            HelloError::HeaderChanged
        );
        assert!(!state.is_armed());
        assert_eq!(state.last_eviction(), Some(EvictReason::HeaderChanged));
        // No Hello prompt was shown for a file the session was not armed for.
        assert_eq!(mock.prompts.get(), before);
    }

    #[test]
    fn header_hash_tracks_header_bytes_only() {
        let (v, bytes) = vault();
        let mut changed = bytes.clone();
        changed[10] ^= 1;
        assert_ne!(header_hash(&bytes), header_hash(&changed));
        let mut tail = bytes.clone();
        let last = tail.len() - 1;
        tail[last] ^= 1;
        assert_eq!(header_hash(&bytes), header_hash(&tail));
        drop(v);
    }

    #[test]
    fn header_hash_survives_saves_but_not_other_credentials() {
        // Every save (and the re-seal after each unlock) rewrites the slot
        // nonce and sealed slot header right after the fixed header. A session
        // must survive that, or Hello would work once per password unlock.
        let (v, first) = vault();
        let second = v.to_bytes().unwrap();
        assert_ne!(
            first[..crate::vault::container::HEADER_LEN],
            second[..crate::vault::container::HEADER_LEN]
        );
        assert_eq!(header_hash(&first), header_hash(&second));
        // A different vault (new salt) does not match.
        let (_, other) = vault();
        assert_ne!(header_hash(&first), header_hash(&other));
    }

    #[test]
    fn hello_unlock_works_again_after_the_vault_is_saved() {
        let (state, mock, c) = (HelloState::default(), Mock::default(), clock(0));
        let (v, _, _) = armed(&state, &mock, &c);
        for _ in 0..3 {
            let saved = v.to_bytes().unwrap();
            let keys = state
                .unlock_keys(&mock, &c, ID, &header_hash(&saved))
                .unwrap();
            OpenVault::unlock_with_keys(&saved, keys).unwrap();
        }
        assert!(state.is_armed());
    }

    #[test]
    fn lowering_the_setting_shortens_the_armed_session() {
        let (state, mock, c) = (HelloState::default(), Mock::default(), clock(0));
        armed(&state, &mock, &c);
        state.limit_hours(&c, 2);
        assert_eq!(state.info(&c, ID).unwrap().seconds_left, 2 * 3600);
        // Raising it again does not lengthen the session.
        state.limit_hours(&c, 8);
        assert_eq!(state.info(&c, ID).unwrap().seconds_left, 2 * 3600);
        c.0.store(3 * 3600, Ordering::Relaxed);
        state.limit_hours(&c, 1);
        assert!(!state.is_armed());
        assert_eq!(state.last_eviction(), Some(EvictReason::Expired));
    }

    #[test]
    fn vault_switch_or_removal_during_the_arming_prompt_wins() {
        struct Racing<'a>(&'a HelloState, bool);
        impl HelloSigner for Racing<'_> {
            fn sign(&self, msg: &[u8]) -> Result<Zeroizing<Vec<u8>>, SignError> {
                if self.1 {
                    self.0.evict_unless_vault("vault-b");
                } else {
                    self.0.evict_vault(ID);
                }
                Ok(Zeroizing::new(Sha256::digest(msg).to_vec()))
            }
            fn verify(&self, _: &[u8], _: &[u8]) -> bool {
                true
            }
        }
        for switch in [true, false] {
            let (v, bytes) = vault();
            let state = HelloState::default();
            let r = state.arm(
                &Racing(&state, switch),
                &clock(0),
                ID,
                header_hash(&bytes),
                &v.keys().export(),
                8,
            );
            assert_eq!(r, Err(HelloError::NoSession));
            assert!(!state.is_armed());
        }
    }

    #[test]
    fn three_cancelled_prompts_in_a_row_wipe() {
        let (state, mock, c) = (HelloState::default(), Mock::default(), clock(0));
        let (_v, _b, hh) = armed(&state, &mock, &c);
        mock.cancel.set(true);
        assert_eq!(
            state.unlock_keys(&mock, &c, ID, &hh).unwrap_err(),
            HelloError::Prompt
        );
        assert_eq!(
            state.unlock_keys(&mock, &c, ID, &hh).unwrap_err(),
            HelloError::Prompt
        );
        assert_eq!(
            state.unlock_keys(&mock, &c, ID, &hh).unwrap_err(),
            HelloError::TooManyFailures
        );
        assert!(!state.is_armed());
        assert_eq!(state.last_eviction(), Some(EvictReason::TooManyFailures));
    }

    #[test]
    fn a_success_resets_the_failure_count() {
        let (state, mock, c) = (HelloState::default(), Mock::default(), clock(0));
        let (_v, _b, hh) = armed(&state, &mock, &c);
        mock.cancel.set(true);
        for _ in 0..2 {
            let _ = state.unlock_keys(&mock, &c, ID, &hh);
        }
        mock.cancel.set(false);
        state.unlock_keys(&mock, &c, ID, &hh).unwrap();
        mock.cancel.set(true);
        for _ in 0..2 {
            assert_eq!(
                state.unlock_keys(&mock, &c, ID, &hh).unwrap_err(),
                HelloError::Prompt
            );
        }
        assert!(state.is_armed());
    }

    #[test]
    fn missing_key_wipes() {
        let (state, mock, c) = (HelloState::default(), Mock::default(), clock(0));
        let (_v, _b, hh) = armed(&state, &mock, &c);
        mock.missing.set(true);
        assert_eq!(
            state.unlock_keys(&mock, &c, ID, &hh).unwrap_err(),
            HelloError::KeyMissing
        );
        assert!(!state.is_armed());
        assert_eq!(state.last_eviction(), Some(EvictReason::KeyMissing));
    }

    #[test]
    fn non_deterministic_signature_falls_back_to_password() {
        let (state, mock, c) = (HelloState::default(), Mock::default(), clock(0));
        mock.random.set(true);
        let (_v, _b, hh) = armed(&state, &mock, &c);
        assert_eq!(
            state.unlock_keys(&mock, &c, ID, &hh).unwrap_err(),
            HelloError::NonDeterministic
        );
        assert!(!state.is_armed());
        assert_eq!(state.last_eviction(), Some(EvictReason::NonDeterministic));
    }

    #[test]
    fn signature_over_another_message_does_not_open_the_blob() {
        // The attacker model: a Hello signature over a different message gives no KEK.
        let (state, mock, c) = (HelloState::default(), Mock::default(), clock(0));
        let (v, _b, hh) = armed(&state, &mock, &c);
        let foreign = mock.sig_for(b"something else");
        let wrong = kek(&foreign, &[0u8; 32]);
        let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&*wrong));
        let g = state.guard();
        let s = g.session.as_ref().unwrap();
        assert!(cipher
            .decrypt(
                XNonce::from_slice(&s.nonce),
                Payload {
                    msg: &s.blob,
                    aad: &aad(ID, &hh)
                }
            )
            .is_err());
        drop(g);
        drop(v);
    }

    #[test]
    fn eviction_during_a_prompt_wins() {
        // A signer that triggers Lock & forget while its prompt is open.
        struct Racing<'a>(&'a HelloState);
        impl HelloSigner for Racing<'_> {
            fn sign(&self, msg: &[u8]) -> Result<Zeroizing<Vec<u8>>, SignError> {
                self.0.evict(EvictReason::LockAndForget);
                Ok(Zeroizing::new(Sha256::digest(msg).to_vec()))
            }
            fn verify(&self, _: &[u8], _: &[u8]) -> bool {
                true
            }
        }
        let (v, bytes) = vault();
        let state = HelloState::default();
        let r = state.arm(
            &Racing(&state),
            &clock(0),
            ID,
            header_hash(&bytes),
            &v.keys().export(),
            8,
        );
        assert_eq!(r, Err(HelloError::NoSession));
        assert!(!state.is_armed());
    }

    #[test]
    fn export_roundtrip_and_wrong_length() {
        let (v, _) = vault();
        let e = v.keys().export();
        assert_eq!(e.len(), VaultKeys::EXPORT_LEN);
        let k = VaultKeys::from_export(&e).unwrap();
        assert!(k
            .vault_encryption_key()
            .ct_eq(v.keys().vault_encryption_key()));
        assert!(VaultKeys::from_export(&e[1..]).is_none());
    }
}
