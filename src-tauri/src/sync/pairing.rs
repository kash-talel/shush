//! Device pairing (`lan-sync.md` §3).
//!
//! The **responder** shows an 8-character one-time code; the **initiator**
//! types it. Over one connection they run, in order:
//!
//! ```text
//! sid   = 16 random bytes, chosen by the responder, sent first in clear
//! SPAKE2-Ed25519 (A = initiator, B = responder), password = normalized code
//!       → msgA (I→R), msgB (R→I), both derive K
//! psk   = HKDF-SHA256(ikm = K, salt = sid, info = "shush-sync-psk-v1")
//! Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s
//!       prologue = "shush-sync-pair-v1" ‖ sid ‖ msgA ‖ msgB
//! then one transport message each way: {"v":1,"name":"<device name>"}
//! ```
//!
//! A wrong code gives a different `psk`, so the responder cannot decrypt Noise
//! message 3 and the initiator never gets a confirmation. A relaying attacker
//! must run SPAKE2 separately with each side and so must guess the code; the
//! prologue binds `sid` and both SPAKE2 messages into the Noise transcript so
//! two runs cannot be spliced. Nothing on the wire is a check value of the
//! code alone, so a recorded transcript allows no offline guessing.
//!
//! Neither side stores anything before it has decrypted the other side's
//! confirmation: the caller's `store` callback runs only then.

use std::io::{Read, Write};

use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use spake2::{Ed25519Group, Identity as SpakeId, Password, Spake2};
use zeroize::Zeroizing;

use super::clean_name;
use super::frame::{read_frame, write_frame, MAX_FRAME};
use super::identity::{Identity, BASE32};
use crate::crypto::fill_random;

/// Noise pattern of the pairing handshake.
pub const PAIR_PATTERN: &str = "Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s";
/// Characters in a pairing code.
pub const CODE_LEN: usize = 8;
/// Length of the responder's session id.
pub const SID_LEN: usize = 16;
/// Length of a SPAKE2-Ed25519 message.
const SPAKE_MSG_LEN: usize = 33;
const ID_INITIATOR: &[u8] = b"shush-sync-v1/initiator";
const ID_RESPONDER: &[u8] = b"shush-sync-v1/responder";
const PSK_INFO: &[u8] = b"shush-sync-psk-v1";
const PROLOGUE_TAG: &[u8] = b"shush-sync-pair-v1";

/// Why pairing failed. Deliberately coarse: users see "wrong code" for every
/// failure that could come from a code mismatch (§3, step 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PairError {
    /// The codes did not match (or the other side gave up after Noise message 3).
    #[error("wrong code")]
    WrongCode,
    /// The code typed is not 8 Base32 characters.
    #[error("the code must be 8 letters and digits")]
    InvalidCode,
    /// The other side broke the protocol or the connection dropped early.
    #[error("the other device did not complete pairing")]
    Protocol,
    /// The other side presented this device's own key.
    #[error("a device cannot pair with itself")]
    SelfPair,
    /// The result could not be saved (for example, the vault was locked).
    #[error("the pairing could not be saved")]
    StoreFailed,
    /// The OS random number generator failed.
    #[error("random number generator failed")]
    Rng,
}

/// The other device, once both confirmations were decrypted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paired {
    /// Its static public key, to pin.
    pub public_key: [u8; 32],
    /// The name it sent (already cleaned).
    pub name: String,
}

/// The confirmation each side sends once the handshake is done.
#[derive(Serialize, Deserialize)]
struct Confirm {
    v: u32,
    name: String,
}

/// Normalizes a typed code (uppercase, separators dropped, `0`→`O`, `1`→`I`,
/// `8`→`B`) and checks it is exactly 8 Base32 characters.
pub fn parse_code(raw: &str) -> Result<Zeroizing<String>, PairError> {
    let n = Zeroizing::new(crate::bridge::pairing::normalize_code(raw));
    let extra = raw
        .chars()
        .filter(|c| !c.is_whitespace() && !c.is_ascii_punctuation())
        .count();
    if n.len() != CODE_LEN || extra != CODE_LEN || !n.bytes().all(|b| BASE32.contains(&b)) {
        return Err(PairError::InvalidCode);
    }
    Ok(n)
}

/// A new one-time code (40 bits from the OS RNG).
pub fn new_code() -> Result<Zeroizing<String>, PairError> {
    super::identity::random_base32(CODE_LEN).map_err(|_| PairError::Rng)
}

fn derive_psk(k: &[u8], sid: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut psk = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(sid), k)
        .expand(PSK_INFO, &mut *psk)
        .expect("32 bytes is a valid HKDF length");
    psk
}

fn prologue(sid: &[u8], msg_a: &[u8], msg_b: &[u8]) -> Vec<u8> {
    [PROLOGUE_TAG, sid, msg_a, msg_b].concat()
}

fn builder<'a>(id: &'a Identity, prologue: &'a [u8], psk: &'a [u8]) -> snow::Builder<'a> {
    snow::Builder::new(PAIR_PATTERN.parse().expect("valid pattern"))
        .local_private_key(id.secret())
        .prologue(prologue)
        .psk(3, psk)
}

fn confirm_bytes(name: &str) -> Vec<u8> {
    serde_json::to_vec(&Confirm {
        v: 1,
        name: clean_name(name),
    })
    .expect("serializable")
}

fn parse_confirm(bytes: &[u8]) -> Result<String, PairError> {
    let c: Confirm = serde_json::from_slice(bytes).map_err(|_| PairError::Protocol)?;
    if c.v != 1 {
        return Err(PairError::Protocol);
    }
    Ok(clean_name(&c.name))
}

fn remote_key(rs: Option<&[u8]>) -> Result<[u8; 32], PairError> {
    rs.and_then(|k| k.try_into().ok())
        .ok_or(PairError::Protocol)
}

fn spake_ids() -> (SpakeId, SpakeId) {
    (SpakeId::new(ID_INITIATOR), SpakeId::new(ID_RESPONDER))
}

/// Responder side: shows `code`, listens on `stream`. `store` is called once
/// the initiator's confirmation was decrypted, before this side sends its own;
/// if it fails, no confirmation is sent and the initiator fails too.
pub fn respond<S: Read + Write>(
    stream: &mut S,
    code: &str,
    id: &Identity,
    my_name: &str,
    store: impl FnOnce(&Paired) -> Result<(), PairError>,
) -> Result<Paired, PairError> {
    let code = parse_code(code)?;
    let io = |_| PairError::Protocol;
    let mut sid = [0u8; SID_LEN];
    fill_random(&mut sid).map_err(|_| PairError::Rng)?;
    write_frame(stream, &sid).map_err(io)?;

    let msg_a = read_frame(stream).map_err(io)?;
    if msg_a.len() != SPAKE_MSG_LEN {
        return Err(PairError::Protocol);
    }
    let (id_a, id_b) = spake_ids();
    let (spake, msg_b) =
        Spake2::<Ed25519Group>::start_b(&Password::new(code.as_bytes()), &id_a, &id_b);
    write_frame(stream, &msg_b).map_err(io)?;
    let k = Zeroizing::new(spake.finish(&msg_a).map_err(|_| PairError::Protocol)?);
    let psk = derive_psk(&k, &sid);
    let pro = prologue(&sid, &msg_a, &msg_b);

    let mut hs = builder(id, &pro, &psk[..])
        .build_responder()
        .map_err(|_| PairError::Protocol)?;
    let mut buf = Zeroizing::new(vec![0u8; MAX_FRAME]);
    // -> e
    let m1 = read_frame(stream).map_err(io)?;
    hs.read_message(&m1, &mut buf)
        .map_err(|_| PairError::Protocol)?;
    // <- e, ee, s, es
    let n = hs
        .write_message(&[], &mut buf)
        .map_err(|_| PairError::Protocol)?;
    write_frame(stream, &buf[..n]).map_err(io)?;
    // -> s, se, psk: fails to decrypt when the codes differ.
    let m3 = read_frame(stream).map_err(|_| PairError::WrongCode)?;
    hs.read_message(&m3, &mut buf)
        .map_err(|_| PairError::WrongCode)?;
    let remote = remote_key(hs.get_remote_static())?;
    let mut t = hs.into_transport_mode().map_err(|_| PairError::Protocol)?;

    let c = read_frame(stream).map_err(io)?;
    let n = t
        .read_message(&c, &mut buf)
        .map_err(|_| PairError::Protocol)?;
    let name = parse_confirm(&buf[..n])?;
    if &remote == id.public() {
        return Err(PairError::SelfPair);
    }
    let paired = Paired {
        public_key: remote,
        name,
    };
    store(&paired)?;
    let n = t
        .write_message(&confirm_bytes(my_name), &mut buf)
        .map_err(|_| PairError::Protocol)?;
    // Stored already; a lost confirmation leaves the initiator unpaired, which
    // it reports, and re-pairing updates this entry.
    let _ = write_frame(stream, &buf[..n]);
    Ok(paired)
}

/// Initiator side: the user typed `code`. `store` is called once the
/// responder's confirmation was decrypted.
pub fn initiate<S: Read + Write>(
    stream: &mut S,
    code: &str,
    id: &Identity,
    my_name: &str,
    store: impl FnOnce(&Paired) -> Result<(), PairError>,
) -> Result<Paired, PairError> {
    let code = parse_code(code)?;
    let io = |_| PairError::Protocol;
    let sid = read_frame(stream).map_err(io)?;
    if sid.len() != SID_LEN {
        return Err(PairError::Protocol);
    }
    let (id_a, id_b) = spake_ids();
    let (spake, msg_a) =
        Spake2::<Ed25519Group>::start_a(&Password::new(code.as_bytes()), &id_a, &id_b);
    write_frame(stream, &msg_a).map_err(io)?;
    let msg_b = read_frame(stream).map_err(io)?;
    if msg_b.len() != SPAKE_MSG_LEN {
        return Err(PairError::Protocol);
    }
    let k = Zeroizing::new(spake.finish(&msg_b).map_err(|_| PairError::Protocol)?);
    let psk = derive_psk(&k, &sid);
    let pro = prologue(&sid, &msg_a, &msg_b);

    let mut hs = builder(id, &pro, &psk[..])
        .build_initiator()
        .map_err(|_| PairError::Protocol)?;
    let mut buf = Zeroizing::new(vec![0u8; MAX_FRAME]);
    let n = hs
        .write_message(&[], &mut buf)
        .map_err(|_| PairError::Protocol)?;
    write_frame(stream, &buf[..n]).map_err(io)?;
    let m2 = read_frame(stream).map_err(io)?;
    hs.read_message(&m2, &mut buf)
        .map_err(|_| PairError::Protocol)?;
    let remote = remote_key(hs.get_remote_static())?;
    if &remote == id.public() {
        return Err(PairError::SelfPair);
    }
    let n = hs
        .write_message(&[], &mut buf)
        .map_err(|_| PairError::Protocol)?;
    write_frame(stream, &buf[..n]).map_err(io)?;
    let mut t = hs.into_transport_mode().map_err(|_| PairError::Protocol)?;
    let n = t
        .write_message(&confirm_bytes(my_name), &mut buf)
        .map_err(|_| PairError::Protocol)?;
    write_frame(stream, &buf[..n]).map_err(|_| PairError::WrongCode)?;

    // No confirmation (closed, garbage, or undecryptable) means the responder
    // could not read message 3: the codes differed.
    let c = read_frame(stream).map_err(|_| PairError::WrongCode)?;
    let n = t
        .read_message(&c, &mut buf)
        .map_err(|_| PairError::WrongCode)?;
    let name = parse_confirm(&buf[..n]).map_err(|_| PairError::WrongCode)?;
    let paired = Paired {
        public_key: remote,
        name,
    };
    store(&paired)?;
    Ok(paired)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{mpsc, Arc, Mutex};
    use std::time::Duration;

    /// One end of an in-memory duplex pipe. Reads block until data arrives or
    /// the other end is dropped; every byte written is also recorded.
    pub(crate) struct End {
        tx: Option<mpsc::Sender<Vec<u8>>>,
        rx: mpsc::Receiver<Vec<u8>>,
        pending: VecDeque<u8>,
        pub(crate) sent: Arc<Mutex<Vec<u8>>>,
    }

    pub(crate) fn pipe() -> (End, End) {
        let (t1, r1) = mpsc::channel();
        let (t2, r2) = mpsc::channel();
        let mk = |tx, rx| End {
            tx: Some(tx),
            rx,
            pending: VecDeque::new(),
            sent: Arc::default(),
        };
        (mk(t1, r2), mk(t2, r1))
    }

    impl End {
        /// Closes the sending half (the peer then reads end of stream).
        pub(crate) fn close(&mut self) {
            self.tx = None;
        }
    }

    impl Read for End {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            while self.pending.is_empty() {
                match self.rx.recv_timeout(Duration::from_secs(10)) {
                    Ok(v) => self.pending.extend(v),
                    Err(_) => return Ok(0),
                }
            }
            let n = buf.len().min(self.pending.len());
            for b in buf.iter_mut().take(n) {
                *b = self.pending.pop_front().unwrap();
            }
            Ok(n)
        }
    }

    impl Write for End {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.sent.lock().unwrap().extend_from_slice(buf);
            match &self.tx {
                Some(tx) if tx.send(buf.to_vec()).is_ok() => Ok(buf.len()),
                _ => Err(std::io::ErrorKind::BrokenPipe.into()),
            }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    type Outcome = (Result<Paired, PairError>, Result<Paired, PairError>);

    fn run_pair(code_r: &str, code_i: &str, r: &Identity, i: &Identity) -> Outcome {
        let (mut a, mut b) = pipe();
        std::thread::scope(|s| {
            let resp = s.spawn(|| {
                let out = respond(&mut a, code_r, r, "Desktop", |_| Ok(()));
                a.close();
                out
            });
            let init = initiate(&mut b, code_i, i, "Laptop", |_| Ok(()));
            b.close();
            (resp.join().unwrap(), init)
        })
    }

    #[test]
    fn matching_codes_pin_each_other() {
        let r = Identity::generate().unwrap();
        let i = Identity::generate().unwrap();
        let (resp, init) = run_pair("ABCD-EFGH", "abcdefgh", &r, &i);
        let resp = resp.unwrap();
        let init = init.unwrap();
        assert_eq!(&resp.public_key, i.public());
        assert_eq!(resp.name, "Laptop");
        assert_eq!(&init.public_key, r.public());
        assert_eq!(init.name, "Desktop");
    }

    #[test]
    fn wrong_code_fails_both_sides() {
        let r = Identity::generate().unwrap();
        let i = Identity::generate().unwrap();
        let (resp, init) = run_pair("ABCDEFGH", "ABCDEFGI", &r, &i);
        assert_eq!(resp, Err(PairError::WrongCode));
        assert_eq!(init, Err(PairError::WrongCode));
    }

    #[test]
    fn nothing_is_stored_on_failure() {
        let r = Identity::generate().unwrap();
        let i = Identity::generate().unwrap();
        let (mut a, mut b) = pipe();
        let stored = Mutex::new(0);
        std::thread::scope(|s| {
            s.spawn(|| {
                let _ = respond(&mut a, "ABCDEFGH", &r, "R", |_| {
                    *stored.lock().unwrap() += 1;
                    Ok(())
                });
                a.close();
            });
            let _ = initiate(&mut b, "ZZZZZZZZ", &i, "I", |_| {
                *stored.lock().unwrap() += 1;
                Ok(())
            });
            b.close();
        });
        assert_eq!(*stored.lock().unwrap(), 0);
    }

    #[test]
    fn responder_store_failure_sends_no_confirmation() {
        let r = Identity::generate().unwrap();
        let i = Identity::generate().unwrap();
        let (mut a, mut b) = pipe();
        std::thread::scope(|s| {
            let h = s.spawn(|| {
                let out = respond(&mut a, "ABCDEFGH", &r, "R", |_| Err(PairError::StoreFailed));
                a.close();
                out
            });
            let init = initiate(&mut b, "ABCDEFGH", &i, "I", |_| Ok(()));
            b.close();
            assert_eq!(h.join().unwrap(), Err(PairError::StoreFailed));
            assert_eq!(init, Err(PairError::WrongCode));
        });
    }

    #[test]
    fn self_pairing_is_refused() {
        let r = Identity::generate().unwrap();
        let same = Identity::from_secret(Zeroizing::new(r.secret().try_into().unwrap()));
        let (resp, init) = run_pair("ABCDEFGH", "ABCDEFGH", &r, &same);
        assert_eq!(init, Err(PairError::SelfPair));
        assert!(resp.is_err());
    }

    #[test]
    fn codes_are_parsed_strictly() {
        assert_eq!(&*parse_code("abcd-efgh").unwrap(), "ABCDEFGH");
        assert_eq!(&*parse_code("0I8B 2345").unwrap(), "OIBB2345");
        assert_eq!(parse_code("ABCDEFG"), Err(PairError::InvalidCode));
        assert_eq!(parse_code("ABCDEFGHI"), Err(PairError::InvalidCode));
        assert_eq!(parse_code("ABCDEFG9"), Err(PairError::InvalidCode));
        assert_eq!(parse_code("ABCDÉFGH"), Err(PairError::InvalidCode));
        let c = new_code().unwrap();
        assert_eq!(c.len(), CODE_LEN);
        assert!(parse_code(&c).is_ok());
    }

    /// Man in the middle without the code (acceptance: "a MITM without the code
    /// cannot complete pairing, test with a relaying peer"). The attacker sits
    /// on the wire, runs its own SPAKE2 + Noise with each side using a guessed
    /// code, and would relay between them. Both genuine sides fail and neither
    /// pins the attacker's key.
    #[test]
    fn active_relay_without_the_code_fails() {
        let r = Identity::generate().unwrap();
        let i = Identity::generate().unwrap();
        let m = Identity::generate().unwrap();
        let (mut r_end, mut m_to_r) = pipe();
        let (mut i_end, mut m_to_i) = pipe();
        std::thread::scope(|s| {
            let resp = s.spawn(|| {
                let out = respond(&mut r_end, "ABCDEFGH", &r, "R", |_| Ok(()));
                r_end.close();
                out
            });
            let init = s.spawn(|| {
                let out = initiate(&mut i_end, "ABCDEFGH", &i, "I", |_| Ok(()));
                i_end.close();
                out
            });
            // The attacker plays responder to I and initiator to R.
            let mitm_r = s.spawn(|| {
                let out = initiate(&mut m_to_r, "QQQQQQQQ", &m, "M", |_| Ok(()));
                m_to_r.close();
                out
            });
            let mitm_i = respond(&mut m_to_i, "QQQQQQQQ", &m, "M", |_| Ok(()));
            m_to_i.close();
            assert_eq!(resp.join().unwrap(), Err(PairError::WrongCode));
            assert_eq!(init.join().unwrap(), Err(PairError::WrongCode));
            assert!(mitm_r.join().unwrap().is_err());
            assert!(mitm_i.is_err());
        });
    }

    /// A passive relay (forwards every byte) does not stop pairing, but the
    /// two devices pin each other's keys, never the relay's.
    #[test]
    fn transparent_relay_learns_nothing_to_pin() {
        let r = Identity::generate().unwrap();
        let i = Identity::generate().unwrap();
        let (mut r_end, mut relay_r) = pipe();
        let (mut i_end, mut relay_i) = pipe();
        let transcript = std::thread::scope(|s| {
            let resp = s.spawn(|| {
                let out = respond(&mut r_end, "ABCDEFGH", &r, "R", |_| Ok(()));
                r_end.close();
                out
            });
            let init = s.spawn(|| {
                let out = initiate(&mut i_end, "ABCDEFGH", &i, "I", |_| Ok(()));
                i_end.close();
                out
            });
            // Frame-by-frame relay in the protocol's order:
            // R: sid, I: msgA, R: msgB, I: n1, R: n2, I: n3, I: confirm, R: confirm.
            let order = [true, false, true, false, true, false, false, true];
            let mut frames = Vec::new();
            for from_r in order {
                let f = if from_r {
                    let f = read_frame(&mut relay_r).unwrap();
                    write_frame(&mut relay_i, &f).unwrap();
                    f
                } else {
                    let f = read_frame(&mut relay_i).unwrap();
                    write_frame(&mut relay_r, &f).unwrap();
                    f
                };
                frames.push(f);
            }
            let resp = resp.join().unwrap().unwrap();
            let init = init.join().unwrap().unwrap();
            assert_eq!(&resp.public_key, i.public());
            assert_eq!(&init.public_key, r.public());
            frames
        });
        offline_guess_is_impossible(&transcript);
    }

    /// Acceptance: a recorded transcript cannot confirm a code guess offline.
    /// An offline attacker who replays the recorded messages against its own
    /// SPAKE2 + Noise state fails the same way for the right code as for a
    /// wrong one, so the transcript does not distinguish them.
    fn offline_guess_is_impossible(frames: &[Vec<u8>]) {
        let (sid, msg_a, msg_b, n1, _n2, n3) = (
            &frames[0], &frames[1], &frames[2], &frames[3], &frames[4], &frames[5],
        );
        let attacker = Identity::generate().unwrap();
        for guess in ["ABCDEFGH", "ZZZZZZZZ"] {
            // As responder B: a fresh scalar, the recorded msgA.
            let (id_a, id_b) = spake_ids();
            let (st, my_b) =
                Spake2::<Ed25519Group>::start_b(&Password::new(guess.as_bytes()), &id_a, &id_b);
            let k = st.finish(msg_a).unwrap();
            let psk = derive_psk(&k, sid);
            // The prologue must use the recorded msgB, or the transcript differs anyway.
            assert_ne!(&my_b, msg_b);
            let pro = prologue(sid, msg_a, msg_b);
            let mut hs = builder(&attacker, &pro, &psk[..])
                .build_responder()
                .unwrap();
            let mut buf = vec![0u8; MAX_FRAME];
            hs.read_message(n1, &mut buf).unwrap();
            hs.write_message(&[], &mut buf).unwrap();
            assert!(
                hs.read_message(n3, &mut buf).is_err(),
                "guess {guess} must not be checkable offline"
            );
        }
    }

    /// Fixed-output RNG for the SPAKE2 known-answer test.
    struct FixedRng([u8; 64], usize);
    impl rand::RngCore for FixedRng {
        fn next_u32(&mut self) -> u32 {
            unreachable!()
        }
        fn next_u64(&mut self) -> u64 {
            unreachable!()
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            let end = self.1 + dest.len();
            dest.copy_from_slice(&self.0[self.1..end]);
            self.1 = end;
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
    impl rand::CryptoRng for FixedRng {}

    fn scalar_rng(le_hex: &str) -> FixedRng {
        // A 64-byte wide reduction of a value below the group order is that value.
        let mut b = [0u8; 64];
        b[..32].copy_from_slice(&hex::decode(le_hex).unwrap());
        FixedRng(b, 0)
    }

    /// SPAKE2-Ed25519 known answers (the python-spake2 interoperability vectors
    /// the `spake2` crate is tested against: password "password", ids "idA"/"idB").
    #[test]
    fn spake2_known_answer() {
        let pw = Password::new(b"password");
        let (ia, ib) = (SpakeId::new(b"idA"), SpakeId::new(b"idB"));
        let (sa, ma) = Spake2::<Ed25519Group>::start_a_with_rng(
            &pw,
            &ia,
            &ib,
            scalar_rng("25184061a70b1142f1a9f043a52cf7033dc308b5a0a32e42b003ecd59c2ac605"),
        );
        let (sb, mb) = Spake2::<Ed25519Group>::start_b_with_rng(
            &pw,
            &ia,
            &ib,
            scalar_rng("9fb5e845084e0cbe27ac8b4d3af139b33f3f8a047d4234e2d45d33c5cd367b0f"),
        );
        assert_eq!(
            hex::encode(&ma),
            "416fc960df73c9cf8ed7198b0c9534e2e96a5984bfc5edc023fd24dacf371f2af9"
        );
        assert_eq!(
            hex::encode(&mb),
            "42354e97b88406922b1df4bea1d7870f17aed3dba7c720b313edae315b00959309"
        );
        let ka = sa.finish(&mb).unwrap();
        let kb = sb.finish(&ma).unwrap();
        assert_eq!(ka, kb);
        assert_eq!(
            hex::encode(ka),
            "712295de7219c675ddd31942184aa26e0a957cf216bc230d165b215047b520c1"
        );
    }

    /// Runs a cacophony test vector for an XX-family pattern with snow.
    fn noise_vector(pattern: &str, psk: Option<&str>, hash: &str, msgs: &[(&str, &str)]) {
        let h = |s: &str| hex::decode(s).unwrap();
        let prologue = h("4a6f686e2047616c74");
        let (is, ie) = (
            h("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1"),
            h("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a"),
        );
        let (rs, re) = (
            h("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893"),
            h("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b"),
        );
        let psk = psk.map(h);
        fn mk<'a>(
            pattern: &str,
            prologue: &'a [u8],
            psk: Option<&'a [u8]>,
            s: &'a [u8],
            e: &'a [u8],
        ) -> snow::Builder<'a> {
            let mut b = snow::Builder::new(pattern.parse().unwrap())
                .prologue(prologue)
                .local_private_key(s)
                .fixed_ephemeral_key_for_testing_only(e);
            if let Some(p) = psk {
                b = b.psk(3, p);
            }
            b
        }
        let mk = |s, e| mk(pattern, &prologue, psk.as_deref(), s, e);
        let mut init = mk(&is, &ie).build_initiator().unwrap();
        let mut resp = mk(&rs, &re).build_responder().unwrap();
        let mut buf = vec![0u8; MAX_FRAME];
        let mut out = vec![0u8; MAX_FRAME];
        // Three handshake messages, alternating from the initiator.
        for (n, (payload, ct)) in msgs[..3].iter().enumerate() {
            let (w, r) = if n % 2 == 0 {
                (&mut init, &mut resp)
            } else {
                (&mut resp, &mut init)
            };
            let len = w.write_message(&h(payload), &mut buf).unwrap();
            assert_eq!(hex::encode(&buf[..len]), *ct, "{pattern} message {n}");
            let p = r.read_message(&buf[..len], &mut out).unwrap();
            assert_eq!(hex::encode(&out[..p]), *payload);
        }
        assert_eq!(hex::encode(init.get_handshake_hash()), hash);
        let mut ti = init.into_transport_mode().unwrap();
        let mut tr = resp.into_transport_mode().unwrap();
        for (n, (payload, ct)) in msgs[3..].iter().enumerate() {
            let (w, r) = if n % 2 == 0 {
                (&mut tr, &mut ti)
            } else {
                (&mut ti, &mut tr)
            };
            let len = w.write_message(&h(payload), &mut buf).unwrap();
            assert_eq!(hex::encode(&buf[..len]), *ct, "{pattern} transport {n}");
            let p = r.read_message(&buf[..len], &mut out).unwrap();
            assert_eq!(hex::encode(&out[..p]), *payload);
        }
    }

    /// Cacophony known answers for the two patterns shush uses
    /// (`Noise_XX_…` sessions and `Noise_XXpsk3_…` pairing).
    #[test]
    fn noise_known_answers() {
        noise_vector(
            "Noise_XX_25519_ChaChaPoly_BLAKE2s",
            None,
            "6c4c56cf71612f72d05ceb96c0155e6f4ea54a26b504c93de632a2db4a49d200",
            &[
                ("4c756477696720766f6e204d69736573", "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c756477696720766f6e204d69736573"),
                ("4d757272617920526f746862617264", "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f1448088437c365eb362a1c991b0557fe8a7fb187d99346765d93ec63db6c1b01504ebeec55a2298d2dbff80eff034d20595153f63a196a6cead1e11b2bb13e336fa13616dd3e8b0a070c882ed3f1a78c7c06c93"),
                ("462e20412e20486179656b", "46c3307de83b014258717d97781c1f50936d8b7d50c0722a1739654d10392d415b670c114f79b9a4f80541570f77ce88802efa4220cff733e7b5668ba38059ec904b4b8eef9448085faf51"),
                ("4361726c204d656e676572", "d5e83adfaac5dc324a68f1862df54549e56d209fba707205f328b2"),
                ("4a65616e2d426170746973746520536179", "d102c9029b1f55c788f561ba7737afbccef9c9f1bf2f238167fd40ba9c1c134867"),
                ("457567656e2042f6686d20766f6e2042617765726b", "cb1ce80960382c6d5d5e740ffb724d1432f0310b200fb6f8424120f506092744baa415e155"),
            ],
        );
        noise_vector(
            "Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s",
            Some("54686973206973206d7920417573747269616e20706572737065637469766521"),
            "fc0819f08aebc23de9a783653d8d7d6395b7d243d9deec12f5d6fe2f4c206673",
            &[
                ("4c756477696720766f6e204d69736573", "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944325ea71699951ece20f284b6ad9604a029eb335bf84564c308b6ade90ae45078"),
                ("4d757272617920526f746862617264", "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f1448088432645535233ffe1432564d66a85227b677ced6fc2730ae0998ff49aa1dc56b8186e31b16e416f5d9c03c71f6c34fd37ec013105020070a8b00c000ce7ed56629c119795f96463274bc05519d5c24dc1"),
                ("462e20412e20486179656b", "adf16c5375ec4172576783fd59f2bfa5c7a320d0a13b759592e1a2ddf5524cce59ccbb92ff5d321fced3bdb2840596df562c0e68aad41b090abd285f6d300130072e06964a6ba494e58d47"),
                ("4361726c204d656e676572", "dcdc045c8e9ec36c8ea4078552e5849f87cb9bdfbd2a4eee3baaf6"),
                ("4a65616e2d426170746973746520536179", "4d11ed1f242e199dbcbc9773495834a95e8a6109e2b555aeb50780e69b152821e4"),
                ("457567656e2042f6686d20766f6e2042617765726b", "4d1e6873ffcc88490be6914928590f63253c2db434f1f206f083f89ca559a3e60a8dcc4f12"),
            ],
        );
    }
}
