//! Sync sessions between paired devices (`lan-sync.md` §4).
//!
//! `Noise_XX_25519_ChaChaPoly_BLAKE2s`, prologue `"shush-sync-v1"`, the sync
//! identity as the static key. As soon as the remote static key is known it is
//! checked against the pinned peers; an unknown or forgotten key ends the
//! connection at once:
//!
//! - the initiator learns the responder's key from message 2 and, if it is not
//!   pinned, stops before message 3, so it never reveals its own key;
//! - the responder learns the initiator's key from message 3 and, if it is not
//!   pinned, sends nothing more.
//!
//! Handshake payloads are empty; transport messages use Noise's counters as
//! nonces, so replayed or reordered messages fail to decrypt.

use std::io::{Read, Write};

use zeroize::Zeroizing;

use super::frame::{read_frame, write_frame, MAX_FRAME};
use super::identity::Identity;

/// Noise pattern of a sync session.
pub const SESSION_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
const PROLOGUE: &[u8] = b"shush-sync-v1";
/// Noise adds a 16-byte tag to every transport message.
const TAG_LEN: usize = 16;
/// Largest plaintext one session message can carry.
pub const MAX_PLAINTEXT: usize = MAX_FRAME - TAG_LEN;
/// The courtesy message sent before forgetting a connected peer (§7).
pub const REVOKE: &[u8] = br#"{"v":1,"revoke":true}"#;

/// Which end dialled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Dialled the other device.
    Initiator,
    /// Accepted the connection inside a window.
    Responder,
}

/// Why a session could not be opened or used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    /// The remote key is not a pinned peer (never paired, forgotten, or reset).
    #[error("this device is not paired")]
    NotPaired,
    /// Malformed or undecryptable message, or the connection dropped.
    #[error("the sync connection failed")]
    Protocol,
    /// Message too large for one frame.
    #[error("message too large")]
    TooLarge,
}

/// An authenticated session with a pinned peer.
pub struct Session {
    transport: snow::TransportState,
    remote: [u8; 32],
}

fn remote_key(rs: Option<&[u8]>) -> Result<[u8; 32], SessionError> {
    rs.and_then(|k| k.try_into().ok())
        .ok_or(SessionError::Protocol)
}

/// Runs the session handshake. `is_pinned` decides whether the remote static
/// key belongs to a paired device.
pub fn open<S: Read + Write>(
    stream: &mut S,
    role: Role,
    id: &Identity,
    is_pinned: impl Fn(&[u8; 32]) -> bool,
) -> Result<Session, SessionError> {
    fn p<E>(_: E) -> SessionError {
        SessionError::Protocol
    }
    let b = snow::Builder::new(SESSION_PATTERN.parse().expect("valid pattern"))
        .local_private_key(id.secret())
        .prologue(PROLOGUE);
    let mut buf = Zeroizing::new(vec![0u8; MAX_FRAME]);
    let (hs, remote) = match role {
        Role::Initiator => {
            let mut hs = b.build_initiator().map_err(p)?;
            let n = hs.write_message(&[], &mut buf).map_err(p)?;
            write_frame(stream, &buf[..n]).map_err(p)?;
            let m2 = read_frame(stream).map_err(p)?;
            hs.read_message(&m2, &mut buf).map_err(p)?;
            let remote = remote_key(hs.get_remote_static())?;
            if !is_pinned(&remote) {
                return Err(SessionError::NotPaired);
            }
            let n = hs.write_message(&[], &mut buf).map_err(p)?;
            write_frame(stream, &buf[..n]).map_err(p)?;
            (hs, remote)
        }
        Role::Responder => {
            let mut hs = b.build_responder().map_err(p)?;
            let m1 = read_frame(stream).map_err(p)?;
            hs.read_message(&m1, &mut buf).map_err(p)?;
            let n = hs.write_message(&[], &mut buf).map_err(p)?;
            write_frame(stream, &buf[..n]).map_err(p)?;
            let m3 = read_frame(stream).map_err(p)?;
            hs.read_message(&m3, &mut buf).map_err(p)?;
            let remote = remote_key(hs.get_remote_static())?;
            if !is_pinned(&remote) {
                return Err(SessionError::NotPaired);
            }
            (hs, remote)
        }
    };
    if &remote == id.public() {
        return Err(SessionError::NotPaired);
    }
    Ok(Session {
        transport: hs.into_transport_mode().map_err(p)?,
        remote,
    })
}

impl Session {
    /// The peer's static public key.
    pub fn remote(&self) -> &[u8; 32] {
        &self.remote
    }

    /// Encrypts and sends one message.
    pub fn send<W: Write>(&mut self, w: &mut W, plaintext: &[u8]) -> Result<(), SessionError> {
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(SessionError::TooLarge);
        }
        let mut buf = Zeroizing::new(vec![0u8; MAX_FRAME]);
        let n = self
            .transport
            .write_message(plaintext, &mut buf)
            .map_err(|_| SessionError::Protocol)?;
        write_frame(w, &buf[..n]).map_err(|_| SessionError::Protocol)
    }

    /// Receives and decrypts one message.
    pub fn recv<R: Read>(&mut self, r: &mut R) -> Result<Zeroizing<Vec<u8>>, SessionError> {
        let frame = read_frame(r).map_err(|_| SessionError::Protocol)?;
        let mut buf = Zeroizing::new(vec![0u8; MAX_FRAME]);
        let n = self
            .transport
            .read_message(&frame, &mut buf)
            .map_err(|_| SessionError::Protocol)?;
        buf.truncate(n);
        Ok(buf)
    }
}

/// Whether a received message is the revocation courtesy (§7).
pub fn is_revoke(msg: &[u8]) -> bool {
    #[derive(serde::Deserialize)]
    struct Ctl {
        v: u32,
        #[serde(default)]
        revoke: bool,
    }
    serde_json::from_slice::<Ctl>(msg).is_ok_and(|c| c.v == 1 && c.revoke)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::pairing::tests::pipe;

    type Outcome = (Result<Session, SessionError>, Result<Session, SessionError>);

    fn run(
        r: &Identity,
        i: &Identity,
        r_pins: &[[u8; 32]],
        i_pins: &[[u8; 32]],
    ) -> (Outcome, Vec<u8>, Vec<u8>) {
        let (mut a, mut b) = pipe();
        let (r_sent, i_sent) = (a.sent.clone(), b.sent.clone());
        let out = std::thread::scope(|s| {
            let resp = s.spawn(|| {
                let out = open(&mut a, Role::Responder, r, |k| r_pins.contains(k));
                a.close();
                out
            });
            let init = open(&mut b, Role::Initiator, i, |k| i_pins.contains(k));
            b.close();
            (resp.join().unwrap(), init)
        });
        let r_bytes = r_sent.lock().unwrap().clone();
        let i_bytes = i_sent.lock().unwrap().clone();
        (out, r_bytes, i_bytes)
    }

    fn frames(mut wire: &[u8]) -> Vec<Vec<u8>> {
        let mut v = Vec::new();
        while let Ok(f) = read_frame(&mut wire) {
            v.push(f);
        }
        v
    }

    #[test]
    fn pinned_peers_talk() {
        let r = Identity::generate().unwrap();
        let i = Identity::generate().unwrap();
        let (mut a, mut b) = pipe();
        std::thread::scope(|s| {
            let h = s.spawn(|| {
                let mut sess = open(&mut a, Role::Responder, &r, |k| k == i.public()).unwrap();
                let got = sess.recv(&mut a).unwrap();
                sess.send(&mut a, b"pong").unwrap();
                (got, *sess.remote())
            });
            let mut sess = open(&mut b, Role::Initiator, &i, |k| k == r.public()).unwrap();
            assert_eq!(sess.remote(), r.public());
            sess.send(&mut b, REVOKE).unwrap();
            assert_eq!(&**sess.recv(&mut b).unwrap(), b"pong");
            let (got, remote) = h.join().unwrap();
            assert!(is_revoke(&got));
            assert_eq!(&remote, i.public());
        });
        assert!(!is_revoke(b"{\"v\":1}"));
        assert!(!is_revoke(b"pong"));
    }

    /// Acceptance: a forgotten (revoked) initiator is refused by the responder
    /// with nothing sent after the handshake.
    #[test]
    fn revoked_initiator_is_refused_without_payload() {
        let r = Identity::generate().unwrap();
        let i = Identity::generate().unwrap();
        // R forgot I; I still pins R.
        let ((resp, init), r_sent, _) = run(&r, &i, &[], &[*r.public()]);
        assert_eq!(resp.err(), Some(SessionError::NotPaired));
        // I finishes its side of the handshake, but R sends nothing after
        // message 2: any receive on I's side fails.
        let mut init = init.unwrap();
        assert_eq!(frames(&r_sent).len(), 1, "responder sent only message 2");
        let mut empty: &[u8] = &[];
        assert!(init.recv(&mut empty).is_err());
    }

    /// Acceptance: a forgotten responder is refused by the initiator, which
    /// never sends message 3 (so never reveals its own static key).
    #[test]
    fn revoked_responder_is_refused_before_message_3() {
        let r = Identity::generate().unwrap();
        let i = Identity::generate().unwrap();
        let ((resp, init), _, i_sent) = run(&r, &i, &[*i.public()], &[]);
        assert_eq!(init.err(), Some(SessionError::NotPaired));
        assert_eq!(resp.err(), Some(SessionError::Protocol));
        assert_eq!(frames(&i_sent).len(), 1, "initiator sent only message 1");
    }

    #[test]
    fn strangers_are_refused() {
        let r = Identity::generate().unwrap();
        let i = Identity::generate().unwrap();
        let other = Identity::generate().unwrap();
        let ((resp, init), _, _) = run(&r, &i, &[*other.public()], &[*other.public()]);
        assert!(resp.is_err() && init.is_err());
    }

    #[test]
    fn replayed_messages_fail() {
        let r = Identity::generate().unwrap();
        let i = Identity::generate().unwrap();
        let (mut a, mut b) = pipe();
        std::thread::scope(|s| {
            let h = s.spawn(|| open(&mut a, Role::Responder, &r, |_| true).map(|x| (x, a)));
            let mut si = open(&mut b, Role::Initiator, &i, |_| true).unwrap();
            let (mut sr, _a) = h.join().unwrap().unwrap();
            let mut wire = Vec::new();
            si.send(&mut wire, b"one").unwrap();
            let copy = wire.clone();
            assert_eq!(&**sr.recv(&mut &wire[..]).unwrap(), b"one");
            assert!(sr.recv(&mut &copy[..]).is_err(), "replay must fail");
            assert_eq!(
                si.send(&mut Vec::new(), &vec![0u8; MAX_PLAINTEXT + 1])
                    .err(),
                Some(SessionError::TooLarge)
            );
        });
    }
}
