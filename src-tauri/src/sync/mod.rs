//! LAN sync pairing and transport (issue #156, Phase 8b).
//!
//! Normative design: `docs/spec/lan-sync.md`. This module is the protocol
//! core; it speaks over any `Read + Write` stream and never names a socket
//! type. Sockets and discovery are opened only through [`crate::net::NetGate`].
//!
//! - [`identity`]: the per-vault X25519 sync identity and its fingerprint (§2).
//! - [`frame`]: `u16` big-endian length framing of Noise messages (§1).
//! - [`pairing`]: SPAKE2 over a one-time code keying `Noise_XXpsk3` (§3).
//! - [`session`]: `Noise_XX` sessions with a pin check on the peer's key (§4).
//! - [`window`]: the 2-minute, 3-failure, one-success window rules (§3, §4).
//! - [`runtime`]: the open pairing window's state and (with the `network`
//!   feature) its listener loop (§3, §5).
//!
//! Merging inside a session (§8) is not wired here yet: a session currently
//! authenticates and exchanges control messages only.

pub mod frame;
pub mod identity;
pub mod pairing;
pub mod runtime;
pub mod session;
pub mod window;

use crate::vault::models::{now_rfc3339, SyncData, SyncPeer};
use base64::Engine;

/// Characters allowed in a device name sent during pairing.
pub const MAX_NAME_CHARS: usize = 64;

/// Name shown when a peer sends an empty one.
const UNNAMED: &str = "Unnamed device";

/// Cleans a device name received from (or sent to) a peer: control and
/// format characters dropped, whitespace trimmed, at most
/// [`MAX_NAME_CHARS`] characters.
pub fn clean_name(raw: &str) -> String {
    let s: String = raw
        .chars()
        .filter(|c| !c.is_control() && !is_format_char(*c))
        .take(MAX_NAME_CHARS)
        .collect();
    let s = s.trim();
    if s.is_empty() {
        UNNAMED.to_owned()
    } else {
        s.to_owned()
    }
}

/// Bidirectional overrides and zero-width characters, which could make a
/// name display as something else.
fn is_format_char(c: char) -> bool {
    matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}')
}

/// Records a freshly paired device in the vault's peer list (`lan-sync.md`
/// §6). Pairing again with a known key updates its name, time and address.
pub fn upsert_peer(
    sync: &mut SyncData,
    public_key: &[u8; 32],
    name: &str,
    address: Option<String>,
) {
    let id = identity::fingerprint(public_key);
    let b64 = base64::engine::general_purpose::STANDARD.encode(public_key);
    let now = now_rfc3339();
    if let Some(p) = sync.peers.iter_mut().find(|p| p.public_key == b64) {
        p.name = clean_name(name);
        p.paired_at = now;
        p.last_address = address;
        return;
    }
    sync.peers.push(SyncPeer {
        id,
        name: clean_name(name),
        public_key: b64,
        paired_at: now,
        last_sync_at: None,
        last_address: address,
    });
}

/// Whether `public_key` belongs to a pinned (not forgotten) peer.
pub fn is_pinned(sync: &SyncData, public_key: &[u8; 32]) -> bool {
    let b64 = base64::engine::general_purpose::STANDARD.encode(public_key);
    sync.peers.iter().any(|p| p.public_key == b64)
}

/// *Forget device* (§7): removes the peer with this fingerprint. Returns
/// whether one was removed.
pub fn forget_peer(sync: &mut SyncData, id: &str) -> bool {
    let before = sync.peers.len();
    sync.peers.retain(|p| p.id != id);
    sync.peers.len() != before
}

/// *Reset sync identity* (§7): drops the key pair and every pinned peer. A
/// new identity is generated the next time this vault pairs.
pub fn reset_identity(sync: &mut SyncData) {
    sync.identity = None;
    sync.peers.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_cleaned() {
        assert_eq!(clean_name("  Laptop \n"), "Laptop");
        assert_eq!(clean_name("\u{202E}evil"), "evil");
        assert_eq!(clean_name(""), UNNAMED);
        assert_eq!(clean_name(&"x".repeat(200)).chars().count(), MAX_NAME_CHARS);
    }

    #[test]
    fn peers_are_pinned_forgotten_and_reset() {
        let mut s = SyncData::default();
        let k1 = [1u8; 32];
        let k2 = [2u8; 32];
        upsert_peer(&mut s, &k1, "One", None);
        upsert_peer(&mut s, &k2, "Two", Some("10.0.0.2:5000".into()));
        upsert_peer(&mut s, &k1, "One again", None);
        assert_eq!(s.peers.len(), 2);
        assert_eq!(s.peers[0].name, "One again");
        assert!(is_pinned(&s, &k1) && is_pinned(&s, &k2));
        let id1 = identity::fingerprint(&k1);
        assert!(forget_peer(&mut s, &id1));
        assert!(!forget_peer(&mut s, &id1));
        assert!(!is_pinned(&s, &k1));
        assert!(is_pinned(&s, &k2));
        reset_identity(&mut s);
        assert!(!is_pinned(&s, &k2));
        assert!(s.is_empty());
    }
}
