//! Merge of a LAN sync peer's vault into ours (issue #137, spec §9.2).
//!
//! Pure data merge: no transport, no I/O. Call it inside
//! [`super::OpenVault::modify`] so the result is saved crash-safely.
//!
//! Rules (normative, mirrored in `master-specification.md` §9.2):
//! - Per-item [`Hlc`] orders edits; wall-clock `updated_at` is never consulted.
//! - A peer clock more than 24 h ahead of local time is **parked**, not merged.
//! - A password never auto-promotes, whatever the clocks say: the current one
//!   stays active and the peer's differing passwords are archived
//!   (`archived_conflict`). Only non-secret fields follow the newer clock.
//! - Tombstones are unioned (the higher clock wins per id). An edit newer than
//!   a tombstone is **parked** as a conflict, never silently resurrected and
//!   never silently deleted.

use super::hlc::{newer, Hlc};
use super::items::{base, base_mut, MAX_HISTORY};
use super::models::{now_rfc3339, PasswordHistoryEntry, VaultData, VaultItem};

/// Why a peer change was held back for the Conflict Inbox instead of applied.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub enum ParkReason {
    /// The peer's clock is more than 24 h ahead of local time.
    ClockTooFarAhead,
    /// The peer edited an item we deleted, later than our deletion.
    EditAfterLocalDelete,
    /// The peer deleted an item we edited, later than their deletion.
    EditAfterPeerDelete,
}

/// A held-back peer change (ids only; no secrets).
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct Parked {
    /// Item id.
    pub id: String,
    /// Why it was parked.
    pub reason: ParkReason,
}

/// What a merge did.
#[derive(Default, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct MergeReport {
    /// Items added from the peer.
    pub added: usize,
    /// Items whose non-secret fields were taken from the peer (newer clock).
    pub updated: usize,
    /// Peer passwords archived (never promoted).
    pub passwords_archived: usize,
    /// Items removed because of a peer tombstone.
    pub deleted: usize,
    /// Changes held back for the Conflict Inbox.
    pub parked: Vec<Parked>,
}

fn id_of(i: &VaultItem) -> &str {
    &base(i).id
}

/// Merges `peer` into `local` using local time `now_ms` for the drift bound.
pub fn merge_peer(local: &mut VaultData, peer: &VaultData, now_ms: u64) -> MergeReport {
    let mut r = MergeReport::default();
    let plausible = |h: &Option<Hlc>| h.as_ref().map_or(true, |h| h.is_plausible(now_ms));

    // Tombstones first, so item decisions see the unioned set.
    for t in &peer.tombstones {
        if !plausible(&t.hlc) {
            r.parked.push(Parked {
                id: t.id.clone(),
                reason: ParkReason::ClockTooFarAhead,
            });
            continue;
        }
        if let Some(i) = local.items.iter().position(|i| id_of(i) == t.id) {
            if newer(base(&local.items[i]).hlc.as_ref(), t.hlc.as_ref()) {
                r.parked.push(Parked {
                    id: t.id.clone(),
                    reason: ParkReason::EditAfterPeerDelete,
                });
                continue;
            }
            local.items.remove(i);
            r.deleted += 1;
        }
        match local.tombstones.iter_mut().find(|l| l.id == t.id) {
            None => local.tombstones.push(t.clone()),
            Some(l) if newer(t.hlc.as_ref(), l.hlc.as_ref()) => *l = t.clone(),
            Some(_) => {}
        }
    }

    for inc in &peer.items {
        let id = id_of(inc);
        let inc_hlc = base(inc).hlc.clone();
        if !plausible(&inc_hlc) {
            r.parked.push(Parked {
                id: id.to_string(),
                reason: ParkReason::ClockTooFarAhead,
            });
            continue;
        }
        if let Some(t) = local.tombstones.iter().find(|t| t.id == id) {
            if newer(inc_hlc.as_ref(), t.hlc.as_ref()) {
                r.parked.push(Parked {
                    id: id.to_string(),
                    reason: ParkReason::EditAfterLocalDelete,
                });
            }
            continue;
        }
        let Some(cur) = local.items.iter_mut().find(|c| id_of(c) == id) else {
            local.items.push(inc.clone());
            r.added += 1;
            continue;
        };
        if *cur == *inc {
            continue;
        }
        let peer_newer = newer(inc_hlc.as_ref(), base(cur).hlc.as_ref());
        if let (VaultItem::Login(c), VaultItem::Login(i)) = (&mut *cur, inc) {
            let source = "Synced from a paired device".to_string();
            let candidates = std::iter::once(i.password.as_str())
                .chain(i.password_history.iter().map(|h| h.password.as_str()));
            let mut fresh: Vec<String> = Vec::new();
            for p in candidates {
                let known = c.password == p || c.password_history.iter().any(|h| h.password == p);
                if !p.is_empty() && !known && !fresh.iter().any(|f| f == p) {
                    fresh.push(p.to_string());
                }
            }
            r.passwords_archived += fresh.len();
            for p in fresh {
                c.password_history.push(PasswordHistoryEntry {
                    password: p,
                    changed_at: now_rfc3339(),
                    source: Some(source.clone()),
                    status: Some("archived_conflict".into()),
                });
            }
            let excess = c.password_history.len().saturating_sub(MAX_HISTORY);
            c.password_history.drain(..excess);
            if peer_newer {
                // Non-secret fields only; password and TOTP secret stay ours.
                c.username = i.username.clone();
                c.url = i.url.clone();
                if c.totp_secret.is_none() {
                    c.totp_secret = i.totp_secret.clone();
                }
            }
        }
        if peer_newer {
            if let (VaultItem::SecureNote(c), VaultItem::SecureNote(i)) = (&mut *cur, inc) {
                c.content = i.content.clone();
            }
            let ib = base(inc);
            let b = base_mut(cur);
            b.title = ib.title.clone();
            b.folder_id = ib.folder_id.clone();
            b.tags = ib.tags.clone();
            b.favorite = ib.favorite;
            b.notes = ib.notes.clone();
            b.hlc = ib.hlc.clone();
            r.updated += 1;
        }
    }

    // Observe the peer's (plausible) clocks so our next local edit orders after
    // everything merged here.
    let seen = peer
        .items
        .iter()
        .filter_map(|i| base(i).hlc.as_ref())
        .chain(peer.tombstones.iter().filter_map(|t| t.hlc.as_ref()))
        .filter(|h| h.is_plausible(now_ms))
        .max();
    if let Some(h) = seen {
        if newer(Some(h), local.last_hlc.as_ref()) {
            local.last_hlc = Some(h.clone());
        }
    }
    local.gc_tombstones();
    if r.added + r.updated + r.passwords_archived + r.deleted > 0 {
        local.updated_at = now_rfc3339();
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::hlc::{self, MAX_DRIFT_MS};
    use crate::vault::items::{ItemDraft, ItemKind};
    use crate::vault::models::LoginItem;

    fn draft(title: &str, pw: &str) -> ItemDraft {
        ItemDraft {
            title: title.into(),
            username: "u".into(),
            url: "https://example.com".into(),
            password: Some(pw.into()),
            ..Default::default()
        }
    }

    /// Two vaults sharing one item, as after a first sync.
    fn pair() -> (VaultData, VaultData, String) {
        let mut a = VaultData::new();
        let id = a
            .create_item(ItemKind::Login, &draft("Site", "pw-a"))
            .unwrap();
        let mut b = a.clone();
        b.device_id = "peer".into();
        (a, b, id)
    }

    fn tick() {
        std::thread::sleep(std::time::Duration::from_millis(3));
    }

    fn login(v: &VaultData, id: &str) -> LoginItem {
        match v.items.iter().find(|i| id_of(i) == id) {
            Some(VaultItem::Login(l)) => l.clone(),
            _ => panic!("missing"),
        }
    }

    #[test]
    fn higher_clock_never_promotes_a_password() {
        let (mut a, mut b, id) = pair();
        tick();
        let mut d = draft("Renamed", "pw-b");
        d.url = "https://new.example.com".into();
        b.update_item(&id, &d).unwrap();
        let r = merge_peer(&mut a, &b, hlc::now_ms());
        let l = login(&a, &id);
        assert_eq!(l.password, "pw-a");
        assert_eq!(l.base.title, "Renamed");
        assert_eq!(l.url, "https://new.example.com");
        assert!(l
            .password_history
            .iter()
            .any(|h| h.password == "pw-b" && h.status.as_deref() == Some("archived_conflict")));
        assert_eq!((r.updated, r.passwords_archived), (1, 1));
    }

    #[test]
    fn lower_clock_keeps_local_fields_but_archives_password() {
        let (mut a, mut b, id) = pair();
        b.update_item(&id, &draft("Peer title", "pw-b")).unwrap();
        tick();
        a.update_item(&id, &draft("Local title", "pw-a")).unwrap();
        merge_peer(&mut a, &b, hlc::now_ms());
        let l = login(&a, &id);
        assert_eq!(l.base.title, "Local title");
        assert_eq!(l.password, "pw-a");
        assert_eq!(
            l.password_history
                .iter()
                .filter(|h| h.password == "pw-b")
                .count(),
            1
        );
    }

    #[test]
    fn far_future_clock_is_parked() {
        let (mut a, mut b, id) = pair();
        b.update_item(&id, &draft("Evil", "pw-evil")).unwrap();
        let now = hlc::now_ms();
        if let VaultItem::Login(l) = &mut b.items[0] {
            l.base.hlc.as_mut().unwrap().physical_ms = now + MAX_DRIFT_MS + 10_000;
        }
        let r = merge_peer(&mut a, &b, now);
        assert_eq!(r.parked.len(), 1);
        assert_eq!(r.parked[0].reason, ParkReason::ClockTooFarAhead);
        let l = login(&a, &id);
        assert_eq!(l.base.title, "Site");
        assert!(l.password_history.is_empty());
    }

    #[test]
    fn peer_tombstone_deletes_unedited_item_and_unions() {
        let (mut a, mut b, id) = pair();
        b.delete_item(&id).unwrap();
        let r = merge_peer(&mut a, &b, hlc::now_ms());
        assert_eq!(r.deleted, 1);
        assert!(a.items.is_empty() && a.is_tombstoned(&id));
    }

    #[test]
    fn edit_after_peer_delete_is_parked_not_deleted() {
        let (mut a, mut b, id) = pair();
        b.delete_item(&id).unwrap();
        tick();
        a.update_item(&id, &draft("Edited", "pw-a")).unwrap();
        let r = merge_peer(&mut a, &b, hlc::now_ms());
        assert_eq!(r.parked[0].reason, ParkReason::EditAfterPeerDelete);
        assert_eq!(a.items.len(), 1);
        assert!(!a.is_tombstoned(&id));
    }

    #[test]
    fn edit_after_local_delete_is_parked_not_resurrected() {
        let (mut a, mut b, id) = pair();
        a.delete_item(&id).unwrap();
        tick();
        b.update_item(&id, &draft("Edited", "pw-b")).unwrap();
        let r = merge_peer(&mut a, &b, hlc::now_ms());
        assert_eq!(r.parked[0].reason, ParkReason::EditAfterLocalDelete);
        assert!(a.items.is_empty() && a.is_tombstoned(&id));
    }

    #[test]
    fn new_peer_items_are_added_and_clock_is_observed() {
        let (mut a, mut b, _) = pair();
        let new = b.create_item(ItemKind::Login, &draft("New", "x")).unwrap();
        let peer_clock = b.last_hlc.clone();
        let r = merge_peer(&mut a, &b, hlc::now_ms());
        assert_eq!(r.added, 1);
        assert!(a.items.iter().any(|i| id_of(i) == new));
        assert!(a.last_hlc >= peer_clock);
        // Merging again changes nothing.
        assert_eq!(
            merge_peer(&mut a, &b, hlc::now_ms()),
            MergeReport::default()
        );
    }

    #[test]
    fn legacy_payloads_without_clock_fields_still_load() {
        let (a, _, _) = pair();
        let mut json = serde_json::to_value(&a).unwrap();
        json.as_object_mut().unwrap().remove("device_id");
        json.as_object_mut().unwrap().remove("last_hlc");
        json["items"][0].as_object_mut().unwrap().remove("hlc");
        let mut back: VaultData = serde_json::from_value(json).unwrap();
        assert!(back.items.iter().all(|i| base(i).hlc.is_none()));
        let h = back.next_hlc();
        assert!(!back.device_id.is_empty() && h.device_id == back.device_id);
    }
}
