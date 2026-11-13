//! Browser bridge protocol v1 (issue #16, roadmap Phase 7b).
//!
//! Request envelope (one frame):
//!
//! ```json
//! {"v":1,"rid":7,"pair_id":"…","counter":3,"mac":"<base64>","body":"{\"type\":\"match\",…}"}
//! ```
//!
//! `body` is the request as a JSON *string*, so the MAC covers exact bytes
//! with no canonicalization. `pair_id`, `counter` and `mac` are required for
//! everything except `hello` and `pair`. Answers use the same shape: `body`
//! is `{"ok":true,"result":…}` or `{"ok":false,"error":"CODE"}`, MACed with
//! the request's counter when the request was authenticated.
//!
//! | body `type` | needs | answer |
//! |---|---|---|
//! | `hello` | — | `{version, locked, paired, pairing_nonce?}` |
//! | `pair {ext_nonce, proof}` | live code | `{pair_id}` |
//! | `match {tab_origin}` | paired, unlocked | `[{id, title, username}]` (no secrets) |
//! | `fill {id, tab_origin}` | paired, unlocked, exact origin | `{username, password, totp?}` |
//! | `save {tab_origin, username, password}` | paired, unlocked | `{queued}`; written only after approval in shush |
//! | `revoke` | paired | `{}` |
//!
//! `fill` only ever returns the item's current password. Archived passwords
//! are never sent to a browser: no automatic "try the old password" fallback.

use std::time::Instant;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::origin::{item_matches, Origin};
use super::pairing::{AuthError, Pairing, PairingOffer};
use crate::vault::models::StoredPairing;
use crate::vault::models::VaultItem;
use crate::vault::VaultData;

/// Protocol version.
pub const VERSION: u32 = 1;
/// Most saves waiting for approval; older ones are dropped first.
pub const MAX_PENDING_SAVES: usize = 20;
const MAX_FIELD: usize = 4096;

#[derive(Deserialize)]
struct Envelope {
    v: u32,
    rid: u64,
    pair_id: Option<String>,
    counter: Option<u64>,
    mac: Option<String>,
    body: String,
}

impl Drop for Envelope {
    fn drop(&mut self) {
        self.body.zeroize(); // may hold a password (`save`)
    }
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Hello,
    Pair {
        #[serde(alias = "ext_msg")]
        ext_nonce: String,
        proof: String,
    },
    Match {
        tab_origin: String,
    },
    Fill {
        id: String,
        tab_origin: String,
    },
    Save {
        tab_origin: String,
        username: String,
        password: String,
    },
    Revoke,
}

/// A login the extension offered to save, waiting for approval in shush.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PendingSave {
    /// Normalized origin of the tab, e.g. `https://github.com:443`.
    pub origin: String,
    /// Username typed on the page.
    pub username: String,
    /// Password typed on the page.
    pub password: String,
}

impl PendingSave {
    /// Item URL for the saved login: the origin without its default port.
    pub fn url(&self) -> String {
        for suffix in ["https://", "http://"] {
            if let Some(rest) = self.origin.strip_prefix(suffix) {
                let port = if suffix == "https://" { ":443" } else { ":80" };
                return format!("{suffix}{}", rest.strip_suffix(port).unwrap_or(rest));
            }
        }
        self.origin.clone()
    }

    /// Item title: the host.
    pub fn title(&self) -> String {
        let url = self.url();
        let rest = url.split_once("://").map_or(url.as_str(), |(_, r)| r);
        rest.to_string()
    }
}

/// Writes an approved save into the vault: a login for the same site and user
/// gets its password updated (the old one is archived by `update_item`),
/// anything else becomes a new login. Returns the item id.
pub fn apply_save(
    d: &mut VaultData,
    p: &PendingSave,
) -> Result<String, crate::vault::items::ItemError> {
    use crate::vault::items::{ItemDraft, ItemKind};
    let tab = Origin::parse_tab(&p.origin);
    let existing = tab.and_then(|tab| {
        logins(d)
            .find(|l| l.username == p.username && item_matches(&l.url, &tab))
            .map(|l| {
                (
                    l.base.id.clone(),
                    ItemDraft {
                        title: l.base.title.clone(),
                        username: l.username.clone(),
                        password: Some(p.password.clone().into()),
                        url: l.url.clone(),
                        notes: l.base.notes.clone(),
                        favorite: l.base.favorite,
                        tags: l.base.tags.clone(),
                        folder_id: l.base.folder_id.clone(),
                        ..ItemDraft::default()
                    },
                )
            })
    });
    if let Some((id, draft)) = existing {
        d.update_item(&id, &draft)?;
        return Ok(id);
    }
    d.create_item(
        ItemKind::Login,
        &ItemDraft {
            title: p.title(),
            username: p.username.clone(),
            password: Some(p.password.clone().into()),
            url: p.url(),
            ..ItemDraft::default()
        },
    )
}

/// Bridge state owned by the main instance.
#[derive(Default)]
pub struct Bridge {
    offer: Option<PairingOffer>,
    pairings: Vec<Pairing>,
    pending: Vec<PendingSave>,
    /// Pairings live inside the vault; while it is locked none are loaded and
    /// every request but `hello` answers `LOCKED`. `Default` is unsealed (tests).
    sealed: bool,
    /// Pairings or counters changed since the last [`Bridge::take_dirty`].
    dirty: bool,
}

/// Error codes sent to the extension.
fn code(e: AuthError) -> &'static str {
    match e {
        AuthError::NoOffer => "NO_PAIRING_CODE",
        AuthError::WrongCode => "WRONG_PAIRING_CODE",
        AuthError::NotPaired => "NOT_PAIRED",
        AuthError::BadMac => "BAD_MAC",
        AuthError::Rng => "INTERNAL",
    }
}

impl Bridge {
    /// The state the app starts in: locked, no pairings loaded.
    pub fn sealed() -> Self {
        Self {
            sealed: true,
            ..Self::default()
        }
    }

    /// Whether no vault's pairings are loaded (vault locked).
    pub fn is_sealed(&self) -> bool {
        self.sealed
    }

    /// Loads the unlocked vault's pairings. Does nothing if already loaded.
    pub fn load_pairings(&mut self, stored: &[StoredPairing]) {
        if !self.sealed {
            return;
        }
        self.pairings = stored.iter().filter_map(Pairing::from_stored).collect();
        self.sealed = false;
        self.dirty = false;
    }

    /// Pairings in their persisted form.
    pub fn export_pairings(&self) -> Vec<StoredPairing> {
        self.pairings.iter().map(Pairing::to_stored).collect()
    }

    /// Whether the persisted pairings are out of date; resets the flag.
    pub fn take_dirty(&mut self) -> bool {
        std::mem::take(&mut self.dirty)
    }

    /// Re-flags the pairings as unsaved (a failed save must be retried).
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// The pairing code on screen, if one is live: `(code, seconds left)`.
    pub fn live_offer(&self, now: Instant) -> Option<(String, u64)> {
        let o = self.offer.as_ref().filter(|o| o.is_live(now))?;
        Some((o.formatted_code(), o.seconds_left(now)))
    }

    /// Cancels the pairing code on screen.
    pub fn cancel_pairing(&mut self) {
        self.offer = None;
    }

    /// *Settings → Pair browser*: starts a new pairing and returns the formatted code to show (`XXXX-XXXX`).
    pub fn start_pairing(&mut self, now: Instant) -> Result<String, AuthError> {
        let offer = PairingOffer::new(now)?;
        let code = offer.formatted_code();
        self.offer = Some(offer);
        Ok(code)
    }

    /// Ids of paired browsers.
    pub fn pairing_ids(&self) -> Vec<String> {
        self.pairings.iter().map(|p| p.id().to_string()).collect()
    }

    /// Revokes a pairing from the shush side.
    pub fn revoke(&mut self, pair_id: &str) {
        let before = self.pairings.len();
        self.pairings.retain(|p| p.id() != pair_id);
        self.dirty |= self.pairings.len() != before;
    }

    /// Saves waiting for approval.
    pub fn pending_saves(&self) -> &[PendingSave] {
        &self.pending
    }

    /// Removes and returns a pending save (approve or reject in the UI).
    pub fn take_pending(&mut self, index: usize) -> Option<PendingSave> {
        (index < self.pending.len()).then(|| self.pending.remove(index))
    }

    /// Puts a save back after a failed approval (it stays at the end of the queue).
    pub fn requeue(&mut self, p: PendingSave) {
        self.pending.push(p);
    }

    /// Removes and returns the pending save for this login (approve or reject in the UI).
    pub fn take_pending_for(&mut self, origin: &str, username: &str) -> Option<PendingSave> {
        let i = self
            .pending
            .iter()
            .position(|p| p.origin == origin && p.username == username)?;
        Some(self.pending.remove(i))
    }

    /// Call when the vault locks: queued plaintext passwords are wiped, the
    /// pairing keys are dropped from memory and the pairing code is withdrawn.
    pub fn on_vault_locked(&mut self) {
        self.pending.clear();
        self.pairings.clear();
        self.offer = None;
        self.sealed = true;
        self.dirty = false;
    }

    /// Handles one framed request. `vault` is `None` while locked. Always
    /// returns an answer frame body; never panics on hostile input.
    pub fn handle(
        &mut self,
        raw: &[u8],
        vault: Option<&VaultData>,
        now: Instant,
    ) -> Zeroizing<Vec<u8>> {
        let env: Envelope = match serde_json::from_slice(raw) {
            Ok(e) => e,
            Err(_) => return answer(0, None, None, Err("BAD_REQUEST")),
        };
        if env.v != VERSION {
            return answer(env.rid, None, None, Err("UNSUPPORTED_VERSION"));
        }
        let req: Request = match serde_json::from_str(&env.body) {
            Ok(r) => r,
            Err(_) => return answer(env.rid, None, None, Err("BAD_REQUEST")),
        };

        if self.sealed {
            // No pairing is loaded: only `hello` is answered (unsigned).
            let result = match req {
                Request::Hello => self.dispatch(&req, None, vault, now),
                _ => Err("LOCKED"),
            };
            return answer(env.rid, None, None, result);
        }

        // Authenticate if the caller claims a pairing; require it unless the
        // request is `hello` or `pair`.
        let auth = match (&env.pair_id, env.counter, &env.mac) {
            (Some(id), Some(counter), Some(mac)) => {
                match self.authenticate(id, counter, &env.body, mac) {
                    Ok(i) => Some((i, counter)),
                    Err(e) => return answer(env.rid, None, None, Err(code(e))),
                }
            }
            (None, None, None) => None,
            _ => return answer(env.rid, None, None, Err("BAD_REQUEST")),
        };
        let open = matches!(req, Request::Hello | Request::Pair { .. });
        if auth.is_none() && !open {
            return answer(env.rid, None, None, Err("NOT_PAIRED"));
        }

        let result = self.dispatch(&req, auth.map(|(i, _)| i), vault, now);
        // Looked up by id again: `revoke` may have removed the pairing, and
        // then the answer goes out unsigned rather than under another key.
        let signer = auth.and_then(|(_, c)| {
            let id = env.pair_id.as_deref()?;
            self.pairings.iter().find(|p| p.id() == id).map(|p| (p, c))
        });
        answer(
            env.rid,
            signer.map(|(p, _)| p),
            signer.map(|(_, c)| c),
            result,
        )
    }

    fn authenticate(
        &mut self,
        id: &str,
        counter: u64,
        body: &str,
        mac: &str,
    ) -> Result<usize, AuthError> {
        let i = self
            .pairings
            .iter()
            .position(|p| p.id() == id)
            .ok_or(AuthError::NotPaired)?;
        let mac = B64.decode(mac).map_err(|_| AuthError::BadMac)?;
        self.pairings[i].verify(counter, body.as_bytes(), &mac)?;
        self.dirty = true; // the replay counter advanced
        Ok(i)
    }

    fn dispatch(
        &mut self,
        req: &Request,
        paired: Option<usize>,
        vault: Option<&VaultData>,
        now: Instant,
    ) -> Result<Value, &'static str> {
        match req {
            Request::Hello => {
                let nonce = self
                    .offer
                    .as_ref()
                    .filter(|o| o.is_live(now))
                    .map(|o| B64.encode(o.host_nonce()));
                Ok(json!({
                    "version": VERSION,
                    "locked": vault.is_none(),
                    "paired": paired.is_some(),
                    "pairing_nonce": nonce,
                }))
            }
            Request::Pair { ext_nonce, proof } => {
                let ext = B64.decode(ext_nonce).map_err(|_| "BAD_REQUEST")?;
                let proof = B64.decode(proof).map_err(|_| "BAD_REQUEST")?;
                let offer = self.offer.as_mut().ok_or(code(AuthError::NoOffer))?;
                let result = offer.redeem(&ext, &proof, now);
                if !offer.is_live(now) {
                    self.offer = None;
                }
                let pairing = result.map_err(code)?;
                let id = pairing.id().to_string();
                self.pairings.push(pairing);
                self.dirty = true;
                Ok(json!({ "pair_id": id }))
            }
            Request::Match { tab_origin } => {
                let data = vault.ok_or("LOCKED")?;
                let tab = Origin::parse_tab(tab_origin).ok_or("BAD_ORIGIN")?;
                let hits: Vec<Value> = logins(data)
                    .filter(|l| item_matches(&l.url, &tab))
                    .map(|l| json!({ "id": l.base.id, "title": l.base.title, "username": l.username }))
                    .collect();
                Ok(Value::Array(hits))
            }
            Request::Fill { id, tab_origin } => {
                let data = vault.ok_or("LOCKED")?;
                let tab = Origin::parse_tab(tab_origin).ok_or("BAD_ORIGIN")?;
                let login = logins(data).find(|l| &l.base.id == id).ok_or("NOT_FOUND")?;
                // Re-checked here: the extension's `match` result is not trusted.
                if !item_matches(&login.url, &tab) {
                    return Err("ORIGIN_MISMATCH");
                }
                let totp = login
                    .totp_secret
                    .as_deref()
                    .and_then(|s| crate::totp::current_code(s).ok())
                    .map(|c| c.code);
                // Only the current password; `password_history` is never sent.
                Ok(json!({ "username": login.username, "password": login.password, "totp": totp }))
            }
            Request::Save {
                tab_origin,
                username,
                password,
            } => {
                vault.ok_or("LOCKED")?;
                let tab = Origin::parse_tab(tab_origin).ok_or("BAD_ORIGIN")?;
                if password.is_empty() || password.len() > MAX_FIELD || username.len() > MAX_FIELD {
                    return Err("BAD_REQUEST");
                }
                let origin = tab.to_string();
                self.pending
                    .retain(|p| !(p.origin == origin && &p.username == username));
                if self.pending.len() >= MAX_PENDING_SAVES {
                    self.pending.remove(0);
                }
                self.pending.push(PendingSave {
                    origin,
                    username: username.clone(),
                    password: password.clone(),
                });
                Ok(json!({ "queued": true }))
            }
            Request::Revoke => {
                let i = paired.ok_or("NOT_PAIRED")?;
                self.pairings.remove(i);
                self.dirty = true;
                Ok(json!({}))
            }
        }
    }
}

fn logins(data: &VaultData) -> impl Iterator<Item = &crate::vault::models::LoginItem> {
    data.items.iter().filter_map(|i| match i {
        VaultItem::Login(l) => Some(l),
        VaultItem::SecureNote(_) => None,
    })
}

/// Builds the answer frame. Values that may hold secrets are serialized into
/// wipeable buffers.
fn answer(
    rid: u64,
    signer: Option<&Pairing>,
    counter: Option<u64>,
    result: Result<Value, &'static str>,
) -> Zeroizing<Vec<u8>> {
    let mut body_value = match result {
        Ok(v) => json!({ "ok": true, "result": v }),
        Err(e) => json!({ "ok": false, "error": e }),
    };
    let body = Zeroizing::new(body_value.to_string());
    wipe_value(&mut body_value);
    let mac = signer
        .zip(counter)
        .map(|(p, c)| B64.encode(p.sign(c, body.as_bytes())));
    let mut env = json!({ "v": VERSION, "rid": rid, "body": &*body });
    if let Some(mac) = mac {
        env["counter"] = json!(counter);
        env["mac"] = json!(mac);
    }
    let out = Zeroizing::new(env.to_string().into_bytes());
    wipe_value(&mut env);
    out
}

/// Best-effort wipe of strings inside a JSON value (issue #6 limits apply).
fn wipe_value(v: &mut Value) {
    match v {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(wipe_value),
        Value::Object(o) => o.values_mut().for_each(wipe_value),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::pairing::{extension_pair, request_mac};
    use crate::vault::models::{BaseItem, LoginItem, PasswordHistoryEntry};

    struct Ext {
        pair_id: String,
        key: [u8; 32],
        counter: u64,
    }

    fn login(id: &str, url: &str, user: &str, pw: &str) -> VaultItem {
        VaultItem::Login(LoginItem {
            base: BaseItem {
                id: id.into(),
                title: format!("t-{id}"),
                folder_id: None,
                tags: vec![],
                favorite: false,
                notes: String::new(),
                attachments: vec![],
                created_at: String::new(),
                updated_at: String::new(),
                last_used_at: None,
            },
            username: user.into(),
            password: pw.into(),
            url: url.into(),
            totp_secret: None,
            password_history: vec![PasswordHistoryEntry {
                password: "OLD-ARCHIVED-PW".into(),
                changed_at: String::new(),
                source: Some("Imported from Firefox".into()),
                status: Some("archived_conflict".into()),
            }],
        })
    }

    fn vault() -> VaultData {
        let mut d = VaultData::new();
        d.items.push(login(
            "gh",
            "https://github.com/login",
            "octo",
            "current-pw",
        ));
        d.items
            .push(login("ev", "https://github.com.evil.test", "x", "y"));
        d
    }

    fn send(b: &mut Bridge, env: Value, v: Option<&VaultData>) -> Value {
        let out = b.handle(env.to_string().as_bytes(), v, Instant::now());
        let env: Value = serde_json::from_slice(&out).unwrap();
        serde_json::from_str(env["body"].as_str().unwrap()).unwrap()
    }

    fn open(b: &mut Bridge, body: Value) -> Value {
        send(b, json!({"v":1,"rid":1,"body":body.to_string()}), None)
    }

    fn signed(b: &mut Bridge, ext: &mut Ext, body: Value, v: Option<&VaultData>) -> Value {
        ext.counter += 1;
        let body = body.to_string();
        let mac = B64.encode(request_mac(&ext.key, ext.counter, body.as_bytes()));
        send(
            b,
            json!({"v":1,"rid":ext.counter,"pair_id":ext.pair_id,"counter":ext.counter,"mac":mac,"body":body}),
            v,
        )
    }

    fn paired(b: &mut Bridge) -> Ext {
        let code = b.start_pairing(Instant::now()).unwrap();
        let hello = open(b, json!({"type":"hello"}));
        let host_msg = B64
            .decode(hello["result"]["pairing_nonce"].as_str().unwrap())
            .unwrap();
        let (ext_msg, proof, key) = extension_pair(&code, &host_msg).unwrap();
        let r = open(
            b,
            json!({"type":"pair","ext_nonce":B64.encode(ext_msg),"proof":B64.encode(proof)}),
        );
        assert_eq!(r["ok"], true, "{r}");
        let pair_id = r["result"]["pair_id"].as_str().unwrap().to_string();
        Ext {
            pair_id,
            key,
            counter: 0,
        }
    }

    #[test]
    fn unpaired_gets_hello_only() {
        let mut b = Bridge::default();
        let d = vault();
        let r = open(&mut b, json!({"type":"hello"}));
        assert_eq!(r["result"]["paired"], false);
        assert_eq!(r["result"]["pairing_nonce"], Value::Null);
        for body in [
            json!({"type":"match","tab_origin":"https://github.com"}),
            json!({"type":"fill","id":"gh","tab_origin":"https://github.com"}),
            json!({"type":"save","tab_origin":"https://a.test","username":"u","password":"p"}),
            json!({"type":"revoke"}),
        ] {
            let r = send(
                &mut b,
                json!({"v":1,"rid":1,"body":body.to_string()}),
                Some(&d),
            );
            assert_eq!(r["error"], "NOT_PAIRED", "{body}");
        }
        // Pairing without a code on screen.
        let r = open(
            &mut b,
            json!({"type":"pair","ext_nonce":B64.encode([0u8;32]),"proof":"AA=="}),
        );
        assert_eq!(r["error"], "NO_PAIRING_CODE");
    }

    #[test]
    fn match_and_fill_are_origin_exact() {
        let mut b = Bridge::default();
        let mut ext = paired(&mut b);
        let d = vault();

        let r = signed(
            &mut b,
            &mut ext,
            json!({"type":"match","tab_origin":"https://github.com/x"}),
            Some(&d),
        );
        assert_eq!(
            r["result"],
            json!([{"id":"gh","title":"t-gh","username":"octo"}])
        );
        for o in ["https://github.com.evil.test", "http://github.com"] {
            let r = signed(
                &mut b,
                &mut ext,
                json!({"type":"match","tab_origin":o}),
                Some(&d),
            );
            let ids: Vec<_> = r["result"]
                .as_array()
                .unwrap()
                .iter()
                .map(|h| h["id"].clone())
                .collect();
            assert!(!ids.contains(&json!("gh")), "{o}");
        }

        let r = signed(
            &mut b,
            &mut ext,
            json!({"type":"fill","id":"gh","tab_origin":"https://github.com"}),
            Some(&d),
        );
        assert_eq!(r["result"]["password"], "current-pw");
        let r = signed(
            &mut b,
            &mut ext,
            json!({"type":"fill","id":"gh","tab_origin":"https://github.com.evil.test"}),
            Some(&d),
        );
        assert_eq!(r["error"], "ORIGIN_MISMATCH");
        let r = signed(
            &mut b,
            &mut ext,
            json!({"type":"fill","id":"gh","tab_origin":"https://github.com"}),
            None,
        );
        assert_eq!(r["error"], "LOCKED");
    }

    #[test]
    fn archived_passwords_never_leave() {
        let mut b = Bridge::default();
        let mut ext = paired(&mut b);
        let d = vault();
        let raw = {
            ext.counter += 1;
            let body =
                json!({"type":"fill","id":"gh","tab_origin":"https://github.com"}).to_string();
            let mac = B64.encode(request_mac(&ext.key, ext.counter, body.as_bytes()));
            let env = json!({"v":1,"rid":1,"pair_id":ext.pair_id,"counter":ext.counter,"mac":mac,"body":body});
            b.handle(env.to_string().as_bytes(), Some(&d), Instant::now())
        };
        let text = String::from_utf8(raw.to_vec()).unwrap();
        assert!(text.contains("current-pw"));
        assert!(!text.contains("OLD-ARCHIVED-PW"));
    }

    #[test]
    fn replay_and_forgery_are_refused() {
        let mut b = Bridge::default();
        let mut ext = paired(&mut b);
        let d = vault();
        let body = json!({"type":"match","tab_origin":"https://github.com"}).to_string();
        let mac = B64.encode(request_mac(&ext.key, 5, body.as_bytes()));
        let env = json!({"v":1,"rid":1,"pair_id":ext.pair_id,"counter":5,"mac":mac,"body":body});
        assert_eq!(send(&mut b, env.clone(), Some(&d))["ok"], true);
        assert_eq!(send(&mut b, env, Some(&d))["error"], "BAD_MAC");

        let r = send(
            &mut b,
            json!({"v":1,"rid":1,"pair_id":"nope","counter":9,"mac":"AA==","body":body}),
            Some(&d),
        );
        assert_eq!(r["error"], "NOT_PAIRED");
        ext.counter = 5;
        assert_eq!(
            signed(&mut b, &mut ext, json!({"type":"hello"}), None)["result"]["paired"],
            true
        );
    }

    #[test]
    fn answers_to_paired_requests_are_signed() {
        let mut b = Bridge::default();
        let ext = paired(&mut b);
        let body = json!({"type":"hello"}).to_string();
        let mac = B64.encode(request_mac(&ext.key, 1, body.as_bytes()));
        let env = json!({"v":1,"rid":1,"pair_id":ext.pair_id,"counter":1,"mac":mac,"body":body});
        let out: Value =
            serde_json::from_slice(&b.handle(env.to_string().as_bytes(), None, Instant::now()))
                .unwrap();
        let expect = B64.encode(request_mac(
            &ext.key,
            1,
            out["body"].as_str().unwrap().as_bytes(),
        ));
        assert_eq!(out["mac"], expect);
    }

    #[test]
    fn save_is_queued_not_written_and_wiped_on_lock() {
        let mut b = Bridge::default();
        let mut ext = paired(&mut b);
        let d = vault();
        let before = d.clone();
        let body = json!({"type":"save","tab_origin":"https://new.test/signup","username":"me","password":"s3cret"});
        assert_eq!(
            signed(&mut b, &mut ext, body.clone(), Some(&d))["result"]["queued"],
            true
        );
        assert!(d == before, "vault untouched");
        signed(&mut b, &mut ext, body.clone(), Some(&d)); // same login: replaced, not duplicated
        assert_eq!(b.pending_saves().len(), 1);
        assert_eq!(b.pending_saves()[0].origin, "https://new.test:443");
        assert_eq!(signed(&mut b, &mut ext, body, None)["error"], "LOCKED");
        b.on_vault_locked();
        assert!(b.pending_saves().is_empty());
    }

    #[test]
    fn revoke_ends_the_pairing() {
        let mut b = Bridge::default();
        let mut ext = paired(&mut b);
        assert_eq!(
            signed(&mut b, &mut ext, json!({"type":"revoke"}), None)["ok"],
            true
        );
        assert!(b.pairing_ids().is_empty());
        let r = signed(&mut b, &mut ext, json!({"type":"hello"}), None);
        assert_eq!(r["error"], "NOT_PAIRED");
    }

    #[test]
    fn pairings_survive_a_restart_with_their_counters() {
        let mut b = Bridge::default();
        let mut ext = paired(&mut b);
        let d = vault();
        signed(&mut b, &mut ext, json!({"type":"hello"}), Some(&d));
        assert!(b.take_dirty());
        assert!(!b.take_dirty());
        let stored = b.export_pairings();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].last_counter, ext.counter);

        // Through the encrypted payload's JSON, then into a fresh bridge.
        let mut data = VaultData::new();
        data.browser_pairings = stored;
        let json = serde_json::to_string(&data).unwrap();
        let back: VaultData = serde_json::from_str(&json).unwrap();
        let mut b2 = Bridge::sealed();
        b2.load_pairings(&back.browser_pairings);
        assert_eq!(b2.pairing_ids(), b.pairing_ids());
        // The old counter is refused (replay); the next one is accepted.
        let body = json!({"type":"hello"}).to_string();
        let mac = B64.encode(request_mac(&ext.key, ext.counter, body.as_bytes()));
        let env = json!({"v":1,"rid":1,"pair_id":ext.pair_id,"counter":ext.counter,"mac":mac,"body":body});
        assert_eq!(send(&mut b2, env, Some(&d))["error"], "BAD_MAC");
        assert_eq!(
            signed(&mut b2, &mut ext, json!({"type":"hello"}), Some(&d))["ok"],
            true
        );
        // An empty vault has no `browser_pairings` key at all (format compat).
        assert!(!serde_json::to_string(&VaultData::new())
            .unwrap()
            .contains("browser_pairings"));
    }

    #[test]
    fn sealed_bridge_answers_only_hello_and_lock_drops_keys() {
        let mut b = Bridge::default();
        let mut ext = paired(&mut b);
        let d = vault();
        b.on_vault_locked();
        assert!(b.is_sealed() && b.pairing_ids().is_empty());
        let r = signed(&mut b, &mut ext, json!({"type":"hello"}), None);
        assert_eq!(r["ok"], true);
        assert_eq!(r["result"]["locked"], true);
        let r = signed(
            &mut b,
            &mut ext,
            json!({"type":"match","tab_origin":"https://github.com"}),
            Some(&d),
        );
        assert_eq!(r["error"], "LOCKED");
        let r = open(
            &mut b,
            json!({"type":"pair","ext_nonce":"AA==","proof":"AA=="}),
        );
        assert_eq!(r["error"], "LOCKED");
    }

    #[test]
    fn revoke_marks_dirty_and_apply_save_creates_or_updates() {
        let mut b = Bridge::default();
        let ext = paired(&mut b);
        b.take_dirty();
        b.revoke(&ext.pair_id);
        assert!(b.take_dirty());

        let mut d = vault();
        let new = PendingSave {
            origin: "https://new.test:443".into(),
            username: "me".into(),
            password: "pw1".into(),
        };
        assert_eq!(new.url(), "https://new.test");
        assert_eq!(new.title(), "new.test");
        let id = apply_save(&mut d, &new).unwrap();
        assert_eq!(d.items.len(), 3);
        // Same site and user again: the password is updated, not duplicated.
        let again = PendingSave {
            origin: new.origin.clone(),
            username: new.username.clone(),
            password: "pw2".into(),
        };
        assert_eq!(apply_save(&mut d, &again).unwrap(), id);
        assert_eq!(d.items.len(), 3);
        let l = logins(&d).find(|l| l.base.id == id).unwrap();
        assert_eq!(l.password, "pw2");
        assert_eq!(l.password_history.len(), 1);
    }

    #[test]
    fn garbage_never_panics() {
        let mut b = Bridge::default();
        for raw in [
            &b""[..],
            b"null",
            b"{\"v\":1}",
            b"{\"v\":2,\"rid\":1,\"body\":\"{}\"}",
            b"{\"v\":1,\"rid\":1,\"body\":\"{\\\"type\\\":\\\"nope\\\"}\"}",
            b"{\"v\":1,\"rid\":1,\"pair_id\":\"x\",\"body\":\"{\\\"type\\\":\\\"hello\\\"}\"}",
        ] {
            let out: Value = serde_json::from_slice(&b.handle(raw, None, Instant::now())).unwrap();
            let body: Value = serde_json::from_str(out["body"].as_str().unwrap()).unwrap();
            assert_eq!(body["ok"], false);
        }
    }
}
