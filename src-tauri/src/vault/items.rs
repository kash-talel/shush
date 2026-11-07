//! Item CRUD on the decrypted vault (roadmap Step 4).
//!
//! The UI only ever receives *redacted* views ([`ItemSummary`], [`ItemDetail`]).
//! Passwords and TOTP secrets stay in Rust: they are acted on via clipboard /
//! TOTP commands, or revealed one at a time on explicit request (issue #6).
//! Edits use `Option` for secrets: `None` means "keep the current value", so an
//! edit form never needs the existing password in JavaScript.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::models::{
    now_rfc3339, BaseItem, LoginItem, PasswordHistoryEntry, SecureNoteItem, VaultData, VaultItem,
};
use crate::crypto::fill_random;

const MAX_TITLE: usize = 256;
const MAX_SHORT: usize = 4096;
const MAX_LONG: usize = 1024 * 1024;
const MAX_TAGS: usize = 32;
/// Newest entries kept per login (issue #19: history must be bounded).
pub const MAX_HISTORY: usize = 50;

/// Item type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    /// A login.
    Login,
    /// A secure note.
    SecureNote,
}

/// What the editor submits.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ItemDraft {
    /// Title (required).
    pub title: String,
    /// Login username.
    #[serde(default)]
    pub username: String,
    /// `None` keeps the current password; `Some("")` clears it.
    #[serde(default)]
    pub password: Option<SecretInput>,
    /// Login URL.
    #[serde(default)]
    pub url: String,
    /// `None` keeps the current TOTP secret; `Some("")` removes it.
    #[serde(default)]
    pub totp: Option<SecretInput>,
    /// Plain notes.
    #[serde(default)]
    pub notes: String,
    /// Secure note body (Markdown).
    #[serde(default)]
    pub content: String,
    /// Favorite flag.
    #[serde(default)]
    pub favorite: bool,
    /// Tags.
    #[serde(default)]
    pub tags: Vec<String>,
}

/// A secret string received from the UI, wiped when dropped.
#[derive(Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct SecretInput(String);

impl SecretInput {
    /// Borrows the value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for SecretInput {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

impl std::fmt::Debug for SecretInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretInput([REDACTED])")
    }
}

impl From<&str> for SecretInput {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for SecretInput {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// Validation / lookup failures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ItemError {
    /// No item with this id.
    #[error("item not found")]
    NotFound,
    /// A field failed validation.
    #[error("{0}")]
    Invalid(String),
}

/// One row of the item list. No secrets.
#[derive(Debug, Clone, Serialize)]
pub struct ItemSummary {
    /// Item id.
    pub id: String,
    /// Type.
    pub kind: ItemKind,
    /// Title.
    pub title: String,
    /// Username for logins, empty for notes.
    pub subtitle: String,
    /// Host part of the URL (for badges / search).
    pub host: String,
    /// Favorite flag.
    pub favorite: bool,
    /// Whether a TOTP secret is configured.
    pub has_totp: bool,
    /// Last modification time.
    pub updated_at: String,
}

/// Item detail for display / editing. Contains no password or TOTP secret.
#[derive(Debug, Clone, Serialize)]
pub struct ItemDetail {
    /// Item id.
    pub id: String,
    /// Type.
    pub kind: ItemKind,
    /// Title.
    pub title: String,
    /// Username.
    pub username: String,
    /// URL.
    pub url: String,
    /// Plain notes.
    pub notes: String,
    /// Secure note body.
    pub content: String,
    /// Tags.
    pub tags: Vec<String>,
    /// Favorite flag.
    pub favorite: bool,
    /// Whether a password is stored.
    pub has_password: bool,
    /// Whether a TOTP secret is stored.
    pub has_totp: bool,
    /// Number of archived passwords.
    pub history_count: usize,
    /// Creation time.
    pub created_at: String,
    /// Last modification time.
    pub updated_at: String,
}

/// A secret field that can be copied / revealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretField {
    /// The login password.
    Password,
    /// The login username (not secret, but copied through the same path).
    Username,
    /// The current TOTP code (computed at copy time).
    Totp,
}

/// Random UUID v4 (RFC 9562) from the OS CSPRNG.
pub fn new_id() -> String {
    let mut b = [0u8; 16];
    fill_random(&mut b).expect("OS RNG unavailable");
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = |r: std::ops::Range<usize>| b[r].iter().map(|x| format!("{x:02x}")).collect::<String>();
    format!(
        "{}-{}-{}-{}-{}",
        h(0..4),
        h(4..6),
        h(6..8),
        h(8..10),
        h(10..16)
    )
}

fn check(name: &str, value: &str, max: usize) -> Result<(), ItemError> {
    if value.len() > max {
        return Err(ItemError::Invalid(format!("{name} is too long")));
    }
    Ok(())
}

fn validate(kind: ItemKind, d: &ItemDraft) -> Result<(), ItemError> {
    if d.title.trim().is_empty() {
        return Err(ItemError::Invalid("Title is required".into()));
    }
    check("Title", &d.title, MAX_TITLE)?;
    check("Username", &d.username, MAX_SHORT)?;
    check("URL", &d.url, MAX_SHORT)?;
    check("Notes", &d.notes, MAX_LONG)?;
    check("Note", &d.content, MAX_LONG)?;
    if let Some(p) = &d.password {
        check("Password", p.as_str(), MAX_SHORT)?;
    }
    if d.tags.len() > MAX_TAGS || d.tags.iter().any(|t| t.len() > MAX_TITLE) {
        return Err(ItemError::Invalid("Too many or too long tags".into()));
    }
    if let Some(t) = d
        .totp
        .as_ref()
        .map(SecretInput::as_str)
        .filter(|t| !t.trim().is_empty())
    {
        if kind != ItemKind::Login {
            return Err(ItemError::Invalid(
                "Only logins can have a TOTP secret".into(),
            ));
        }
        crate::totp::parse(t).map_err(|e| ItemError::Invalid(format!("TOTP: {e}")))?;
    }
    Ok(())
}

/// Lower-cased host of a URL, without `www.`, port or credentials.
pub(crate) fn host_of(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = host.rsplit_once('@').map_or(host, |(_, h)| h);
    let host = host.split(':').next().unwrap_or("");
    host.trim_start_matches("www.").to_ascii_lowercase()
}

fn clean_tags(tags: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for t in tags.iter().map(|t| t.trim()).filter(|t| !t.is_empty()) {
        if !out.iter().any(|o| o.eq_ignore_ascii_case(t)) {
            out.push(t.to_string());
        }
    }
    out
}

fn base(item: &VaultItem) -> &BaseItem {
    match item {
        VaultItem::Login(l) => &l.base,
        VaultItem::SecureNote(n) => &n.base,
    }
}

fn base_mut(item: &mut VaultItem) -> &mut BaseItem {
    match item {
        VaultItem::Login(l) => &mut l.base,
        VaultItem::SecureNote(n) => &mut n.base,
    }
}

fn kind(item: &VaultItem) -> ItemKind {
    match item {
        VaultItem::Login(_) => ItemKind::Login,
        VaultItem::SecureNote(_) => ItemKind::SecureNote,
    }
}

fn non_empty(s: Option<&str>) -> Option<String> {
    s.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

impl VaultData {
    fn find(&self, id: &str) -> Result<&VaultItem, ItemError> {
        self.items
            .iter()
            .find(|i| base(i).id == id)
            .ok_or(ItemError::NotFound)
    }

    fn find_mut(&mut self, id: &str) -> Result<&mut VaultItem, ItemError> {
        self.items
            .iter_mut()
            .find(|i| base(i).id == id)
            .ok_or(ItemError::NotFound)
    }

    /// Adds a new item and returns its id.
    pub fn create_item(&mut self, kind: ItemKind, d: &ItemDraft) -> Result<String, ItemError> {
        validate(kind, d)?;
        let now = now_rfc3339();
        let base = BaseItem {
            id: new_id(),
            title: d.title.trim().to_string(),
            folder_id: None,
            tags: clean_tags(&d.tags),
            favorite: d.favorite,
            notes: d.notes.clone(),
            attachments: vec![],
            created_at: now.clone(),
            updated_at: now.clone(),
            last_used_at: None,
        };
        let id = base.id.clone();
        self.items.push(match kind {
            ItemKind::Login => VaultItem::Login(LoginItem {
                base,
                username: d.username.trim().to_string(),
                password: d
                    .password
                    .as_ref()
                    .map_or_else(String::new, |p| p.as_str().to_string()),
                url: d.url.trim().to_string(),
                totp_secret: non_empty(d.totp.as_ref().map(SecretInput::as_str)),
                password_history: vec![],
            }),
            ItemKind::SecureNote => VaultItem::SecureNote(SecureNoteItem {
                base,
                content: d.content.clone(),
            }),
        });
        self.updated_at = now;
        Ok(id)
    }

    /// Applies an edit. Changing a login password archives the previous one.
    pub fn update_item(&mut self, id: &str, d: &ItemDraft) -> Result<(), ItemError> {
        let k = kind(self.find(id)?);
        validate(k, d)?;
        let now = now_rfc3339();
        let item = self.find_mut(id)?;
        {
            let b = base_mut(item);
            b.title = d.title.trim().to_string();
            b.tags = clean_tags(&d.tags);
            b.favorite = d.favorite;
            b.notes = d.notes.clone();
            b.updated_at = now.clone();
        }
        match item {
            VaultItem::Login(l) => {
                l.username = d.username.trim().to_string();
                l.url = d.url.trim().to_string();
                if let Some(new) = d.password.as_ref().map(SecretInput::as_str) {
                    if new != l.password {
                        let old = std::mem::replace(&mut l.password, new.to_string());
                        if !old.is_empty() {
                            l.password_history.push(PasswordHistoryEntry {
                                password: old,
                                changed_at: now.clone(),
                                source: None,
                                status: Some("active_superseded".into()),
                            });
                            let excess = l.password_history.len().saturating_sub(MAX_HISTORY);
                            l.password_history.drain(..excess);
                        }
                    }
                }
                if let Some(t) = &d.totp {
                    l.totp_secret = non_empty(Some(t.as_str()));
                }
            }
            VaultItem::SecureNote(n) => n.content = d.content.clone(),
        }
        self.updated_at = now;
        Ok(())
    }

    /// Removes an item.
    pub fn delete_item(&mut self, id: &str) -> Result<(), ItemError> {
        let before = self.items.len();
        self.items.retain(|i| base(i).id != id);
        if self.items.len() == before {
            return Err(ItemError::NotFound);
        }
        self.updated_at = now_rfc3339();
        Ok(())
    }

    /// Sets the favorite flag.
    pub fn set_favorite(&mut self, id: &str, favorite: bool) -> Result<(), ItemError> {
        base_mut(self.find_mut(id)?).favorite = favorite;
        Ok(())
    }

    /// Records that a secret of this item was used (copied).
    pub fn touch_used(&mut self, id: &str) -> Result<(), ItemError> {
        base_mut(self.find_mut(id)?).last_used_at = Some(now_rfc3339());
        Ok(())
    }

    /// Redacted list, favorites first, then by title.
    pub fn summaries(&self) -> Vec<ItemSummary> {
        let mut out: Vec<ItemSummary> = self
            .items
            .iter()
            .map(|i| {
                let b = base(i);
                let (subtitle, host, has_totp) = match i {
                    VaultItem::Login(l) => {
                        (l.username.clone(), host_of(&l.url), l.totp_secret.is_some())
                    }
                    VaultItem::SecureNote(_) => (String::new(), String::new(), false),
                };
                ItemSummary {
                    id: b.id.clone(),
                    kind: kind(i),
                    title: b.title.clone(),
                    subtitle,
                    host,
                    favorite: b.favorite,
                    has_totp,
                    updated_at: b.updated_at.clone(),
                }
            })
            .collect();
        out.sort_by(|a, b| {
            b.favorite
                .cmp(&a.favorite)
                .then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase()))
        });
        out
    }

    /// Redacted detail view.
    pub fn detail(&self, id: &str) -> Result<ItemDetail, ItemError> {
        let i = self.find(id)?;
        let b = base(i);
        let mut d = ItemDetail {
            id: b.id.clone(),
            kind: kind(i),
            title: b.title.clone(),
            username: String::new(),
            url: String::new(),
            notes: b.notes.clone(),
            content: String::new(),
            tags: b.tags.clone(),
            favorite: b.favorite,
            has_password: false,
            has_totp: false,
            history_count: 0,
            created_at: b.created_at.clone(),
            updated_at: b.updated_at.clone(),
        };
        match i {
            VaultItem::Login(l) => {
                d.username = l.username.clone();
                d.url = l.url.clone();
                d.has_password = !l.password.is_empty();
                d.has_totp = l.totp_secret.is_some();
                d.history_count = l.password_history.len();
            }
            VaultItem::SecureNote(n) => d.content = n.content.clone(),
        }
        Ok(d)
    }

    /// One secret field, in a wiped buffer.
    pub fn secret(&self, id: &str, field: SecretField) -> Result<Zeroizing<String>, ItemError> {
        match (self.find(id)?, field) {
            (VaultItem::Login(l), SecretField::Password) => Ok(Zeroizing::new(l.password.clone())),
            (VaultItem::Login(l), SecretField::Username) => Ok(Zeroizing::new(l.username.clone())),
            (
                VaultItem::Login(LoginItem {
                    totp_secret: Some(t),
                    ..
                }),
                SecretField::Totp,
            ) => crate::totp::current_code(t)
                .map(|c| Zeroizing::new(c.code))
                .map_err(|e| ItemError::Invalid(format!("TOTP: {e}"))),
            _ => Err(ItemError::Invalid("This item has no such field".into())),
        }
    }

    /// The stored TOTP secret / URI of a login.
    pub fn totp_secret(&self, id: &str) -> Result<Zeroizing<String>, ItemError> {
        match self.find(id)? {
            VaultItem::Login(LoginItem {
                totp_secret: Some(t),
                ..
            }) => Ok(Zeroizing::new(t.clone())),
            _ => Err(ItemError::Invalid("No TOTP configured".into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login(title: &str, pw: &str) -> ItemDraft {
        ItemDraft {
            title: title.into(),
            username: " alice@example.com ".into(),
            password: Some(pw.into()),
            url: "https://www.GitHub.com:443/login?x=1".into(),
            tags: vec!["dev".into(), " Dev ".into(), "".into(), "work".into()],
            ..Default::default()
        }
    }

    #[test]
    fn create_list_detail_without_secrets() {
        let mut v = VaultData::new();
        let id = v
            .create_item(ItemKind::Login, &login("GitHub", "hunter2"))
            .unwrap();
        let s = &v.summaries()[0];
        assert_eq!(
            (
                s.id.as_str(),
                s.title.as_str(),
                s.subtitle.as_str(),
                s.host.as_str()
            ),
            (id.as_str(), "GitHub", "alice@example.com", "github.com")
        );
        let d = v.detail(&id).unwrap();
        assert!(d.has_password && !d.has_totp);
        assert_eq!(d.tags, vec!["dev", "work"]);
        let json = serde_json::to_string(&(v.summaries(), d)).unwrap();
        assert!(
            !json.contains("hunter2"),
            "redacted views must not contain the password"
        );
        assert_eq!(&*v.secret(&id, SecretField::Password).unwrap(), "hunter2");
    }

    #[test]
    fn password_change_archives_old_and_is_bounded() {
        let mut v = VaultData::new();
        let id = v
            .create_item(ItemKind::Login, &login("Site", "pw-0"))
            .unwrap();
        // `None` keeps the password: no history entry.
        v.update_item(
            &id,
            &ItemDraft {
                password: None,
                ..login("Site", "")
            },
        )
        .unwrap();
        assert_eq!(&*v.secret(&id, SecretField::Password).unwrap(), "pw-0");
        assert_eq!(v.detail(&id).unwrap().history_count, 0);

        for n in 1..=(MAX_HISTORY + 5) {
            v.update_item(&id, &login("Site", &format!("pw-{n}")))
                .unwrap();
        }
        assert_eq!(v.detail(&id).unwrap().history_count, MAX_HISTORY);
        let VaultItem::Login(l) = &v.items[0] else {
            panic!()
        };
        assert_eq!(
            l.password_history.last().unwrap().password,
            format!("pw-{}", MAX_HISTORY + 4)
        );
        assert_eq!(
            l.password_history[0].status.as_deref(),
            Some("active_superseded")
        );
    }

    #[test]
    fn totp_is_validated_and_only_for_logins() {
        let mut v = VaultData::new();
        let bad = ItemDraft {
            totp: Some("not-base32!".into()),
            ..login("x", "p")
        };
        assert!(matches!(
            v.create_item(ItemKind::Login, &bad),
            Err(ItemError::Invalid(_))
        ));
        let ok = ItemDraft {
            totp: Some("JBSWY3DPEHPK3PXP".into()),
            ..login("x", "p")
        };
        let id = v.create_item(ItemKind::Login, &ok).unwrap();
        assert!(v.detail(&id).unwrap().has_totp);
        let note = ItemDraft {
            title: "n".into(),
            totp: Some("JBSWY3DPEHPK3PXP".into()),
            ..Default::default()
        };
        assert!(v.create_item(ItemKind::SecureNote, &note).is_err());
        // Some("") removes it.
        v.update_item(
            &id,
            &ItemDraft {
                totp: Some(SecretInput::default()),
                password: None,
                ..login("x", "")
            },
        )
        .unwrap();
        assert!(!v.detail(&id).unwrap().has_totp);
    }

    #[test]
    fn validation_and_not_found() {
        let mut v = VaultData::new();
        assert!(matches!(
            v.create_item(ItemKind::Login, &login("   ", "p")),
            Err(ItemError::Invalid(_))
        ));
        let long = "x".repeat(MAX_TITLE + 1);
        assert!(v.create_item(ItemKind::Login, &login(&long, "p")).is_err());
        assert_eq!(v.delete_item("missing"), Err(ItemError::NotFound));
        assert_eq!(v.detail("missing").unwrap_err(), ItemError::NotFound);
    }

    #[test]
    fn notes_favorites_sorting_and_delete() {
        let mut v = VaultData::new();
        let b = v.create_item(ItemKind::Login, &login("beta", "p")).unwrap();
        let a = v
            .create_item(ItemKind::Login, &login("Alpha", "p"))
            .unwrap();
        let n = v
            .create_item(
                ItemKind::SecureNote,
                &ItemDraft {
                    title: "Zeta note".into(),
                    content: "# secret".into(),
                    ..Default::default()
                },
            )
            .unwrap();
        v.set_favorite(&n, true).unwrap();
        let order: Vec<_> = v.summaries().into_iter().map(|s| s.id).collect();
        assert_eq!(order, vec![n.clone(), a.clone(), b.clone()]);
        assert_eq!(v.detail(&n).unwrap().content, "# secret");
        assert!(v.secret(&n, SecretField::Password).is_err());
        v.delete_item(&a).unwrap();
        assert_eq!(v.items.len(), 2);
    }

    #[test]
    fn uuid_v4_format() {
        let id = new_id();
        assert_eq!(id.len(), 36);
        assert_eq!(&id[14..15], "4");
        assert!(matches!(&id[19..20], "8" | "9" | "a" | "b"));
        assert_ne!(new_id(), id);
    }

    #[test]
    fn host_parsing() {
        assert_eq!(
            host_of("https://user:pw@www.Example.com:8443/a?b#c"),
            "example.com"
        );
        assert_eq!(host_of("github.com/login"), "github.com");
        assert_eq!(host_of(""), "");
    }
}
