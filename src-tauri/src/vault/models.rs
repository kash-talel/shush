//! Decrypted vault data model (spec §5).
//!
//! Every type derives `Zeroize`, and the root [`VaultData`] wipes the whole
//! tree on drop. `Debug` is only derived in tests so secrets can never end up
//! in logs.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Version of the JSON payload schema (independent of the binary format).
pub const DATA_VERSION: u32 = 1;

/// Root of the decrypted payload.
#[derive(Clone, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(test, derive(Debug))]
pub struct VaultData {
    /// Payload schema version.
    pub version: u32,
    /// Last modification time, RFC 3339 UTC.
    pub updated_at: String,
    /// Logins and secure notes.
    pub items: Vec<VaultItem>,
    /// User folders.
    pub folders: Vec<Folder>,
    /// Per-vault settings.
    pub settings: VaultSettings,
    /// Ids of deleted items (issue #19), so a merge never resurrects them.
    /// Absent in vaults written before tombstones existed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tombstones: Vec<Tombstone>,
}

impl VaultData {
    /// A new, empty vault.
    pub fn new() -> Self {
        Self {
            version: DATA_VERSION,
            updated_at: now_rfc3339(),
            items: Vec::new(),
            folders: Vec::new(),
            settings: VaultSettings::default(),
            tombstones: Vec::new(),
        }
    }
}

impl Default for VaultData {
    fn default() -> Self {
        Self::new()
    }
}

/// A vault entry, tagged by `type` as in the spec's TypeScript union.
#[derive(Clone, PartialEq, Serialize, Deserialize, Zeroize)]
#[cfg_attr(test, derive(Debug))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum VaultItem {
    /// Website / app login.
    Login(LoginItem),
    /// Free-form Markdown note.
    SecureNote(SecureNoteItem),
}

/// Fields shared by every item type.
#[derive(Clone, PartialEq, Serialize, Deserialize, Zeroize)]
#[cfg_attr(test, derive(Debug))]
pub struct BaseItem {
    /// UUID v4.
    pub id: String,
    /// Display title.
    pub title: String,
    /// Owning folder, if any.
    pub folder_id: Option<String>,
    /// Free-form tags.
    pub tags: Vec<String>,
    /// Pinned to Favorites.
    pub favorite: bool,
    /// Plain-text notes.
    pub notes: String,
    /// Encrypted-at-rest file attachments.
    pub attachments: Vec<Attachment>,
    /// RFC 3339 creation time.
    pub created_at: String,
    /// RFC 3339 last-modified time.
    pub updated_at: String,
    /// RFC 3339 last-used time.
    pub last_used_at: Option<String>,
}

/// A stored login.
#[derive(Clone, PartialEq, Serialize, Deserialize, Zeroize)]
#[cfg_attr(test, derive(Debug))]
pub struct LoginItem {
    /// Common fields.
    #[serde(flatten)]
    pub base: BaseItem,
    /// Account username / e-mail.
    pub username: String,
    /// Current password.
    pub password: String,
    /// Site URL.
    pub url: String,
    /// Base32 TOTP secret, or a full `otpauth://` / `steam://` URI carrying algorithm, digits and period (issue #24).
    pub totp_secret: Option<String>,
    /// Previous / archived passwords.
    pub password_history: Vec<PasswordHistoryEntry>,
}

/// A Markdown secure note.
#[derive(Clone, PartialEq, Serialize, Deserialize, Zeroize)]
#[cfg_attr(test, derive(Debug))]
pub struct SecureNoteItem {
    /// Common fields.
    #[serde(flatten)]
    pub base: BaseItem,
    /// Markdown body.
    pub content: String,
}

/// File attached to an item.
#[derive(Clone, PartialEq, Serialize, Deserialize, Zeroize)]
#[cfg_attr(test, derive(Debug))]
pub struct Attachment {
    /// UUID v4.
    pub id: String,
    /// Original file name.
    pub filename: String,
    /// MIME type.
    pub mime_type: String,
    /// Uncompressed size.
    pub size_bytes: u64,
    /// Base64 data (issue #5 tracks moving attachments out of the JSON).
    pub data_base64: String,
    /// RFC 3339 creation time.
    pub created_at: String,
}

/// One entry of a login's password history.
#[derive(Clone, PartialEq, Serialize, Deserialize, Zeroize)]
#[cfg_attr(test, derive(Debug))]
pub struct PasswordHistoryEntry {
    /// The previous password.
    pub password: String,
    /// When it was replaced.
    pub changed_at: String,
    /// Where it came from, e.g. "Imported from Chrome Profile".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// `active_superseded` or `archived_conflict`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// Marker left by a deleted item (issue #19). Holds no item contents.
///
/// `deleted_at` is wall-clock time and is only used to expire the marker
/// (see `items::TOMBSTONE_TTL_DAYS`); it never decides a merge.
#[derive(Clone, PartialEq, Serialize, Deserialize, Zeroize)]
#[cfg_attr(test, derive(Debug))]
pub struct Tombstone {
    /// Id of the deleted item.
    pub id: String,
    /// RFC 3339 deletion time.
    pub deleted_at: String,
}

/// A folder.
#[derive(Clone, PartialEq, Serialize, Deserialize, Zeroize)]
#[cfg_attr(test, derive(Debug))]
pub struct Folder {
    /// UUID v4.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Optional icon name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
}

/// Per-vault settings (spec §5 defaults).
#[derive(Clone, PartialEq, Serialize, Deserialize, Zeroize)]
#[cfg_attr(test, derive(Debug))]
pub struct VaultSettings {
    /// Seconds before a copied secret is cleared.
    pub clipboard_clear_seconds: u32,
    /// Idle minutes before auto-lock.
    pub auto_lock_idle_minutes: u32,
    /// Lock when the machine sleeps.
    pub auto_lock_on_sleep: bool,
    /// Windows Hello quick unlock.
    pub enable_windows_hello: bool,
    /// Disable every network feature. Default true: all network features are opt-in.
    pub air_gapped_mode: bool,
    /// Duress PIN / decoy vault.
    pub duress_pin_enabled: bool,
}

impl Default for VaultSettings {
    fn default() -> Self {
        Self {
            clipboard_clear_seconds: 30,
            auto_lock_idle_minutes: 15,
            auto_lock_on_sleep: true,
            enable_windows_hello: false,
            air_gapped_mode: true,
            duress_pin_enabled: false,
        }
    }
}

/// Current UTC time as RFC 3339 (`YYYY-MM-DDTHH:MM:SSZ`).
pub fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    rfc3339_from_unix(secs)
}

/// Formats Unix seconds as RFC 3339 UTC. Uses Howard Hinnant's
/// `civil_from_days` algorithm; valid for all dates after 1970.
pub fn rfc3339_from_unix(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(mo <= 2);

    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_known_values() {
        assert_eq!(rfc3339_from_unix(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_from_unix(951_782_400), "2000-02-29T00:00:00Z"); // leap day
        assert_eq!(rfc3339_from_unix(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(rfc3339_from_unix(4_102_444_799), "2099-12-31T23:59:59Z");
    }

    #[test]
    fn json_shape_matches_spec() {
        let mut data = VaultData::new();
        data.items.push(VaultItem::Login(LoginItem {
            base: BaseItem {
                id: "id-1".into(),
                title: "GitHub".into(),
                folder_id: None,
                tags: vec!["dev".into()],
                favorite: true,
                notes: String::new(),
                attachments: vec![],
                created_at: "2026-11-07T00:00:00Z".into(),
                updated_at: "2026-11-07T00:00:00Z".into(),
                last_used_at: None,
            },
            username: "octo".into(),
            password: "hunter2".into(),
            url: "https://github.com".into(),
            totp_secret: None,
            password_history: vec![],
        }));
        let json: serde_json::Value = serde_json::to_value(&data).unwrap();
        let item = &json["items"][0];
        assert_eq!(item["type"], "login");
        assert_eq!(item["title"], "GitHub"); // base fields are flattened
        assert_eq!(item["password"], "hunter2");
        assert_eq!(json["settings"]["clipboard_clear_seconds"], 30);

        let back: VaultData = serde_json::from_value(json).unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn zeroize_clears_secrets() {
        let mut data = VaultData::new();
        data.folders.push(Folder {
            id: "f".into(),
            name: "Work".into(),
            icon: None,
        });
        data.zeroize();
        assert!(data.folders.is_empty());
        assert!(data.updated_at.is_empty());
    }
}
