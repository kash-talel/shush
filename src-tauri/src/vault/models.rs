//! Decrypted vault data model (spec §5).
//!
//! Every type derives `Zeroize`, and the root [`VaultData`] wipes the whole
//! tree on drop. `Debug` is only derived in tests so secrets can never end up
//! in logs.

use super::hlc::Hlc;
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
    /// Random 32-byte key (hex) for the login-identity digests kept in
    /// tombstones (issue #138). Empty until the first login is deleted.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub identity_key: String,
    /// Browser-extension pairings (issue #52). Inside the encrypted payload so
    /// revocations and replay counters survive restarts. Absent in older vaults.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub browser_pairings: Vec<StoredPairing>,
    /// Stable id of this vault on this device, the final tie-break of every
    /// [`Hlc`] it issues (issue #137). Empty in vaults written before sync;
    /// filled lazily by [`VaultData::next_hlc`].
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub device_id: String,
    /// Last clock value this vault issued or observed, so new ones only grow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_hlc: Option<Hlc>,
    /// LAN sync identity and pinned peers (issue #156, `docs/spec/lan-sync.md` §6).
    /// Absent until the user first pairs a device from this vault.
    #[serde(default, skip_serializing_if = "SyncData::is_empty")]
    pub sync: SyncData,
}

/// LAN sync state stored in the encrypted payload (`lan-sync.md` §6). Each
/// payload (and each duress slot) has its own identity and peer list.
#[derive(Clone, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(test, derive(Debug))]
pub struct SyncData {
    /// This vault's X25519 static key pair, created on first pairing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<SyncIdentityRecord>,
    /// Pinned peers. Only these may open a sync session.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<SyncPeer>,
    /// Advertise pairing and sync windows on the local network (mDNS). Off
    /// means manual address entry only (`lan-sync.md` §5). Default on.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub advertise: bool,
}

fn default_true() -> bool {
    true
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde passes a reference
fn is_true(b: &bool) -> bool {
    *b
}

impl Default for SyncData {
    fn default() -> Self {
        Self {
            identity: None,
            peers: Vec::new(),
            advertise: true,
        }
    }
}

impl SyncData {
    /// Nothing worth writing: no identity, no peers, default settings.
    pub fn is_empty(&self) -> bool {
        self.identity.is_none() && self.peers.is_empty() && self.advertise
    }
}

/// The sync identity's secret half (the public key is derived from it).
#[derive(Clone, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(test, derive(Debug))]
pub struct SyncIdentityRecord {
    /// X25519 secret key, standard base64 (32 bytes).
    pub secret: String,
    /// When it was generated, RFC 3339 UTC.
    pub created_at: String,
}

/// A paired device (`lan-sync.md` §6).
#[derive(Clone, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(test, derive(Debug))]
pub struct SyncPeer {
    /// Device fingerprint (`XXXX-XXXX-XXXX-XXXX`), unique per public key.
    pub id: String,
    /// Name the device sent in its pairing confirmation.
    pub name: String,
    /// Pinned X25519 static public key, standard base64 (32 bytes).
    pub public_key: String,
    /// When it was paired, RFC 3339 UTC.
    pub paired_at: String,
    /// Last completed sync session, if any.
    #[serde(default)]
    pub last_sync_at: Option<String>,
    /// Address it was last seen at (`ip:port`), if known.
    #[serde(default)]
    pub last_address: Option<String>,
}

/// A paired browser as stored in the vault (issue #52).
#[derive(Clone, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(test, derive(Debug))]
pub struct StoredPairing {
    /// Public pairing id (32 hex characters).
    pub id: String,
    /// Shared HMAC key, standard base64 (32 bytes).
    pub key: String,
    /// Highest request counter accepted so far.
    pub last_counter: u64,
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
            identity_key: String::new(),
            browser_pairings: Vec::new(),
            device_id: String::new(),
            last_hlc: None,
            sync: SyncData::default(),
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
    /// Hybrid logical clock of the last edit (issue #137). Absent in items
    /// written before LAN sync existed; those compare as oldest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hlc: Option<Hlc>,
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
    /// Also match subdomains of the saved host in the browser bridge (issue
    /// #152). Off by default; absent in older vaults, which read as off.
    #[serde(default, skip_serializing_if = "is_false")]
    pub match_subdomains: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
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
    /// Clock of the deletion (issue #137); lets sync order it against edits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hlc: Option<Hlc>,
    /// Keyed digest of a deleted login's identity (issue #138), so a CSV
    /// re-import can tell the user "you deleted this". Hex HMAC-SHA256 over
    /// canonical host and lower-cased username; never the plaintext.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
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

fn default_hello_session_max_hours() -> u32 {
    8
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
    /// Longest Windows Hello session in hours (1-8; 8 is the hard cap).
    #[serde(default = "default_hello_session_max_hours")]
    pub hello_session_max_hours: u32,
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
            hello_session_max_hours: default_hello_session_max_hours(),
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
    fn settings_from_before_hello_session_setting_default_to_eight_hours() {
        let old = r#"{"clipboard_clear_seconds":30,"auto_lock_idle_minutes":15,
            "auto_lock_on_sleep":true,"enable_windows_hello":true,
            "air_gapped_mode":true,"duress_pin_enabled":false}"#;
        let s: VaultSettings = serde_json::from_str(old).unwrap();
        assert_eq!(s.hello_session_max_hours, 8);
        assert!(s.enable_windows_hello);
    }

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
                hlc: None,
            },
            username: "octo".into(),
            password: "hunter2".into(),
            url: "https://github.com".into(),
            totp_secret: None,
            password_history: vec![],
            match_subdomains: false,
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
