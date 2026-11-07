//! CSV migration from other password managers and browsers (spec §9.3, §10.1).
//!
//! Supported exports, detected from the header row: Chrome / Edge / Brave,
//! Firefox, Bitwarden, 1Password, KeePass 2, KeePassXC, plus a generic
//! fallback that maps common column names.
//!
//! Conflict policy (issue #19): CSV files are untrusted plaintext. A row that
//! matches an existing login (same host + username) never replaces its
//! password; a differing password is archived in history as
//! `archived_conflict`. Identical rows are skipped, so re-importing is a no-op.

use std::io::Read;
use std::path::Path;

use serde::Serialize;
use zeroize::Zeroizing;

use super::items::{host_of, ItemDraft, ItemKind, SecretInput, MAX_HISTORY};
use super::models::{now_rfc3339, PasswordHistoryEntry, VaultData, VaultItem};

/// Largest CSV accepted (bounded memory, #5).
pub const MAX_CSV_BYTES: u64 = 50 * 1024 * 1024;
/// Most rows imported in one go.
pub const MAX_ROWS: usize = 100_000;

/// Source format, detected from the header row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CsvFormat {
    /// Chrome / Edge / Brave password export.
    Chromium,
    /// Firefox `logins.csv`.
    Firefox,
    /// Bitwarden CSV export.
    Bitwarden,
    /// 1Password CSV export.
    OnePassword,
    /// KeePass 2 CSV.
    KeePass,
    /// KeePassXC CSV.
    KeePassXc,
    /// Unknown, mapped from common column names.
    Generic,
}

impl CsvFormat {
    /// Human-readable source name (used in password-history `source`).
    pub fn label(self) -> &'static str {
        match self {
            Self::Chromium => "Chrome / Edge",
            Self::Firefox => "Firefox",
            Self::Bitwarden => "Bitwarden",
            Self::OnePassword => "1Password",
            Self::KeePass => "KeePass",
            Self::KeePassXc => "KeePassXC",
            Self::Generic => "CSV",
        }
    }
}

/// Import failures (whole-file problems; bad rows are skipped and counted).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ImportError {
    /// Could not read the file.
    #[error("could not read the CSV file ({0})")]
    Io(std::io::ErrorKind),
    /// Larger than [`MAX_CSV_BYTES`] or more than [`MAX_ROWS`] rows.
    #[error("the CSV file is too large")]
    TooLarge,
    /// Not UTF-8 / malformed CSV.
    #[error("the file is not a valid CSV export")]
    Malformed,
    /// No recognisable title / URL / password columns.
    #[error("unrecognised CSV format: no password or URL columns found")]
    Unrecognised,
}

/// One parsed row, ready to become an item.
#[derive(Debug)]
struct Row {
    kind: ItemKind,
    title: String,
    username: String,
    password: Zeroizing<String>,
    url: String,
    notes: String,
    totp: Option<Zeroizing<String>>,
    favorite: bool,
    tags: Vec<String>,
}

/// Column indexes for one format.
#[derive(Debug, Default)]
struct Columns {
    title: Option<usize>,
    url: Option<usize>,
    username: Option<usize>,
    password: Option<usize>,
    notes: Option<usize>,
    totp: Option<usize>,
    favorite: Option<usize>,
    folder: Option<usize>,
    tags: Option<usize>,
    /// Bitwarden `type` (`login` / `note`).
    kind: Option<usize>,
}

fn norm(h: &str) -> String {
    h.trim().trim_start_matches('\u{feff}').to_ascii_lowercase()
}

fn detect(headers: &[String]) -> (CsvFormat, Columns) {
    let find = |names: &[&str]| headers.iter().position(|h| names.contains(&h.as_str()));
    let has = |n: &str| headers.iter().any(|h| h == n);

    let format = if has("login_password") && has("login_uri") {
        CsvFormat::Bitwarden
    } else if has("httprealm") || has("formactionorigin") {
        CsvFormat::Firefox
    } else if has("otpauth") && has("title") {
        CsvFormat::OnePassword
    } else if has("login name") && has("web site") {
        CsvFormat::KeePass
    } else if has("group") && has("title") && has("totp") {
        CsvFormat::KeePassXc
    } else if headers == ["name", "url", "username", "password", "note"]
        || headers == ["name", "url", "username", "password"]
    {
        CsvFormat::Chromium
    } else {
        CsvFormat::Generic
    };

    let cols = Columns {
        title: find(&["name", "title", "account"]),
        url: find(&["url", "login_uri", "web site", "website", "uri", "urls"]),
        username: find(&["username", "login_username", "login name", "user", "email"]),
        password: find(&["password", "login_password"]),
        notes: find(&["note", "notes", "comments", "extra"]),
        totp: find(&["login_totp", "otpauth", "totp", "otp"]),
        favorite: find(&["favorite"]),
        folder: find(&["folder", "group"]),
        tags: find(&["tags"]),
        kind: if format == CsvFormat::Bitwarden {
            find(&["type"])
        } else {
            None
        },
    };
    (format, cols)
}

fn cell(rec: &csv::StringRecord, i: Option<usize>) -> String {
    i.and_then(|i| rec.get(i))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn parse(bytes: &[u8]) -> Result<(CsvFormat, Vec<Row>, usize), ImportError> {
    let mut reader = csv::ReaderBuilder::new().flexible(true).from_reader(bytes);
    let headers: Vec<String> = reader
        .headers()
        .map_err(|_| ImportError::Malformed)?
        .iter()
        .map(norm)
        .collect();
    let (format, c) = detect(&headers);
    if c.password.is_none() && c.url.is_none() {
        return Err(ImportError::Unrecognised);
    }
    let mut rows = Vec::new();
    let mut skipped = 0;
    for (n, rec) in reader.records().enumerate() {
        if n >= MAX_ROWS {
            return Err(ImportError::TooLarge);
        }
        let Ok(rec) = rec else {
            skipped += 1;
            continue;
        };
        let url = cell(&rec, c.url);
        let username = cell(&rec, c.username);
        let password = Zeroizing::new(
            c.password
                .and_then(|i| rec.get(i))
                .unwrap_or("")
                .to_string(),
        );
        let notes = c.notes.and_then(|i| rec.get(i)).unwrap_or("").to_string();
        let is_note = cell(&rec, c.kind).eq_ignore_ascii_case("note");
        let mut title = cell(&rec, c.title);
        if title.is_empty() {
            title = if url.is_empty() {
                username.clone()
            } else {
                host_of(&url)
            };
        }
        if title.is_empty()
            || (!is_note && password.is_empty() && username.is_empty() && url.is_empty())
        {
            skipped += 1;
            continue;
        }
        let totp = Some(cell(&rec, c.totp))
            .filter(|t| !t.is_empty())
            .map(Zeroizing::new);
        let mut tags: Vec<String> = cell(&rec, c.tags)
            .split([',', ';'])
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(String::from)
            .collect();
        let folder = cell(&rec, c.folder);
        if !folder.is_empty() && !folder.eq_ignore_ascii_case("root") {
            tags.push(folder);
        }
        rows.push(Row {
            kind: if is_note {
                ItemKind::SecureNote
            } else {
                ItemKind::Login
            },
            title,
            username,
            password,
            url,
            notes,
            totp,
            favorite: matches!(
                cell(&rec, c.favorite).to_ascii_lowercase().as_str(),
                "1" | "true" | "yes"
            ),
            tags,
        });
    }
    Ok((format, rows, skipped))
}

/// What an import would do / did. Counts only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CsvSummary {
    /// Detected source format.
    pub format: Option<CsvFormat>,
    /// Usable rows in the file.
    pub total: usize,
    /// Rows that become new items.
    pub new_items: usize,
    /// Rows identical to an existing login (skipped).
    pub identical: usize,
    /// Rows whose password differs from an existing login (archived).
    pub conflicts: usize,
    /// Rows without enough data, or malformed.
    pub skipped: usize,
    /// TOTP values that were invalid and dropped.
    pub invalid_totp: usize,
}

fn same_login(item: &VaultItem, host: &str, username: &str) -> bool {
    match item {
        VaultItem::Login(l) => {
            !host.is_empty() && host_of(&l.url) == host && l.username.eq_ignore_ascii_case(username)
        }
        VaultItem::SecureNote(_) => false,
    }
}

/// Reads a CSV export into a wiped buffer, refusing oversized files first.
pub fn read_csv(path: &Path) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    let meta = std::fs::metadata(path).map_err(|e| ImportError::Io(e.kind()))?;
    if meta.len() > MAX_CSV_BYTES {
        return Err(ImportError::TooLarge);
    }
    let mut buf = Zeroizing::new(Vec::with_capacity(meta.len() as usize));
    std::fs::File::open(path)
        .and_then(|f| f.take(MAX_CSV_BYTES).read_to_end(&mut buf))
        .map_err(|e| ImportError::Io(e.kind()))?;
    Ok(buf)
}

/// Previews (`apply = false`) or performs (`apply = true`) a CSV import.
///
/// Limitation (issue #6): the `csv` crate and `String` fields keep unwiped
/// copies of plaintext rows in freed memory; the source buffer is wiped.
pub fn import(data: &mut VaultData, bytes: &[u8], apply: bool) -> Result<CsvSummary, ImportError> {
    let (format, rows, skipped) = parse(bytes)?;
    let mut s = CsvSummary {
        format: Some(format),
        total: rows.len(),
        skipped,
        ..Default::default()
    };
    let source = format!("Imported from {} (CSV)", format.label());

    for row in rows {
        let host = host_of(&row.url);
        let existing = (row.kind == ItemKind::Login)
            .then(|| {
                data.items
                    .iter_mut()
                    .find(|i| same_login(i, &host, &row.username))
            })
            .flatten();
        if let Some(VaultItem::Login(cur)) = existing {
            let known = cur.password == *row.password
                || cur
                    .password_history
                    .iter()
                    .any(|h| h.password == *row.password);
            if known || row.password.is_empty() {
                s.identical += 1;
            } else {
                s.conflicts += 1;
                if apply {
                    cur.password_history.push(PasswordHistoryEntry {
                        password: row.password.to_string(),
                        changed_at: now_rfc3339(),
                        source: Some(source.clone()),
                        status: Some("archived_conflict".into()),
                    });
                    let excess = cur.password_history.len().saturating_sub(MAX_HISTORY);
                    cur.password_history.drain(..excess);
                }
            }
            continue;
        }

        let totp = row.totp.as_ref().filter(|t| crate::totp::parse(t).is_ok());
        if row.totp.is_some() && totp.is_none() {
            s.invalid_totp += 1;
        }
        let draft = ItemDraft {
            title: row.title.chars().take(256).collect(),
            username: row.username.clone(),
            password: (row.kind == ItemKind::Login)
                .then(|| SecretInput::from(row.password.as_str())),
            url: row.url.clone(),
            totp: totp.map(|t| SecretInput::from(t.as_str())),
            notes: if row.kind == ItemKind::Login {
                row.notes.clone()
            } else {
                String::new()
            },
            content: if row.kind == ItemKind::SecureNote {
                row.notes.clone()
            } else {
                String::new()
            },
            favorite: row.favorite,
            tags: row.tags.clone(),
            folder_id: None, // CSV folders are carried over as tags
        };
        if apply {
            match data.create_item(row.kind, &draft) {
                Ok(_) => s.new_items += 1,
                Err(_) => s.skipped += 1, // e.g. oversized field
            }
        } else {
            s.new_items += 1;
        }
    }
    Ok(s)
}

/// Best-effort removal of a plaintext CSV export after import (#17):
/// overwrite with zeros, flush, then delete. On SSDs / with Volume Shadow
/// Copies or cloud sync the old blocks may survive; the UI says so.
pub fn shred_csv(path: &Path) -> Result<(), ImportError> {
    if path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("csv"))
        != Some(true)
    {
        return Err(ImportError::Unrecognised);
    }
    let len = std::fs::metadata(path)
        .map_err(|e| ImportError::Io(e.kind()))?
        .len();
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|e| ImportError::Io(e.kind()))?;
        let zeros = vec![0u8; 64 * 1024];
        let mut left = len;
        while left > 0 {
            let n = left.min(zeros.len() as u64) as usize;
            f.write_all(&zeros[..n])
                .map_err(|e| ImportError::Io(e.kind()))?;
            left -= n as u64;
        }
        f.sync_all().map_err(|e| ImportError::Io(e.kind()))?;
    }
    std::fs::remove_file(path).map_err(|e| ImportError::Io(e.kind()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::items::SecretField;

    fn run(csv: &str) -> (VaultData, CsvSummary) {
        let mut v = VaultData::new();
        let s = import(&mut v, csv.as_bytes(), true).unwrap();
        (v, s)
    }

    #[test]
    fn chrome_export() {
        let (v, s) = run("name,url,username,password,note\ngithub.com,https://github.com/login,octo,pw1,\"multi\nline\"\n");
        assert_eq!(s.format, Some(CsvFormat::Chromium));
        assert_eq!((s.total, s.new_items), (1, 1));
        let item = &v.summaries()[0];
        assert_eq!(
            (
                item.title.as_str(),
                item.subtitle.as_str(),
                item.host.as_str()
            ),
            ("github.com", "octo", "github.com")
        );
        assert_eq!(&*v.secret(&item.id, SecretField::Password).unwrap(), "pw1");
        assert_eq!(v.detail(&item.id).unwrap().notes, "multi\nline");
    }

    #[test]
    fn firefox_export_titles_from_host() {
        let (v, s) = run(concat!(
            "\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\",\"timeLastUsed\",\"timePasswordChanged\"\n",
            "\"https://www.example.org\",\"me@x.y\",\"s3cret\",,\"https://www.example.org\",\"{a}\",\"1\",\"1\",\"1\"\n"
        ));
        assert_eq!(s.format, Some(CsvFormat::Firefox));
        assert_eq!(v.summaries()[0].title, "example.org");
    }

    #[test]
    fn bitwarden_export_with_notes_totp_and_folders() {
        let (v, s) = run(concat!(
            "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n",
            "Work,1,login,GitLab,,,0,https://gitlab.com,dev,pw,JBSWY3DPEHPK3PXP\n",
            ",,note,Recovery codes,1111-2222,,0,,,,\n",
            ",,login,Broken totp,,,0,https://b.example,u,p,not-a-secret!\n"
        ));
        assert_eq!(s.format, Some(CsvFormat::Bitwarden));
        assert_eq!((s.new_items, s.invalid_totp), (3, 1));
        let gitlab = v
            .summaries()
            .into_iter()
            .find(|i| i.title == "GitLab")
            .unwrap();
        assert!(gitlab.favorite && gitlab.has_totp);
        assert_eq!(v.detail(&gitlab.id).unwrap().tags, vec!["Work"]);
        let note = v
            .summaries()
            .into_iter()
            .find(|i| i.title == "Recovery codes")
            .unwrap();
        assert_eq!(note.kind, ItemKind::SecureNote);
        assert_eq!(v.detail(&note.id).unwrap().content, "1111-2222");
    }

    #[test]
    fn onepassword_keepass_and_keepassxc_are_detected() {
        let (_, s) = run("Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\nA,https://a.io,u,p,,,,\"x,y\",\n");
        assert_eq!(s.format, Some(CsvFormat::OnePassword));
        let (_, s) = run("\"Account\",\"Login Name\",\"Password\",\"Web Site\",\"Comments\"\n\"B\",\"u\",\"p\",\"https://b.io\",\"\"\n");
        assert_eq!(s.format, Some(CsvFormat::KeePass));
        let (_, s) = run("\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\",\"Icon\",\"Last Modified\",\"Created\"\n\"Root\",\"C\",\"u\",\"p\",\"https://c.io\",\"\",\"\",\"0\",\"\",\"\"\n");
        assert_eq!(s.format, Some(CsvFormat::KeePassXc));
    }

    #[test]
    fn conflicts_are_archived_never_promoted_and_reimport_is_noop() {
        let csv1 = "name,url,username,password\ngithub.com,https://github.com,octo,current\n";
        let csv2 = "name,url,username,password\ngithub.com,https://www.github.com/x,OCTO,other-browser-pw\n";
        let mut v = VaultData::new();
        import(&mut v, csv1.as_bytes(), true).unwrap();
        let id = v.summaries()[0].id.clone();

        let preview = import(&mut v.clone(), csv2.as_bytes(), false).unwrap();
        assert_eq!((preview.new_items, preview.conflicts), (0, 1));

        let s = import(&mut v, csv2.as_bytes(), true).unwrap();
        assert_eq!((s.new_items, s.conflicts), (0, 1));
        assert_eq!(
            &*v.secret(&id, SecretField::Password).unwrap(),
            "current",
            "CSV must not promote"
        );
        let VaultItem::Login(l) = &v.items[0] else {
            panic!()
        };
        assert_eq!(l.password_history[0].password, "other-browser-pw");
        assert_eq!(
            l.password_history[0].source.as_deref(),
            Some("Imported from Chrome / Edge (CSV)")
        );

        let again = import(&mut v, csv2.as_bytes(), true).unwrap();
        assert_eq!(
            (again.new_items, again.conflicts, again.identical),
            (0, 0, 1)
        );
        assert_eq!(v.items.len(), 1);
    }

    #[test]
    fn preview_does_not_modify() {
        let mut v = VaultData::new();
        let s = import(
            &mut v,
            b"name,url,username,password\na,https://a.io,u,p\n",
            false,
        )
        .unwrap();
        assert_eq!(s.new_items, 1);
        assert!(v.items.is_empty());
    }

    #[test]
    fn junk_rows_skipped_and_unknown_files_rejected() {
        let (_, s) = run("name,url,username,password\n,,,\nok,https://ok.io,u,p\n");
        assert_eq!((s.total, s.skipped), (1, 1));
        let mut v = VaultData::new();
        assert_eq!(
            import(&mut v, b"a,b,c\n1,2,3\n", false).unwrap_err(),
            ImportError::Unrecognised
        );
        assert_eq!(
            import(&mut v, &[0xff, 0xfe, 0x00], false).unwrap_err(),
            ImportError::Malformed
        );
    }

    #[test]
    fn bom_header_is_tolerated() {
        let (_, s) = run("\u{feff}name,url,username,password\nx,https://x.io,u,p\n");
        assert_eq!((s.format, s.new_items), (Some(CsvFormat::Chromium), 1));
    }

    #[test]
    fn shred_overwrites_and_deletes_only_csv() {
        let dir = tempfile::tempdir().unwrap();
        let csv = dir.path().join("passwords.csv");
        std::fs::write(&csv, b"name,password\nx,secret\n").unwrap();
        shred_csv(&csv).unwrap();
        assert!(!csv.exists());
        let other = dir.path().join("vault.shush");
        std::fs::write(&other, b"keep").unwrap();
        assert!(shred_csv(&other).is_err());
        assert!(other.exists());
    }
}
