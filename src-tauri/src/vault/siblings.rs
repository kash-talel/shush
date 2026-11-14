//! Detection of files the vault's sync client or a crash left next to it
//! (issue #80): conflicted copies and a stale `vault.shush.tmp`.
//!
//! Detection is read-only and never merges anything. Removing a file is an
//! explicit user action, and only a name this scan reports can be removed.

use std::path::{Path, PathBuf};

use serde::Serialize;

use super::container::sibling;
use super::read_header;

/// What was found next to one vault file.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct SiblingReport {
    /// File names (not paths) of probable cloud-sync conflicted copies.
    pub conflicted_copies: Vec<String>,
    /// A `.tmp` left behind by an interrupted save, while the main vault is intact.
    pub stale_tmp: Option<String>,
}

impl SiblingReport {
    /// Nothing found.
    pub fn is_empty(&self) -> bool {
        self.conflicted_copies.is_empty() && self.stale_tmp.is_none()
    }

    /// Whether `name` is one of the reported files.
    pub fn contains(&self, name: &str) -> bool {
        self.stale_tmp.as_deref() == Some(name) || self.conflicted_copies.iter().any(|c| c == name)
    }
}

/// Whether `rest` (the file name after the vault's stem, before the extension)
/// looks like a sync client's conflict marker.
fn is_conflict_suffix(rest: &str) -> bool {
    let lower = rest.to_ascii_lowercase();
    // Dropbox / Nextcloud: " (Name's conflicted copy 2026-01-01)"
    if lower.starts_with(" (") && lower.contains("conflicted copy") {
        return true;
    }
    // Google Drive / Windows copy: " (1)"
    if let Some(n) = lower.strip_prefix(" (").and_then(|r| r.strip_suffix(')')) {
        return !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit());
    }
    // Syncthing: ".sync-conflict-20260101-120000-ABCDEFG"
    if lower.starts_with(".sync-conflict-") {
        return true;
    }
    // OneDrive: "-DESKTOP-ABC" or "-DESKTOP-ABC-2" (machine name, upper case).
    if let Some(host) = rest.strip_prefix('-') {
        return host.len() >= 2
            && host
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
    }
    false
}

/// Scans the folder of `vault` for conflicted copies and a stale tmp file.
/// `known` are other vaults the user registered: never reported as conflicts.
pub fn scan(vault: &Path, known: &[PathBuf]) -> SiblingReport {
    let mut report = SiblingReport::default();
    let (Some(dir), Some(name)) = (vault.parent(), vault.file_name().and_then(|n| n.to_str()))
    else {
        return report;
    };
    let Some((stem, ext)) = name.rsplit_once('.') else {
        return report;
    };
    if let Ok(rd) = std::fs::read_dir(dir) {
        for entry in rd.flatten() {
            let p = entry.path();
            let Some(fname) = p.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Some(base) = fname
                .rsplit_once('.')
                .filter(|(_, e)| e.eq_ignore_ascii_case(ext))
                .map(|(b, _)| b)
            else {
                continue;
            };
            let Some(rest) = base.strip_prefix(stem) else {
                continue;
            };
            if rest.is_empty()
                || p == vault
                || known.iter().any(|k| k == &p)
                || !is_conflict_suffix(rest)
                || !p.is_file()
                || read_header(&p).is_err()
            {
                continue;
            }
            report.conflicted_copies.push(fname.to_string());
        }
    }
    report.conflicted_copies.sort();
    let tmp = sibling(vault, "tmp");
    if tmp.is_file() && read_header(vault).is_ok() {
        report.stale_tmp = sibling_name(&tmp);
    }
    report
}

fn sibling_name(p: &Path) -> Option<String> {
    p.file_name().and_then(|n| n.to_str()).map(str::to_string)
}

/// Deletes `file` from the folder of `vault`, but only if a fresh scan reports it.
/// Returns `false` when the name is not (or no longer) a reported sibling.
pub fn discard(vault: &Path, known: &[PathBuf], file: &str) -> std::io::Result<bool> {
    if !scan(vault, known).contains(file) {
        return Ok(false);
    }
    let Some(dir) = vault.parent() else {
        return Ok(false);
    };
    std::fs::remove_file(dir.join(file))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{create_vault_file, CreateOptions};

    fn make_vault(p: &Path) {
        create_vault_file(p, b"pw", None, CreateOptions::default()).unwrap();
    }

    #[test]
    fn suffix_patterns() {
        for ok in [
            " (Ann's conflicted copy 2026-01-01)",
            " (1)",
            ".sync-conflict-20260101-120000-ABCDEFG",
            "-DESKTOP-AB12CD",
            "-DESKTOP-AB12CD-2",
        ] {
            assert!(is_conflict_suffix(ok), "{ok}");
        }
        for bad in [" backup", "-work", "2", " (x)", "-"] {
            assert!(!is_conflict_suffix(bad), "{bad}");
        }
    }

    #[test]
    fn finds_conflicts_and_stale_tmp_and_discards_only_reported() {
        let dir = tempfile::tempdir().unwrap();
        let v = dir.path().join("vault.shush");
        make_vault(&v);
        let conflict = dir
            .path()
            .join("vault (Bob's conflicted copy 2026-01-01).shush");
        std::fs::copy(&v, &conflict).unwrap();
        // Registered vault with a conflict-looking name, junk, and non-vault file.
        let known = dir.path().join("vault (1).shush");
        std::fs::copy(&v, &known).unwrap();
        std::fs::write(dir.path().join("vault-DESKTOP-AB.shush"), b"junk").unwrap();
        std::fs::write(dir.path().join("vault.shush.tmp"), b"partial").unwrap();
        let other = dir.path().join("notes.txt");
        std::fs::write(&other, b"x").unwrap();

        let r = scan(&v, std::slice::from_ref(&known));
        assert_eq!(
            r.conflicted_copies,
            vec!["vault (Bob's conflicted copy 2026-01-01).shush".to_string()]
        );
        assert_eq!(r.stale_tmp.as_deref(), Some("vault.shush.tmp"));

        assert!(!discard(&v, &[], "notes.txt").unwrap());
        assert!(other.exists() && v.exists());
        assert!(discard(&v, std::slice::from_ref(&known), "vault.shush.tmp").unwrap());
        assert!(discard(
            &v,
            std::slice::from_ref(&known),
            "vault (Bob's conflicted copy 2026-01-01).shush"
        )
        .unwrap());
        assert!(scan(&v, std::slice::from_ref(&known)).is_empty());
        assert!(v.exists());
    }

    #[test]
    fn tmp_not_reported_when_main_vault_is_broken() {
        let dir = tempfile::tempdir().unwrap();
        let v = dir.path().join("vault.shush");
        std::fs::write(&v, b"garbage").unwrap();
        std::fs::write(dir.path().join("vault.shush.tmp"), b"x").unwrap();
        assert!(scan(&v, &[]).stale_tmp.is_none());
    }
}
