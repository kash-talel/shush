//! Encrypted `.shushbackup` export and import (spec §9.1, roadmap Step 6).
//!
//! A backup uses the same authenticated container as `vault.shush` with the
//! `SHBKP` magic, so it can never be opened as the live vault by accident
//! (and relabelling it breaks authentication). The payload is the spec's
//! manifest: `{ backup_version, exported_at, app_version, items_count, vault_data }`.
//!
//! Merge policy (deliberate deviation from spec §9.2, see issue #19): an
//! imported file is untrusted, so its timestamps never decide which password
//! is active. New items are added; for an item that exists on both sides the
//! **current item is kept** and a differing imported password is archived in
//! its history as `archived_conflict`. Nothing is lost and nothing is promoted.

use std::path::Path;

use serde::{Deserialize, Serialize};

use super::container::{self, FileKind, Header, HEADER_LEN, MAX_PAYLOAD_LEN};
use super::models::{now_rfc3339, PasswordHistoryEntry, VaultData, VaultItem};
use super::{decode_json, encode_json, items::MAX_HISTORY, OpenVault, VaultError};
use crate::crypto::{derive_master_key, kdf, CipherSuite, KdfParams, KeyfileDigest, VaultKeys};

/// Backup manifest schema version.
pub const BACKUP_VERSION: u32 = 1;
/// Recommended file extension.
pub const EXTENSION: &str = "shushbackup";

/// Decrypted backup payload (spec §9.1).
#[derive(Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// Manifest schema version.
    pub backup_version: u32,
    /// RFC 3339 export time.
    pub exported_at: String,
    /// shush version that wrote it.
    pub app_version: String,
    /// Number of items (informational; recomputed on import).
    pub items_count: usize,
    /// The vault contents.
    pub vault_data: VaultData,
}

/// Which credentials protect a new backup.
pub enum BackupCredentials<'a> {
    /// The vault's own password / keyfile (reuses the derived keys and salt;
    /// fresh nonces make every backup ciphertext unique).
    SameAsVault,
    /// A dedicated password (+ optional keyfile), with a fresh salt.
    Dedicated {
        /// Backup password (UTF-8, NFC-normalized by the KDF).
        password: &'a [u8],
        /// Optional backup keyfile digest.
        keyfile: Option<&'a KeyfileDigest>,
        /// Cipher suite for the backup.
        suite: CipherSuite,
        /// KDF parameters for the backup.
        kdf: KdfParams,
    },
}

/// Seals `data` (normally the vault's data with attachments embedded, see
/// [`OpenVault::data_with_embedded_attachments`]) into a backup file image.
/// `vault` supplies the header and keys for [`BackupCredentials::SameAsVault`].
pub fn export_bytes(
    vault: &OpenVault,
    data: &VaultData,
    creds: BackupCredentials<'_>,
) -> Result<Vec<u8>, VaultError> {
    let manifest = Manifest {
        backup_version: BACKUP_VERSION,
        exported_at: now_rfc3339(),
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        items_count: data.items.len(),
        vault_data: data.clone(),
    };
    let plaintext = encode_json(&manifest)?;
    match creds {
        BackupCredentials::SameAsVault => {
            let header = Header {
                kind: FileKind::Backup,
                ..vault.header().clone()
            };
            container::seal(&header, vault.keys(), &plaintext)
        }
        BackupCredentials::Dedicated {
            password,
            keyfile,
            suite,
            kdf,
        } => {
            let header = Header {
                kind: FileKind::Backup,
                suite,
                keyfile_required: keyfile.is_some(),
                kdf,
                salt: kdf::generate_salt()?,
            };
            let master = derive_master_key(password, keyfile, &header.salt, &header.kdf)?;
            container::seal(&header, &VaultKeys::derive(&master), &plaintext)
        }
    }
}

/// Writes a backup crash-safely, verifying it decrypts before replacing any
/// existing file at `path`.
pub fn export_to(
    path: &Path,
    vault: &OpenVault,
    data: &VaultData,
    creds: BackupCredentials<'_>,
) -> Result<usize, VaultError> {
    let bytes = export_bytes(vault, data, creds)?;
    container::write_atomic(path, &bytes, |written| {
        let sealed = container::parse(written)?;
        if sealed.header.kind == FileKind::Backup {
            Ok(())
        } else {
            Err(VaultError::WriteVerifyFailed)
        }
    })?;
    Ok(data.items.len())
}

/// Reads just a backup's header (to know whether it needs a keyfile).
pub fn read_backup_header(path: &Path) -> Result<Header, VaultError> {
    let h = super::read_header(path)?;
    if h.kind != FileKind::Backup {
        return Err(VaultError::WrongKind(h.kind));
    }
    Ok(h)
}

/// Decrypts a backup file image.
pub fn open_bytes(
    bytes: &[u8],
    password: &[u8],
    keyfile: Option<&KeyfileDigest>,
) -> Result<Manifest, VaultError> {
    // Kind first: a (v3, two-slot) vault must say "wrong kind", not "version".
    let kind = Header::parse(bytes)?.kind;
    if kind != FileKind::Backup {
        return Err(VaultError::WrongKind(kind));
    }
    let sealed = container::parse(bytes)?;
    let header = &sealed.header;
    match (header.keyfile_required, keyfile.is_some()) {
        (true, false) => return Err(VaultError::KeyfileRequired),
        (false, true) => return Err(VaultError::KeyfileNotExpected),
        _ => {}
    }
    let master = derive_master_key(password, keyfile, &header.salt, &header.kdf)?;
    let keys = VaultKeys::derive(&master);
    sealed.verify_canary(&keys)?;
    let manifest: Manifest = decode_json(&sealed.open_payload(&keys)?)?;
    if manifest.backup_version != BACKUP_VERSION {
        return Err(VaultError::CorruptPayload("unsupported backup version"));
    }
    Ok(manifest)
}

/// Reads and decrypts a backup file.
pub fn open_file(
    path: &Path,
    password: &[u8],
    keyfile: Option<&KeyfileDigest>,
) -> Result<Manifest, VaultError> {
    let len = std::fs::metadata(path)?.len();
    if len > HEADER_LEN as u64 + u64::from(MAX_PAYLOAD_LEN) {
        return Err(VaultError::TooLarge);
    }
    open_bytes(&std::fs::read(path)?, password, keyfile)
}

/// What an import would do. Counts only, no item contents.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ImportPreview {
    /// Export time of the backup.
    pub exported_at: String,
    /// Items in the backup.
    pub total: usize,
    /// Items not present in the vault (would be added).
    pub new_items: usize,
    /// Items present on both sides with identical content.
    pub identical: usize,
    /// Items present on both sides that differ (current kept; see module docs).
    pub conflicts: usize,
}

/// How to apply a backup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportMode {
    /// Add new items; keep current items; archive differing passwords.
    Merge,
    /// Replace the vault's contents with the backup's (spec "Clean Restore").
    Replace,
}

fn item_id(i: &VaultItem) -> &str {
    match i {
        VaultItem::Login(l) => &l.base.id,
        VaultItem::SecureNote(n) => &n.base.id,
    }
}

/// Computes what [`apply`] would do in merge mode.
pub fn preview(current: &VaultData, manifest: &Manifest) -> ImportPreview {
    let mut p = ImportPreview {
        exported_at: manifest.exported_at.clone(),
        total: manifest.vault_data.items.len(),
        ..Default::default()
    };
    for incoming in &manifest.vault_data.items {
        match current
            .items
            .iter()
            .find(|c| item_id(c) == item_id(incoming))
        {
            None => p.new_items += 1,
            Some(c) if c == incoming => p.identical += 1,
            Some(_) => p.conflicts += 1,
        }
    }
    p
}

/// Applies a backup to `current` (call inside [`OpenVault::modify`] so the
/// result is saved crash-safely, with a `.bak` of the previous vault).
/// Returns the number of items added (merge) or restored (replace).
pub fn apply(current: &mut VaultData, manifest: &Manifest, mode: ImportMode) -> usize {
    match mode {
        ImportMode::Replace => {
            current.items = manifest.vault_data.items.clone();
            current.folders = manifest.vault_data.folders.clone();
            current.settings = manifest.vault_data.settings.clone();
            current.updated_at = now_rfc3339();
            current.items.len()
        }
        ImportMode::Merge => {
            let source = format!("Imported from backup ({})", manifest.exported_at);
            let mut added = 0;
            for incoming in &manifest.vault_data.items {
                let existing = current
                    .items
                    .iter_mut()
                    .find(|c| item_id(c) == item_id(incoming));
                match (existing, incoming) {
                    (None, _) => {
                        current.items.push(incoming.clone());
                        added += 1;
                    }
                    (Some(VaultItem::Login(cur)), VaultItem::Login(inc)) => {
                        // Archive every password the backup knows that the
                        // current item does not: zero data loss, no promotion.
                        let known = |p: &str, cur: &super::models::LoginItem| {
                            cur.password == p
                                || cur.password_history.iter().any(|h| h.password == p)
                        };
                        let candidates = std::iter::once(inc.password.as_str())
                            .chain(inc.password_history.iter().map(|h| h.password.as_str()));
                        let mut fresh: Vec<String> = Vec::new();
                        for p in candidates {
                            if !p.is_empty() && !known(p, cur) && !fresh.iter().any(|f| f == p) {
                                fresh.push(p.to_string());
                            }
                        }
                        for p in fresh {
                            cur.password_history.push(PasswordHistoryEntry {
                                password: p,
                                changed_at: now_rfc3339(),
                                source: Some(source.clone()),
                                status: Some("archived_conflict".into()),
                            });
                        }
                        let excess = cur.password_history.len().saturating_sub(MAX_HISTORY);
                        cur.password_history.drain(..excess);
                    }
                    // Notes or mismatched kinds: keep the current item.
                    (Some(_), _) => {}
                }
            }
            if added > 0 {
                current.updated_at = now_rfc3339();
            }
            added
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keyfile;
    use crate::vault::items::{ItemDraft, ItemKind, SecretField};
    use crate::vault::CreateOptions;

    const FAST: KdfParams = KdfParams {
        mem_kib: 1024,
        iterations: 1,
        parallelism: 1,
    };

    fn vault_with(titles_pw: &[(&str, &str)]) -> OpenVault {
        let mut v = OpenVault::create(
            b"vault pw",
            None,
            CreateOptions {
                kdf: FAST,
                ..Default::default()
            },
        )
        .unwrap();
        for (t, p) in titles_pw {
            let d = ItemDraft {
                title: (*t).into(),
                password: Some((*p).into()),
                ..Default::default()
            };
            v.data_mut().create_item(ItemKind::Login, &d).unwrap();
        }
        v
    }

    #[test]
    fn export_same_credentials_roundtrip() {
        let v = vault_with(&[("GitHub", "pw1"), ("Mail", "pw2")]);
        let bytes = export_bytes(&v, v.data(), BackupCredentials::SameAsVault).unwrap();
        assert_eq!(&bytes[..5], b"SHBKP");
        let m = open_bytes(&bytes, b"vault pw", None).unwrap();
        assert_eq!(m.items_count, 2);
        assert_eq!(m.backup_version, BACKUP_VERSION);
        assert!(m.vault_data == *v.data());
        assert_eq!(
            open_bytes(&bytes, b"wrong", None).err(),
            Some(VaultError::Crypto(
                crate::crypto::CryptoError::WrongCredentials
            ))
        );
        // A backup can never be unlocked as the live vault.
        assert_eq!(
            OpenVault::unlock(&bytes, b"vault pw", None).err(),
            Some(VaultError::WrongKind(FileKind::Backup))
        );
    }

    #[test]
    fn export_dedicated_credentials_with_keyfile() {
        let v = vault_with(&[("GitHub", "pw1")]);
        let kf = keyfile::digest_bytes(b"cold-storage usb").unwrap();
        let creds = BackupCredentials::Dedicated {
            password: b"backup pw",
            keyfile: Some(&kf),
            suite: CipherSuite::XChaCha20Poly1305,
            kdf: FAST,
        };
        let bytes = export_bytes(&v, v.data(), creds).unwrap();
        let sealed = container::parse(&bytes).unwrap();
        assert_ne!(
            sealed.header.salt,
            v.header().salt,
            "dedicated backup gets a fresh salt"
        );
        assert_eq!(sealed.header.suite, CipherSuite::XChaCha20Poly1305);
        assert!(open_bytes(&bytes, b"backup pw", Some(&kf)).is_ok());
        assert_eq!(
            open_bytes(&bytes, b"backup pw", None).err(),
            Some(VaultError::KeyfileRequired)
        );
        assert!(open_bytes(&bytes, b"vault pw", Some(&kf)).is_err());
    }

    #[test]
    fn vault_file_is_rejected_as_backup() {
        let v = vault_with(&[]);
        let vault_bytes = v.to_bytes().unwrap();
        assert_eq!(
            open_bytes(&vault_bytes, b"vault pw", None).err(),
            Some(VaultError::WrongKind(FileKind::Vault))
        );
    }

    #[test]
    fn merge_adds_new_keeps_current_archives_conflicts() {
        let mut current = vault_with(&[("GitHub", "current-pw")]);
        let shared_id = current.data().summaries()[0].id.clone();

        // Backup: same item with a different (older or attacker-chosen) password,
        // plus one item the vault does not have.
        let mut other = current.data().clone();
        if let VaultItem::Login(l) = &mut other.items[0] {
            l.password = "backup-pw".into();
            l.base.updated_at = "2099-01-01T00:00:00Z".into(); // future timestamp must not win
        }
        other
            .create_item(
                ItemKind::Login,
                &ItemDraft {
                    title: "New".into(),
                    password: Some("n".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        let manifest = Manifest {
            backup_version: 1,
            exported_at: "2026-11-01T00:00:00Z".into(),
            app_version: "0".into(),
            items_count: 2,
            vault_data: other,
        };

        let p = preview(current.data(), &manifest);
        assert_eq!(
            (p.total, p.new_items, p.identical, p.conflicts),
            (2, 1, 0, 1)
        );

        let added = apply(current.data_mut(), &manifest, ImportMode::Merge);
        assert_eq!(added, 1);
        assert_eq!(current.data().items.len(), 2);
        assert_eq!(
            &*current
                .data()
                .secret(&shared_id, SecretField::Password)
                .unwrap(),
            "current-pw",
            "current password stays active"
        );
        let VaultItem::Login(l) = &current.data().items[0] else {
            panic!()
        };
        let h = l.password_history.last().unwrap();
        assert_eq!(h.password, "backup-pw");
        assert_eq!(h.status.as_deref(), Some("archived_conflict"));
        assert!(h
            .source
            .as_deref()
            .unwrap()
            .starts_with("Imported from backup"));

        // Re-importing the same backup is idempotent.
        assert_eq!(apply(current.data_mut(), &manifest, ImportMode::Merge), 0);
        let VaultItem::Login(l) = &current.data().items[0] else {
            panic!()
        };
        assert_eq!(l.password_history.len(), 1);
        assert_eq!(preview(current.data(), &manifest).new_items, 0);
    }

    #[test]
    fn replace_restores_backup_contents() {
        let mut current = vault_with(&[("A", "1"), ("B", "2")]);
        let backup = vault_with(&[("Only", "x")]);
        let manifest = Manifest {
            backup_version: 1,
            exported_at: String::new(),
            app_version: String::new(),
            items_count: 1,
            vault_data: backup.data().clone(),
        };
        assert_eq!(apply(current.data_mut(), &manifest, ImportMode::Replace), 1);
        assert_eq!(current.data().summaries()[0].title, "Only");
    }

    #[test]
    fn export_to_file_and_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.shushbackup");
        let v = vault_with(&[("GitHub", "pw")]);
        assert_eq!(
            export_to(&path, &v, v.data(), BackupCredentials::SameAsVault).unwrap(),
            1
        );
        assert!(read_backup_header(&path).unwrap().kind == FileKind::Backup);
        assert_eq!(open_file(&path, b"vault pw", None).unwrap().items_count, 1);
    }
}
