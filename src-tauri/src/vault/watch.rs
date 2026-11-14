//! Notices when another program replaces the unlocked vault file (issue #113),
//! for example a cloud sync client bringing in another machine's save.
//!
//! Polled rather than event-driven so it also works on sync folders and
//! network paths. Each poll costs one `metadata` call; the file is read and
//! hashed only when its size or modification time changed, and that read
//! happens outside the vault state lock so a slow disk does not hold up
//! commands or `lock()` (only a `metadata` call runs under the lock).

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use super::disk_fingerprint;
use super::state::VaultState;

/// Size and modification time: the cheap gate before hashing.
type FileSig = (u64, Option<SystemTime>);

fn file_sig(path: &Path) -> Option<FileSig> {
    std::fs::metadata(path)
        .ok()
        .map(|m| (m.len(), m.modified().ok()))
}

/// What one poll found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Poll {
    /// Nothing new (locked, unchanged, our own save, or not settled yet).
    Quiet,
    /// The file differs from the one the unlocked vault was loaded from or
    /// last wrote. Reported once per distinct file image.
    Changed,
}

/// Poll state for [`DiskWatch::poll`].
#[derive(Default)]
pub struct DiskWatch {
    /// The vault path and file signature already compared with the vault.
    checked: Option<(PathBuf, Option<FileSig>)>,
}

impl DiskWatch {
    /// Compares the unlocked vault's file on disk with what the vault last
    /// loaded or wrote. A file still being written, a read error, or a save
    /// racing the check is retried on the next poll instead of being
    /// recorded, so a change is never silently skipped.
    pub fn poll(&mut self, state: &VaultState) -> Poll {
        let Some(path) = state.with(|u| u.path.clone()) else {
            self.checked = None;
            return Poll::Quiet;
        };
        // `None` = the file is gone (deleted or moved by the sync client).
        let sig = file_sig(&path);
        let key = Some((path.clone(), sig));
        if self.checked == key {
            return Poll::Quiet;
        }
        // Read and hash without the vault lock.
        let fingerprint = match sig {
            Some(_) => match disk_fingerprint(&path) {
                Ok(f) => f,
                Err(_) => return Poll::Quiet, // sharing violation etc.: retry
            },
            None => None,
        };
        if file_sig(&path) != sig {
            return Poll::Quiet; // still being written: retry
        }
        // Compare under the lock, and only if no save moved the file since:
        // our own saves hold the same lock.
        let changed = state
            .with(|u| {
                (u.path == path && file_sig(&u.path) == sig)
                    .then(|| !u.vault.matches_disk(fingerprint.as_ref()))
            })
            .flatten();
        let Some(changed) = changed else {
            return Poll::Quiet;
        };
        self.checked = key;
        if changed {
            Poll::Changed
        } else {
            Poll::Quiet
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KdfParams;
    use crate::vault::models::{self, BaseItem, SecureNoteItem, VaultItem};
    use crate::vault::state::Unlocked;
    use crate::vault::{create_vault_file, read_vault_file, CreateOptions, OpenVault, VaultError};

    const FAST: CreateOptions = CreateOptions {
        suite: crate::crypto::CipherSuite::XChaCha20Poly1305,
        kdf: KdfParams {
            mem_kib: 256,
            iterations: 1,
            parallelism: 1,
        },
    };

    fn add_note(v: &mut OpenVault, path: &Path, title: &str) {
        v.modify::<_, VaultError>(path, |d| {
            d.items.push(VaultItem::SecureNote(SecureNoteItem {
                base: BaseItem {
                    id: title.into(),
                    title: title.into(),
                    folder_id: None,
                    tags: vec![],
                    favorite: false,
                    notes: String::new(),
                    attachments: vec![],
                    created_at: models::now_rfc3339(),
                    updated_at: models::now_rfc3339(),
                    last_used_at: None,
                    hlc: None,
                },
                content: "x".into(),
            }));
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn reports_each_foreign_change_once_and_ignores_own_saves() {
        // Issue #113
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.shush");
        create_vault_file(&path, b"pw", None, FAST).unwrap();
        let bytes = read_vault_file(&path).unwrap();
        let mut other = OpenVault::unlock(&bytes, b"pw", None).unwrap();

        let state = VaultState::default();
        let t = state.begin_unlock();
        let vault = OpenVault::unlock(&bytes, b"pw", None).unwrap();
        state
            .finish_unlock(
                t,
                Unlocked {
                    path: path.clone(),
                    vault,
                    lock: None,
                    read_only: false,
                },
            )
            .unwrap();
        let mut w = DiskWatch::default();
        assert_eq!(w.poll(&state), Poll::Quiet, "fresh unlock");

        // Our own save.
        state
            .with_mut(|u| add_note(&mut u.vault, &u.path, "own"))
            .unwrap();
        assert_eq!(w.poll(&state), Poll::Quiet, "own save is not a change");

        // Another writer (the sync client) replaces the file.
        other.reload(&path, None, None).unwrap();
        add_note(&mut other, &path, "foreign");
        assert_eq!(w.poll(&state), Poll::Changed);
        assert_eq!(w.poll(&state), Poll::Quiet, "announced once");

        // After a reload, the same file is not a change.
        state
            .with_mut(|u| u.vault.reload(&u.path, None, None).unwrap())
            .unwrap();
        assert_eq!(w.poll(&state), Poll::Quiet);

        // A deleted file is a change.
        std::fs::remove_file(&path).unwrap();
        assert_eq!(w.poll(&state), Poll::Changed);

        // Locked: nothing to watch.
        state.lock();
        assert_eq!(w.poll(&state), Poll::Quiet);
    }
}
