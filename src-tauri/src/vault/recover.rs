//! Recovery of a damaged vault from its `.bak` copy (issue #170).
//!
//! `.bak` is the previous generation of the file, re-sealed on every unlock,
//! so it is not a history: it is only worth restoring when the main file can
//! no longer be read. Nothing is ever deleted here. The damaged file is
//! copied to `vault.shush.corrupt-<UTC timestamp>` and stays until the user
//! discards it from the lock screen's banner.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::container::{sibling, write_atomic_keep_bak};
use super::models::rfc3339_from_unix;
use super::{check_structure, read_vault_file, VaultError};

/// Prefix (after the vault's file name and a dot) of a quarantined file.
pub const CORRUPT_PREFIX: &str = "corrupt-";

/// Whether the main file's failure means "damaged" (as opposed to a newer
/// format, a busy file or a missing one), so that `.bak` may stand in for it.
pub fn is_damage(e: &VaultError) -> bool {
    matches!(
        e,
        VaultError::NotAVault | VaultError::Truncated | VaultError::Malformed(_)
    )
}

/// Reads `path` and runs the structural checks unlock makes before the KDF.
fn check_file(path: &Path) -> Result<(), VaultError> {
    check_structure(&read_vault_file(path)?)
}

/// Whether `path` is damaged (its header or its layout) and `.bak` is
/// structurally intact: the only case in which recovery is offered. Wrong
/// credentials never lead here: they only show when decrypting.
pub fn can_recover(path: &Path) -> bool {
    path.is_file()
        && check_file(path).is_err_and(|e| is_damage(&e))
        && check_file(&sibling(path, "bak")).is_ok()
}

fn quarantine_path(path: &Path) -> PathBuf {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let stamp: String = rfc3339_from_unix(secs)
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect();
    let base = sibling(path, &format!("{CORRUPT_PREFIX}{stamp}"));
    let mut candidate = base.clone();
    let mut n = 1;
    while candidate.exists() {
        let mut s = base.as_os_str().to_os_string();
        s.push(format!("-{n}"));
        candidate = PathBuf::from(s);
        n += 1;
    }
    candidate
}

/// Copies `from` to a new file `to` (never overwriting one) and flushes it.
fn copy_new(from: &Path, to: &Path) -> io::Result<()> {
    let mut src = fs::File::open(from)?;
    let mut dst = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(to)?;
    io::copy(&mut src, &mut dst)?;
    dst.sync_all()
}

/// Replaces the damaged vault at `path` with the contents of its `.bak`.
///
/// `verify` receives the `.bak` bytes and must fully decrypt them with the
/// user's credentials; if it fails nothing on disk has changed. The damaged
/// file is then copied to `vault.shush.corrupt-<UTC>` and the `.bak` bytes
/// replace `path` through a crash-safe write that never touches `.bak`
/// (plain `write_atomic` would copy the damaged file over it), so at every
/// step both the damaged original and the good backup exist on disk.
/// Returns the quarantine path.
pub fn recover_from_backup<E: From<VaultError>>(
    path: &Path,
    verify: impl FnOnce(&[u8]) -> Result<(), E>,
) -> Result<PathBuf, E> {
    if !can_recover(path) {
        return Err(VaultError::Malformed("no damaged vault with an intact backup").into());
    }
    let bytes = read_vault_file(&sibling(path, "bak"))?;
    verify(&bytes)?;

    let quarantine = quarantine_path(path);
    copy_new(path, &quarantine).map_err(VaultError::from)?;
    let result = write_atomic_keep_bak(path, &bytes, |written| {
        if written == bytes.as_slice() {
            Ok(())
        } else {
            Err(VaultError::WriteVerifyFailed)
        }
    });
    if let Err(e) = result {
        // The damaged original is still at `path`: drop the extra copy so a
        // failed recovery changes nothing.
        let _ = fs::remove_file(&quarantine);
        return Err(e.into());
    }
    Ok(quarantine)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{create_vault_file, CreateOptions, OpenVault};

    fn setup() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let v = dir.path().join("vault.shush");
        let mut open = create_vault_file(&v, b"pw", None, CreateOptions::default()).unwrap();
        // The refresh after an unlock is what produces `.bak`.
        open.refresh(&v).unwrap();
        (dir, v)
    }

    fn verify_pw(pw: &'static [u8]) -> impl FnOnce(&[u8]) -> Result<(), VaultError> {
        move |b| OpenVault::unlock(b, pw, None).map(drop)
    }

    #[test]
    fn restores_bak_and_quarantines_damaged_file() {
        let (_dir, v) = setup();
        let bak = sibling(&v, "bak");
        let good = fs::read(&bak).unwrap();
        fs::write(&v, b"damaged header").unwrap();

        let q = recover_from_backup(&v, verify_pw(b"pw")).unwrap();
        assert_eq!(fs::read(&v).unwrap(), good);
        assert_eq!(
            fs::read(&bak).unwrap(),
            good,
            ".bak must stay the good copy"
        );
        assert_eq!(fs::read(&q).unwrap(), b"damaged header");
        assert!(q
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("vault.shush.corrupt-"));
        assert!(OpenVault::unlock(&fs::read(&v).unwrap(), b"pw", None).is_ok());
    }

    #[test]
    fn wrong_password_changes_nothing() {
        let (_dir, v) = setup();
        let bak = sibling(&v, "bak");
        let bak_before = fs::read(&bak).unwrap();
        fs::write(&v, b"damaged header").unwrap();

        assert!(recover_from_backup(&v, verify_pw(b"nope")).is_err());
        assert_eq!(fs::read(&v).unwrap(), b"damaged header");
        assert_eq!(fs::read(&bak).unwrap(), bak_before);
        let names: Vec<_> = fs::read_dir(v.parent().unwrap())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(!names.iter().any(|n| n.contains("corrupt")), "{names:?}");
    }

    #[test]
    fn not_offered_when_main_missing_or_intact_or_no_bak() {
        let (_dir, v) = setup();
        assert!(!can_recover(&v), "intact main");
        assert!(recover_from_backup(&v, verify_pw(b"pw")).is_err());
        let bak = sibling(&v, "bak");
        fs::write(&v, b"damaged").unwrap();
        assert!(can_recover(&v));
        fs::remove_file(&v).unwrap();
        assert!(!can_recover(&v), "main missing");
        fs::write(&v, b"damaged").unwrap();
        fs::remove_file(&bak).unwrap();
        assert!(!can_recover(&v), "no bak");
    }

    #[test]
    fn recovers_file_cut_short_after_an_intact_header() {
        let (_dir, v) = setup();
        let bak = sibling(&v, "bak");
        let good = fs::read(&bak).unwrap();
        let cut = &good[..good.len() - 1];
        fs::write(&v, cut).unwrap();
        assert!(crate::vault::read_header(&v).is_ok(), "header still reads");
        assert!(can_recover(&v));

        let q = recover_from_backup(&v, verify_pw(b"pw")).unwrap();
        assert_eq!(fs::read(&v).unwrap(), good);
        assert_eq!(fs::read(&bak).unwrap(), good);
        assert_eq!(fs::read(&q).unwrap(), cut);
    }

    #[test]
    fn not_offered_when_bak_is_damaged_too() {
        let (_dir, v) = setup();
        let bak = sibling(&v, "bak");
        let good = fs::read(&bak).unwrap();
        fs::write(&v, b"damaged").unwrap();
        fs::write(&bak, &good[..good.len() - 1]).unwrap();
        assert!(!can_recover(&v));
        assert!(recover_from_backup(&v, verify_pw(b"pw")).is_err());
        assert_eq!(fs::read(&v).unwrap(), b"damaged");
    }

    #[test]
    fn duress_vault_restores_byte_identical_with_either_password() {
        for (pw, other) in [
            (&b"master"[..], &b"duress"[..]),
            (&b"duress"[..], &b"master"[..]),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let v = dir.path().join("vault.shush");
            let mut open =
                create_vault_file(&v, b"master", None, CreateOptions::default()).unwrap();
            open.set_duress(&v, b"master", b"duress", None).unwrap();
            open.refresh(&v).unwrap();
            let bak = sibling(&v, "bak");
            let good = fs::read(&bak).unwrap();
            fs::write(&v, &good[..10]).unwrap();

            let q = recover_from_backup(&v, |b| OpenVault::unlock(b, pw, None).map(drop)).unwrap();
            assert_eq!(fs::read(&v).unwrap(), good);
            assert_eq!(fs::read(&bak).unwrap(), good);
            assert!(q.exists());
            assert!(OpenVault::unlock(&good, other, None).is_ok());
        }
    }

    #[test]
    fn quarantine_names_do_not_collide() {
        let (_dir, v) = setup();
        let a = quarantine_path(&v);
        fs::write(&a, b"x").unwrap();
        assert_ne!(quarantine_path(&v), a);
    }
}
