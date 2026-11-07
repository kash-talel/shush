//! shush — offline-first, zero-knowledge password manager core.
//!
//! Phase 1 delivers the cryptographic engine ([`crypto`]). Vault container,
//! OS integration, sync and TOTP modules land in later phases (spec §12).

#![deny(unsafe_code)] // OS modules opt in locally with a SAFETY comment.
#![warn(missing_docs)]

pub mod crypto;

use std::path::{Path, PathBuf};

use serde::Serialize;
use tauri::Manager;
use zeroize::Zeroizing;

use crypto::{CipherSuite, CryptoError, KdfParams};

/// File name of the primary vault inside the app data directory.
const VAULT_FILE_NAME: &str = "vault.shush";

/// Error returned to the UI: a stable machine-readable code plus a message.
/// Never contains secret material.
#[derive(Debug, Serialize)]
struct CmdError {
    code: &'static str,
    message: String,
}

impl CmdError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[derive(Debug, Serialize)]
struct CipherInfo {
    id: u8,
    name: &'static str,
}

/// Static, non-sensitive build information for the UI status bar.
#[derive(Debug, Serialize)]
struct AppInfo {
    version: &'static str,
    default_cipher: CipherInfo,
    supported_ciphers: Vec<CipherInfo>,
    default_kdf: KdfParams,
}

fn cipher_info(s: CipherSuite) -> CipherInfo {
    CipherInfo {
        id: s.id(),
        name: s.display_name(),
    }
}

#[tauri::command]
fn app_info() -> AppInfo {
    AppInfo {
        version: env!("CARGO_PKG_VERSION"),
        default_cipher: cipher_info(CipherSuite::default()),
        supported_ciphers: CipherSuite::ALL.into_iter().map(cipher_info).collect(),
        default_kdf: KdfParams::default(),
    }
}

#[derive(Debug, Serialize)]
struct VaultStatus {
    path: String,
    exists: bool,
}

fn vault_path(app: &tauri::AppHandle) -> Result<PathBuf, CmdError> {
    app.path()
        .app_data_dir()
        .map(|d| d.join(VAULT_FILE_NAME))
        .map_err(|e| CmdError::new("APP_DATA_UNAVAILABLE", e.to_string()))
}

#[tauri::command]
fn vault_status(app: tauri::AppHandle) -> Result<VaultStatus, CmdError> {
    let path = vault_path(&app)?;
    Ok(VaultStatus {
        exists: path.is_file(),
        path: path.display().to_string(),
    })
}

/// Non-secret facts about a candidate keyfile. The digest itself never
/// crosses the IPC boundary.
#[derive(Debug, Serialize)]
struct KeyfileInfo {
    file_name: String,
    size_bytes: u64,
}

fn inspect_keyfile_blocking(path: &Path) -> Result<KeyfileInfo, CmdError> {
    let meta =
        std::fs::metadata(path).map_err(|e| keyfile_error(CryptoError::KeyfileIo(e.kind())))?;
    if meta.is_dir() {
        return Err(CmdError::new(
            "KEYFILE_IS_DIRECTORY",
            "That is a folder, not a keyfile.",
        ));
    }
    // Hash it now so unreadable/empty files are rejected at selection time,
    // not after a slow KDF run. The digest is wiped on drop.
    let _digest = crypto::keyfile::digest_file(path).map_err(keyfile_error)?;
    Ok(KeyfileInfo {
        file_name: path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        size_bytes: meta.len(),
    })
}

fn keyfile_error(e: CryptoError) -> CmdError {
    use std::io::ErrorKind;
    match e {
        CryptoError::EmptyKeyfile => CmdError::new("KEYFILE_EMPTY", "Keyfile is empty."),
        CryptoError::KeyfileIo(ErrorKind::NotFound) => CmdError::new(
            "KEYFILE_NOT_FOUND",
            "Keyfile not found. Is the USB drive connected?",
        ),
        CryptoError::KeyfileIo(ErrorKind::PermissionDenied) => {
            CmdError::new("KEYFILE_ACCESS_DENIED", "Access to the keyfile was denied.")
        }
        other => CmdError::new("KEYFILE_UNREADABLE", other.to_string()),
    }
}

#[tauri::command]
async fn inspect_keyfile(path: String) -> Result<KeyfileInfo, CmdError> {
    tauri::async_runtime::spawn_blocking(move || inspect_keyfile_blocking(Path::new(&path)))
        .await
        .map_err(|e| CmdError::new("INTERNAL", e.to_string()))?
}

/// Unlock entry point. The vault container arrives in Phase 3, so for now
/// this validates input and reports the honest state of the vault file.
#[tauri::command]
fn unlock(
    app: tauri::AppHandle,
    password: String,
    keyfile_path: Option<String>,
) -> Result<(), CmdError> {
    // Move the IPC-owned string into a wiped buffer immediately (issue #6:
    // the WebView and IPC layer still hold copies we cannot scrub).
    let password = Zeroizing::new(password);
    if password.is_empty() && keyfile_path.is_none() {
        return Err(CmdError::new(
            "EMPTY_CREDENTIALS",
            "Enter your master password.",
        ));
    }
    let path = vault_path(&app)?;
    if !path.is_file() {
        return Err(CmdError::new(
            "NO_VAULT",
            "No vault exists yet. Vault creation ships with the Phase 3 container.",
        ));
    }
    Err(CmdError::new(
        "NOT_IMPLEMENTED",
        "Opening vault files ships with the Phase 3 container.",
    ))
}

/// Tauri builder with every shush command registered.
///
/// GUI plugins (e.g. the native file dialog) are attached in `main.rs`, not
/// here: on Windows they import Common Controls v6 symbols that only resolve
/// in a binary carrying the app manifest. Keeping them out of the library lets
/// `cargo test --lib` run without that manifest.
pub fn builder() -> tauri::Builder<tauri::Wry> {
    tauri::Builder::default().invoke_handler(tauri::generate_handler![
        app_info,
        vault_status,
        inspect_keyfile,
        unlock
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspect_keyfile_reports_metadata_and_rejects_bad_inputs() {
        let dir = tempfile::tempdir().unwrap();
        let kf = dir.path().join("vault.key");
        std::fs::write(&kf, [7u8; 32]).unwrap();
        let info = inspect_keyfile_blocking(&kf).unwrap();
        assert_eq!(info.file_name, "vault.key");
        assert_eq!(info.size_bytes, 32);

        let empty = dir.path().join("empty.key");
        std::fs::write(&empty, b"").unwrap();
        assert_eq!(
            inspect_keyfile_blocking(&empty).unwrap_err().code,
            "KEYFILE_EMPTY"
        );
        assert_eq!(
            inspect_keyfile_blocking(dir.path()).unwrap_err().code,
            "KEYFILE_IS_DIRECTORY"
        );
        assert_eq!(
            inspect_keyfile_blocking(&dir.path().join("nope"))
                .unwrap_err()
                .code,
            "KEYFILE_NOT_FOUND"
        );
    }
}
