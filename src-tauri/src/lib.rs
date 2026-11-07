//! shush — offline-first, zero-knowledge password manager core.
//!
//! - [`crypto`]: Argon2id KDF, keyfiles, AEAD envelope (Phase 1).
//! - [`vault`]: `vault.shush` container, data model, in-memory state (Phase 3).
//!
//! OS integration, sync and TOTP modules land in later phases (spec §12).

#![deny(unsafe_code)] // OS modules opt in locally with a SAFETY comment.
#![warn(missing_docs)]

pub mod crypto;
pub mod os;
pub mod totp;
pub mod vault;

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tauri::{Emitter, Manager};
use zeroize::Zeroizing;

use crypto::{CipherSuite, CryptoError, KdfParams, KeyfileDigest};
use vault::container::Header;
use vault::items::{ItemDetail, ItemDraft, ItemError, ItemKind, ItemSummary, SecretField};
use vault::state::{Unlocked, VaultState};
use vault::{CreateOptions, OpenVault, VaultData, VaultError};

/// File name of the primary vault inside the app data directory.
const VAULT_FILE_NAME: &str = "vault.shush";
/// Minimum master password length (characters, after NFC) for new vaults.
const MIN_PASSWORD_CHARS: usize = 8;

/// Error returned to the UI: a stable machine-readable code plus a message.
/// Never contains secret material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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

impl From<VaultError> for CmdError {
    fn from(e: VaultError) -> Self {
        use CryptoError as C;
        use VaultError as V;
        match e {
            V::Crypto(C::WrongCredentials) => {
                Self::new("WRONG_CREDENTIALS", "Wrong master password or keyfile.")
            }
            V::Crypto(C::AuthenticationFailed) => Self::new(
                "VAULT_TAMPERED",
                "The vault failed its integrity check: it is corrupt or was modified. \
                 The previous version is kept next to it as vault.shush.bak.",
            ),
            V::Crypto(C::EmptyCredentials) => {
                Self::new("EMPTY_CREDENTIALS", "Enter your master password.")
            }
            V::Crypto(C::InvalidPasswordEncoding) => {
                Self::new("INVALID_PASSWORD", "Password is not valid text.")
            }
            V::KeyfileRequired => Self::new(
                "KEYFILE_REQUIRED",
                "This vault needs its keyfile. Attach it to unlock.",
            ),
            V::KeyfileNotExpected => Self::new(
                "KEYFILE_NOT_EXPECTED",
                "This vault does not use a keyfile. Remove it and try again.",
            ),
            V::NotFound => Self::new(
                "NO_VAULT",
                "No vault exists yet. Create one to get started.",
            ),
            V::AlreadyExists => Self::new(
                "VAULT_EXISTS",
                "A vault already exists. It will not be overwritten.",
            ),
            V::Io(kind) => Self::new(
                "IO_ERROR",
                format!("Could not access the vault file ({kind})."),
            ),
            V::WriteVerifyFailed => Self::new("WRITE_FAILED", e.to_string()),
            V::NotAVault
            | V::WrongKind(_)
            | V::UnsupportedVersion(_)
            | V::Truncated
            | V::Malformed(_)
            | V::TooLarge
            | V::CorruptPayload(_)
            | V::Crypto(C::InvalidKdfParams(_) | C::UnsupportedCipherSuite(_)) => {
                Self::new("VAULT_UNREADABLE", e.to_string())
            }
            other => Self::new("INTERNAL", other.to_string()),
        }
    }
}

impl From<ItemError> for CmdError {
    fn from(e: ItemError) -> Self {
        match e {
            ItemError::NotFound => Self::new("ITEM_NOT_FOUND", "That item no longer exists."),
            ItemError::Invalid(m) => Self::new("INVALID_INPUT", m),
        }
    }
}

fn locked() -> CmdError {
    CmdError::new("VAULT_LOCKED", "The vault is locked.")
}

#[derive(Debug, Serialize)]
struct CipherInfo {
    id: u8,
    name: &'static str,
}

fn cipher_info(s: CipherSuite) -> CipherInfo {
    CipherInfo {
        id: s.id(),
        name: s.display_name(),
    }
}

/// Static, non-sensitive build information for the UI status bar.
#[derive(Debug, Serialize)]
struct AppInfo {
    version: &'static str,
    default_cipher: CipherInfo,
    supported_ciphers: Vec<CipherInfo>,
    default_kdf: KdfParams,
    min_password_chars: usize,
}

#[tauri::command]
fn app_info() -> AppInfo {
    AppInfo {
        version: env!("CARGO_PKG_VERSION"),
        default_cipher: cipher_info(CipherSuite::default()),
        supported_ciphers: CipherSuite::ALL.into_iter().map(cipher_info).collect(),
        default_kdf: KdfParams::default(),
        min_password_chars: MIN_PASSWORD_CHARS,
    }
}

fn vault_path(app: &tauri::AppHandle) -> Result<PathBuf, CmdError> {
    // Debug builds only: point the app at a scratch vault for testing without
    // touching the real one. Compiled out of release builds.
    #[cfg(debug_assertions)]
    if let Some(p) = std::env::var_os("SHUSH_VAULT_PATH") {
        return Ok(PathBuf::from(p));
    }
    app.path()
        .app_data_dir()
        .map(|d| d.join(VAULT_FILE_NAME))
        .map_err(|e| CmdError::new("APP_DATA_UNAVAILABLE", e.to_string()))
}

/// What the unlock/create screens need to know before any credentials.
#[derive(Debug, Serialize)]
struct VaultStatus {
    path: String,
    exists: bool,
    unlocked: bool,
    /// From the (authenticated) header; `None` if there is no readable vault.
    keyfile_required: Option<bool>,
    cipher: Option<CipherInfo>,
    kdf: Option<KdfParams>,
    /// Set when a file exists but its header is unreadable.
    error: Option<CmdError>,
}

fn status_for(path: &Path, unlocked: bool) -> VaultStatus {
    let mut status = VaultStatus {
        path: path.display().to_string(),
        exists: path.is_file(),
        unlocked,
        keyfile_required: None,
        cipher: None,
        kdf: None,
        error: None,
    };
    if status.exists {
        match vault::read_header(path) {
            Ok(h) => {
                status.keyfile_required = Some(h.keyfile_required);
                status.cipher = Some(cipher_info(h.suite));
                status.kdf = Some(h.kdf);
            }
            Err(e) => status.error = Some(e.into()),
        }
    }
    status
}

#[tauri::command]
fn vault_status(app: tauri::AppHandle) -> Result<VaultStatus, CmdError> {
    let unlocked = app.state::<VaultState>().is_unlocked();
    Ok(status_for(&vault_path(&app)?, unlocked))
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
        CryptoError::KeyfileIo(ErrorKind::AlreadyExists) => CmdError::new(
            "KEYFILE_EXISTS",
            "A file with that name already exists. Choose a new name for the keyfile.",
        ),
        CryptoError::KeyfileIo(ErrorKind::PermissionDenied) => {
            CmdError::new("KEYFILE_ACCESS_DENIED", "Access to the keyfile was denied.")
        }
        other => CmdError::new("KEYFILE_UNREADABLE", other.to_string()),
    }
}

/// Runs blocking work (KDF, file I/O) off the async runtime.
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, CmdError> + Send + 'static,
) -> Result<T, CmdError> {
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| CmdError::new("INTERNAL", e.to_string()))?
}

#[tauri::command]
async fn inspect_keyfile(path: String) -> Result<KeyfileInfo, CmdError> {
    blocking(move || inspect_keyfile_blocking(Path::new(&path))).await
}

/// Summary of an unlocked vault. Counts only; never item contents.
#[derive(Debug, Serialize)]
struct VaultSummary {
    path: String,
    cipher: CipherInfo,
    kdf: KdfParams,
    keyfile_required: bool,
    item_count: usize,
    folder_count: usize,
}

fn summary(path: &Path, v: &OpenVault) -> VaultSummary {
    let h: &Header = v.header();
    VaultSummary {
        path: path.display().to_string(),
        cipher: cipher_info(h.suite),
        kdf: h.kdf,
        keyfile_required: h.keyfile_required,
        item_count: v.data().items.len(),
        folder_count: v.data().folders.len(),
    }
}

/// How the user wants to use a keyfile for a new vault.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
enum KeyfileChoice {
    /// Password only.
    None,
    /// Use an existing file.
    Existing { path: String },
    /// Generate 32 random bytes into a new file.
    Generate { path: String },
}

fn create_vault_blocking(
    vault_file: &Path,
    password: &[u8],
    keyfile: &KeyfileChoice,
    cipher_id: u8,
    kdf: KdfParams,
) -> Result<OpenVault, CmdError> {
    let suite = CipherSuite::from_id(cipher_id).map_err(VaultError::from)?;
    if !kdf.meets_policy() {
        return Err(CmdError::new(
            "WEAK_KDF",
            "Key derivation parameters are below the safety floor.",
        ));
    }
    let normalized = crypto::kdf::normalize_password(password).map_err(VaultError::from)?;
    if normalized.chars().count() < MIN_PASSWORD_CHARS {
        return Err(CmdError::new(
            "WEAK_PASSWORD",
            format!("Use a master password of at least {MIN_PASSWORD_CHARS} characters."),
        ));
    }
    if vault_file.exists() {
        return Err(VaultError::AlreadyExists.into());
    }

    let mut generated: Option<PathBuf> = None;
    let digest: Option<KeyfileDigest> = match keyfile {
        KeyfileChoice::None => None,
        KeyfileChoice::Existing { path } => {
            Some(crypto::keyfile::digest_file(Path::new(path)).map_err(keyfile_error)?)
        }
        KeyfileChoice::Generate { path } => {
            let p = PathBuf::from(path);
            let d = crypto::keyfile::create_keyfile(&p).map_err(keyfile_error)?;
            generated = Some(p);
            Some(d)
        }
    };

    let result = vault::create_vault_file(
        vault_file,
        password,
        digest.as_ref(),
        CreateOptions { suite, kdf },
    );
    if result.is_err() {
        // A freshly generated keyfile for a vault that was never written is
        // useless and confusing; remove it.
        if let Some(p) = generated {
            let _ = std::fs::remove_file(p);
        }
    }
    Ok(result?)
}

#[tauri::command]
async fn create_vault(
    app: tauri::AppHandle,
    password: String,
    keyfile: KeyfileChoice,
    cipher_id: u8,
) -> Result<VaultSummary, CmdError> {
    // Move the IPC-owned string into a wiped buffer immediately (issue #6).
    let password = Zeroizing::new(password);
    let path = vault_path(&app)?;
    blocking(move || {
        let state = app.state::<VaultState>();
        let ticket = state.begin_unlock();
        let vault = create_vault_blocking(
            &path,
            password.as_bytes(),
            &keyfile,
            cipher_id,
            KdfParams::default(),
        )?;
        let s = summary(&path, &vault);
        state
            .finish_unlock(ticket, Unlocked { path, vault })
            .map_err(|_| {
                CmdError::new("LOCKED_DURING_UNLOCK", "Vault was locked while opening.")
            })?;
        Ok(s)
    })
    .await
}

fn unlock_blocking(
    path: &Path,
    password: &[u8],
    keyfile_path: Option<&str>,
) -> Result<OpenVault, CmdError> {
    let digest = keyfile_path
        .map(|p| crypto::keyfile::digest_file(Path::new(p)).map_err(keyfile_error))
        .transpose()?;
    let bytes = vault::read_vault_file(path)?;
    Ok(OpenVault::unlock(&bytes, password, digest.as_ref())?)
}

#[tauri::command]
async fn unlock(
    app: tauri::AppHandle,
    password: String,
    keyfile_path: Option<String>,
) -> Result<VaultSummary, CmdError> {
    let password = Zeroizing::new(password);
    let path = vault_path(&app)?;
    blocking(move || {
        let state = app.state::<VaultState>();
        let ticket = state.begin_unlock();
        let vault = unlock_blocking(&path, password.as_bytes(), keyfile_path.as_deref())?;
        let s = summary(&path, &vault);
        state
            .finish_unlock(ticket, Unlocked { path, vault })
            .map_err(|_| {
                CmdError::new("LOCKED_DURING_UNLOCK", "Vault was locked while opening.")
            })?;
        Ok(s)
    })
    .await
}

#[tauri::command]
fn lock(app: tauri::AppHandle) {
    app.state::<VaultState>().lock();
    // Never leave a copied secret behind on the clipboard after locking.
    os::clipboard::clear_if_ours();
}

/// Event sent to the UI when the vault locks without the user clicking Lock.
const EVENT_AUTO_LOCKED: &str = "vault-auto-locked";

/// Automatic lock from a session / power / idle trigger (issue #15).
fn auto_lock(app: &tauri::AppHandle, reason: os::session::LockReason) {
    let state = app.state::<VaultState>();
    // Sleep-related triggers honour the vault's `auto_lock_on_sleep` setting;
    // workstation lock, log-off and disconnect always lock.
    let wanted = state
        .with(|u| !reason.is_sleep_related() || u.vault.data().settings.auto_lock_on_sleep)
        .unwrap_or(false); // already locked: nothing to do
    if wanted {
        state.lock();
        os::clipboard::clear_if_ours();
        let _ = app.emit(EVENT_AUTO_LOCKED, reason);
    }
}

/// Shows, un-minimizes and focuses the main window (tray click, second launch).
pub fn show_main_window(app: &tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

fn setup_tray(app: &tauri::App) -> tauri::Result<()> {
    use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
    use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

    let open = MenuItem::with_id(app, "open", "Open shush", true, None::<&str>)?;
    let lock_item = MenuItem::with_id(app, "lock", "Lock vault", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit shush", true, None::<&str>)?;
    let menu = Menu::with_items(
        app,
        &[
            &open,
            &lock_item,
            &PredefinedMenuItem::separator(app)?,
            &quit,
        ],
    )?;

    let mut tray = TrayIconBuilder::with_id("main")
        .tooltip("shush")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open" => show_main_window(app),
            "lock" => {
                app.state::<VaultState>().lock();
                os::clipboard::clear_if_ours();
                let _ = app.emit(EVENT_AUTO_LOCKED, "tray");
            }
            "quit" => {
                app.state::<VaultState>().lock();
                os::clipboard::clear_if_ours();
                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        tray = tray.icon(icon.clone());
    }
    tray.build(app)?;
    Ok(())
}

// ---- Items (roadmap Step 4) -------------------------------------------------

/// Read-only access to the unlocked vault data.
fn read<R>(
    app: &tauri::AppHandle,
    f: impl FnOnce(&VaultData) -> Result<R, CmdError>,
) -> Result<R, CmdError> {
    app.state::<VaultState>()
        .with(|u| f(u.vault.data()))
        .unwrap_or_else(|| Err(locked()))
}

/// Transactional mutation: applied, saved crash-safely, then committed.
fn write<R>(
    app: &tauri::AppHandle,
    f: impl FnOnce(&mut VaultData) -> Result<R, CmdError>,
) -> Result<R, CmdError> {
    app.state::<VaultState>()
        .with_mut(|u| {
            let path = u.path.clone();
            u.vault.modify(&path, f)
        })
        .unwrap_or_else(|| Err(locked()))
}

#[tauri::command]
fn list_items(app: tauri::AppHandle) -> Result<Vec<ItemSummary>, CmdError> {
    read(&app, |d| Ok(d.summaries()))
}

#[tauri::command]
fn get_item(app: tauri::AppHandle, id: String) -> Result<ItemDetail, CmdError> {
    read(&app, |d| Ok(d.detail(&id)?))
}

#[tauri::command]
async fn create_item(
    app: tauri::AppHandle,
    kind: ItemKind,
    draft: ItemDraft,
) -> Result<ItemDetail, CmdError> {
    blocking(move || {
        write(&app, |d| {
            let id = d.create_item(kind, &draft)?;
            Ok(d.detail(&id)?)
        })
    })
    .await
}

#[tauri::command]
async fn update_item(
    app: tauri::AppHandle,
    id: String,
    draft: ItemDraft,
) -> Result<ItemDetail, CmdError> {
    blocking(move || {
        write(&app, |d| {
            d.update_item(&id, &draft)?;
            Ok(d.detail(&id)?)
        })
    })
    .await
}

#[tauri::command]
async fn delete_item(app: tauri::AppHandle, id: String) -> Result<(), CmdError> {
    blocking(move || write(&app, |d| Ok(d.delete_item(&id)?))).await
}

#[tauri::command]
async fn set_favorite(app: tauri::AppHandle, id: String, favorite: bool) -> Result<(), CmdError> {
    blocking(move || write(&app, |d| Ok(d.set_favorite(&id, favorite)?))).await
}

/// Copies a field to the clipboard from Rust; the secret never reaches JS.
/// Returns the number of seconds until it is cleared.
#[tauri::command]
fn copy_field(app: tauri::AppHandle, id: String, field: SecretField) -> Result<u32, CmdError> {
    read(&app, |d| {
        let value = d.secret(&id, field)?;
        if value.is_empty() {
            return Err(CmdError::new("EMPTY_FIELD", "Nothing to copy."));
        }
        let secs = d.settings.clipboard_clear_seconds.clamp(5, 600);
        os::clipboard::copy_secret(&value, std::time::Duration::from_secs(u64::from(secs)))
            .map_err(|e| CmdError::new("CLIPBOARD", e.to_string()))?;
        Ok(secs)
    })
}

/// Explicit, user-initiated reveal of one password (issue #6: this is the
/// only path by which a stored password reaches the WebView).
#[tauri::command]
fn reveal_password(app: tauri::AppHandle, id: String) -> Result<String, CmdError> {
    read(&app, |d| {
        Ok(d.secret(&id, SecretField::Password)?.to_string())
    })
}

#[tauri::command]
fn totp_code(app: tauri::AppHandle, id: String) -> Result<totp::TotpCode, CmdError> {
    read(&app, |d| {
        let secret = d.totp_secret(&id)?;
        totp::current_code(&secret).map_err(|e| CmdError::new("TOTP", e.to_string()))
    })
}

// ---- Backup / import (roadmap Step 6) ----------------------------------------

/// Credentials for a new backup, as chosen in the UI.
#[derive(Debug, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
enum BackupCredentialChoice {
    /// Same password / keyfile as the vault.
    SameAsVault,
    /// Dedicated password and optional keyfile (fresh salt).
    Dedicated {
        password: vault::items::SecretInput,
        keyfile_path: Option<String>,
    },
}

#[tauri::command]
async fn export_backup(
    app: tauri::AppHandle,
    path: String,
    credentials: BackupCredentialChoice,
) -> Result<usize, CmdError> {
    use vault::backup::{export_to, BackupCredentials};
    blocking(move || {
        let path = PathBuf::from(path);
        if path.extension().and_then(|e| e.to_str()) != Some(vault::backup::EXTENSION) {
            return Err(CmdError::new("INVALID_INPUT", "Backups must use the .shushbackup extension."));
        }
        let state = app.state::<VaultState>();
        let result = state.with(|u| {
            if path == u.path {
                return Err(CmdError::new("INVALID_INPUT", "Choose a different file than the vault itself."));
            }
            match &credentials {
                BackupCredentialChoice::SameAsVault => Ok(export_to(&path, &u.vault, BackupCredentials::SameAsVault)?),
                BackupCredentialChoice::Dedicated { password, keyfile_path } => {
                    let normalized = crypto::kdf::normalize_password(password.as_str().as_bytes()).map_err(VaultError::from)?;
                    if normalized.chars().count() < MIN_PASSWORD_CHARS {
                        return Err(CmdError::new(
                            "WEAK_PASSWORD",
                            format!("Use a backup password of at least {MIN_PASSWORD_CHARS} characters."),
                        ));
                    }
                    let digest = keyfile_path
                        .as_deref()
                        .map(|p| crypto::keyfile::digest_file(Path::new(p)).map_err(keyfile_error))
                        .transpose()?;
                    let creds = BackupCredentials::Dedicated {
                        password: password.as_str().as_bytes(),
                        keyfile: digest.as_ref(),
                        suite: u.vault.header().suite,
                        kdf: u.vault.header().kdf,
                    };
                    Ok(export_to(&path, &u.vault, creds)?)
                }
            }
        });
        result.unwrap_or_else(|| Err(locked()))
    })
    .await
}

/// Non-secret facts about a backup file, read from its header.
#[derive(Debug, Serialize)]
struct BackupInfo {
    keyfile_required: bool,
    cipher: CipherInfo,
}

#[tauri::command]
async fn inspect_backup(path: String) -> Result<BackupInfo, CmdError> {
    blocking(move || {
        let h = vault::backup::read_backup_header(Path::new(&path))?;
        Ok(BackupInfo {
            keyfile_required: h.keyfile_required,
            cipher: cipher_info(h.suite),
        })
    })
    .await
}

fn open_backup(
    path: &str,
    password: &str,
    keyfile_path: Option<&str>,
) -> Result<vault::backup::Manifest, CmdError> {
    let digest = keyfile_path
        .map(|p| crypto::keyfile::digest_file(Path::new(p)).map_err(keyfile_error))
        .transpose()?;
    Ok(vault::backup::open_file(
        Path::new(path),
        password.as_bytes(),
        digest.as_ref(),
    )?)
}

#[tauri::command]
async fn preview_import(
    app: tauri::AppHandle,
    path: String,
    password: vault::items::SecretInput,
    keyfile_path: Option<String>,
) -> Result<vault::backup::ImportPreview, CmdError> {
    blocking(move || {
        let manifest = open_backup(&path, password.as_str(), keyfile_path.as_deref())?;
        read(&app, |d| Ok(vault::backup::preview(d, &manifest)))
    })
    .await
}

#[tauri::command]
async fn apply_import(
    app: tauri::AppHandle,
    path: String,
    password: vault::items::SecretInput,
    keyfile_path: Option<String>,
    mode: vault::backup::ImportMode,
) -> Result<usize, CmdError> {
    blocking(move || {
        // Decrypt (slow KDF) before taking the vault lock.
        let manifest = open_backup(&path, password.as_str(), keyfile_path.as_deref())?;
        write(&app, |d| Ok(vault::backup::apply(d, &manifest, mode)))
    })
    .await
}

#[derive(Debug, Serialize)]
struct GeneratedPassword {
    password: String,
    entropy_bits: f64,
}

#[tauri::command]
fn generate_password(
    options: crypto::generator::GeneratorOptions,
) -> Result<GeneratedPassword, CmdError> {
    let g = crypto::generator::generate(&options)
        .map_err(|e| CmdError::new("INVALID_INPUT", e.to_string()))?;
    Ok(GeneratedPassword {
        password: g.password.to_string(),
        entropy_bits: g.entropy_bits,
    })
}

/// Tauri builder with every shush command and the vault state registered.
///
/// GUI plugins (e.g. the native file dialog) are attached in `main.rs`, not
/// here: on Windows they import Common Controls v6 symbols that only resolve
/// in a binary carrying the app manifest. Keeping them out of the library lets
/// `cargo test --lib` run without that manifest.
pub fn builder() -> tauri::Builder<tauri::Wry> {
    tauri::Builder::default()
        .manage(VaultState::default())
        .setup(|app| {
            setup_tray(app)?;
            let handle = app.handle().clone();
            os::session::watch_session(move |reason| auto_lock(&handle, reason));
            let handle = app.handle().clone();
            let idle_handle = app.handle().clone();
            os::session::watch_idle(
                move || {
                    idle_handle
                        .state::<VaultState>()
                        .with(|u| u.vault.data().settings.auto_lock_idle_minutes)
                        .unwrap_or(0)
                },
                move || auto_lock(&handle, os::session::LockReason::Idle),
            );
            Ok(())
        })
        // Spec §1: tray persistence. Closing the window hides it; the idle /
        // session auto-lock keeps an unattended vault from staying open.
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == "main" {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            app_info,
            vault_status,
            inspect_keyfile,
            create_vault,
            unlock,
            lock,
            list_items,
            get_item,
            create_item,
            update_item,
            delete_item,
            set_favorite,
            copy_field,
            reveal_password,
            totp_code,
            generate_password,
            export_backup,
            inspect_backup,
            preview_import,
            apply_import
        ])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Production default is too slow for many test cases; this still meets policy.
    const POLICY_MIN: KdfParams = KdfParams {
        mem_kib: KdfParams::POLICY_MIN_MEM_KIB,
        iterations: KdfParams::POLICY_MIN_ITERATIONS,
        parallelism: 1,
    };

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

    #[test]
    fn create_then_unlock_with_generated_keyfile() {
        let dir = tempfile::tempdir().unwrap();
        let vault_file = dir.path().join("vault.shush");
        let key = dir.path().join("usb").join("vault.key");
        std::fs::create_dir_all(key.parent().unwrap()).unwrap();
        let choice = KeyfileChoice::Generate {
            path: key.display().to_string(),
        };

        let v = create_vault_blocking(&vault_file, b"correct horse", &choice, 0x02, POLICY_MIN)
            .unwrap();
        assert_eq!(v.header().suite, CipherSuite::XChaCha20Poly1305);
        assert_eq!(std::fs::metadata(&key).unwrap().len(), 32);

        let status = status_for(&vault_file, false);
        assert!(status.exists);
        assert_eq!(status.keyfile_required, Some(true));
        assert!(status.error.is_none());

        let k = key.to_str();
        assert!(unlock_blocking(&vault_file, b"correct horse", k).is_ok());
        assert_eq!(
            unlock_blocking(&vault_file, b"correct horse", None)
                .unwrap_err()
                .code,
            "KEYFILE_REQUIRED"
        );
        assert_eq!(
            unlock_blocking(&vault_file, b"wrong horse", k)
                .unwrap_err()
                .code,
            "WRONG_CREDENTIALS"
        );
    }

    #[test]
    fn create_validations() {
        let dir = tempfile::tempdir().unwrap();
        let vault_file = dir.path().join("vault.shush");
        let none = KeyfileChoice::None;

        assert_eq!(
            create_vault_blocking(&vault_file, b"short", &none, 1, POLICY_MIN)
                .unwrap_err()
                .code,
            "WEAK_PASSWORD"
        );
        assert_eq!(
            create_vault_blocking(&vault_file, b"long enough", &none, 9, POLICY_MIN)
                .unwrap_err()
                .code,
            "VAULT_UNREADABLE"
        );
        let weak_kdf = KdfParams {
            mem_kib: 1024,
            iterations: 1,
            parallelism: 1,
        };
        assert_eq!(
            create_vault_blocking(&vault_file, b"long enough", &none, 1, weak_kdf)
                .unwrap_err()
                .code,
            "WEAK_KDF"
        );
        assert!(!vault_file.exists());

        create_vault_blocking(&vault_file, b"long enough", &none, 1, POLICY_MIN).unwrap();
        assert_eq!(
            create_vault_blocking(&vault_file, b"long enough", &none, 1, POLICY_MIN)
                .unwrap_err()
                .code,
            "VAULT_EXISTS"
        );
    }

    #[test]
    fn generated_keyfile_is_removed_if_vault_creation_fails() {
        let dir = tempfile::tempdir().unwrap();
        let vault_file = dir.path().join("vault.shush");
        std::fs::write(&vault_file, b"existing").unwrap(); // forces VAULT_EXISTS
        let key = dir.path().join("new.key");
        let choice = KeyfileChoice::Generate {
            path: key.display().to_string(),
        };
        assert!(
            create_vault_blocking(&vault_file, b"long enough", &choice, 1, POLICY_MIN).is_err()
        );
        assert!(!key.exists());
    }

    #[test]
    fn unreadable_vault_reports_error_in_status() {
        let dir = tempfile::tempdir().unwrap();
        let vault_file = dir.path().join("vault.shush");
        std::fs::write(
            &vault_file,
            b"definitely not a vault, just text of some length",
        )
        .unwrap();
        let status = status_for(&vault_file, false);
        assert!(status.exists);
        assert_eq!(status.error.unwrap().code, "VAULT_UNREADABLE");
        assert_eq!(
            unlock_blocking(&vault_file, b"pw", None).unwrap_err().code,
            "VAULT_UNREADABLE"
        );
    }

    #[test]
    fn tampered_vault_reports_integrity_failure() {
        let dir = tempfile::tempdir().unwrap();
        let vault_file = dir.path().join("vault.shush");
        create_vault_blocking(
            &vault_file,
            b"long enough",
            &KeyfileChoice::None,
            1,
            POLICY_MIN,
        )
        .unwrap();
        let mut bytes = std::fs::read(&vault_file).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        std::fs::write(&vault_file, &bytes).unwrap();
        assert_eq!(
            unlock_blocking(&vault_file, b"long enough", None)
                .unwrap_err()
                .code,
            "VAULT_TAMPERED"
        );
    }
}
