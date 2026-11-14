//! shush — offline-first, zero-knowledge password manager core.
//!
//! - [`crypto`]: Argon2id KDF, keyfiles, AEAD envelope (Phase 1).
//! - [`vault`]: `vault.shush` container, data model, in-memory state (Phase 3).
//!
//! OS integration, sync and TOTP modules land in later phases (spec §12).

#![deny(unsafe_code)] // OS modules opt in locally with a SAFETY comment.
#![warn(missing_docs)]

pub mod bridge;
pub mod crypto;
pub mod net;
pub mod os;
pub mod totp;
pub mod update;
pub mod vault;

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tauri::{Emitter, Manager};
use zeroize::Zeroizing;

use crypto::{CipherSuite, CryptoError, KdfParams, KeyfileDigest};
use vault::container::Header;
use vault::items::{ItemDetail, ItemDraft, ItemError, ItemKind, ItemSummary, SecretField};
use vault::registry::{DeleteThrottle, Registry, RegistryError, VaultEntry, VAULT_COLORS};
use vault::state::{Unlocked, VaultState};
use vault::{CreateOptions, OpenVault, VaultData, VaultError};

/// File name of the primary vault inside the app data directory.
const VAULT_FILE_NAME: &str = "vault.shush";
/// Global hotkey for the Spotlight overlay (owner decision on #14: avoids the
/// Windows `Alt+Shift` input-language switch).
pub const SPOTLIGHT_HOTKEY: &str = "Ctrl+Alt+Space";
/// Whether the hotkey was registered (another app may already own it).
static HOTKEY_REGISTERED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// Event sent to the Spotlight window each time it opens.
const EVENT_SPOTLIGHT_OPEN: &str = "spotlight-open";
/// Event broadcast when a secret is copied (drives the status-bar countdown).
const EVENT_CLIPBOARD: &str = "clipboard-copied";

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
            V::InUse => Self::new(
                "VAULT_IN_USE",
                "This vault is open in another shush window or program. Close it there first.",
            ),
            V::ChangedOnDisk => Self::new(
                "VAULT_CHANGED_ON_DISK",
                "The vault file was changed by another program since you unlocked it. Your change was not saved. Reload to load the current version from disk.",
            ),
            V::PasswordRequired => Self::new(
                "PASSWORD_REQUIRED",
                "The vault credentials or parameters changed on disk. Enter your password to reload.",
            ),
            V::DuressWithAttachments => Self::new(
                "DURESS_WITH_ATTACHMENTS",
                "Remove every attachment before setting a duress password: attachment files                  beside the vault would give the decoy away.",
            ),
            V::AttachmentsDisabled => Self::new(
                "ATTACHMENTS_DISABLED",
                "Attachments are turned off while a duress password is set.",
            ),
            V::DuressSameAsMaster => Self::new(
                "DURESS_SAME_AS_MASTER",
                "The duress password must be different from the master password.",
            ),
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
    /// The Spotlight hotkey, or `None` if it could not be registered.
    spotlight_hotkey: Option<&'static str>,
}

#[tauri::command]
fn app_info() -> AppInfo {
    AppInfo {
        version: env!("CARGO_PKG_VERSION"),
        default_cipher: cipher_info(CipherSuite::default()),
        supported_ciphers: CipherSuite::ALL.into_iter().map(cipher_info).collect(),
        default_kdf: KdfParams::default(),
        min_password_chars: MIN_PASSWORD_CHARS,
        spotlight_hotkey: HOTKEY_REGISTERED
            .load(std::sync::atomic::Ordering::Relaxed)
            .then_some(SPOTLIGHT_HOTKEY),
    }
}

/// The registry folder and the default vault path.
fn vault_home(app: &tauri::AppHandle) -> Result<(PathBuf, PathBuf), CmdError> {
    // Debug builds only: point the app at a scratch vault (and keep the vault
    // list next to it) for testing without touching the real one. Compiled
    // out of release builds.
    #[cfg(debug_assertions)]
    if let Some(p) = std::env::var_os("SHUSH_VAULT_PATH") {
        let p = PathBuf::from(p);
        let dir = p.parent().map(Path::to_path_buf).unwrap_or_default();
        return Ok((dir, p));
    }
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| CmdError::new("APP_DATA_UNAVAILABLE", e.to_string()))?;
    let def = dir.join(VAULT_FILE_NAME);
    Ok((dir, def))
}

impl From<RegistryError> for CmdError {
    fn from(e: RegistryError) -> Self {
        let code = match e {
            RegistryError::BadName => "BAD_VAULT_NAME",
            RegistryError::DuplicateName => "DUPLICATE_VAULT_NAME",
            RegistryError::BadColor => "BAD_VAULT_COLOR",
            RegistryError::AlreadyListed => "VAULT_ALREADY_LISTED",
            RegistryError::UnknownVault => "UNKNOWN_VAULT",
            RegistryError::NoSuchFolder => "NO_SUCH_FOLDER",
            RegistryError::LocationTaken => "LOCATION_TAKEN",
            RegistryError::NotAbsolute => "BAD_LOCATION",
            RegistryError::DefaultPinned => "DEFAULT_VAULT_PINNED",
            RegistryError::Io(_) => "REGISTRY_IO",
        };
        Self::new(code, e.to_string())
    }
}

/// Serialises every read-modify-write of `vaults.json`.
static REGISTRY_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Loads the vault list, applies `f`, and saves it if `f` succeeded.
fn edit_registry<R>(
    app: &tauri::AppHandle,
    f: impl FnOnce(&mut Registry, &Path) -> Result<R, CmdError>,
) -> Result<R, CmdError> {
    let (dir, def) = vault_home(app)?;
    let _g = REGISTRY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut reg = Registry::load_persisted(&dir, &def)?;
    let before = reg.clone();
    let out = f(&mut reg, &def)?;
    if reg != before {
        reg.save(&dir)?;
    }
    Ok(out)
}

/// The vault the unlock / create screens act on: the selected entry, or the
/// default location on first run.
fn selected_vault(app: &tauri::AppHandle) -> Result<(Option<VaultEntry>, PathBuf), CmdError> {
    edit_registry(app, |reg, def| {
        Ok(match reg.selected_entry() {
            Some(e) => (Some(e.clone()), e.path.clone()),
            None => (None, def.to_path_buf()),
        })
    })
}

/// Refuses vault-list changes that would pull the rug from an open vault.
fn require_locked(app: &tauri::AppHandle) -> Result<(), CmdError> {
    if app.state::<VaultState>().is_unlocked() {
        return Err(CmdError::new(
            "VAULT_UNLOCKED",
            "Lock the open vault first.",
        ));
    }
    Ok(())
}

/// What the unlock/create screens need to know before any credentials.
#[derive(Debug, Serialize)]
struct VaultStatus {
    /// Registry id; `None` on first run before any vault exists.
    id: Option<String>,
    name: Option<String>,
    color: String,
    path: String,
    exists: bool,
    unlocked: bool,
    read_only: bool,
    /// From the (authenticated) header; `None` if there is no readable vault.
    keyfile_required: Option<bool>,
    cipher: Option<CipherInfo>,
    kdf: Option<KdfParams>,
    /// Set when a file exists but its header is unreadable.
    error: Option<CmdError>,
    /// Whether vault names and paths are hidden on the lock screen.
    hide_names: bool,
    /// Whether the vault can be deleted (header or .bak decrypts).
    can_delete: bool,
    /// Probable cloud-sync conflicted copies next to the vault (issue #80).
    conflicted_copies: Vec<String>,
    /// A stale `.tmp` from an interrupted save (name), while the vault is intact.
    stale_tmp: Option<String>,
}

fn status_for(
    entry: Option<&VaultEntry>,
    path: &Path,
    unlocked: bool,
    read_only: bool,
    hide_names: bool,
) -> VaultStatus {
    let exists = path.is_file();
    let file_ro = std::fs::metadata(path)
        .map(|m| m.permissions().readonly())
        .unwrap_or(false);
    let mut status = VaultStatus {
        id: entry.map(|e| e.id.clone()),
        name: entry.map(|e| e.name.clone()),
        color: entry
            .map_or(VAULT_COLORS[0], |e| e.color.as_str())
            .to_string(),
        path: path.display().to_string(),
        exists,
        unlocked,
        read_only: if unlocked { read_only } else { file_ro },
        keyfile_required: None,
        cipher: None,
        kdf: None,
        error: None,
        hide_names,
        can_delete: false,
        conflicted_copies: Vec::new(),
        stale_tmp: None,
    };
    if entry.is_some() && !status.exists {
        status.error = Some(CmdError::new(
            "VAULT_MISSING",
            "The vault file is not there. Was it moved, or is its drive disconnected? If it was removed, use Edit to remove it from this list.",
        ));
    }
    if status.exists {
        match vault::read_header(path) {
            Ok(h) => {
                status.keyfile_required = Some(h.keyfile_required);
                status.cipher = Some(cipher_info(h.suite));
                status.kdf = Some(h.kdf);
                status.can_delete = true;
            }
            Err(e) => {
                let bak = vault::container::sibling(path, "bak");
                if bak.is_file() {
                    if let Ok(bh) = vault::read_header(&bak) {
                        status.keyfile_required = Some(bh.keyfile_required);
                        status.cipher = Some(cipher_info(bh.suite));
                        status.kdf = Some(bh.kdf);
                        status.can_delete = true;
                        status.error = Some(CmdError::new(
                            "VAULT_UNREADABLE",
                            "Vault header is unreadable, but its backup (.bak) is intact. You can delete this vault using its master password.",
                        ));
                    }
                }
                if status.error.is_none() {
                    status.error = Some(e.into());
                }
            }
        }
    }
    status
}

#[tauri::command]
fn vault_status(app: tauri::AppHandle) -> Result<VaultStatus, CmdError> {
    let state = app.state::<VaultState>();
    let unlocked = state.is_unlocked();
    let read_only = state.with(|u| u.read_only).unwrap_or(false);
    let (entry, path, hide_names, known) = edit_registry(&app, |reg, def| {
        let known: Vec<PathBuf> = reg.vaults.iter().map(|v| v.path.clone()).collect();
        Ok(match reg.selected_entry() {
            Some(e) => (Some(e.clone()), e.path.clone(), reg.hide_names, known),
            None => (None, def.to_path_buf(), reg.hide_names, known),
        })
    })?;
    let mut status = status_for(entry.as_ref(), &path, unlocked, read_only, hide_names);
    if !unlocked {
        let found = vault::siblings::scan(&path, &known);
        status.conflicted_copies = found.conflicted_copies;
        status.stale_tmp = found.stale_tmp;
    }
    Ok(status)
}

/// Deletes a conflicted copy or stale `.tmp` that `vault_status` reported next
/// to the selected vault. Any other name is refused (issue #80).
#[tauri::command]
fn discard_vault_sibling(app: tauri::AppHandle, file: String) -> Result<(), CmdError> {
    let (path, known) = edit_registry(&app, |reg, def| {
        let known: Vec<PathBuf> = reg.vaults.iter().map(|v| v.path.clone()).collect();
        let path = reg
            .selected_entry()
            .map_or_else(|| def.to_path_buf(), |e| e.path.clone());
        Ok((path, known))
    })?;
    match vault::siblings::discard(&path, &known, &file) {
        Ok(true) => Ok(()),
        Ok(false) => Err(CmdError::new(
            "SIBLING_NOT_FOUND",
            "That file is no longer next to the vault.",
        )),
        Err(e) => Err(CmdError::new(
            "SIBLING_REMOVE_FAILED",
            format!("Could not remove the file: {e}"),
        )),
    }
}

// ---- Vault list: switch, add, create elsewhere, delete ----------------------

/// One vault on the unlock screen's shelf. No secrets, no item data.
#[derive(Debug, Serialize)]
struct VaultCard {
    id: String,
    name: String,
    path: String,
    color: String,
    /// The vault in the app data folder (created on first run).
    is_default: bool,
    selected: bool,
    exists: bool,
    keyfile_required: Option<bool>,
    /// Set when the file is missing or unreadable.
    error: Option<CmdError>,
    /// Whether the vault can be deleted (header or .bak decrypts).
    can_delete: bool,
}

#[derive(Debug, Serialize)]
struct VaultList {
    vaults: Vec<VaultCard>,
    colors: Vec<&'static str>,
    max_name_chars: usize,
    hide_names: bool,
}

#[tauri::command]
fn list_vaults(app: tauri::AppHandle) -> Result<VaultList, CmdError> {
    let (reg, def) = edit_registry(&app, |reg, def| Ok((reg.clone(), def.to_path_buf())))?;
    let hide_names = reg.hide_names;
    let vaults = reg
        .vaults
        .iter()
        .map(|e| {
            let s = status_for(Some(e), &e.path, false, false, hide_names);
            VaultCard {
                id: e.id.clone(),
                name: e.name.clone(),
                path: s.path,
                color: e.color.clone(),
                is_default: vault::registry::same_file(&e.path, &def),
                selected: reg.selected.as_deref() == Some(e.id.as_str()),
                exists: s.exists,
                keyfile_required: s.keyfile_required,
                error: s.error,
                can_delete: s.can_delete,
            }
        })
        .collect();
    Ok(VaultList {
        vaults,
        colors: VAULT_COLORS.to_vec(),
        max_name_chars: vault::registry::MAX_NAME_CHARS,
        hide_names,
    })
}

/// Switches the unlock screen to another vault.
#[tauri::command]
fn select_vault(app: tauri::AppHandle, id: String) -> Result<VaultStatus, CmdError> {
    require_locked(&app)?;
    let (entry, hide_names) = edit_registry(&app, |reg, _| {
        reg.select(&id)?;
        Ok((
            reg.get(&id).cloned().expect("just selected"),
            reg.hide_names,
        ))
    })?;
    Ok(status_for(
        Some(&entry),
        &entry.path,
        false,
        false,
        hide_names,
    ))
}

/// Validates a location and name for a new vault before the user sets a
/// password. Returns the final path (`.shush` added when missing).
#[tauri::command]
fn check_new_vault(app: tauri::AppHandle, path: String, name: String) -> Result<String, CmdError> {
    edit_registry(&app, |reg, _| {
        let (p, _) = reg.check_new(Path::new(&path), &name)?;
        Ok(p.display().to_string())
    })
}

/// Adds an existing `.shush` file (another folder, a USB drive) to the list
/// and selects it. Only a readable vault header is accepted.
#[tauri::command]
async fn add_existing_vault(
    app: tauri::AppHandle,
    path: String,
    name: String,
    color: Option<String>,
) -> Result<VaultStatus, CmdError> {
    require_locked(&app)?;
    blocking(move || {
        let p = PathBuf::from(&path);
        vault::read_header(&p)?;
        let (entry, hide_names) = edit_registry(&app, |reg, def| {
            if def.is_file() && vault::registry::same_file(&p, def) {
                reg.hide_default = false;
            }
            let entry = reg.add(p.clone(), &name, color.as_deref())?;
            Ok((entry, reg.hide_names))
        })?;
        Ok(status_for(
            Some(&entry),
            &entry.path,
            false,
            false,
            hide_names,
        ))
    })
    .await
}

/// Renames or recolours a vault. Only the list changes; the file does not.
#[tauri::command]
fn update_vault(
    app: tauri::AppHandle,
    id: String,
    name: String,
    color: String,
) -> Result<(), CmdError> {
    edit_registry(&app, |reg, _| Ok(reg.update(&id, &name, &color)?))
}

/// Removes a vault from the list without touching its file.
#[tauri::command]
fn forget_vault(app: tauri::AppHandle, id: String) -> Result<(), CmdError> {
    require_locked(&app)?;
    edit_registry(&app, |reg, def| {
        let e = reg.get(&id).ok_or(RegistryError::UnknownVault)?;
        let is_default = def.is_file() && vault::registry::same_file(&e.path, def);
        if is_default {
            if !reg.has_other_reachable_vault(def) {
                return Err(RegistryError::DefaultPinned.into());
            }
            reg.hide_default = true;
        }
        reg.remove(&id)?;
        reg.ensure_safety_net(def);
        Ok(())
    })?;
    app.state::<std::sync::Mutex<DeleteThrottle>>()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .succeed(&id);
    Ok(())
}

/// Toggles or sets whether vault names and paths are hidden on the lock screen.
#[tauri::command]
fn set_hide_vault_names(app: tauri::AppHandle, hide: bool) -> Result<VaultStatus, CmdError> {
    require_locked(&app)?;
    let (entry, path) = edit_registry(&app, |reg, def| {
        reg.hide_names = hide;
        let (entry, path) = match reg.selected_entry() {
            Some(e) => (Some(e.clone()), e.path.clone()),
            None => (None, def.to_path_buf()),
        };
        Ok((entry, path))
    })?;
    Ok(status_for(entry.as_ref(), &path, false, false, hide))
}

/// Deletes a vault: its file, backup generation, temp file and attachments
/// go to the Recycle Bin. Guarded against accidents and pranks:
///
/// - only while every vault is locked;
/// - the vault's name must be typed exactly;
/// - the master password (and keyfile, if the vault uses one) must actually
///   decrypt the vault: a full Argon2id unlock, not a header check;
/// - wrong passwords are throttled with a doubling wait;
/// - only the vault's own known files are touched, and only after the file
///   has been verified as a shush vault;
/// - nothing is destroyed outright: Windows asks first if the drive has no
///   Recycle Bin.
fn authenticate_for_delete_blocking(
    path: &Path,
    password: &[u8],
    keyfile_path: Option<&str>,
) -> Result<(), CmdError> {
    let bak = vault::container::sibling(path, "bak");
    let auth_path = if vault::read_header(path).is_ok() {
        path.to_path_buf()
    } else if bak.is_file() && vault::read_header(&bak).is_ok() {
        bak
    } else {
        vault::read_header(path)?;
        unreachable!()
    };
    let v = unlock_blocking(&auth_path, password, keyfile_path)?;
    drop(v);
    Ok(())
}

fn delete_vault_files_blocking(path: &Path) -> Result<(), CmdError> {
    let files: Vec<PathBuf> = vault::registry::vault_files(path)
        .into_iter()
        .filter(|p| p.exists())
        .collect();
    let refs: Vec<&Path> = files.iter().map(PathBuf::as_path).collect();
    os::recycle::recycle(&refs).map_err(|e| match e {
        os::recycle::RecycleError::Cancelled => {
            CmdError::new("DELETE_CANCELLED", "Deletion cancelled. The vault was kept.")
        }
        os::recycle::RecycleError::Failed(code) => CmdError::new(
            "DELETE_FAILED",
            format!("Windows could not move the vault to the Recycle Bin (error {code}). Is a file open elsewhere?"),
        ),
    })
}

#[tauri::command]
async fn delete_vault(
    app: tauri::AppHandle,
    id: String,
    password: String,
    keyfile_path: Option<String>,
    confirm_name: String,
) -> Result<(), CmdError> {
    let password = Zeroizing::new(password);
    require_locked(&app)?;
    let entry = edit_registry(&app, |reg, _| {
        Ok(reg.get(&id).cloned().ok_or(RegistryError::UnknownVault)?)
    })?;
    if confirm_name.trim() != entry.name {
        return Err(CmdError::new(
            "CONFIRM_MISMATCH",
            "Type the vault's name exactly as shown to confirm.",
        ));
    }
    let (dir, _) = vault_home(&app)?;
    let throttle = app.state::<std::sync::Mutex<DeleteThrottle>>();
    let wait = {
        let mut t = throttle.lock().unwrap_or_else(|e| e.into_inner());
        t.set_dir_if_none(&dir);
        t.wait_secs(&id)
    };
    if let Some(s) = wait {
        return Err(wait_error(s));
    }

    blocking(move || {
        let path = entry.path.clone();
        let throttle = app.state::<std::sync::Mutex<DeleteThrottle>>();
        match authenticate_for_delete_blocking(&path, password.as_bytes(), keyfile_path.as_deref())
        {
            Ok(()) => {
                throttle
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .succeed(&id);
            }
            Err(e) if e.code == "WRONG_CREDENTIALS" => {
                let wait = throttle.lock().unwrap_or_else(|e| e.into_inner()).fail(&id);
                return Err(match wait {
                    Some(s) => CmdError::new(
                        "WRONG_CREDENTIALS",
                        format!(
                            "Wrong master password or keyfile. Try again in {}.",
                            human_secs(s)
                        ),
                    ),
                    None => e,
                });
            }
            Err(e) => return Err(e),
        }
        // Someone may have unlocked during the slow KDF.
        require_locked(&app)?;

        delete_vault_files_blocking(&path)?;
        edit_registry(&app, |reg, def| {
            reg.remove(&id)?;
            reg.ensure_safety_net(def);
            Ok(())
        })
    })
    .await
}

/// Opens Windows Explorer to reveal the vault file (or its containing folder).
#[tauri::command]
fn show_in_explorer(app: tauri::AppHandle, id: String) -> Result<(), CmdError> {
    let (reg, def) = edit_registry(&app, |reg, def| Ok((reg.clone(), def.to_path_buf())))?;
    let path = if let Some(e) = reg.get(&id) {
        e.path.clone()
    } else if def.exists() {
        def
    } else {
        return Err(RegistryError::UnknownVault.into());
    };

    reveal_path_in_explorer(&path)
}

fn reveal_path_in_explorer(path: &Path) -> Result<(), CmdError> {
    #[cfg(windows)]
    {
        use std::process::Command;
        if path.exists() {
            Command::new("explorer")
                .arg(format!("/select,{}", path.display()))
                .spawn()
                .map_err(|e| {
                    CmdError::new("EXPLORER_ERROR", format!("Could not open Explorer: {e}"))
                })?;
        } else if let Some(parent) = path.parent().filter(|p| p.exists()) {
            Command::new("explorer")
                .arg(parent.display().to_string())
                .spawn()
                .map_err(|e| {
                    CmdError::new("EXPLORER_ERROR", format!("Could not open Explorer: {e}"))
                })?;
        } else {
            return Err(CmdError::new(
                "PATH_NOT_FOUND",
                "Neither the vault file nor its folder could be found on disk.",
            ));
        }
    }
    #[cfg(not(windows))]
    {
        if !path.exists() && !path.parent().map_or(false, |p| p.exists()) {
            return Err(CmdError::new(
                "PATH_NOT_FOUND",
                "Neither the vault file nor its folder could be found on disk.",
            ));
        }
    }
    Ok(())
}

fn human_secs(s: u64) -> String {
    if s < 90 {
        format!("{s} seconds")
    } else {
        format!("{} minutes", s.div_ceil(60))
    }
}

fn wait_error(s: u64) -> CmdError {
    CmdError::new(
        "DELETE_COOLDOWN",
        format!("Too many wrong passwords. Try again in {}.", human_secs(s)),
    )
}

/// Non-secret facts about a candidate keyfile. The digest itself never
/// crosses the IPC boundary.
#[derive(Debug, Serialize)]
struct KeyfileInfo {
    file_name: String,
    size_bytes: u64,
    /// `true` for a shush-generated keyfile with a verified checksum; `false`
    /// for an arbitrary file, where any changed byte locks the vault.
    generated: bool,
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
    let kind = crypto::keyfile::inspect_file(path).map_err(keyfile_error)?;
    Ok(KeyfileInfo {
        generated: kind == crypto::keyfile::KeyfileKind::Generated,
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
        CryptoError::KeyfileCorrupt => CmdError::new(
            "KEYFILE_CORRUPT",
            "This keyfile is damaged (its checksum does not match). Use an intact copy of the keyfile.",
        ),
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
    read_only: bool,
}

fn summary(path: &Path, v: &OpenVault, read_only: bool) -> VaultSummary {
    let h: &Header = v.header();
    VaultSummary {
        path: path.display().to_string(),
        cipher: cipher_info(h.suite),
        kdf: h.kdf,
        keyfile_required: h.keyfile_required,
        item_count: v.data().items.len(),
        folder_count: v.data().folders.len(),
        read_only,
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

/// Where and under which name to create an additional vault.
#[derive(Debug, Clone, Deserialize)]
struct NewVaultTarget {
    path: String,
    name: String,
    color: Option<String>,
}

#[tauri::command]
async fn create_vault(
    app: tauri::AppHandle,
    password: String,
    keyfile: KeyfileChoice,
    cipher_id: u8,
    target: Option<NewVaultTarget>,
) -> Result<VaultSummary, CmdError> {
    // Move the IPC-owned string into a wiped buffer immediately (issue #6).
    let password = Zeroizing::new(password);
    require_locked(&app)?;
    // A chosen location is validated now; without one, this is the first-run
    // vault at the selected (default) location.
    let (path, name) = match &target {
        Some(t) => edit_registry(&app, |reg, _| {
            Ok(reg.check_new(Path::new(&t.path), &t.name)?)
        })?,
        None => {
            let (entry, path) = selected_vault(&app)?;
            (path, entry.map(|e| e.name).unwrap_or_default())
        }
    };
    let color = target.as_ref().and_then(|t| t.color.clone());
    blocking(move || {
        let state = app.state::<VaultState>();
        let ticket = state.begin_unlock();
        let lock = vault::lock::VaultLock::acquire(&path)?;
        let vault = create_vault_blocking(
            &path,
            password.as_bytes(),
            &keyfile,
            cipher_id,
            KdfParams::default(),
        )?;
        // List the new vault (first run: the default one) and select it.
        edit_registry(&app, |reg, def| {
            if let Some(e) = reg.find_path(&path) {
                let id = e.id.clone();
                reg.select(&id)?;
            } else {
                let is_default = vault::registry::same_file(&path, def);
                if is_default {
                    reg.hide_default = false;
                }
                let name = if name.is_empty() {
                    reg.unique_name("Personal")
                } else {
                    name
                };
                let color = color.as_deref().or(is_default.then_some(VAULT_COLORS[0]));
                reg.add(path.clone(), &name, color)?;
            }
            Ok(())
        })?;
        let s = summary(&path, &vault, false);
        state
            .finish_unlock(
                ticket,
                Unlocked {
                    path,
                    vault,
                    lock: Some(lock),
                    read_only: false,
                },
            )
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

struct ParsedUnlockRequest {
    password: os::memory::LockedBytes,
    keyfile_path: Option<String>,
    vault_id: Option<String>,
}

fn parse_unlock_request(body: &tauri::ipc::InvokeBody) -> Result<ParsedUnlockRequest, CmdError> {
    match body {
        tauri::ipc::InvokeBody::Raw(bytes) => {
            let slice = bytes.as_slice();
            if slice.is_empty() {
                return Err(CmdError::new("INVALID_INPUT", "Unlock payload is empty."));
            }
            let flags = slice[0];
            let mut off = 1;

            let vault_id = if (flags & 1) != 0 {
                if slice.len() < off + 2 {
                    return Err(CmdError::new(
                        "INVALID_INPUT",
                        "Truncated vault_id in unlock payload.",
                    ));
                }
                let len = u16::from_le_bytes([slice[off], slice[off + 1]]) as usize;
                off += 2;
                if slice.len() < off + len {
                    return Err(CmdError::new(
                        "INVALID_INPUT",
                        "Truncated vault_id string in unlock payload.",
                    ));
                }
                let s = std::str::from_utf8(&slice[off..off + len])
                    .map_err(|_| CmdError::new("INVALID_INPUT", "Invalid UTF-8 in vault_id."))?
                    .to_string();
                off += len;
                Some(s)
            } else {
                None
            };

            let keyfile_path = if (flags & 2) != 0 {
                if slice.len() < off + 2 {
                    return Err(CmdError::new(
                        "INVALID_INPUT",
                        "Truncated keyfile_path in unlock payload.",
                    ));
                }
                let len = u16::from_le_bytes([slice[off], slice[off + 1]]) as usize;
                off += 2;
                if slice.len() < off + len {
                    return Err(CmdError::new(
                        "INVALID_INPUT",
                        "Truncated keyfile_path string in unlock payload.",
                    ));
                }
                let s = std::str::from_utf8(&slice[off..off + len])
                    .map_err(|_| CmdError::new("INVALID_INPUT", "Invalid UTF-8 in keyfile_path."))?
                    .to_string();
                off += len;
                Some(s)
            } else {
                None
            };

            let pw_slice = &slice[off..];
            let password = os::memory::LockedBytes::from_slice(pw_slice);

            // Wiping Tauri's InvokeBody::Raw buffer immediately ensures no plaintext
            // master password remains in Tauri's intermediate heap (issue #59).
            os::memory::wipe_ipc_buffer(bytes);

            Ok(ParsedUnlockRequest {
                password,
                keyfile_path,
                vault_id,
            })
        }
        tauri::ipc::InvokeBody::Json(val) => {
            #[derive(serde::Deserialize)]
            struct JsonUnlock {
                password: String,
                keyfile_path: Option<String>,
                vault_id: Option<String>,
            }
            let parsed: JsonUnlock = serde_json::from_value(val.clone())
                .map_err(|e| CmdError::new("INVALID_INPUT", e.to_string()))?;
            let password = os::memory::LockedBytes::from_slice(parsed.password.as_bytes());
            Ok(ParsedUnlockRequest {
                password,
                keyfile_path: parsed.keyfile_path,
                vault_id: parsed.vault_id,
            })
        }
    }
}

#[tauri::command]
async fn unlock(
    app: tauri::AppHandle,
    request: tauri::ipc::Request<'_>,
) -> Result<VaultSummary, CmdError> {
    let parsed = parse_unlock_request(request.body())?;
    let password = parsed.password;
    let keyfile_path = parsed.keyfile_path;
    let vault_id = parsed.vault_id;

    // The UI names the vault it shows, so a switch in another window can
    // never make this unlock a different vault than the one on screen.
    let path = match vault_id {
        Some(id) => edit_registry(&app, |reg, _| {
            let p = reg
                .get(&id)
                .ok_or(RegistryError::UnknownVault)?
                .path
                .clone();
            reg.select(&id)?;
            Ok(p)
        })?,
        None => selected_vault(&app)?.1,
    };
    blocking(move || {
        let state = app.state::<VaultState>();
        let ticket = state.begin_unlock();
        // Taken before reading the file, so the snapshot we load cannot be
        // replaced by another process while we hold it (issue #9).
        // If the lock cannot be taken because the location or media is
        // read-only or access is denied (not a sharing violation), unlock in
        // read-only mode without a lock (issue #48).
        let (lock, read_only) = {
            let file_ro = std::fs::metadata(&path)
                .map(|m| m.permissions().readonly())
                .unwrap_or(false);
            if file_ro {
                (None, true)
            } else {
                match vault::lock::VaultLock::try_acquire(&path)? {
                    Some(lock) => (Some(lock), false),
                    None => (None, true),
                }
            }
        };
        let mut vault = unlock_blocking(&path, &password, keyfile_path.as_deref())?;
        // Re-seal a v3 vault so `.bak` and the file differ only in the slot
        // opened last (issue #8). Best effort: read-only media still unlock.
        if !read_only && vault.is_current_format() {
            let _ = vault.refresh(&path);
        }
        // Remove attachment blobs left behind by an interrupted add/delete.
        if !read_only {
            vault::attachments::gc_orphans(&path, vault.data());
        }
        let s = summary(&path, &vault, read_only);
        state
            .finish_unlock(
                ticket,
                Unlocked {
                    path,
                    vault,
                    lock,
                    read_only,
                },
            )
            .map_err(|_| {
                CmdError::new("LOCKED_DURING_UNLOCK", "Vault was locked while opening.")
            })?;
        Ok(s)
    })
    .await
}

/// Reloads the active vault from disk (issue #49).
///
/// Uses the existing derived keys in memory if salt and KDF are unchanged;
/// otherwise uses `password` if credentials changed on disk.
#[tauri::command]
async fn reload_vault(
    app: tauri::AppHandle,
    password: Option<String>,
    keyfile_path: Option<String>,
) -> Result<VaultSummary, CmdError> {
    blocking(move || {
        let password = password.map(Zeroizing::new);
        let digest = keyfile_path
            .as_deref()
            .map(|p| crypto::keyfile::digest_file(Path::new(p)).map_err(keyfile_error))
            .transpose()?;
        let s = app
            .state::<VaultState>()
            .with_mut(|u| {
                let pw_bytes = password.as_ref().map(|p| p.as_bytes());
                u.vault.reload(&u.path, pw_bytes, digest.as_ref())?;
                if !u.read_only {
                    vault::attachments::gc_orphans(&u.path, u.vault.data());
                }
                Ok(summary(&u.path, &u.vault, u.read_only))
            })
            .unwrap_or_else(|| Err(locked()))?;
        Ok(s)
    })
    .await
}

/// Whether the unlocked vault has a duress password (issue #8).
#[tauri::command]
fn duress_status(app: tauri::AppHandle) -> Result<bool, CmdError> {
    app.state::<VaultState>()
        .with(|u| u.vault.duress_enabled())
        .ok_or_else(locked)
}

/// Whether the unlocked vault file sits inside a known cloud-sync or backup
/// folder, whose version history could reveal that two slots change
/// independently (issue #68).
#[tauri::command]
fn vault_in_sync_folder(app: tauri::AppHandle) -> Result<bool, CmdError> {
    app.state::<VaultState>()
        .with(|u| path_in_sync_folder(&u.path))
        .ok_or_else(locked)
}

fn path_in_sync_folder(path: &Path) -> bool {
    const MARKERS: [&str; 9] = [
        "onedrive",
        "dropbox",
        "google drive",
        "googledrive",
        "icloud",
        "box sync",
        "nextcloud",
        "pcloud",
        "sync.com",
    ];
    path.components().any(|c| {
        let c = c.as_os_str().to_string_lossy().to_lowercase();
        MARKERS.iter().any(|m| c.contains(m))
    })
}

/// Seals an empty decoy vault into the other slot under `password` (and the
/// vault's keyfile, if it has one), replacing any previous decoy. The vault's
/// own current password must be re-entered first: a decoy cannot tell it is
/// one, so this must not be a one-click way to destroy the real vault.
#[tauri::command]
async fn set_duress_password(
    app: tauri::AppHandle,
    current_password: String,
    password: String,
    keyfile_path: Option<String>,
) -> Result<(), CmdError> {
    let password = Zeroizing::new(password);
    let current_password = Zeroizing::new(current_password);
    blocking(move || {
        let normalized =
            crypto::kdf::normalize_password(password.as_bytes()).map_err(VaultError::from)?;
        if normalized.chars().count() < MIN_PASSWORD_CHARS {
            return Err(CmdError::new(
                "WEAK_PASSWORD",
                format!("Use a duress password of at least {MIN_PASSWORD_CHARS} characters."),
            ));
        }
        let digest = keyfile_path
            .map(|p| crypto::keyfile::digest_file(Path::new(&p)).map_err(keyfile_error))
            .transpose()?;
        app.state::<VaultState>()
            .with_mut(|u| {
                if u.read_only {
                    return Err(read_only_err());
                }
                let path = u.path.clone();
                Ok(u.vault.set_duress(
                    &path,
                    current_password.as_bytes(),
                    password.as_bytes(),
                    digest.as_ref(),
                )?)
            })
            .unwrap_or_else(|| Err(locked()))
    })
    .await
}

/// Destroys the decoy vault (its slot becomes random bytes again).
#[tauri::command]
async fn clear_duress_password(app: tauri::AppHandle) -> Result<(), CmdError> {
    blocking(move || {
        app.state::<VaultState>()
            .with_mut(|u| {
                if u.read_only {
                    return Err(read_only_err());
                }
                let path = u.path.clone();
                Ok(u.vault.clear_duress(&path)?)
            })
            .unwrap_or_else(|| Err(locked()))
    })
    .await
}

/// Locks the vault and everything derived from it: the bridge drops its
/// pairing keys and wipes queued plaintext passwords (issue #52).
fn lock_vault(app: &tauri::AppHandle) {
    app.state::<VaultState>().lock();
    app.state::<bridge::state::BridgeState>()
        .bridge()
        .on_vault_locked();
}

#[tauri::command]
fn lock(app: tauri::AppHandle) {
    lock_vault(&app);
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
        lock_vault(app);
        os::clipboard::clear_if_ours();
        let _ = app.emit(EVENT_AUTO_LOCKED, reason);
    }
}

#[derive(Debug, Clone, Serialize)]
struct SpotlightOpen {
    /// Cleaned title of the window that was active when the hotkey was pressed.
    context: Option<String>,
}

/// Hotkey handler: show Spotlight (pre-selecting by window context) or hide it.
fn toggle_spotlight(app: &tauri::AppHandle) {
    let Some(w) = app.get_webview_window("spotlight") else {
        return;
    };
    if w.is_visible().unwrap_or(false) {
        let _ = w.hide();
        return;
    }
    // Read the context *before* Spotlight takes focus.
    let context = os::win_context::foreground_title();
    let _ = w.emit(EVENT_SPOTLIGHT_OPEN, SpotlightOpen { context });
    let _ = w.center();
    let _ = w.show();
    let _ = w.set_focus();
}

/// Opens Spotlight from the main window's "Quick search" button.
#[tauri::command]
fn show_spotlight(app: tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("spotlight") {
        if !w.is_visible().unwrap_or(false) {
            toggle_spotlight(&app);
        }
    }
}

#[tauri::command]
fn hide_spotlight(app: tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("spotlight") {
        let _ = w.hide();
    }
}

/// From Spotlight: open the main window (e.g. to unlock).
#[tauri::command]
fn open_main_window(app: tauri::AppHandle) {
    hide_spotlight(app.clone());
    show_main_window(&app);
}

/// Shows, un-minimizes and focuses the main window (tray click, second launch).
pub fn show_main_window(app: &tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

/// True for URLs that serve shush's own bundled frontend (issue #20). Release
/// builds load from Tauri's custom protocol (`http://tauri.localhost` on
/// Windows, `tauri://localhost` elsewhere); debug builds also allow the Vite
/// dev server from `tauri.conf.json` (`devUrl`).
fn is_app_url(url: &tauri::Url) -> bool {
    match (url.scheme(), url.host_str()) {
        ("tauri", Some("localhost")) => true,
        ("http" | "https", Some("tauri.localhost")) => url.port().is_none(),
        ("http", Some("localhost")) if cfg!(debug_assertions) => url.port() == Some(1420),
        _ => false,
    }
}

/// The app identifier for debug builds. Keys on `com.shush.vault.debug`, and
/// when a scratch vault path is set, incorporates a normalized hash of that path
/// so independent test runs do not hand off to each other (issue #56).
pub fn debug_app_identifier(vault_path: Option<&Path>) -> String {
    match vault_path {
        Some(p) => {
            use std::hash::{Hash, Hasher};
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            p.to_string_lossy()
                .replace('\\', "/")
                .to_lowercase()
                .hash(&mut hasher);
            format!("com.shush.vault.debug-{:016x}", hasher.finish())
        }
        None => "com.shush.vault.debug".to_string(),
    }
}

/// The WebView2 user data directory for the windows. In debug builds, avoids
/// clashing with an installed shush instance (issue #56).
fn webview_data_dir() -> Option<PathBuf> {
    #[cfg(debug_assertions)]
    {
        resolve_webview_data_dir(
            std::env::var_os("WEBVIEW2_USER_DATA_FOLDER"),
            std::env::var_os("SHUSH_VAULT_PATH"),
        )
    }
    #[cfg(not(debug_assertions))]
    {
        None
    }
}

/// Computes the debug WebView2 data directory from environment variables:
/// 1. An explicit `WEBVIEW2_USER_DATA_FOLDER` takes precedence.
/// 2. If `SHUSH_VAULT_PATH` is set, WebView2 uses a `webview2` scratch folder
///    alongside the scratch vault.
/// 3. Otherwise returns `None`, falling back to Tauri's local data directory
///    (which uses the debug identifier in debug builds).
fn resolve_webview_data_dir(
    wv_env: Option<std::ffi::OsString>,
    vault_env: Option<std::ffi::OsString>,
) -> Option<PathBuf> {
    if let Some(folder) = wv_env {
        return Some(PathBuf::from(folder));
    }
    if let Some(p) = vault_env {
        let p = PathBuf::from(p);
        let dir = p.parent().map(Path::to_path_buf).unwrap_or_default();
        return Some(dir.join("webview2"));
    }
    None
}

/// Builds the windows declared in `tauri.conf.json` (they have `create: false`)
/// with navigation locked to the app and every popup refused: injected script
/// can neither leave the bundle nor open a page that phishes from inside a
/// trusted shush window (issue #20).
fn create_windows(app: &tauri::App) -> tauri::Result<()> {
    let data_dir = webview_data_dir();
    for cfg in &app.config().app.windows {
        let mut builder = tauri::WebviewWindowBuilder::from_config(app.handle(), cfg)?
            .on_navigation(is_app_url)
            .on_new_window(|_url, _features| tauri::webview::NewWindowResponse::Deny);
        if let Some(ref dir) = data_dir {
            let _ = std::fs::create_dir_all(dir);
            builder = builder.data_directory(dir.clone());
        }
        builder.build()?;
    }
    Ok(())
}

fn setup_tray(app: &tauri::App) -> tauri::Result<()> {
    use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
    use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

    let open = MenuItem::with_id(app, "open", "Open shush", true, None::<&str>)?;
    let spotlight = MenuItem::with_id(
        app,
        "spotlight",
        format!("Quick search ({SPOTLIGHT_HOTKEY})"),
        true,
        None::<&str>,
    )?;
    let lock_item = MenuItem::with_id(app, "lock", "Lock vault", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit shush", true, None::<&str>)?;
    let menu = Menu::with_items(
        app,
        &[
            &open,
            &spotlight,
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
            "spotlight" => toggle_spotlight(app),
            "lock" => {
                lock_vault(app);
                os::clipboard::clear_if_ours();
                let _ = app.emit(EVENT_AUTO_LOCKED, "tray");
            }
            "quit" => {
                lock_vault(app);
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

fn read_only_err() -> CmdError {
    CmdError::new("READ_ONLY", "This vault is read-only.")
}

/// Transactional mutation: applied, saved crash-safely, then committed.
fn write<R>(
    app: &tauri::AppHandle,
    f: impl FnOnce(&mut VaultData) -> Result<R, CmdError>,
) -> Result<R, CmdError> {
    app.state::<VaultState>()
        .with_mut(|u| {
            if u.read_only {
                return Err(read_only_err());
            }
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
    blocking(move || {
        write(&app, |d| Ok(d.delete_item(&id)?))?;
        // The item's attachment blobs are now unreferenced.
        app.state::<VaultState>()
            .with(|u| vault::attachments::gc_orphans(&u.path, u.vault.data()));
        Ok(())
    })
    .await
}

/// Erases a login's password history (issue #19). Returns the updated item.
#[tauri::command]
async fn purge_history(app: tauri::AppHandle, id: String) -> Result<ItemDetail, CmdError> {
    blocking(move || {
        write(&app, |d| {
            d.purge_history(&id)?;
            Ok(d.detail(&id)?)
        })
    })
    .await
}

// ---- Attachments (roadmap Step 4c) ---------------------------------------------

fn guess_mime(path: &Path) -> &'static str {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    match ext.as_deref() {
        Some("pdf") => "application/pdf",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("txt" | "md") => "text/plain",
        Some("json") => "application/json",
        Some("pem" | "crt" | "cer" | "key") => "application/x-pem-file",
        Some("zip") => "application/zip",
        _ => "application/octet-stream",
    }
}

fn io_err(e: std::io::Error) -> CmdError {
    CmdError::new(
        "IO_ERROR",
        format!("Could not access the file ({}).", e.kind()),
    )
}

#[tauri::command]
async fn add_attachment(
    app: tauri::AppHandle,
    item_id: String,
    path: String,
) -> Result<ItemDetail, CmdError> {
    blocking(move || {
        let src = PathBuf::from(&path);
        let meta = std::fs::metadata(&src).map_err(io_err)?;
        if !meta.is_file() {
            return Err(CmdError::new(
                "INVALID_INPUT",
                "Choose a file, not a folder.",
            ));
        }
        if meta.len() > vault::attachments::MAX_ATTACHMENT_BYTES {
            return Err(CmdError::new(
                "TOO_LARGE",
                "Attachments are limited to 10 MB.",
            ));
        }
        let data = Zeroizing::new(std::fs::read(&src).map_err(io_err)?);
        let name = src
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| String::from("file"));
        app.state::<VaultState>()
            .with_mut(|u| {
                if u.read_only {
                    return Err(read_only_err());
                }
                let path = u.path.clone();
                u.vault
                    .add_attachment(&path, &item_id, &name, guess_mime(&src), &data)?;
                Ok(u.vault.data().detail(&item_id)?)
            })
            .unwrap_or_else(|| Err(locked()))
    })
    .await
}

/// Decrypts an attachment to a file the user chose (explicit export).
#[tauri::command]
async fn save_attachment(
    app: tauri::AppHandle,
    attachment_id: String,
    dest: String,
) -> Result<(), CmdError> {
    blocking(move || {
        let bytes = app
            .state::<VaultState>()
            .with(|u| u.vault.read_attachment(&u.path, &attachment_id))
            .unwrap_or(Err(VaultError::NotFound))?;
        std::fs::write(&dest, bytes.as_slice()).map_err(io_err)
    })
    .await
}

#[tauri::command]
async fn delete_attachment(
    app: tauri::AppHandle,
    item_id: String,
    attachment_id: String,
) -> Result<ItemDetail, CmdError> {
    blocking(move || {
        app.state::<VaultState>()
            .with_mut(|u| {
                if u.read_only {
                    return Err(read_only_err());
                }
                let path = u.path.clone();
                u.vault.delete_attachment(&path, &item_id, &attachment_id)?;
                Ok(u.vault.data().detail(&item_id)?)
            })
            .unwrap_or_else(|| Err(locked()))
    })
    .await
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
        let _ = app.emit(EVENT_CLIPBOARD, secs);
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
                BackupCredentialChoice::SameAsVault => {
                    // Backups are self-contained: attachment files are embedded.
                    let data = u.vault.data_with_embedded_attachments(&u.path)?;
                    Ok(export_to(&path, &u.vault, &data, BackupCredentials::SameAsVault)?)
                }
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
                    let data = u.vault.data_with_embedded_attachments(&u.path)?;
                    Ok(export_to(&path, &u.vault, &data, creds)?)
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
        let mut manifest = open_backup(&path, password.as_str(), keyfile_path.as_deref())?;
        app.state::<VaultState>()
            .with_mut(|u| {
                if u.read_only {
                    return Err(read_only_err());
                }
                let path = u.path.clone();
                // Embedded files become this vault's blobs first; unreferenced
                // ones (e.g. merge conflicts) are cleaned up afterwards.
                u.vault
                    .materialize_embedded(&path, &mut manifest.vault_data)?;
                let n = u.vault.modify(&path, |d| {
                    Ok::<_, CmdError>(vault::backup::apply(d, &manifest, mode))
                })?;
                vault::attachments::gc_orphans(&path, u.vault.data());
                Ok(n)
            })
            .unwrap_or_else(|| Err(locked()))
    })
    .await
}

// ---- Folders (roadmap Step 4b) -----------------------------------------------

#[derive(Debug, Serialize)]
struct FolderInfo {
    id: String,
    name: String,
    item_count: usize,
}

#[tauri::command]
fn list_folders(app: tauri::AppHandle) -> Result<Vec<FolderInfo>, CmdError> {
    read(&app, |d| {
        let summaries = d.summaries();
        Ok(d.folders
            .iter()
            .map(|f| FolderInfo {
                id: f.id.clone(),
                name: f.name.clone(),
                item_count: summaries
                    .iter()
                    .filter(|s| s.folder_id.as_deref() == Some(f.id.as_str()))
                    .count(),
            })
            .collect())
    })
}

#[tauri::command]
async fn create_folder(app: tauri::AppHandle, name: String) -> Result<String, CmdError> {
    blocking(move || write(&app, |d| Ok(d.create_folder(&name)?))).await
}

#[tauri::command]
async fn rename_folder(app: tauri::AppHandle, id: String, name: String) -> Result<(), CmdError> {
    blocking(move || write(&app, |d| Ok(d.rename_folder(&id, &name)?))).await
}

/// Deletes a folder; its items are kept. Returns how many were moved out.
#[tauri::command]
async fn delete_folder(app: tauri::AppHandle, id: String) -> Result<usize, CmdError> {
    blocking(move || write(&app, |d| Ok(d.delete_folder(&id)?))).await
}

// ---- First-run onboarding (roadmap Step 7a) ----------------------------------

/// Browsers installed for this user (profile folder exists; nothing is read).
#[tauri::command]
fn detect_browsers() -> Vec<os::browsers::Browser> {
    os::browsers::detect()
}

// ---- CSV migration (roadmap Step 6b) -----------------------------------------

impl From<vault::importer::ImportError> for CmdError {
    fn from(e: vault::importer::ImportError) -> Self {
        Self::new("CSV_IMPORT", e.to_string())
    }
}

#[tauri::command]
async fn preview_csv(
    app: tauri::AppHandle,
    path: String,
) -> Result<vault::importer::CsvSummary, CmdError> {
    blocking(move || {
        let bytes = vault::importer::read_csv(Path::new(&path))?;
        // Preview runs on a copy: nothing is changed or saved.
        read(&app, |d| {
            Ok(vault::importer::import(&mut d.clone(), &bytes, false)?)
        })
    })
    .await
}

#[tauri::command]
async fn import_csv(
    app: tauri::AppHandle,
    path: String,
) -> Result<vault::importer::CsvSummary, CmdError> {
    blocking(move || {
        let bytes = vault::importer::read_csv(Path::new(&path))?;
        write(&app, |d| Ok(vault::importer::import(d, &bytes, true)?))
    })
    .await
}

/// Best-effort overwrite + delete of the plaintext CSV after import (#17).
#[tauri::command]
async fn shred_csv(path: String) -> Result<(), CmdError> {
    blocking(move || Ok(vault::importer::shred_csv(Path::new(&path))?)).await
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

// ---- Browser bridge (issue #52) ---------------------------------------------

/// A paired browser, as listed in Settings. Never includes the key.
#[derive(Serialize)]
struct PairedBrowser {
    id: String,
}

/// A save the extension offered, waiting for approval. Never includes the password.
#[derive(Serialize)]
struct PendingSaveInfo {
    origin: String,
    username: String,
}

/// The pairing code on screen.
#[derive(Serialize)]
struct PairingCode {
    code: String,
    seconds_left: u64,
}

/// Everything the Settings -> Browser panel shows.
#[derive(Serialize)]
struct BridgeInfo {
    /// Whether the pipe listener is serving.
    serving: bool,
    /// Why not, in plain words (a squatted pipe name is the notable case).
    warning: Option<String>,
    pairings: Vec<PairedBrowser>,
    pending: Vec<PendingSaveInfo>,
    code: Option<PairingCode>,
}

fn serving_warning(s: bridge::state::Serving) -> (bool, Option<String>) {
    use bridge::state::Serving;
    match s {
        Serving::Yes => (true, None),
        Serving::Starting => (false, None),
        Serving::NameTaken => (
            false,
            Some(
                "Another program is using shush's browser pipe, so the browser extension is \
                 disabled. Close the other program and restart shush."
                    .into(),
            ),
        ),
        Serving::Failed(e) => (
            false,
            Some(format!("The browser bridge could not start: {e}")),
        ),
    }
}

/// Loads the unlocked vault's pairings into the bridge if that has not happened yet.
fn sync_pairings(app: &tauri::AppHandle, b: &mut bridge::protocol::Bridge) {
    app.state::<VaultState>().with(|u| {
        b.load_pairings(&u.vault.data().browser_pairings);
    });
}

/// Writes the bridge's pairings into the vault when they changed (revocation).
fn persist_pairings(app: &tauri::AppHandle) {
    let bridge = app.state::<bridge::state::BridgeState>();
    app.state::<VaultState>().with_mut(|u| {
        let mut b = bridge.bridge();
        if b.take_dirty() {
            persist_into(&mut b, u);
        }
    });
}

#[cfg(windows)]
fn persist_into(b: &mut bridge::protocol::Bridge, u: &mut vault::state::Unlocked) {
    bridge::server::persist(b, u);
}

#[cfg(not(windows))]
fn persist_into(_: &mut bridge::protocol::Bridge, _: &mut vault::state::Unlocked) {}

#[tauri::command]
fn bridge_state(app: tauri::AppHandle) -> Result<BridgeInfo, CmdError> {
    if !app.state::<VaultState>().is_unlocked() {
        return Err(locked());
    }
    let bridge = app.state::<bridge::state::BridgeState>();
    let (serving, warning) = serving_warning(bridge.serving());
    let mut b = bridge.bridge();
    sync_pairings(&app, &mut b);
    Ok(BridgeInfo {
        serving,
        warning,
        pairings: b
            .pairing_ids()
            .into_iter()
            .map(|id| PairedBrowser { id })
            .collect(),
        pending: b
            .pending_saves()
            .iter()
            .map(|p| PendingSaveInfo {
                origin: p.origin.clone(),
                username: p.username.clone(),
            })
            .collect(),
        code: b
            .live_offer(std::time::Instant::now())
            .map(|(code, seconds_left)| PairingCode { code, seconds_left }),
    })
}

#[tauri::command]
fn bridge_start_pairing(app: tauri::AppHandle) -> Result<PairingCode, CmdError> {
    let read_only = app
        .state::<VaultState>()
        .with(|u| u.read_only)
        .ok_or_else(locked)?;
    if read_only {
        return Err(CmdError::new(
            "READ_ONLY",
            "A read-only vault cannot remember paired browsers.",
        ));
    }
    let bridge = app.state::<bridge::state::BridgeState>();
    let mut b = bridge.bridge();
    sync_pairings(&app, &mut b);
    let now = std::time::Instant::now();
    let code = b
        .start_pairing(now)
        .map_err(|_| CmdError::new("INTERNAL", "Could not create a pairing code. Try again."))?;
    let seconds_left = b.live_offer(now).map_or(0, |(_, s)| s);
    Ok(PairingCode { code, seconds_left })
}

#[tauri::command]
fn bridge_cancel_pairing(app: tauri::AppHandle) {
    app.state::<bridge::state::BridgeState>()
        .bridge()
        .cancel_pairing();
}

#[tauri::command]
fn bridge_revoke(app: tauri::AppHandle, id: String) -> Result<(), CmdError> {
    if !app.state::<VaultState>().is_unlocked() {
        return Err(locked());
    }
    app.state::<bridge::state::BridgeState>()
        .bridge()
        .revoke(&id);
    persist_pairings(&app);
    Ok(())
}

#[tauri::command]
async fn bridge_approve_save(
    app: tauri::AppHandle,
    origin: String,
    username: String,
) -> Result<String, CmdError> {
    blocking(move || {
        let bridge = app.state::<bridge::state::BridgeState>();
        let pending = bridge
            .bridge()
            .take_pending_for(&origin, &username)
            .ok_or_else(|| CmdError::new("NOT_FOUND", "That save is no longer waiting."))?;
        // Through the normal transactional path; the bridge is not held across it.
        match write(&app, |d| Ok(bridge::protocol::apply_save(d, &pending)?)) {
            Ok(id) => Ok(id),
            Err(e) => {
                bridge.bridge().requeue(pending);
                Err(e)
            }
        }
    })
    .await
}

#[tauri::command]
fn bridge_reject_save(app: tauri::AppHandle, origin: String, username: String) {
    // Dropping the pending save wipes its password.
    let _ = app
        .state::<bridge::state::BridgeState>()
        .bridge()
        .take_pending_for(&origin, &username);
}

// ---- Browser support registration (issue #53) -------------------------------

/// Whether the native-messaging host is registered with the browsers.
#[derive(Serialize)]
struct BrowserSupport {
    /// All supported browsers are registered.
    enabled: bool,
    /// Names of the browsers currently registered.
    browsers: Vec<&'static str>,
    /// Whether `shush-host.exe` was found next to the app (it is what browsers launch).
    host_found: bool,
}

/// Registry root and manifest folder for the registration. Debug builds can
/// redirect the registry root (`SHUSH_NMH_REGISTRY_ROOT`) so tests never touch
/// the real browser keys.
#[cfg(windows)]
fn browser_support_paths(app: &tauri::AppHandle) -> Result<(String, PathBuf), CmdError> {
    let root = os::native_host::HKCU_SOFTWARE.to_string();
    #[cfg(debug_assertions)]
    let root = std::env::var("SHUSH_NMH_REGISTRY_ROOT").unwrap_or(root);
    let dir = vault_home(app)?.0.join("native-messaging");
    Ok((root, dir))
}

#[cfg(windows)]
fn browser_support_info(app: &tauri::AppHandle) -> Result<BrowserSupport, CmdError> {
    let (root, dir) = browser_support_paths(app)?;
    let on = os::native_host::is_registered(&root, &dir);
    Ok(BrowserSupport {
        enabled: on.len() == os::native_host::ALL.len(),
        browsers: on.iter().map(|b| b.name()).collect(),
        host_found: os::native_host::host_exe_beside_app().is_ok_and(|p| p.is_file()),
    })
}

#[cfg(not(windows))]
fn browser_support_info(_: &tauri::AppHandle) -> Result<BrowserSupport, CmdError> {
    Err(CmdError::new(
        "UNSUPPORTED",
        "Browser support is only available on Windows.",
    ))
}

#[tauri::command]
fn browser_support_status(app: tauri::AppHandle) -> Result<BrowserSupport, CmdError> {
    browser_support_info(&app)
}

/// Settings toggle: writes or removes the per-user (`HKCU`) host registration.
#[tauri::command]
fn set_browser_support(app: tauri::AppHandle, enabled: bool) -> Result<BrowserSupport, CmdError> {
    #[cfg(windows)]
    {
        let (root, dir) = browser_support_paths(&app)?;
        if enabled {
            let host = os::native_host::host_exe_beside_app()
                .ok()
                .filter(|p| p.is_file())
                .ok_or_else(|| {
                    CmdError::new(
                        "HOST_NOT_FOUND",
                        "shush-host.exe was not found next to shush. Reinstall shush.",
                    )
                })?;
            os::native_host::register(&root, &dir, &host).map_err(|e| {
                // Do not leave a half-written registration behind.
                let _ = os::native_host::unregister(&root, &dir);
                CmdError::new(
                    "REGISTRY_FAILED",
                    format!("Could not register the browser host: {e}"),
                )
            })?;
        } else {
            os::native_host::unregister(&root, &dir).map_err(|e| {
                CmdError::new(
                    "REGISTRY_FAILED",
                    format!("Could not remove the browser host: {e}"),
                )
            })?;
        }
    }
    #[cfg(not(windows))]
    let _ = enabled;
    browser_support_info(&app)
}

/// What Settings -> Network shows (issue #157).
#[derive(serde::Serialize)]
struct NetworkStatus {
    /// True while the network gate is closed (the default).
    air_gapped: bool,
    /// False in a build made without the `network` cargo feature.
    available: bool,
}

fn network_info(app: &tauri::AppHandle) -> NetworkStatus {
    NetworkStatus {
        air_gapped: app.state::<net::NetGate>().is_air_gapped(),
        available: net::NetGate::compiled_in(),
    }
}

#[tauri::command]
fn network_status(app: tauri::AppHandle) -> NetworkStatus {
    network_info(&app)
}

/// Settings toggle for air-gapped mode. Saved before it takes effect.
#[tauri::command]
fn set_air_gapped(app: tauri::AppHandle, enabled: bool) -> Result<NetworkStatus, CmdError> {
    // A build without network support is always air-gapped; never record a
    // "network on" choice there that a later network build would pick up.
    if !enabled && !net::NetGate::compiled_in() {
        return Err(CmdError::new(
            "NETWORK_NOT_COMPILED_IN",
            net::NetError::NotCompiledIn.to_string(),
        ));
    }
    let (dir, _) = vault_home(&app)?;
    app.state::<net::NetGate>()
        .save_and_set(&dir, enabled)
        .map_err(|e| {
            CmdError::new(
                "NETWORK_SETTING_FAILED",
                format!("Could not save the network setting: {e}"),
            )
        })?;
    Ok(network_info(&app))
}

/// What Settings -> Updates shows (issue #78, notify-only).
#[derive(serde::Serialize)]
struct UpdateInfo {
    /// The user's choice (`off` or `notify`).
    mode: update::client::UpdateMode,
    /// True while the network gate is closed: nothing is checked.
    air_gapped: bool,
    /// Last check result.
    status: update::client::UpdateStatus,
    /// Unix seconds of the last check, if any.
    checked_at: Option<i64>,
    /// Version of this build.
    installed: &'static str,
}

fn update_info(app: &tauri::AppHandle) -> UpdateInfo {
    let st = app.state::<update::client::UpdateState>();
    let (status, checked_at) = st.snapshot();
    UpdateInfo {
        mode: st.mode(),
        // Also true in a build without network support: no check can run there either.
        air_gapped: app.state::<net::NetGate>().check().is_err(),
        status,
        checked_at,
        installed: env!("CARGO_PKG_VERSION"),
    }
}

fn unix_now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// Runs one check through the network gate and records the result. Blocking; checks run one at
/// a time. Returns whether the check reached a verified answer (false: retry sooner).
fn run_update_check(app: &tauri::AppHandle) -> bool {
    let state = app.state::<update::client::UpdateState>();
    let _running = state.running.lock().unwrap_or_else(|e| e.into_inner());
    let gate = app.state::<net::NetGate>();
    let now = unix_now();
    let status = update::client::check(
        &update::client::GateFetch(&gate),
        &update::client::pinned_anchors(),
        env!("CARGO_PKG_VERSION"),
        now,
    );
    // The gate closed mid-check: keep the last real result rather than an air-gap error.
    if matches!(
        status,
        update::client::UpdateStatus::Failed {
            code: "UPDATE_AIR_GAPPED",
            ..
        }
    ) {
        return false;
    }
    let settled = !matches!(
        status,
        update::client::UpdateStatus::Failed {
            code: "UPDATE_FETCH_FAILED" | "UPDATE_FEED_MISMATCH",
            ..
        }
    );
    state.record(status, now);
    settled
}

/// Background checker: first check shortly after start, then every 24 h plus up to 2 h of
/// jitter; after a fetch failure (offline at boot, say) it retries in 1 h plus jitter instead.
/// Does nothing while air-gapped or when updates are off, and re-arms when that changes.
fn spawn_update_checker(app: tauri::AppHandle) {
    use rand::Rng;
    std::thread::spawn(move || {
        let mut due: Option<std::time::Instant> = None;
        loop {
            std::thread::sleep(std::time::Duration::from_secs(60));
            let eligible = app.state::<update::client::UpdateState>().mode()
                == update::client::UpdateMode::Notify
                && app.state::<net::NetGate>().check().is_ok();
            if !eligible {
                due = None;
                continue;
            }
            let now = std::time::Instant::now();
            match due {
                None => due = Some(now + std::time::Duration::from_secs(30)),
                Some(t) if now >= t => {
                    let base = if run_update_check(&app) {
                        24 * 60 * 60
                    } else {
                        60 * 60
                    };
                    let jitter = rand::thread_rng().gen_range(0..2 * 60 * 60);
                    due = Some(
                        std::time::Instant::now() + std::time::Duration::from_secs(base + jitter),
                    );
                }
                Some(_) => {}
            }
        }
    });
}

#[tauri::command]
fn update_status(app: tauri::AppHandle) -> UpdateInfo {
    update_info(&app)
}

/// Settings choice for update checks. Saved before it takes effect.
#[tauri::command]
fn set_update_mode(
    app: tauri::AppHandle,
    mode: update::client::UpdateMode,
) -> Result<UpdateInfo, CmdError> {
    let (dir, _) = vault_home(&app)?;
    mode.save(&dir).map_err(|e| {
        CmdError::new(
            "UPDATE_SETTING_FAILED",
            format!("Could not save the update setting: {e}"),
        )
    })?;
    *app.state::<update::client::UpdateState>()
        .mode
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = mode;
    Ok(update_info(&app))
}

/// "Check now": one gated check, run off the UI thread. Refused while updates are off.
#[tauri::command]
async fn check_for_update(app: tauri::AppHandle) -> Result<UpdateInfo, CmdError> {
    if app.state::<update::client::UpdateState>().mode() == update::client::UpdateMode::Off {
        return Err(CmdError::new(
            "UPDATE_OFF",
            "Update checks are off. Turn them on first.",
        ));
    }
    if let Err(e) = app.state::<net::NetGate>().check() {
        return Err(CmdError::new("UPDATE_AIR_GAPPED", e.to_string()));
    }
    let a = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        run_update_check(&a);
    })
    .await
    .map_err(|_| CmdError::new("UPDATE_CHECK_FAILED", "The update check did not finish."))?;
    Ok(update_info(&app))
}

/// Tauri builder with every shush command and the vault state registered.
///
/// GUI plugins (e.g. the native file dialog) are attached in `main.rs`, not
/// here: on Windows they import Common Controls v6 symbols that only resolve
/// in a binary carrying the app manifest. Keeping them out of the library lets
/// `cargo test --lib` run without that manifest.
pub fn builder() -> tauri::Builder<tauri::Wry> {
    use tauri_plugin_global_shortcut::{GlobalShortcutExt, ShortcutState};

    tauri::Builder::default()
        .manage(VaultState::default())
        .manage(bridge::state::BridgeState::default())
        .manage(net::NetGate::default())
        .manage(update::client::UpdateState::default())
        .manage(std::sync::Mutex::new(DeleteThrottle::default()))
        .plugin(
            tauri_plugin_global_shortcut::Builder::new()
                .with_handler(|app, _shortcut, event| {
                    if event.state == ShortcutState::Pressed {
                        toggle_spotlight(app);
                    }
                })
                .build(),
        )
        .setup(|app| {
            // Keep the unlocked vault out of crash reports (issue #6).
            os::memory::harden_process();
            create_windows(app)?;
            setup_tray(app)?;
            #[cfg(windows)]
            bridge::server::start(app.handle().clone());
            if let Ok((dir, _)) = vault_home(app.handle()) {
                *app.state::<std::sync::Mutex<DeleteThrottle>>()
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = DeleteThrottle::load(&dir);
                app.state::<net::NetGate>().load(&dir);
                *app.state::<update::client::UpdateState>()
                    .mode
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = update::client::UpdateMode::load(&dir);
            }
            spawn_update_checker(app.handle().clone());
            // Another application may own the combination; Spotlight then stays
            // reachable from the tray and app_info reports it (issue #14).
            let ok = app.global_shortcut().register(SPOTLIGHT_HOTKEY).is_ok();
            HOTKEY_REGISTERED.store(ok, std::sync::atomic::Ordering::Relaxed);
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
        .on_window_event(|window, event| match event {
            tauri::WindowEvent::CloseRequested { api, .. } => {
                api.prevent_close();
                let _ = window.hide();
            }
            // Spotlight is transient: clicking elsewhere dismisses it.
            tauri::WindowEvent::Focused(false) if window.label() == "spotlight" => {
                let _ = window.hide();
            }
            _ => {}
        })
        .invoke_handler(tauri::generate_handler![
            app_info,
            vault_status,
            discard_vault_sibling,
            list_vaults,
            select_vault,
            check_new_vault,
            add_existing_vault,
            update_vault,
            forget_vault,
            set_hide_vault_names,
            delete_vault,
            show_in_explorer,
            inspect_keyfile,
            create_vault,
            unlock,
            reload_vault,
            lock,
            list_items,
            get_item,
            create_item,
            update_item,
            delete_item,
            purge_history,
            set_favorite,
            copy_field,
            reveal_password,
            totp_code,
            generate_password,
            export_backup,
            inspect_backup,
            preview_import,
            apply_import,
            preview_csv,
            import_csv,
            shred_csv,
            detect_browsers,
            list_folders,
            create_folder,
            rename_folder,
            delete_folder,
            show_spotlight,
            hide_spotlight,
            open_main_window,
            add_attachment,
            save_attachment,
            delete_attachment,
            duress_status,
            set_duress_password,
            vault_in_sync_folder,
            clear_duress_password,
            bridge_state,
            bridge_start_pairing,
            bridge_cancel_pairing,
            bridge_revoke,
            bridge_approve_save,
            bridge_reject_save,
            browser_support_status,
            set_browser_support,
            network_status,
            set_air_gapped,
            update_status,
            set_update_mode,
            check_for_update
        ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_folder_detection() {
        assert!(path_in_sync_folder(Path::new(
            r"C:\Users\a\OneDrive\Docs\vault.shush"
        )));
        assert!(path_in_sync_folder(Path::new(
            "/home/a/Dropbox/vault.shush"
        )));
        assert!(!path_in_sync_folder(Path::new(
            r"C:\Users\a\AppData\vault.shush"
        )));
    }

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
        assert!(!info.generated);

        let gen = dir.path().join("gen.key");
        crypto::keyfile::create_keyfile(&gen).unwrap();
        assert!(inspect_keyfile_blocking(&gen).unwrap().generated);
        let mut bytes = std::fs::read(&gen).unwrap();
        bytes[20] ^= 1;
        std::fs::write(&gen, bytes).unwrap();
        assert_eq!(
            inspect_keyfile_blocking(&gen).unwrap_err().code,
            "KEYFILE_CORRUPT"
        );

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
        assert_eq!(
            std::fs::metadata(&key).unwrap().len(),
            crypto::keyfile::GENERATED_FILE_LEN as u64
        );

        let status = status_for(None, &vault_file, false, false, false);
        assert!(status.exists);
        assert!(!status.hide_names);
        assert!(status_for(None, &vault_file, false, false, true).hide_names);
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
        let status = status_for(None, &vault_file, false, false, false);
        assert!(status.exists);
        assert!(!status.hide_names);
        assert!(status_for(None, &vault_file, false, false, true).hide_names);
        assert!(!status.can_delete);
        assert_eq!(status.error.unwrap().code, "VAULT_UNREADABLE");
        assert_eq!(
            unlock_blocking(&vault_file, b"pw", None).unwrap_err().code,
            "VAULT_UNREADABLE"
        );
        assert_eq!(
            authenticate_for_delete_blocking(&vault_file, b"pw", None)
                .unwrap_err()
                .code,
            "VAULT_UNREADABLE"
        );
    }

    #[test]
    fn corrupt_vault_with_valid_backup_can_authenticate_for_delete() {
        let dir = tempfile::tempdir().unwrap();
        let vault_file = dir.path().join("vault.shush");
        let bak_file = dir.path().join("vault.shush.bak");

        // Create a valid vault, then copy it to .bak and corrupt the main file.
        create_vault_blocking(
            &vault_file,
            b"correct horse",
            &KeyfileChoice::None,
            1,
            POLICY_MIN,
        )
        .unwrap();
        std::fs::copy(&vault_file, &bak_file).unwrap();
        std::fs::write(&vault_file, b"corrupted header content").unwrap();

        let status = status_for(None, &vault_file, false, false, false);
        assert!(status.exists);
        assert!(status.can_delete);
        let err = status.error.unwrap();
        assert_eq!(err.code, "VAULT_UNREADABLE");
        assert!(err.message.contains(".bak"));

        // Authenticating for delete with wrong password fails and returns WRONG_CREDENTIALS
        assert_eq!(
            authenticate_for_delete_blocking(&vault_file, b"wrong horse", None)
                .unwrap_err()
                .code,
            "WRONG_CREDENTIALS"
        );

        // Authenticating for delete with correct password succeeds against .bak
        assert!(authenticate_for_delete_blocking(&vault_file, b"correct horse", None).is_ok());
    }

    #[test]
    fn missing_vault_reports_missing_and_cannot_delete() {
        let dir = tempfile::tempdir().unwrap();
        let vault_file = dir.path().join("nonexistent.shush");
        let entry = vault::registry::VaultEntry {
            id: "v1".into(),
            name: "Missing".into(),
            path: vault_file.clone(),
            color: "crimson".into(),
        };
        let status = status_for(Some(&entry), &vault_file, false, false, false);
        assert!(!status.exists);
        assert!(!status.can_delete);
        let err = status.error.unwrap();
        assert_eq!(err.code, "VAULT_MISSING");
        assert!(err.message.contains("remove"));
    }

    #[test]
    fn reveal_path_in_explorer_returns_not_found_for_missing_path() {
        let dir = tempfile::tempdir().unwrap();
        let ghost = dir.path().join("ghost_dir").join("ghost.shush");
        let res = reveal_path_in_explorer(&ghost);
        assert_eq!(res.unwrap_err().code, "PATH_NOT_FOUND");
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
        // A payload byte in both slots (the end of a slot is random fill).
        let fixed = vault::container::FIXED_LEN;
        let slot_len = (bytes.len() - fixed) / vault::slots::SLOT_COUNT;
        let in_payload = CipherSuite::Aes256Gcm.nonce_len() + vault::slots::SLOT_HEADER_CT_LEN + 10;
        for i in 0..vault::slots::SLOT_COUNT {
            bytes[fixed + i * slot_len + in_payload] ^= 1;
        }
        std::fs::write(&vault_file, &bytes).unwrap();
        assert_eq!(
            unlock_blocking(&vault_file, b"long enough", None)
                .unwrap_err()
                .code,
            "VAULT_TAMPERED"
        );
    }

    #[test]
    fn read_only_vault_status_and_unlock() {
        let dir = tempfile::tempdir().unwrap();
        let vault_file = dir.path().join("vault.shush");
        let v = create_vault_blocking(
            &vault_file,
            b"correct horse",
            &KeyfileChoice::None,
            0x01,
            POLICY_MIN,
        )
        .unwrap();

        // Mark the file read-only on disk.
        let mut perms = std::fs::metadata(&vault_file).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&vault_file, perms).unwrap();

        let status = status_for(None, &vault_file, false, false, false);
        assert!(status.exists);
        assert!(status.read_only);

        // Verify summary reports read-only.
        let s = summary(&vault_file, &v, true);
        assert!(s.read_only);

        // Revert permissions so tempdir can clean up cleanly on drop.
        let mut perms = std::fs::metadata(&vault_file).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        let _ = std::fs::set_permissions(&vault_file, perms);
    }

    #[test]
    fn navigation_is_limited_to_the_bundled_frontend() {
        let ok = |u: &str| is_app_url(&u.parse().unwrap());
        assert!(ok("http://tauri.localhost/"));
        assert!(ok("http://tauri.localhost/index.html#x"));
        assert!(ok("https://tauri.localhost/"));
        assert!(ok("tauri://localhost/"));
        assert!(!ok("http://tauri.localhost:8080/"));
        assert!(!ok("https://evil.example/"));
        assert!(!ok("http://tauri.localhost.evil.example/"));
        assert!(!ok("file:///C:/Windows/win.ini"));
        assert!(!ok("javascript:alert(1)"));
        assert!(!ok("data:text/html,<script>1</script>"));
        assert!(!ok("http://localhost:1421/"));
        assert_eq!(ok("http://localhost:1420/"), cfg!(debug_assertions));
    }

    /// Issue #20: every handler command must be declared in build.rs (or the
    /// ACL denies it everywhere), the main window must be granted each one,
    /// and the Spotlight window must stay on a short allowlist with nothing
    /// that returns secrets, exports, imports or manages vaults.
    #[test]
    fn command_permissions_match_handler_and_scope_spotlight() {
        fn quoted(block: &str) -> Vec<String> {
            block
                .split('"')
                .skip(1)
                .step_by(2)
                .map(str::to_owned)
                .collect()
        }
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let lib = std::fs::read_to_string(root.join("src/lib.rs")).unwrap();
        let start = lib.find("generate_handler![").unwrap() + "generate_handler![".len();
        let end = start + lib[start..].find(']').unwrap();
        let mut handler: Vec<String> = lib[start..end]
            .split(',')
            .map(|c| c.trim().to_owned())
            .filter(|c| !c.is_empty())
            .collect();
        handler.sort();

        let build = std::fs::read_to_string(root.join("build.rs")).unwrap();
        let start = build.find("COMMANDS: &[&str] = &[").unwrap();
        let end = start + build[start..].find("];").unwrap();
        let mut declared = quoted(&build[start..end]);
        declared.sort();
        assert_eq!(
            handler, declared,
            "build.rs COMMANDS out of sync with generate_handler!"
        );

        let caps = |name: &str| -> Vec<String> {
            let text = std::fs::read_to_string(root.join("capabilities").join(name)).unwrap();
            let v: serde_json::Value = serde_json::from_str(&text).unwrap();
            v["permissions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| p.as_str().unwrap().to_owned())
                .collect()
        };
        let main = caps("main.json");
        for cmd in &handler {
            let perm = format!("allow-{}", cmd.replace('_', "-"));
            assert!(main.contains(&perm), "main window lacks {perm}");
        }

        let mut spotlight = caps("spotlight.json");
        spotlight.sort();
        assert_eq!(
            spotlight,
            [
                "allow-copy-field",
                "allow-hide-spotlight",
                "allow-list-items",
                "allow-open-main-window",
                "allow-vault-status",
                "core:event:default",
            ]
        );
        let files: Vec<_> = std::fs::read_dir(root.join("capabilities"))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(files.len(), 2, "unexpected capability file: {files:?}");
    }

    #[test]
    fn debug_app_identifier_isolation() {
        assert_eq!(debug_app_identifier(None), "com.shush.vault.debug");
        let p1 = Path::new("C:\\temp\\scratch\\vault.shush");
        let p2 = Path::new("c:/temp/scratch/vault.shush");
        let id1 = debug_app_identifier(Some(p1));
        let id2 = debug_app_identifier(Some(p2));
        assert!(id1.starts_with("com.shush.vault.debug-"));
        assert_eq!(
            id1, id2,
            "path normalization should yield identical identifiers"
        );

        let p3 = Path::new("C:\\temp\\other\\vault.shush");
        let id3 = debug_app_identifier(Some(p3));
        assert_ne!(
            id1, id3,
            "different scratch vaults get distinct identifiers"
        );
    }

    #[test]
    fn resolve_webview_data_dir_precedence() {
        let explicit = resolve_webview_data_dir(
            Some("C:\\custom\\wv2".into()),
            Some("C:\\scratch\\vault.shush".into()),
        );
        assert_eq!(explicit, Some(PathBuf::from("C:\\custom\\wv2")));

        let from_vault = resolve_webview_data_dir(None, Some("C:\\scratch\\vault.shush".into()));
        assert_eq!(from_vault, Some(PathBuf::from("C:\\scratch\\webview2")));

        let none = resolve_webview_data_dir(None, None);
        assert_eq!(none, None);
    }

    #[test]
    fn parse_unlock_request_raw_payload_wipes_buffer() {
        let mut raw = Vec::new();
        let flags: u8 = 1 | 2; // vault_id + keyfile_path
        raw.push(flags);
        let vid = b"test-vault-id-42";
        raw.extend_from_slice(&(vid.len() as u16).to_le_bytes());
        raw.extend_from_slice(vid);
        let kf = b"C:\\path\\to\\key.kf";
        raw.extend_from_slice(&(kf.len() as u16).to_le_bytes());
        raw.extend_from_slice(kf);
        let pw = b"super-secret-password-123";
        raw.extend_from_slice(pw);

        let initial_len = raw.len();
        let body = tauri::ipc::InvokeBody::Raw(raw);
        let parsed = parse_unlock_request(&body).expect("successful parse");

        assert_eq!(parsed.vault_id.as_deref(), Some("test-vault-id-42"));
        assert_eq!(parsed.keyfile_path.as_deref(), Some("C:\\path\\to\\key.kf"));
        assert_eq!(&parsed.password[..], pw);

        // Verify that Tauri's raw buffer has been wiped in place to zeroes
        if let tauri::ipc::InvokeBody::Raw(wiped) = body {
            assert_eq!(wiped.len(), initial_len);
            assert!(
                wiped.iter().all(|&b| b == 0),
                "Raw buffer must be wiped to zeroes"
            );
        } else {
            panic!("Expected Raw body");
        }
    }

    #[test]
    fn parse_unlock_request_json_payload_compat() {
        let val = serde_json::json!({
            "password": "json-secret-password",
            "keyfile_path": "my.key",
            "vault_id": "vid-1",
        });
        let body = tauri::ipc::InvokeBody::Json(val);
        let parsed = parse_unlock_request(&body).expect("successful JSON parse");
        assert_eq!(parsed.vault_id.as_deref(), Some("vid-1"));
        assert_eq!(parsed.keyfile_path.as_deref(), Some("my.key"));
        assert_eq!(&parsed.password[..], b"json-secret-password");
    }

    #[test]
    fn vault_unlock_and_lock_wipes_master_password_from_memory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hygiene.shush");
        let canary_pw = b"__CANARY_MP_SECRET_TEST_99887766__";

        let options = CreateOptions {
            suite: CipherSuite::Aes256Gcm,
            kdf: POLICY_MIN,
        };
        let vault = OpenVault::create(canary_pw, None, options).unwrap();
        std::fs::write(&path, vault.to_bytes().unwrap()).unwrap();
        drop(vault);

        // Open the vault
        let bytes = std::fs::read(&path).unwrap();
        let opened = OpenVault::unlock(&bytes, canary_pw, None).unwrap();
        assert_eq!(opened.data().items.len(), 0);

        // Lock the vault (drop OpenVault)
        drop(opened);

        // Memory scan: canary password must not linger in accessible heap memory
        #[cfg(windows)]
        {
            let matches = os::memory::count_occurrences_in_process_memory(canary_pw);
            assert_eq!(matches, 0, "Master password must be zeroized after lock");
        }
    }
}
