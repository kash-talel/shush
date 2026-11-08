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
    /// From the (authenticated) header; `None` if there is no readable vault.
    keyfile_required: Option<bool>,
    cipher: Option<CipherInfo>,
    kdf: Option<KdfParams>,
    /// Set when a file exists but its header is unreadable.
    error: Option<CmdError>,
}

fn status_for(entry: Option<&VaultEntry>, path: &Path, unlocked: bool) -> VaultStatus {
    let mut status = VaultStatus {
        id: entry.map(|e| e.id.clone()),
        name: entry.map(|e| e.name.clone()),
        color: entry
            .map_or(VAULT_COLORS[0], |e| e.color.as_str())
            .to_string(),
        path: path.display().to_string(),
        exists: path.is_file(),
        unlocked,
        keyfile_required: None,
        cipher: None,
        kdf: None,
        error: None,
    };
    if entry.is_some() && !status.exists {
        status.error = Some(CmdError::new(
            "VAULT_MISSING",
            "The vault file is not there. Was it moved, or is its drive disconnected?",
        ));
    }
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
    let (entry, path) = selected_vault(&app)?;
    Ok(status_for(entry.as_ref(), &path, unlocked))
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
}

#[derive(Debug, Serialize)]
struct VaultList {
    vaults: Vec<VaultCard>,
    colors: Vec<&'static str>,
    max_name_chars: usize,
}

#[tauri::command]
fn list_vaults(app: tauri::AppHandle) -> Result<VaultList, CmdError> {
    let (reg, def) = edit_registry(&app, |reg, def| Ok((reg.clone(), def.to_path_buf())))?;
    let vaults = reg
        .vaults
        .iter()
        .map(|e| {
            let s = status_for(Some(e), &e.path, false);
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
            }
        })
        .collect();
    Ok(VaultList {
        vaults,
        colors: VAULT_COLORS.to_vec(),
        max_name_chars: vault::registry::MAX_NAME_CHARS,
    })
}

/// Switches the unlock screen to another vault.
#[tauri::command]
fn select_vault(app: tauri::AppHandle, id: String) -> Result<VaultStatus, CmdError> {
    require_locked(&app)?;
    let entry = edit_registry(&app, |reg, _| {
        reg.select(&id)?;
        Ok(reg.get(&id).cloned().expect("just selected"))
    })?;
    Ok(status_for(Some(&entry), &entry.path, false))
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
        let entry = edit_registry(&app, |reg, _| {
            Ok(reg.add(p.clone(), &name, color.as_deref())?)
        })?;
        Ok(status_for(Some(&entry), &entry.path, false))
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
        // It would reappear on the next load anyway.
        if def.is_file() && vault::registry::same_file(&e.path, def) {
            return Err(RegistryError::DefaultPinned.into());
        }
        reg.remove(&id)?;
        Ok(())
    })
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
    let throttle = app.state::<std::sync::Mutex<DeleteThrottle>>();
    let now = std::time::Instant::now();
    if let Some(s) = throttle
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .wait_secs(&id, now)
    {
        return Err(wait_error(s));
    }

    blocking(move || {
        let path = entry.path.clone();
        // Must still be a shush vault: never delete whatever a hand-edited
        // vault list points at.
        vault::read_header(&path)?;
        let throttle = app.state::<std::sync::Mutex<DeleteThrottle>>();
        match unlock_blocking(&path, password.as_bytes(), keyfile_path.as_deref()) {
            Ok(v) => {
                drop(v); // keys and data wiped
                throttle.lock().unwrap_or_else(|e| e.into_inner()).succeed(&id);
            }
            Err(e) if e.code == "WRONG_CREDENTIALS" => {
                let wait = throttle
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .fail(&id, std::time::Instant::now());
                return Err(match wait {
                    Some(s) => CmdError::new(
                        "WRONG_CREDENTIALS",
                        format!("Wrong master password or keyfile. Try again in {}.", human_secs(s)),
                    ),
                    None => e,
                });
            }
            Err(e) => return Err(e),
        }
        // Someone may have unlocked during the slow KDF.
        require_locked(&app)?;

        let files: Vec<PathBuf> = vault::registry::vault_files(&path)
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
        })?;
        edit_registry(&app, |reg, _| {
            reg.remove(&id)?;
            Ok(())
        })
    })
    .await
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
    vault_id: Option<String>,
) -> Result<VaultSummary, CmdError> {
    let password = Zeroizing::new(password);
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
        let vault = unlock_blocking(&path, password.as_bytes(), keyfile_path.as_deref())?;
        // Remove attachment blobs left behind by an interrupted add/delete.
        vault::attachments::gc_orphans(&path, vault.data());
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
    blocking(move || {
        write(&app, |d| Ok(d.delete_item(&id)?))?;
        // The item's attachment blobs are now unreferenced.
        app.state::<VaultState>()
            .with(|u| vault::attachments::gc_orphans(&u.path, u.vault.data()));
        Ok(())
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
            setup_tray(app)?;
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
            list_vaults,
            select_vault,
            check_new_vault,
            add_existing_vault,
            update_vault,
            forget_vault,
            delete_vault,
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
            delete_attachment
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

        let status = status_for(None, &vault_file, false);
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
        let status = status_for(None, &vault_file, false);
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
