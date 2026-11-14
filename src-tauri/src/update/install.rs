//! Verified download and install handoff (issue #197, #78 phase 3).
//!
//! The user clicks Download; [`download`] then:
//! 1. fetches and verifies the signed feed again (never trusting the earlier check), with the
//!    persisted `highest_seen` as the rollback floor, and refuses if the release is no longer the
//!    version the user agreed to (`UPDATE_FEED_MISMATCH`, after one re-check);
//! 2. reads the feed's `latest.json` (the Tauri-updater manifest) and requires its version and URL
//!    to equal the signed `release.json`, and its installer signature to decode;
//! 3. streams the installer through the network gate into a fresh private directory
//!    ([`crate::os::private_dir`], never `%TEMP%`), capped at the signed size, with a deadline
//!    and up to [`ATTEMPTS`] tries;
//! 4. reopens the file read-only **denying writers and deleters**, and checks size, SHA-256 and
//!    the minisign signature over those exact bytes ([`super::verify_installer`]);
//! 5. only then persists `highest_seen`, and keeps the handle open in a [`Staged`] value until
//!    install, so the verified bytes cannot be swapped before they run.
//!
//! Any failure deletes the partial or rejected file, leaves `highest_seen` unchanged and runs
//! nothing. `tauri-plugin-updater` is not used at all: it would bring its own HTTP client (a
//! socket outside the gate) and stage files in `%TEMP%`.
//!
//! Install ([`Staged::launch`]) runs the NSIS installer with `/P /R /UPDATE` (passive, relaunch,
//! update mode). The caller locks the vault first and exits right after; the relaunched app
//! starts locked, as every start does. If the installer fails or is cancelled the old version
//! stays installed and the vault stays locked (it was locked before the installer started).

use std::fs::File;
use std::io::{Seek, Write};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::client::{fetch_verified, to_status, Fetch, GateFetch, UpdateStatus};
use super::{verify_installer, ReleaseManifest, TrustAnchors, MAX_MANIFEST_BYTES};
use crate::net::NetError;

/// File (next to `vaults.json`) holding the highest version ever fully verified.
pub const HIGHEST_SEEN_FILE: &str = "update-seen.json";
/// Arguments for the Tauri NSIS installer: passive UI, relaunch the app afterwards, update mode
/// (keeps shortcuts and settings as they are).
pub const INSTALLER_ARGS: [&str; 3] = ["/P", "/R", "/UPDATE"];
/// Download tries before giving up (network errors only).
pub const ATTEMPTS: usize = 3;
/// Longest wait for a connect or a single read.
const STALL: std::time::Duration = std::time::Duration::from_secs(30);
/// Longest a single download attempt may take.
const TOTAL: std::time::Duration = std::time::Duration::from_secs(20 * 60);
/// Platform key of this build in `latest.json`.
const LATEST_PLATFORM: &str = "windows-x86_64";

/// A refused or failed download / install, with a stable code for the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fail {
    /// Stable machine-readable code.
    pub code: &'static str,
    /// Message for the user.
    pub message: String,
    /// A newer check result to record (the feed changed under the user), if any.
    pub status: Option<UpdateStatus>,
}

fn fail(code: &'static str, message: impl Into<String>) -> Fail {
    Fail {
        code,
        message: message.into(),
        status: None,
    }
}

fn invalid_download() -> Fail {
    fail(
        "UPDATE_DOWNLOAD_INVALID",
        "The downloaded update failed verification and was deleted. Nothing was installed.",
    )
}

/// Where installers come from: feed files plus the streamed installer.
pub trait Source: Fetch {
    /// Streams exactly `size` bytes from `url` into `out`.
    fn download(&self, url: &str, size: u64, out: &mut dyn Write) -> Result<(), NetError>;
}

impl Source for GateFetch<'_> {
    fn download(&self, url: &str, size: u64, out: &mut dyn Write) -> Result<(), NetError> {
        self.0.https_download(
            url,
            concat!("shush/", env!("CARGO_PKG_VERSION")),
            size,
            STALL,
            TOTAL,
            out,
        )
    }
}

/// The feed's `latest.json`: only the fields cross-checked here.
#[derive(Deserialize)]
struct Latest {
    version: String,
    platforms: std::collections::HashMap<String, LatestPlatform>,
}

#[derive(Deserialize)]
struct LatestPlatform {
    signature: String,
    url: String,
}

/// A verified installer, held open read-only (writers and deleters denied) until it runs.
pub struct Staged {
    version: String,
    path: PathBuf,
    file: File,
    release: ReleaseManifest,
    sig: String,
}

impl std::fmt::Debug for Staged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Staged")
            .field("version", &self.version)
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl Staged {
    /// Version of the staged installer.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Path of the staged installer.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Checks the held bytes again (size, SHA-256, signature) right before they run.
    pub fn recheck(&mut self, anchors: &TrustAnchors) -> Result<(), Fail> {
        self.file
            .rewind()
            .map_err(|_| invalid_download())
            .and_then(|()| {
                verify_installer(anchors, &self.release, &self.sig, &self.file)
                    .map_err(|_| invalid_download())
            })
    }

    /// Starts the installer with [`INSTALLER_ARGS`]. The caller must have locked the vault and
    /// must exit right after (the installer replaces the running executable).
    pub fn launch(&self) -> Result<(), Fail> {
        self.launch_with(&INSTALLER_ARGS).map(drop).map_err(|e| {
            fail(
                "UPDATE_INSTALL_FAILED",
                format!("The installer could not be started ({e}). shush was not changed."),
            )
        })
    }

    fn launch_with(&self, args: &[&str]) -> std::io::Result<std::process::Child> {
        let mut cmd = std::process::Command::new(&self.path);
        cmd.args(args);
        if let Some(dir) = self.path.parent() {
            cmd.current_dir(dir);
        }
        cmd.spawn()
    }

    /// Releases the handle and deletes the file (rejected or abandoned download).
    pub fn discard(self) {
        let Self { file, path, .. } = self;
        drop(file);
        let _ = std::fs::remove_file(path);
    }
}

/// Highest version ever fully verified (feed **and** downloaded bytes), if recorded.
pub fn load_highest_seen(dir: &Path) -> Option<String> {
    let b = std::fs::read(dir.join(HIGHEST_SEEN_FILE)).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&b).ok()?;
    let s = v.get("highest_seen")?.as_str()?;
    semver::Version::parse(s).ok().map(|_| s.to_owned())
}

/// Raises the recorded `highest_seen` to `version` (never lowers it). Write-through rename.
pub fn save_highest_seen(dir: &Path, version: &str) -> std::io::Result<()> {
    let new = semver::Version::parse(version)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "version"))?;
    if let Some(old) = load_highest_seen(dir).and_then(|o| semver::Version::parse(&o).ok()) {
        if new.cmp_precedence(&old).is_le() {
            return Ok(());
        }
    }
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!("{HIGHEST_SEEN_FILE}.tmp"));
    {
        let mut f = File::create(&tmp)?;
        f.write_all(
            serde_json::json!({ "highest_seen": version })
                .to_string()
                .as_bytes(),
        )?;
        f.sync_all()?;
    }
    crate::os::replace::replace_file(&tmp, &dir.join(HIGHEST_SEEN_FILE))
}

/// What one download needs to know.
pub struct Request<'a> {
    /// Pinned keys.
    pub anchors: &'a TrustAnchors,
    /// This build's version.
    pub installed: &'a str,
    /// The version the user agreed to download.
    pub expected: &'a str,
    /// Current time, unix seconds.
    pub now_unix: i64,
    /// The private directory to (re)create for the installer.
    pub dir: &'a Path,
    /// Where `highest_seen` is read and persisted.
    pub state_dir: &'a Path,
}

/// Turns a pre-verification failure (already a user-facing status) into a [`Fail`].
fn from_status(s: UpdateStatus) -> Fail {
    match s {
        UpdateStatus::Failed { code, message } => fail(code, message),
        UpdateStatus::Stale => fail(
            "UPDATE_FEED_STALE",
            "Can't confirm the update: the update feed is out of date.",
        ),
        _ => fail("UPDATE_FEED_INVALID", "The update feed is malformed."),
    }
}

/// Re-verifies the feed and returns the signed release the user agreed to.
fn verified_release(src: &dyn Source, req: &Request<'_>) -> Result<ReleaseManifest, Fail> {
    let highest = load_highest_seen(req.state_dir);
    let verify = || {
        let r = fetch_verified(
            src,
            req.anchors,
            req.installed,
            highest.as_deref(),
            req.now_unix,
        )
        .map_err(from_status)?;
        match r {
            Ok(v) if v.update_available => Ok(v),
            other => {
                let status = to_status(other, req.installed);
                let mut f = match &status {
                    UpdateStatus::UpToDate { .. } => fail(
                        "UPDATE_NONE",
                        "There is no newer version to download. You are up to date.",
                    ),
                    s => from_status(s.clone()),
                };
                f.status = Some(status);
                Err(f)
            }
        }
    };
    let mut v = verify()?;
    if v.release.version != req.expected {
        // A release was deployed since the check the user saw: look once more before refusing.
        v = verify()?;
        if v.release.version != req.expected {
            return Err(Fail {
                code: "UPDATE_FEED_MISMATCH",
                message: format!(
                    "The update changed while you were downloading (now {}). Nothing was \
                     downloaded; check the new version and try again.",
                    v.release.version
                ),
                status: Some(to_status(Ok(v), req.installed)),
            });
        }
    }
    Ok(v.release)
}

/// Reads `latest.json`, cross-checks it against the signed release and returns the installer's
/// minisign signature text.
fn installer_signature(
    src: &dyn Source,
    release: &ReleaseManifest,
    installed: &str,
) -> Result<String, Fail> {
    let channel = super::client::channel_for(installed);
    let raw = src
        .get(
            &format!("{}/{channel}/latest.json", super::client::FEED_PREFIX),
            MAX_MANIFEST_BYTES,
        )
        .map_err(fetch_fail)?;
    let latest: Latest = serde_json::from_slice(&raw)
        .map_err(|_| fail("UPDATE_FEED_INVALID", "The update feed is malformed."))?;
    if latest.version != release.version {
        return Err(fail(
            "UPDATE_FEED_MISMATCH",
            "The update feed's files disagree about the version. Nothing was downloaded; try \
             again later.",
        ));
    }
    let platform = latest
        .platforms
        .get(LATEST_PLATFORM)
        .ok_or_else(invalid_download)?;
    if platform.url != release.artifact.url {
        return Err(fail(
            "UPDATE_FEED_MISMATCH",
            "The update feed's files disagree about the download. Nothing was downloaded; try \
             again later.",
        ));
    }
    // Tauri stores the minisign text base64-encoded.
    use base64::Engine as _;
    let sig = base64::engine::general_purpose::STANDARD
        .decode(platform.signature.trim())
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .filter(|s| minisign_verify::Signature::decode(s).is_ok())
        .ok_or_else(invalid_download)?;
    Ok(sig)
}

fn fetch_fail(e: NetError) -> Fail {
    match e {
        NetError::AirGapped => fail("UPDATE_AIR_GAPPED", e.to_string()),
        e => fail(
            "UPDATE_FETCH_FAILED",
            format!("Could not reach the update feed. {e}"),
        ),
    }
}

/// Windows "disk full" errors (`ERROR_HANDLE_DISK_FULL`, `ERROR_DISK_FULL`).
pub fn is_disk_full(e: &std::io::Error) -> bool {
    matches!(e.raw_os_error(), Some(39 | 112))
}

fn storage_fail(e: &std::io::Error) -> Fail {
    if is_disk_full(e) {
        fail(
            "UPDATE_DISK_FULL",
            "There is not enough free disk space to download the update. Free some space and \
             try again.",
        )
    } else {
        fail(
            "UPDATE_STORAGE_FAILED",
            format!("Could not save the update ({}).", e.kind()),
        )
    }
}

/// Writes to the download file and remembers the first local write error, so a full disk is
/// reported as such instead of as a network failure.
struct Recorder<'a> {
    file: &'a mut File,
    err: Option<std::io::Error>,
}

impl Write for Recorder<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file.write(buf).inspect_err(|e| {
            if self.err.is_none() {
                self.err = Some(match e.raw_os_error() {
                    Some(code) => std::io::Error::from_raw_os_error(code),
                    None => std::io::Error::new(e.kind(), "write failed"),
                });
            }
        })
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

/// Opens a file for writing that nobody else may open meanwhile.
fn create_exclusive(path: &Path) -> std::io::Result<File> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        o.share_mode(0);
    }
    o.open(path)
}

/// Reopens the finished file read-only, letting others read (the installer must) but denying
/// writers and deleters for as long as the handle lives.
fn open_sealed(path: &Path) -> std::io::Result<File> {
    let mut o = std::fs::OpenOptions::new();
    o.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ: u32 = 1;
        o.share_mode(FILE_SHARE_READ);
    }
    o.open(path)
}

/// Streams the installer into `path`, retrying network failures. Deletes the file on failure.
fn fetch_installer(src: &dyn Source, release: &ReleaseManifest, path: &Path) -> Result<(), Fail> {
    let cleanup = |f: Fail| {
        let _ = std::fs::remove_file(path);
        f
    };
    let mut file = create_exclusive(path).map_err(|e| storage_fail(&e))?;
    let a = &release.artifact;
    let mut attempt = 0;
    loop {
        attempt += 1;
        let mut rec = Recorder {
            file: &mut file,
            err: None,
        };
        let r = src.download(&a.url, a.size, &mut rec);
        if let Some(e) = rec.err.take() {
            drop(file);
            return Err(cleanup(storage_fail(&e)));
        }
        match r {
            Ok(()) => break,
            Err(NetError::AirGapped) => {
                drop(file);
                return Err(cleanup(fail(
                    "UPDATE_AIR_GAPPED",
                    "Air-gapped mode was turned on, so the download stopped. Nothing was \
                     installed.",
                )));
            }
            Err(NetError::Io(_)) if attempt < ATTEMPTS => {
                // Start over: the partial bytes are thrown away.
                if let Err(e) = file.set_len(0).and_then(|()| file.rewind()) {
                    drop(file);
                    return Err(cleanup(storage_fail(&e)));
                }
            }
            Err(e) => {
                drop(file);
                return Err(cleanup(fail(
                    "UPDATE_DOWNLOAD_FAILED",
                    format!("Could not download the update. {e}"),
                )));
            }
        }
    }
    let synced = file.sync_all();
    drop(file);
    synced.map_err(|e| cleanup(storage_fail(&e)))
}

/// Downloads and verifies the update the user agreed to (see the module docs). On success the
/// installer is staged and `highest_seen` is raised; on failure nothing is left behind.
pub fn download(src: &dyn Source, req: &Request<'_>) -> Result<Staged, Fail> {
    let release = verified_release(src, req)?;
    let sig = installer_signature(src, &release, req.installed)?;
    // The version is signed and semver-checked, so it is safe in a file name.
    let name = format!("shush_{}_x64-setup.exe", release.version);
    crate::os::private_dir::create_fresh(req.dir).map_err(|e| storage_fail(&e))?;
    let path = req.dir.join(name);
    fetch_installer(src, &release, &path)?;

    let file = match open_sealed(&path) {
        Ok(f) => f,
        Err(e) => {
            let _ = std::fs::remove_file(&path);
            return Err(storage_fail(&e));
        }
    };
    let mut staged = Staged {
        version: release.version.clone(),
        path,
        file,
        release,
        sig,
    };
    if let Err(f) = staged.recheck(req.anchors) {
        staged.discard();
        return Err(f);
    }
    // Feed and bytes both verified: only now may the rollback floor move.
    if let Err(e) = save_highest_seen(req.state_dir, &staged.version) {
        staged.discard();
        return Err(storage_fail(&e));
    }
    Ok(staged)
}

#[cfg(test)]
mod tests;
