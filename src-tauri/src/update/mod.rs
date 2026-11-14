//! Update trust verification (issue #78): the offline core of the signed-feed client.
//!
//! This module only *decides* whether a feed and a downloaded installer may be trusted. It does no
//! network I/O and installs nothing. Fetching (notify-only) lives in [`client`] and goes through
//! the network gate (#157); download and install come in a later phase.
//!
//! The scheme is a minimal TUF:
//! - `release.json` binds *version -> sha256 + size* and is signed by a **release key**.
//! - `freshness.json` binds *that exact release.json -> an expiry* and is signed by a low-privilege
//!   **timestamp key**.
//!
//! Rules enforced by [`verify_feed`]: both signatures check against pinned keys, the freshness file
//! points at these exact release bytes, it has not expired (else [`UpdateError::Stale`], never
//! "up to date"), the channel matches, and the version is not a rollback (`>= installed` and
//! `>= highest_seen`, by semver precedence so build metadata never counts). The freshness window is
//! at most 14 days and may not start in the future; the artifact must target this platform over
//! https; the stable channel never offers pre-releases. [`verify_download`] then checks the
//! downloaded bytes against the signed size and sha256. Callers persist `highest_seen` only after
//! both succeed.

use serde::Deserialize;
use sha2::{Digest, Sha256};

pub mod client;

/// Hard cap on a manifest's size; both files are tiny, so anything bigger is hostile.
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;
/// Hard cap on an installer; the signed `size` must not exceed it (disk-fill defence).
pub const MAX_INSTALLER_BYTES: u64 = 256 * 1024 * 1024;
/// The only manifest schema this client understands.
pub const SCHEMA: u32 = 1;
/// Longest validity a freshness file may claim (`expires_at - issued_at`). CI signs 14-day
/// windows weekly; anything longer would let one captured file freeze updates for longer.
pub const MAX_FRESHNESS_SECS: i64 = 14 * 24 * 60 * 60;
/// How far `issued_at` may sit ahead of the local clock (skew tolerance). A file "issued" further
/// in the future was minted to outlive the window and is refused.
pub const MAX_CLOCK_SKEW_SECS: i64 = 5 * 60;
/// The channel that never offers pre-release versions.
pub const STABLE_CHANNEL: &str = "stable";
/// Artifact target this build installs. Other targets in a feed are refused.
pub const THIS_TARGET: &str = "windows-x86_64-nsis";

/// Why a feed or download was rejected. Every variant means: do not install.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum UpdateError {
    /// A manifest or key was malformed, oversized, or has an unsupported schema.
    #[error("malformed update metadata: {0}")]
    Malformed(&'static str),
    /// A signature did not verify against any pinned key.
    #[error("{0} signature is not valid for any pinned key")]
    BadSignature(&'static str),
    /// The freshness file does not vouch for this release.json.
    #[error("freshness file does not match release.json")]
    FreshnessMismatch,
    /// The freshness file expired: we cannot confirm we are up to date.
    #[error("the update feed is stale; cannot confirm you are up to date")]
    Stale,
    /// The manifests are for another channel, or offer a pre-release on the stable channel.
    #[error("update channel mismatch")]
    ChannelMismatch,
    /// The installer is built for another platform.
    #[error("update is for another platform")]
    TargetMismatch,
    /// The release is older than what is installed or previously seen.
    #[error(
        "release {offered} is a rollback (installed {installed}, highest seen {highest_seen})"
    )]
    Rollback {
        /// Version offered by the feed.
        offered: String,
        /// Version currently installed.
        installed: String,
        /// Highest version ever fully verified.
        highest_seen: String,
    },
    /// The downloaded bytes differ from what the signed release.json promises.
    #[error("downloaded installer does not match the signed release")]
    ArtifactMismatch,
}

/// A pinned minisign public key (base64, as printed by `minisign -G`).
#[derive(Clone)]
pub struct PinnedKey(minisign_verify::PublicKey);

impl PinnedKey {
    /// Parse a base64 minisign public key (the second line of a `.pub` file).
    pub fn from_base64(b64: &str) -> Result<Self, UpdateError> {
        minisign_verify::PublicKey::from_base64(b64.trim())
            .map(Self)
            .map_err(|_| UpdateError::Malformed("public key"))
    }

    fn verifies(&self, data: &[u8], sig_text: &str) -> bool {
        match minisign_verify::Signature::decode(sig_text) {
            // `allow_legacy = false`: only prehashed (`ED`) signatures, which cover the whole file.
            Ok(sig) => self.0.verify(data, &sig, false).is_ok(),
            Err(_) => false,
        }
    }
}

/// The keys compiled into the app. `release` is `[current, next]` so a rotation needs no trust
/// bootstrap; `timestamp` signs only freshness.
#[derive(Clone)]
pub struct TrustAnchors {
    /// Release keys: `[current, next]` (more allowed).
    pub release: Vec<PinnedKey>,
    /// Timestamp keys.
    pub timestamp: Vec<PinnedKey>,
}

/// The installer a release points at.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Artifact {
    /// Build target, e.g. `windows-x86_64-nsis`.
    pub target: String,
    /// Where to download it.
    pub url: String,
    /// Lower-case hex SHA-256 of the installer.
    pub sha256: String,
    /// Exact size in bytes.
    pub size: u64,
}

/// `release.json`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ReleaseManifest {
    /// Schema version (must be [`SCHEMA`]).
    pub schema: u32,
    /// Update channel.
    pub channel: String,
    /// Release version (semver).
    pub version: String,
    /// RFC 3339 release time.
    pub released_at: String,
    /// Oldest version still supported.
    #[serde(default)]
    pub min_supported: Option<String>,
    /// Whether this is a security update.
    #[serde(default)]
    pub security: bool,
    /// Vault format this release writes.
    #[serde(default)]
    pub vault_format: Option<u32>,
    /// The installer.
    pub artifact: Artifact,
    /// Release notes page.
    #[serde(default)]
    pub notes_url: Option<String>,
}

/// `freshness.json`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct FreshnessManifest {
    /// Schema version (must be [`SCHEMA`]).
    pub schema: u32,
    /// Update channel.
    pub channel: String,
    /// Lower-case hex SHA-256 of the release.json bytes this vouches for.
    pub release_sha256: String,
    /// RFC 3339 issue time.
    pub issued_at: String,
    /// RFC 3339 expiry.
    pub expires_at: String,
}

/// Raw feed files as fetched.
pub struct FeedFiles<'a> {
    /// `release.json` bytes.
    pub release: &'a [u8],
    /// `release.json.minisig` text.
    pub release_sig: &'a str,
    /// `freshness.json` bytes.
    pub freshness: &'a [u8],
    /// `freshness.json.minisig` text.
    pub freshness_sig: &'a str,
}

/// Local state the verdict depends on.
pub struct LocalState<'a> {
    /// Channel this install follows.
    pub channel: &'a str,
    /// Artifact target this install accepts (normally [`THIS_TARGET`]).
    pub target: &'a str,
    /// Installed version.
    pub installed: &'a str,
    /// Highest version ever fully verified (persisted by the caller), if any.
    pub highest_seen: Option<&'a str>,
    /// Current time, unix seconds.
    pub now_unix: i64,
}

/// A feed that passed every check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRelease {
    /// The signed release.
    pub release: ReleaseManifest,
    /// Index into [`TrustAnchors::release`] of the key that signed it (`>= 1` means a next key).
    pub release_key_index: usize,
    /// Freshness expiry, unix seconds (for "verified <date>" in the UI).
    pub fresh_until_unix: i64,
    /// True when `version > installed` (an update is available); false means up to date.
    pub update_available: bool,
}

fn parse_version(s: &str) -> Result<semver::Version, UpdateError> {
    semver::Version::parse(s).map_err(|_| UpdateError::Malformed("version"))
}

fn parse_time(s: &str) -> Result<i64, UpdateError> {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .map(|t| t.unix_timestamp())
        .map_err(|_| UpdateError::Malformed("timestamp"))
}

fn sha256_hex(data: &[u8]) -> String {
    let d = Sha256::digest(data);
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// Compare two hex digests case-insensitively without early exit; length differences fail.
fn hex_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.to_ascii_lowercase(), b.to_ascii_lowercase());
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

fn parse_json<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, UpdateError> {
    serde_json::from_slice(bytes).map_err(|_| UpdateError::Malformed("manifest json"))
}

/// Verify the signed feed (client algorithm steps 2 to 4). Pure: persists nothing. The caller
/// stores `highest_seen = release.version` only after [`verify_download`] also succeeds.
pub fn verify_feed(
    anchors: &TrustAnchors,
    files: &FeedFiles<'_>,
    local: &LocalState<'_>,
) -> Result<VerifiedRelease, UpdateError> {
    // Signatures first: nothing is parsed or trusted before it has been authenticated.
    if files.release.len() > MAX_MANIFEST_BYTES || files.freshness.len() > MAX_MANIFEST_BYTES {
        return Err(UpdateError::Malformed("manifest too large"));
    }
    let release_key_index = anchors
        .release
        .iter()
        .position(|k| k.verifies(files.release, files.release_sig))
        .ok_or(UpdateError::BadSignature("release.json"))?;
    if !anchors
        .timestamp
        .iter()
        .any(|k| k.verifies(files.freshness, files.freshness_sig))
    {
        return Err(UpdateError::BadSignature("freshness.json"));
    }

    let release: ReleaseManifest = parse_json(files.release)?;
    let fresh: FreshnessManifest = parse_json(files.freshness)?;
    if release.schema != SCHEMA || fresh.schema != SCHEMA {
        return Err(UpdateError::Malformed("unsupported schema"));
    }
    if release.channel != local.channel || fresh.channel != local.channel {
        return Err(UpdateError::ChannelMismatch);
    }
    if !hex_eq(&fresh.release_sha256, &sha256_hex(files.release)) {
        return Err(UpdateError::FreshnessMismatch);
    }
    let fresh_until_unix = parse_time(&fresh.expires_at)?;
    let issued_unix = parse_time(&fresh.issued_at)?;
    parse_time(&release.released_at)?;
    // Bound the window so one signed file cannot vouch for "up to date" indefinitely.
    if fresh_until_unix <= issued_unix || fresh_until_unix - issued_unix > MAX_FRESHNESS_SECS {
        return Err(UpdateError::Malformed("freshness window"));
    }
    if issued_unix > local.now_unix.saturating_add(MAX_CLOCK_SKEW_SECS) {
        return Err(UpdateError::Malformed("freshness issued in the future"));
    }
    if local.now_unix >= fresh_until_unix {
        return Err(UpdateError::Stale);
    }

    if release.artifact.target != local.target {
        return Err(UpdateError::TargetMismatch);
    }
    if release.artifact.size == 0 || release.artifact.size > MAX_INSTALLER_BYTES {
        return Err(UpdateError::Malformed("artifact size"));
    }
    match url::Url::parse(&release.artifact.url) {
        Ok(u) if u.scheme() == "https" && u.host_str().is_some_and(|h| !h.is_empty()) => {}
        _ => return Err(UpdateError::Malformed("artifact url")),
    }
    let offered = parse_version(&release.version)?;
    if local.channel == STABLE_CHANNEL && !offered.pre.is_empty() {
        return Err(UpdateError::ChannelMismatch);
    }
    let installed = parse_version(local.installed)?;
    let highest = match local.highest_seen {
        Some(h) => parse_version(h)?,
        None => installed.clone(),
    };
    // Semver precedence ignores build metadata, so `0.1.0+rebuild` is not newer than `0.1.0`.
    let older = |a: &semver::Version, b: &semver::Version| a.cmp_precedence(b).is_lt();
    // A re-pointed older release is a rollback even if both files are validly signed.
    if older(&offered, &installed) || older(&offered, &highest) {
        return Err(UpdateError::Rollback {
            offered: release.version.clone(),
            installed: local.installed.to_owned(),
            highest_seen: local.highest_seen.unwrap_or(local.installed).to_owned(),
        });
    }
    let update_available = offered.cmp_precedence(&installed).is_gt();
    Ok(VerifiedRelease {
        release,
        release_key_index,
        fresh_until_unix,
        update_available,
    })
}

/// Check downloaded installer bytes against the signed release (client algorithm step 6).
pub fn verify_download(release: &ReleaseManifest, bytes: &[u8]) -> Result<(), UpdateError> {
    let a = &release.artifact;
    if bytes.len() as u64 != a.size || !hex_eq(&sha256_hex(bytes), &a.sha256) {
        return Err(UpdateError::ArtifactMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
