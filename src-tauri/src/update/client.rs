//! Notify-only update client (issue #78, phase 2).
//!
//! Fetches the signed feed through the network gate ([`crate::net::NetGate`]), runs it through
//! [`super::verify_feed`], and reports one of a few states. It downloads and installs nothing:
//! the installer URL in `release.json` is never requested here. `highest_seen` is not persisted
//! either, because that only happens after a full download verification (phase 3).
//!
//! An update check sends a plain GET with `User-Agent: shush/<version>`: no identifiers, no
//! cookies, no query string.

use std::path::Path;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use super::{
    verify_feed, FeedFiles, LocalState, PinnedKey, TrustAnchors, UpdateError, MAX_MANIFEST_BYTES,
    THIS_TARGET,
};
use crate::net::{NetError, NetGate};

/// Host serving the feed (GitHub Pages).
pub const FEED_HOST: &str = "kash-talel.github.io";
/// Path prefix of the feed; the channel and file name are appended.
pub const FEED_PREFIX: &str = "/shush/updates";
/// File (next to `vaults.json`) holding the user's update setting.
pub const SETTINGS_FILE: &str = "updates.json";

/// Release keys, `[current, next]` (raw minisign keys, see `docs/RELEASING.md`).
const RELEASE_KEYS: [&str; 2] = [
    "RWSyJnfG6rk6ThxC2aKBL9nuMkq8ZaTMtCdqa8xdDbE0P4egrOeRCUJC",
    "RWT70MSY/r1wK9tvg9kk3Vy850MazrUB93OSnE1gyjNeZBhTryHtrxlc",
];
/// Timestamp key (signs `freshness.json` only).
const TIMESTAMP_KEYS: [&str; 1] = ["RWQULYiCWTkg8ykOuGgFG9cG+c5yJOKF/2gWDpmfnTWcdcb9ByK/iI3z"];

/// The keys compiled into this build.
pub fn pinned_anchors() -> TrustAnchors {
    let parse = |ks: &[&str]| {
        ks.iter()
            .map(|k| PinnedKey::from_base64(k).expect("pinned key is valid"))
            .collect()
    };
    TrustAnchors {
        release: parse(&RELEASE_KEYS),
        timestamp: parse(&TIMESTAMP_KEYS),
    }
}

/// What the user chose for update checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateMode {
    /// Never check.
    Off,
    /// Check and tell the user; never download.
    Notify,
}

impl UpdateMode {
    /// Loads the saved choice: a missing file means the default (`Notify`, which still needs the
    /// network gate open), anything unreadable means `Off`.
    pub fn load(dir: &Path) -> Self {
        match std::fs::read(dir.join(SETTINGS_FILE)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::Notify,
            Err(_) => Self::Off,
            Ok(b) => serde_json::from_slice::<serde_json::Value>(&b)
                .ok()
                .and_then(|v| serde_json::from_value(v.get("mode")?.clone()).ok())
                .unwrap_or(Self::Off),
        }
    }

    /// Saves the choice with a write-through rename.
    pub fn save(self, dir: &Path) -> std::io::Result<()> {
        use std::io::Write;
        std::fs::create_dir_all(dir)?;
        let tmp = dir.join(format!("{SETTINGS_FILE}.tmp"));
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(serde_json::json!({ "mode": self }).to_string().as_bytes())?;
            f.sync_all()?;
        }
        crate::os::replace::replace_file(&tmp, &dir.join(SETTINGS_FILE))
    }
}

/// Outcome of the last check, as shown in Settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum UpdateStatus {
    /// No check has run in this session.
    Unchecked,
    /// Verified feed says this is the newest release.
    UpToDate {
        /// Unix time until which the freshness proof is valid.
        verified_until: i64,
    },
    /// A newer release exists. Nothing was downloaded.
    Available {
        /// Offered version.
        version: String,
        /// Marked as a security update.
        security: bool,
        /// The installed version is below the release's `min_supported`.
        below_min_supported: bool,
    },
    /// The feed's freshness proof expired: "can't confirm you're up to date".
    Stale,
    /// The check failed (offline, bad signature, rollback...). Never "up to date".
    Failed {
        /// Stable machine-readable code.
        code: &'static str,
        /// Message for the user.
        message: String,
    },
}

fn failed(code: &'static str, message: impl Into<String>) -> UpdateStatus {
    UpdateStatus::Failed {
        code,
        message: message.into(),
    }
}

/// Source of feed files; the real one goes through the gate, tests use a fake.
pub trait Fetch {
    /// GET `path` (starting with `/`), returning the body of a 200 response.
    fn get(&self, path: &str, max: usize) -> Result<Vec<u8>, NetError>;
}

/// Fetches over HTTPS through the single network gate.
pub struct GateFetch<'a>(pub &'a NetGate);

impl Fetch for GateFetch<'_> {
    fn get(&self, path: &str, max: usize) -> Result<Vec<u8>, NetError> {
        self.0.https_get(
            FEED_HOST,
            path,
            concat!("shush/", env!("CARGO_PKG_VERSION")),
            max,
            std::time::Duration::from_secs(15),
        )
    }
}

/// The channel an installed version follows: pre-release builds follow `beta`.
pub fn channel_for(installed: &str) -> &'static str {
    match semver::Version::parse(installed) {
        Ok(v) if !v.pre.is_empty() => "beta",
        _ => super::STABLE_CHANNEL,
    }
}

/// Runs one update check (client algorithm steps 1 to 4). Never downloads an installer.
pub fn check(
    fetch: &dyn Fetch,
    anchors: &TrustAnchors,
    installed: &str,
    now_unix: i64,
) -> UpdateStatus {
    let channel = channel_for(installed);
    let get = |name: &str| {
        fetch.get(
            &format!("{FEED_PREFIX}/{channel}/{name}"),
            MAX_MANIFEST_BYTES,
        )
    };
    let files = (|| {
        Ok::<_, NetError>((
            get("freshness.json")?,
            get("freshness.json.minisig")?,
            get("release.json")?,
            get("release.json.minisig")?,
        ))
    })();
    let (freshness, freshness_sig, release, release_sig) = match files {
        Ok(f) => f,
        Err(NetError::AirGapped) => {
            return failed("UPDATE_AIR_GAPPED", NetError::AirGapped.to_string())
        }
        Err(e) => {
            return failed(
                "UPDATE_FETCH_FAILED",
                format!("Could not reach the update feed. {e}"),
            )
        }
    };
    let (Ok(freshness_sig), Ok(release_sig)) = (
        std::str::from_utf8(&freshness_sig),
        std::str::from_utf8(&release_sig),
    ) else {
        return failed("UPDATE_FEED_INVALID", "The update feed is malformed.");
    };
    let verdict = verify_feed(
        anchors,
        &FeedFiles {
            release: &release,
            release_sig,
            freshness: &freshness,
            freshness_sig,
        },
        &LocalState {
            channel,
            target: THIS_TARGET,
            installed,
            highest_seen: None,
            now_unix,
        },
    );
    match verdict {
        Ok(v) if v.update_available => {
            let below_min_supported = v
                .release
                .min_supported
                .as_deref()
                .and_then(|m| semver::Version::parse(m).ok())
                .zip(semver::Version::parse(installed).ok())
                .is_some_and(|(min, inst)| inst.cmp_precedence(&min).is_lt());
            UpdateStatus::Available {
                version: v.release.version,
                security: v.release.security,
                below_min_supported,
            }
        }
        Ok(v) => UpdateStatus::UpToDate {
            verified_until: v.fresh_until_unix,
        },
        Err(UpdateError::Stale) => UpdateStatus::Stale,
        Err(UpdateError::Rollback { .. }) => failed(
            "UPDATE_ROLLBACK",
            "The update feed offers an older version than the one you have. It was ignored.",
        ),
        Err(UpdateError::BadSignature(_) | UpdateError::FreshnessMismatch) => failed(
            "UPDATE_FEED_UNTRUSTED",
            "The update feed failed signature verification and was ignored.",
        ),
        Err(_) => failed("UPDATE_FEED_INVALID", "The update feed is malformed."),
    }
}

/// Settings choice plus the last result, shared with the UI and the background checker.
pub struct UpdateState {
    /// The user's choice.
    pub mode: Mutex<UpdateMode>,
    /// Last result and when it was produced (unix seconds).
    pub last: Mutex<(UpdateStatus, Option<i64>)>,
}

impl Default for UpdateState {
    fn default() -> Self {
        Self {
            mode: Mutex::new(UpdateMode::Notify),
            last: Mutex::new((UpdateStatus::Unchecked, None)),
        }
    }
}

impl UpdateState {
    /// Current mode.
    pub fn mode(&self) -> UpdateMode {
        *self.mode.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Records a check result.
    pub fn record(&self, status: UpdateStatus, now_unix: i64) {
        *self.last.lock().unwrap_or_else(|e| e.into_inner()) = (status, Some(now_unix));
    }

    /// Last result.
    pub fn snapshot(&self) -> (UpdateStatus, Option<i64>) {
        self.last.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

#[cfg(test)]
mod tests;
