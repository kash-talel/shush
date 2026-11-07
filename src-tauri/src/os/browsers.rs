//! Installed-browser detection for first-run onboarding (spec §10.1, issue #17).
//!
//! Detection only checks whether each browser's profile **folder exists**. It
//! never opens `Login Data`, `Local State`, `key4.db` or calls DPAPI: reading
//! another application's credential store is infostealer behaviour (and is
//! blocked by Chrome's App-Bound Encryption anyway). Instead the user exports a
//! CSV from the browser and imports it with [`crate::vault::importer`].

use std::path::{Path, PathBuf};

use serde::Serialize;

/// A browser shush knows how to guide an export from.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Browser {
    /// Stable id.
    pub id: &'static str,
    /// Display name.
    pub name: &'static str,
    /// Where to export passwords inside the browser (typed into its address bar).
    pub export_url: &'static str,
    /// Short export instructions.
    pub steps: &'static str,
}

const KNOWN: &[(Browser, Root, &str)] = &[
    (
        Browser {
            id: "chrome",
            name: "Google Chrome",
            export_url: "chrome://password-manager/settings",
            steps: "Export passwords → Export → save the .csv file",
        },
        Root::Local,
        r"Google\Chrome\User Data",
    ),
    (
        Browser {
            id: "edge",
            name: "Microsoft Edge",
            export_url: "edge://wallet/passwords",
            steps: "⋯ (More actions) → Export passwords → save the .csv file",
        },
        Root::Local,
        r"Microsoft\Edge\User Data",
    ),
    (
        Browser {
            id: "brave",
            name: "Brave",
            export_url: "brave://password-manager/settings",
            steps: "Export passwords → Export → save the .csv file",
        },
        Root::Local,
        r"BraveSoftware\Brave-Browser\User Data",
    ),
    (
        Browser {
            id: "firefox",
            name: "Mozilla Firefox",
            export_url: "about:logins",
            steps: "⋯ (menu) → Export passwords → save the .csv file",
        },
        Root::Roaming,
        r"Mozilla\Firefox\Profiles",
    ),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Root {
    /// `%LOCALAPPDATA%`
    Local,
    /// `%APPDATA%`
    Roaming,
}

/// Browsers whose profile directory exists under the given roots.
pub fn detect_in(local: Option<&Path>, roaming: Option<&Path>) -> Vec<Browser> {
    KNOWN
        .iter()
        .filter(|(_, root, rel)| {
            let base = match root {
                Root::Local => local,
                Root::Roaming => roaming,
            };
            base.is_some_and(|b| b.join(rel).is_dir())
        })
        .map(|(b, _, _)| b.clone())
        .collect()
}

/// Browsers installed for the current Windows user.
pub fn detect() -> Vec<Browser> {
    let local = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    let roaming = std::env::var_os("APPDATA").map(PathBuf::from);
    detect_in(local.as_deref(), roaming.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_only_existing_profile_dirs() {
        let local = tempfile::tempdir().unwrap();
        let roaming = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(local.path().join(r"Google\Chrome\User Data")).unwrap();
        std::fs::create_dir_all(roaming.path().join(r"Mozilla\Firefox\Profiles")).unwrap();
        // A file (not a directory) at Edge's path must not count.
        std::fs::create_dir_all(local.path().join(r"Microsoft\Edge")).unwrap();
        std::fs::write(local.path().join(r"Microsoft\Edge\User Data"), b"").unwrap();

        let ids: Vec<_> = detect_in(Some(local.path()), Some(roaming.path()))
            .into_iter()
            .map(|b| b.id)
            .collect();
        assert_eq!(ids, vec!["chrome", "firefox"]);
    }

    #[test]
    fn no_roots_no_browsers() {
        assert!(detect_in(None, None).is_empty());
    }
}
