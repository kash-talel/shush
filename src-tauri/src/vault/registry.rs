//! The list of vaults this PC knows about (`vaults.json`).
//!
//! Holds only non-secret facts: a display name, the file path, the disc
//! colour and which vault was opened last. Nothing in here helps an attacker
//! decrypt a vault; it is the same information as a "recent files" list.
//!
//! The default vault (`%APPDATA%\com.shush.vault\vault.shush`) is always
//! listed while its file exists, so a lost or corrupt registry never hides it.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Disc colours, in assignment order. The UI has one disc image per name.
pub const VAULT_COLORS: [&str; 6] = ["crimson", "amber", "teal", "cobalt", "violet", "chrome"];
/// File name of the registry inside the app data directory.
pub const REGISTRY_FILE: &str = "vaults.json";
/// Vault file extension.
pub const VAULT_EXTENSION: &str = "shush";
/// Longest vault name, in characters.
pub const MAX_NAME_CHARS: usize = 40;

/// One known vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultEntry {
    /// Stable random id (not derived from the path).
    pub id: String,
    /// Display name, unique (case-insensitive) across the registry.
    pub name: String,
    /// Absolute path of the `.shush` file.
    pub path: PathBuf,
    /// One of [`VAULT_COLORS`].
    pub color: String,
}

/// The persisted registry.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registry {
    /// Format version.
    #[serde(default = "one")]
    pub version: u32,
    /// Known vaults, in display order.
    #[serde(default)]
    pub vaults: Vec<VaultEntry>,
    /// Id of the vault the unlock screen shows (the last one used).
    #[serde(default)]
    pub selected: Option<String>,
}

fn one() -> u32 {
    1
}

/// Registry validation errors; mapped to UI codes in `lib.rs`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    /// Empty, too long or containing control characters.
    #[error("Give the vault a name of 1 to {MAX_NAME_CHARS} characters.")]
    BadName,
    /// Another vault already has this name.
    #[error("Another vault is already called that. Pick a different name.")]
    DuplicateName,
    /// Unknown colour.
    #[error("Unknown disc colour.")]
    BadColor,
    /// This file is already in the list.
    #[error("That vault is already in the list.")]
    AlreadyListed,
    /// No vault with that id.
    #[error("That vault is no longer in the list.")]
    UnknownVault,
    /// The folder for a new vault does not exist.
    #[error("That folder does not exist.")]
    NoSuchFolder,
    /// A file (or attachment folder) is already at the new vault's location.
    #[error("Something is already saved at that location. Choose a new file name.")]
    LocationTaken,
    /// Path is not absolute.
    #[error("Choose a full file location.")]
    NotAbsolute,
    /// The default vault cannot be removed from the list while it exists.
    #[error("The default vault always shows while its file exists. Delete it instead.")]
    DefaultPinned,
    /// Disk error writing the registry.
    #[error("Could not save the vault list ({0}).")]
    Io(std::io::ErrorKind),
}

/// Checks and normalises a display name.
pub fn clean_name(name: &str) -> Result<String, RegistryError> {
    let n = name.trim();
    let chars = n.chars().count();
    if chars == 0 || chars > MAX_NAME_CHARS || n.chars().any(char::is_control) {
        return Err(RegistryError::BadName);
    }
    Ok(n.to_string())
}

/// Case-insensitive path identity. Resolves `..`, short names and symlinks
/// when the file exists, so two spellings of one file compare equal.
pub fn same_file(a: &Path, b: &Path) -> bool {
    fn key(p: &Path) -> String {
        let resolved = std::fs::canonicalize(p)
            .or_else(|_| std::path::absolute(p))
            .unwrap_or_else(|_| p.to_path_buf());
        resolved.to_string_lossy().to_lowercase()
    }
    key(a) == key(b)
}

/// Adds the `.shush` extension when missing.
pub fn with_extension(path: &Path) -> PathBuf {
    let ok = path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case(VAULT_EXTENSION));
    if ok {
        path.to_path_buf()
    } else {
        let mut s = path.as_os_str().to_os_string();
        s.push(".");
        s.push(VAULT_EXTENSION);
        PathBuf::from(s)
    }
}

/// Every file or folder that belongs to the vault at `path`.
pub fn vault_files(path: &Path) -> Vec<PathBuf> {
    use super::container::sibling;
    vec![
        path.to_path_buf(),
        sibling(path, "bak"),
        sibling(path, "tmp"),
        sibling(path, "d"),
        sibling(path, "lock"),
    ]
}

fn new_id() -> String {
    use rand::RngCore;
    let mut b = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl Registry {
    /// Loads `dir/vaults.json` and makes sure the default vault is listed if
    /// its file exists. A missing or unreadable registry starts empty (an
    /// unreadable one is kept aside as `vaults.json.corrupt`).
    pub fn load(dir: &Path, default_vault: &Path) -> Self {
        let file = dir.join(REGISTRY_FILE);
        let mut reg = match std::fs::read(&file) {
            Ok(bytes) => serde_json::from_slice::<Registry>(&bytes).unwrap_or_else(|_| {
                let _ = std::fs::rename(&file, dir.join(format!("{REGISTRY_FILE}.corrupt")));
                Registry::default()
            }),
            Err(_) => Registry::default(),
        };
        reg.version = 1;
        reg.repair();
        if default_vault.is_file() && reg.find_path(default_vault).is_none() {
            let name = reg.unique_name("Personal");
            reg.vaults.insert(
                0,
                VaultEntry {
                    id: new_id(),
                    name,
                    path: default_vault.to_path_buf(),
                    color: VAULT_COLORS[0].to_string(),
                },
            );
        }
        if reg.selected.as_ref().map_or(true, |s| reg.get(s).is_none()) {
            reg.selected = reg.vaults.first().map(|v| v.id.clone());
        }
        reg
    }

    /// [`Registry::load`], then writes the result back if loading changed it
    /// (default vault added, entries repaired), so ids stay stable between calls.
    pub fn load_persisted(dir: &Path, default_vault: &Path) -> Result<Self, RegistryError> {
        let on_disk = std::fs::read(dir.join(REGISTRY_FILE))
            .ok()
            .and_then(|b| serde_json::from_slice::<Registry>(&b).ok());
        let reg = Self::load(dir, default_vault);
        let empty = reg
            == Registry {
                version: 1,
                ..Default::default()
            };
        if on_disk.as_ref() != Some(&reg) && !(on_disk.is_none() && empty) {
            reg.save(dir)?;
        }
        Ok(reg)
    }

    /// Drops entries a hand-edited file could break: bad names, colours,
    /// relative paths and duplicates.
    fn repair(&mut self) {
        let mut seen: Vec<VaultEntry> = Vec::new();
        for mut v in std::mem::take(&mut self.vaults) {
            if v.id.is_empty() || !v.path.is_absolute() {
                continue;
            }
            if seen
                .iter()
                .any(|s| s.id == v.id || same_file(&s.path, &v.path))
            {
                continue;
            }
            v.name = clean_name(&v.name).unwrap_or_else(|_| "Vault".into());
            if !VAULT_COLORS.contains(&v.color.as_str()) {
                v.color = VAULT_COLORS[0].into();
            }
            let base = v.name.clone();
            let mut n = 2;
            while seen.iter().any(|s| s.name.eq_ignore_ascii_case(&v.name)) {
                v.name = format!("{base} {n}");
                n += 1;
            }
            seen.push(v);
        }
        self.vaults = seen;
    }

    /// Writes the registry atomically (tmp file + rename).
    pub fn save(&self, dir: &Path) -> Result<(), RegistryError> {
        let io = |e: std::io::Error| RegistryError::Io(e.kind());
        std::fs::create_dir_all(dir).map_err(io)?;
        let file = dir.join(REGISTRY_FILE);
        let tmp = dir.join(format!("{REGISTRY_FILE}.tmp"));
        let bytes = serde_json::to_vec_pretty(self).expect("registry serialises");
        std::fs::write(&tmp, bytes).map_err(io)?;
        std::fs::rename(&tmp, &file).map_err(io)
    }

    /// Entry by id.
    pub fn get(&self, id: &str) -> Option<&VaultEntry> {
        self.vaults.iter().find(|v| v.id == id)
    }

    /// Entry for a file path.
    pub fn find_path(&self, path: &Path) -> Option<&VaultEntry> {
        self.vaults.iter().find(|v| same_file(&v.path, path))
    }

    /// The selected entry.
    pub fn selected_entry(&self) -> Option<&VaultEntry> {
        self.selected.as_deref().and_then(|id| self.get(id))
    }

    /// `base`, or `base 2`, `base 3`… so it is unique.
    pub fn unique_name(&self, base: &str) -> String {
        let taken = |n: &str| self.vaults.iter().any(|v| v.name.eq_ignore_ascii_case(n));
        if !taken(base) {
            return base.to_string();
        }
        (2..)
            .map(|i| format!("{base} {i}"))
            .find(|n| !taken(n))
            .expect("unbounded")
    }

    /// The first colour no vault uses yet (cycling when all are taken).
    pub fn next_color(&self) -> &'static str {
        VAULT_COLORS
            .iter()
            .find(|c| !self.vaults.iter().any(|v| v.color == **c))
            .copied()
            .unwrap_or(VAULT_COLORS[self.vaults.len() % VAULT_COLORS.len()])
    }

    fn check_name(&self, name: &str, except: Option<&str>) -> Result<String, RegistryError> {
        let n = clean_name(name)?;
        if self
            .vaults
            .iter()
            .any(|v| Some(v.id.as_str()) != except && v.name.eq_ignore_ascii_case(&n))
        {
            return Err(RegistryError::DuplicateName);
        }
        Ok(n)
    }

    fn check_color(color: Option<&str>) -> Result<Option<&'static str>, RegistryError> {
        match color {
            None => Ok(None),
            Some(c) => VAULT_COLORS
                .iter()
                .find(|k| **k == c)
                .copied()
                .map(Some)
                .ok_or(RegistryError::BadColor),
        }
    }

    /// Validates the location and name for a vault that does not exist yet.
    /// Returns the final path (with `.shush`) and the cleaned name.
    pub fn check_new(&self, path: &Path, name: &str) -> Result<(PathBuf, String), RegistryError> {
        if !path.is_absolute() {
            return Err(RegistryError::NotAbsolute);
        }
        let path = with_extension(path);
        if !path.parent().is_some_and(Path::is_dir) {
            return Err(RegistryError::NoSuchFolder);
        }
        if vault_files(&path).iter().any(|p| p.exists()) {
            return Err(RegistryError::LocationTaken);
        }
        if self.find_path(&path).is_some() {
            return Err(RegistryError::AlreadyListed);
        }
        Ok((path, self.check_name(name, None)?))
    }

    /// Adds a vault (new or existing file) and selects it. The caller has
    /// already checked that the file is, or just became, a vault.
    pub fn add(
        &mut self,
        path: PathBuf,
        name: &str,
        color: Option<&str>,
    ) -> Result<VaultEntry, RegistryError> {
        if !path.is_absolute() {
            return Err(RegistryError::NotAbsolute);
        }
        if self.find_path(&path).is_some() {
            return Err(RegistryError::AlreadyListed);
        }
        let name = self.check_name(name, None)?;
        let color = Self::check_color(color)?.unwrap_or_else(|| self.next_color());
        let entry = VaultEntry {
            id: new_id(),
            name,
            path,
            color: color.to_string(),
        };
        self.vaults.push(entry.clone());
        self.selected = Some(entry.id.clone());
        Ok(entry)
    }

    /// Renames and/or recolours a vault.
    pub fn update(&mut self, id: &str, name: &str, color: &str) -> Result<(), RegistryError> {
        let name = self.check_name(name, Some(id))?;
        let color = Self::check_color(Some(color))?.expect("some in, some out");
        let v = self
            .vaults
            .iter_mut()
            .find(|v| v.id == id)
            .ok_or(RegistryError::UnknownVault)?;
        v.name = name;
        v.color = color.to_string();
        Ok(())
    }

    /// Makes `id` the vault the unlock screen shows.
    pub fn select(&mut self, id: &str) -> Result<(), RegistryError> {
        if self.get(id).is_none() {
            return Err(RegistryError::UnknownVault);
        }
        self.selected = Some(id.to_string());
        Ok(())
    }

    /// Removes an entry (the file is untouched). If it was selected, the
    /// first remaining vault becomes selected.
    pub fn remove(&mut self, id: &str) -> Result<VaultEntry, RegistryError> {
        let i = self
            .vaults
            .iter()
            .position(|v| v.id == id)
            .ok_or(RegistryError::UnknownVault)?;
        let entry = self.vaults.remove(i);
        if self.selected.as_deref() == Some(id) {
            self.selected = self.vaults.first().map(|v| v.id.clone());
        }
        Ok(entry)
    }
}

/// Brute-force brake for vault deletion: after a few wrong passwords the
/// next attempt must wait, doubling each time (on top of Argon2id's cost).
#[derive(Debug, Default)]
pub struct DeleteThrottle {
    failures: std::collections::HashMap<String, (u32, Option<std::time::Instant>)>,
}

/// Free attempts before the wait starts.
const FREE_ATTEMPTS: u32 = 3;
/// First wait, in seconds; doubles per further failure, capped at 15 min.
const BASE_WAIT_SECS: u64 = 30;
const MAX_WAIT_SECS: u64 = 15 * 60;

impl DeleteThrottle {
    /// Seconds left before `id` may be tried again, if it is cooling down.
    pub fn wait_secs(&self, id: &str, now: std::time::Instant) -> Option<u64> {
        let (_, until) = self.failures.get(id)?;
        let until = (*until)?;
        (until > now).then(|| (until - now).as_secs().max(1))
    }

    /// Records a wrong password; returns the new wait, if any.
    pub fn fail(&mut self, id: &str, now: std::time::Instant) -> Option<u64> {
        let e = self.failures.entry(id.to_string()).or_insert((0, None));
        e.0 += 1;
        if e.0 < FREE_ATTEMPTS {
            return None;
        }
        let secs = (BASE_WAIT_SECS << (e.0 - FREE_ATTEMPTS).min(10)).min(MAX_WAIT_SECS);
        e.1 = Some(now + std::time::Duration::from_secs(secs));
        Some(secs)
    }

    /// Clears the record after a correct password.
    pub fn succeed(&mut self, id: &str) {
        self.failures.remove(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn touch(p: &Path) {
        std::fs::write(p, b"x").unwrap();
    }

    #[test]
    fn default_vault_is_listed_and_selected_when_it_exists() {
        let dir = tempfile::tempdir().unwrap();
        let def = dir.path().join("vault.shush");
        assert!(Registry::load(dir.path(), &def).vaults.is_empty());

        touch(&def);
        let reg = Registry::load(dir.path(), &def);
        assert_eq!(reg.vaults.len(), 1);
        assert_eq!(reg.vaults[0].name, "Personal");
        assert_eq!(reg.vaults[0].color, "crimson");
        assert_eq!(reg.selected_entry().unwrap().path, def);
    }

    #[test]
    fn add_select_save_and_reload_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let def = dir.path().join("vault.shush");
        touch(&def);
        let mut reg = Registry::load(dir.path(), &def);
        let work = dir.path().join("work.shush");
        let e = reg.add(work.clone(), "  Work ", None).unwrap();
        assert_eq!(e.name, "Work");
        assert_eq!(e.color, "amber", "next unused colour");
        assert_eq!(reg.selected.as_deref(), Some(e.id.as_str()));
        reg.save(dir.path()).unwrap();

        let again = Registry::load(dir.path(), &def);
        assert_eq!(again, reg);
    }

    #[test]
    fn names_are_unique_and_validated() {
        let dir = tempfile::tempdir().unwrap();
        let def = dir.path().join("vault.shush");
        touch(&def);
        let mut reg = Registry::load(dir.path(), &def);
        let p = dir.path().join("b.shush");
        assert_eq!(
            reg.add(p.clone(), "personal", None),
            Err(RegistryError::DuplicateName)
        );
        assert_eq!(reg.add(p.clone(), "   ", None), Err(RegistryError::BadName));
        assert_eq!(
            reg.add(p.clone(), "a\u{7}b", None),
            Err(RegistryError::BadName)
        );
        assert_eq!(
            reg.add(p.clone(), &"x".repeat(41), None),
            Err(RegistryError::BadName)
        );
        assert_eq!(
            reg.add(p.clone(), "B", Some("pink")),
            Err(RegistryError::BadColor)
        );
        let id = reg.add(p, "B", Some("chrome")).unwrap().id;
        // Renaming to its own name in other case is fine; to another's is not.
        reg.update(&id, "b", "teal").unwrap();
        assert_eq!(
            reg.update(&id, "PERSONAL", "teal"),
            Err(RegistryError::DuplicateName)
        );
    }

    #[test]
    fn same_file_cannot_be_listed_twice() {
        let dir = tempfile::tempdir().unwrap();
        let def = dir.path().join("vault.shush");
        touch(&def);
        let mut reg = Registry::load(dir.path(), &def);
        let spelled = dir.path().join("sub").join("..").join("VAULT.SHUSH");
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        assert_eq!(
            reg.add(spelled, "Again", None),
            Err(RegistryError::AlreadyListed)
        );
    }

    #[test]
    fn check_new_adds_extension_and_refuses_taken_locations() {
        let dir = tempfile::tempdir().unwrap();
        let def = dir.path().join("vault.shush");
        let reg = Registry::load(dir.path(), &def);
        let (p, n) = reg.check_new(&dir.path().join("work"), "Work").unwrap();
        assert_eq!(p, dir.path().join("work.shush"));
        assert_eq!(n, "Work");

        touch(&dir.path().join("taken.shush"));
        assert_eq!(
            reg.check_new(&dir.path().join("taken.shush"), "T"),
            Err(RegistryError::LocationTaken)
        );
        // A leftover attachment folder would mix two vaults' blobs.
        std::fs::create_dir(dir.path().join("old.shush.d")).unwrap();
        assert_eq!(
            reg.check_new(&dir.path().join("old.shush"), "O"),
            Err(RegistryError::LocationTaken)
        );
        assert_eq!(
            reg.check_new(&dir.path().join("nope").join("x.shush"), "X"),
            Err(RegistryError::NoSuchFolder)
        );
        assert_eq!(
            reg.check_new(Path::new("relative.shush"), "R"),
            Err(RegistryError::NotAbsolute)
        );
    }

    #[test]
    fn removing_the_selected_vault_selects_another() {
        let dir = tempfile::tempdir().unwrap();
        let def = dir.path().join("vault.shush");
        touch(&def);
        let mut reg = Registry::load(dir.path(), &def);
        let id = reg.add(dir.path().join("w.shush"), "W", None).unwrap().id;
        reg.remove(&id).unwrap();
        assert_eq!(reg.selected_entry().unwrap().path, def);
        assert_eq!(reg.remove(&id), Err(RegistryError::UnknownVault));
    }

    #[test]
    fn corrupt_or_hand_edited_registry_is_repaired() {
        let dir = tempfile::tempdir().unwrap();
        let def = dir.path().join("vault.shush");
        touch(&def);
        std::fs::write(dir.path().join(REGISTRY_FILE), b"{not json").unwrap();
        let reg = Registry::load(dir.path(), &def);
        assert_eq!(reg.vaults.len(), 1);
        assert!(dir.path().join("vaults.json.corrupt").exists());

        let abs = dir.path().join("a.shush");
        let json = serde_json::json!({
            "version": 1,
            "selected": "gone",
            "vaults": [
                { "id": "1", "name": "A", "path": abs, "color": "neon" },
                { "id": "2", "name": "a", "path": dir.path().join("b.shush"), "color": "teal" },
                { "id": "3", "name": "dup path", "path": abs, "color": "teal" },
                { "id": "4", "name": "rel", "path": "rel.shush", "color": "teal" }
            ]
        });
        std::fs::write(dir.path().join(REGISTRY_FILE), json.to_string()).unwrap();
        let reg = Registry::load(dir.path(), &def);
        let names: Vec<_> = reg.vaults.iter().map(|v| v.name.as_str()).collect();
        assert_eq!(names, ["Personal", "A", "a 2"]);
        assert_eq!(reg.vaults[1].color, "crimson");
        assert_eq!(reg.selected.as_deref(), Some(reg.vaults[0].id.as_str()));
    }

    #[test]
    fn throttle_waits_after_free_attempts_and_doubles() {
        let mut t = DeleteThrottle::default();
        let now = std::time::Instant::now();
        assert_eq!(t.fail("v", now), None);
        assert_eq!(t.fail("v", now), None);
        assert_eq!(t.fail("v", now), Some(30));
        assert_eq!(t.wait_secs("v", now), Some(30));
        assert_eq!(t.wait_secs("other", now), None);
        let later = now + std::time::Duration::from_secs(31);
        assert_eq!(t.wait_secs("v", later), None);
        assert_eq!(t.fail("v", later), Some(60));
        for _ in 0..20 {
            t.fail("v", later);
        }
        assert_eq!(t.wait_secs("v", later), Some(MAX_WAIT_SECS));
        t.succeed("v");
        assert_eq!(t.wait_secs("v", later), None);
    }
}
