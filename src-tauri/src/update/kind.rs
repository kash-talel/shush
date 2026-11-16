//! Install-type detection (issue #198).
//!
//! Only a per-user NSIS install may update itself. A per-machine MSI is managed by an
//! administrator (never downloaded or installed over), and a hand-copied `shush.exe` has no
//! install registration, so it is only told about new versions. Detection fails safe: anything
//! unreadable or ambiguous is [`InstallKind::Unknown`], which is notify-only.

use std::path::{Path, PathBuf};

use serde::Serialize;

/// How this copy of shush was installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallKind {
    /// Per-user NSIS install registered under HKCU: may self-update.
    Installer,
    /// Per-machine MSI registered under HKLM: managed by the organization, never touched.
    Managed,
    /// No install registration for this executable (hand-copied): notify only.
    HandCopied,
    /// Registry unreadable or ambiguous: notify only.
    Unknown,
}

impl InstallKind {
    /// May download and run an installer.
    pub fn can_self_update(self) -> bool {
        self == Self::Installer
    }

    /// Update checks make sense (a managed install is updated by its administrator).
    pub fn may_check(self) -> bool {
        self != Self::Managed
    }
}

/// Which registry hive/view to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hive {
    /// `HKEY_CURRENT_USER`.
    User,
    /// `HKEY_LOCAL_MACHINE`, 64-bit view.
    Machine64,
    /// `HKEY_LOCAL_MACHINE`, 32-bit view.
    Machine32,
}

/// Read-only registry access; the real one is Windows-only, tests use a fake.
pub trait Reg {
    /// A string (or DWORD, as decimal text) value; `Ok(None)` when key or value is absent.
    fn value(&self, hive: Hive, key: &str, name: &str) -> Result<Option<String>, String>;
    /// Names of the subkeys; empty when the key is absent.
    fn subkeys(&self, hive: Hive, key: &str) -> Result<Vec<String>, String>;
}

const UNINSTALL: &str = r"Software\Microsoft\Windows\CurrentVersion\Uninstall";

fn norm(p: &str) -> String {
    p.trim()
        .trim_matches('"')
        .trim_end_matches(['\\', '/'])
        .replace('/', "\\")
        .to_lowercase()
}

fn same_dir(a: &str, b: &Path) -> bool {
    norm(a) == norm(&b.to_string_lossy())
}

/// Directory of the executable inside an `UninstallString` such as `"C:\x\uninstall.exe" /arg`.
fn command_dir(cmd: &str) -> String {
    let t = cmd.trim();
    let exe = match t.strip_prefix('"') {
        Some(rest) => rest.split('"').next().unwrap_or(""),
        None => t.split(" /").next().unwrap_or(t),
    };
    PathBuf::from(exe)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Classifies the install of the executable in `exe_dir`. `product` is the product name used as
/// the NSIS uninstall key and as the MSI `DisplayName`. Reasons for `Unknown` go to `log`.
pub fn detect(
    reg: &dyn Reg,
    exe_dir: &Path,
    product: &str,
    log: &mut dyn FnMut(String),
) -> InstallKind {
    let mut unknown = |why: String| {
        log(format!(
            "install type unknown ({why}); updates are notify-only"
        ));
        InstallKind::Unknown
    };

    let key = format!(r"{UNINSTALL}\{product}");
    let per_user = match reg.value(Hive::User, &key, "UninstallString") {
        Err(e) => return unknown(format!("HKCU read failed: {e}")),
        Ok(None) => false,
        Ok(Some(cmd)) => same_dir(&command_dir(&cmd), exe_dir),
    };

    let mut machine = false;
    for hive in [Hive::Machine64, Hive::Machine32] {
        let names = match reg.subkeys(hive, UNINSTALL) {
            Ok(n) => n,
            Err(e) => return unknown(format!("HKLM enumeration failed: {e}")),
        };
        for n in names {
            let sub = format!(r"{UNINSTALL}\{n}");
            // Another program's entry that cannot be read (restricted ACL, odd value type) is
            // skipped: it must not cost a real per-user install its updates. This cannot unlock
            // self-update on its own, which still needs a matching HKCU registration.
            let display = match reg.value(hive, &sub, "DisplayName") {
                Ok(d) => d,
                Err(_) => continue,
            };
            if !display.is_some_and(|d| d.trim().eq_ignore_ascii_case(product)) {
                continue;
            }
            let loc = match reg.value(hive, &sub, "InstallLocation") {
                Ok(l) => l,
                Err(e) => return unknown(format!("HKLM read failed: {e}")),
            };
            let msi = match reg.value(hive, &sub, "WindowsInstaller") {
                Ok(v) => v.as_deref() == Some("1"),
                Err(e) => return unknown(format!("HKLM read failed: {e}")),
            };
            match loc.filter(|l| !l.trim().is_empty()) {
                Some(l) if same_dir(&l, exe_dir) => machine = true,
                Some(_) => {}
                // A machine-wide MSI without a recorded location cannot be ruled out: treat it
                // as covering this copy (this only ever blocks updates).
                None if msi => machine = true,
                None => {}
            }
        }
    }

    match (per_user, machine) {
        (true, true) => unknown("both a per-user and a machine-wide install match".into()),
        (true, false) => InstallKind::Installer,
        (false, true) => InstallKind::Managed,
        (false, false) => InstallKind::HandCopied,
    }
}

/// Detects the install type of the running executable, logging when it cannot tell.
pub fn detect_current(product: &str) -> InstallKind {
    let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
    else {
        eprintln!("shush: install type unknown (cannot find own path); updates are notify-only");
        return InstallKind::Unknown;
    };
    #[cfg(windows)]
    {
        detect(&win::WinReg, &dir, product, &mut |m| {
            eprintln!("shush: {m}")
        })
    }
    #[cfg(not(windows))]
    {
        let _ = (dir, product);
        InstallKind::Unknown
    }
}

#[cfg(windows)]
#[allow(unsafe_code)] // Win32 registry FFI; every block carries a SAFETY comment.
mod win {
    use super::{Hive, Reg};
    use windows_sys::Win32::Foundation::{
        ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_PATH_NOT_FOUND,
        ERROR_SUCCESS,
    };
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_CURRENT_USER,
        HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY, REG_DWORD, REG_EXPAND_SZ,
        REG_SZ,
    };

    pub struct WinReg;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    struct Key(HKEY);
    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: the handle was opened by RegOpenKeyExW and is closed once.
            unsafe { RegCloseKey(self.0) };
        }
    }

    fn open(hive: Hive, key: &str) -> Result<Option<Key>, String> {
        let (root, view) = match hive {
            Hive::User => (HKEY_CURRENT_USER, 0),
            Hive::Machine64 => (HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY),
            Hive::Machine32 => (HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY),
        };
        let mut h: HKEY = 0;
        let w = wide(key);
        // SAFETY: valid NUL-terminated key name and out pointer.
        let rc = unsafe { RegOpenKeyExW(root, w.as_ptr(), 0, KEY_READ | view, &mut h) };
        match rc {
            ERROR_SUCCESS => Ok(Some(Key(h))),
            ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => Ok(None),
            e => Err(format!("error {e}")),
        }
    }

    impl Reg for WinReg {
        fn value(&self, hive: Hive, key: &str, name: &str) -> Result<Option<String>, String> {
            let Some(k) = open(hive, key)? else {
                return Ok(None);
            };
            let n = wide(name);
            let mut cap = 1024u32;
            loop {
                let mut buf = vec![0u8; cap as usize];
                let mut len = cap;
                let mut ty = 0u32;
                // SAFETY: buffer and length describe the same allocation.
                let rc = unsafe {
                    RegQueryValueExW(
                        k.0,
                        n.as_ptr(),
                        std::ptr::null(),
                        &mut ty,
                        buf.as_mut_ptr(),
                        &mut len,
                    )
                };
                match rc {
                    ERROR_SUCCESS => {
                        return match ty {
                            REG_SZ | REG_EXPAND_SZ => {
                                let u: Vec<u16> = buf[..len as usize]
                                    .chunks_exact(2)
                                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                                    .take_while(|&c| c != 0)
                                    .collect();
                                Ok(Some(String::from_utf16_lossy(&u)))
                            }
                            REG_DWORD if len >= 4 => Ok(Some(
                                u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]).to_string(),
                            )),
                            _ => Err("unexpected value type".into()),
                        };
                    }
                    ERROR_FILE_NOT_FOUND => return Ok(None),
                    ERROR_MORE_DATA if cap < 64 * 1024 => cap = len.max(cap * 2),
                    e => return Err(format!("error {e}")),
                }
            }
        }

        fn subkeys(&self, hive: Hive, key: &str) -> Result<Vec<String>, String> {
            let Some(k) = open(hive, key)? else {
                return Ok(Vec::new());
            };
            let mut out = Vec::new();
            for i in 0u32..20_000 {
                let mut name = [0u16; 256];
                let mut len = name.len() as u32;
                // SAFETY: `name` has `len` u16 slots.
                let rc = unsafe {
                    RegEnumKeyExW(
                        k.0,
                        i,
                        name.as_mut_ptr(),
                        &mut len,
                        std::ptr::null(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    )
                };
                match rc {
                    ERROR_SUCCESS => out.push(String::from_utf16_lossy(&name[..len as usize])),
                    ERROR_NO_MORE_ITEMS => return Ok(out),
                    // A key name longer than the buffer cannot be ours: skip it.
                    ERROR_MORE_DATA => {}
                    e => return Err(format!("error {e}")),
                }
            }
            Err("too many subkeys".into())
        }
    }
}

#[cfg(test)]
mod tests;
