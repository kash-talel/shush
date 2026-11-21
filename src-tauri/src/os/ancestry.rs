//! Browser-ancestry check for `shush-host.exe` (issue #159).
//!
//! The pair key lives in the browser profile on disk, so malware running as
//! the user could start the host itself. The host therefore refuses to relay
//! unless it was started by a browser: its parent is `chrome.exe`,
//! `msedge.exe` or `firefox.exe`, or `cmd.exe` whose parent is one of those
//! (Chromium starts native hosts through `cmd.exe`). Brave, Vivaldi and Opera
//! read Chrome's host registration too, so they are allowed as well.
//! Only the image file name is compared: a program renamed to `chrome.exe`
//! or parent-PID spoofing beats this, so it filters commodity tooling and is
//! not a boundary. Verifying the browser image's Authenticode publisher is
//! tracked separately (#260).

const BROWSERS: [&str; 6] = [
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "brave.exe",
    "vivaldi.exe",
    "opera.exe",
];

fn is_browser(name: &str) -> bool {
    BROWSERS.iter().any(|b| name.eq_ignore_ascii_case(b))
}

/// Whether a host whose parent process is `parent` (and that parent's parent
/// is `grandparent`) was started by a browser.
pub fn chain_allowed(parent: &str, grandparent: Option<&str>) -> bool {
    is_browser(parent)
        || (parent.eq_ignore_ascii_case("cmd.exe") && grandparent.is_some_and(is_browser))
}

#[cfg(windows)]
#[allow(unsafe_code)] // Win32 FFI; every block carries a SAFETY comment.
mod imp {
    use std::io;

    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcessId;

    /// `(pid, parent pid, exe file name)` of every running process.
    fn snapshot() -> io::Result<Vec<(u32, u32, String)>> {
        // SAFETY: plain snapshot call; the handle is closed below.
        let h = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if h == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let mut out = Vec::new();
        // SAFETY: zeroed PROCESSENTRY32W with dwSize set is the documented input.
        let mut e: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        // SAFETY: `h` is a live snapshot and `e` a valid entry.
        let mut more = unsafe { Process32FirstW(h, &mut e) } != 0;
        while more {
            let len = e.szExeFile.iter().position(|&c| c == 0).unwrap_or(0);
            out.push((
                e.th32ProcessID,
                e.th32ParentProcessID,
                String::from_utf16_lossy(&e.szExeFile[..len]),
            ));
            // SAFETY: as above.
            more = unsafe { Process32NextW(h, &mut e) } != 0;
        }
        // SAFETY: `h` came from CreateToolhelp32Snapshot.
        unsafe { CloseHandle(h) };
        Ok(out)
    }

    /// Image names of this process's parent and grandparent.
    pub fn parent_names() -> io::Result<(String, Option<String>)> {
        let procs = snapshot()?;
        // SAFETY: no arguments.
        let me = unsafe { GetCurrentProcessId() };
        let find = |pid: u32| procs.iter().find(|p| p.0 == pid);
        let parent = find(me)
            .and_then(|p| find(p.1))
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no parent process"))?;
        let grand = find(parent.1).map(|g| g.2.clone());
        Ok((parent.2.clone(), grand))
    }
}

/// Fails unless this process was started by a browser. Debug builds honour
/// `SHUSH_HOST_SKIP_ANCESTRY` so the e2e probes can start the host from
/// Node; release builds ignore it.
#[cfg(windows)]
pub fn require_browser_parent() -> Result<(), String> {
    if cfg!(debug_assertions) && std::env::var_os("SHUSH_HOST_SKIP_ANCESTRY").is_some() {
        return Ok(());
    }
    let (parent, grand) =
        imp::parent_names().map_err(|e| format!("cannot identify the parent: {e}"))?;
    if chain_allowed(&parent, grand.as_deref()) {
        Ok(())
    } else {
        Err(format!("not started by a browser (parent is {parent})"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browsers_and_cmd_under_a_browser_are_allowed() {
        assert!(chain_allowed("chrome.exe", None));
        assert!(chain_allowed("MSEdge.EXE", Some("explorer.exe")));
        assert!(chain_allowed("firefox.exe", None));
        assert!(chain_allowed("cmd.exe", Some("chrome.exe")));
        assert!(chain_allowed("CMD.EXE", Some("msedge.exe")));
        assert!(chain_allowed("cmd.exe", Some("brave.exe")));
    }

    #[test]
    fn arbitrary_parents_are_refused() {
        assert!(!chain_allowed("node.exe", Some("chrome.exe")));
        assert!(!chain_allowed("powershell.exe", None));
        assert!(!chain_allowed("cmd.exe", None));
        assert!(!chain_allowed("cmd.exe", Some("explorer.exe")));
        assert!(!chain_allowed("chrome.exe.evil.exe", None));
        assert!(!chain_allowed("", None));
    }

    #[cfg(windows)]
    #[test]
    fn this_test_process_is_not_browser_started() {
        let (parent, grand) = imp::parent_names().unwrap();
        assert!(!parent.is_empty());
        assert!(!chain_allowed(&parent, grand.as_deref()));
    }
}
