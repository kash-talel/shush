//! Active foreground window context (spec §6.6), used **only** to pre-select a
//! likely Spotlight result. Owner decision (issues #13/#14): window titles are
//! spoofable by any web page, so they never trigger auto-type; the user still
//! confirms with Enter, which copies to the clipboard.

#![allow(unsafe_code)] // Win32 FFI; every block carries a SAFETY comment.

/// Browser title suffixes stripped before matching, longest first.
const BROWSER_SUFFIXES: &[&str] = &[
    " - Google Chrome",
    " - Microsoft\u{200b} Edge",
    " - Microsoft Edge",
    " — Mozilla Firefox",
    " - Mozilla Firefox",
    " - Brave",
    " - Opera",
    " - Vivaldi",
];

/// Strips a trailing browser name and the "Personal"/profile decorations
/// Edge and Chrome add, e.g. `"Sign in to GitHub · GitHub - Google Chrome"`
/// → `"Sign in to GitHub · GitHub"`.
pub fn clean_title(title: &str) -> String {
    let mut t = title.trim();
    for suffix in BROWSER_SUFFIXES {
        if let Some(stripped) = t.strip_suffix(suffix) {
            t = stripped;
            break;
        }
    }
    // Edge: "Title and 3 more pages - Personal - Microsoft Edge".
    for profile in [" - Personal", " - Work", " - Profile 1"] {
        if let Some(stripped) = t.strip_suffix(profile) {
            t = stripped;
        }
    }
    t.trim().to_string()
}

/// Title of the current foreground window, cleaned, unless it belongs to this
/// process (Spotlight must not "match" shush itself).
#[cfg(windows)]
pub fn foreground_title() -> Option<String> {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GetForegroundWindow, GetWindowTextLengthW, GetWindowTextW, GetWindowThreadProcessId,
    };
    // SAFETY: no preconditions; may return 0 (no foreground window).
    let hwnd = unsafe { GetForegroundWindow() };
    if hwnd == 0 {
        return None;
    }
    let mut pid = 0u32;
    // SAFETY: hwnd came from GetForegroundWindow; pid is a valid out pointer.
    unsafe { GetWindowThreadProcessId(hwnd, &mut pid) };
    if pid == std::process::id() {
        return None;
    }
    // SAFETY: hwnd is a window handle (possibly stale; the call then returns 0).
    let len = unsafe { GetWindowTextLengthW(hwnd) };
    if len <= 0 {
        return None;
    }
    let mut buf = vec![0u16; len as usize + 1];
    // SAFETY: buf has room for len + 1 UTF-16 units including the terminator.
    let n = unsafe { GetWindowTextW(hwnd, buf.as_mut_ptr(), buf.len() as i32) };
    if n <= 0 {
        return None;
    }
    let title = clean_title(&String::from_utf16_lossy(&buf[..n as usize]));
    (!title.is_empty()).then_some(title)
}

/// Non-Windows stub.
#[cfg(not(windows))]
pub fn foreground_title() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_browser_and_profile_suffixes() {
        assert_eq!(
            clean_title("Sign in to GitHub · GitHub - Google Chrome"),
            "Sign in to GitHub · GitHub"
        );
        assert_eq!(
            clean_title("Inbox - Gmail - Personal - Microsoft\u{200b} Edge"),
            "Inbox - Gmail"
        );
        assert_eq!(
            clean_title("Log in | Netflix — Mozilla Firefox"),
            "Log in | Netflix"
        );
        assert_eq!(clean_title("  Notepad  "), "Notepad");
        assert_eq!(clean_title(""), "");
    }
}
