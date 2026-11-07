//! Auto-lock triggers (spec §6.4, issue #15).
//!
//! A dedicated thread owns a hidden window that receives:
//! - `WM_WTSSESSION_CHANGE`: workstation lock (Win+L), log-off, RDP / console
//!   disconnect (fast user switching);
//! - `WM_POWERBROADCAST`: `PBT_APMSUSPEND` via `RegisterSuspendResumeNotification`
//!   (also delivered on Modern Standby), and `GUID_CONSOLE_DISPLAY_STATE` = off,
//!   which is what lid-close on S0ix laptops reliably produces.
//!
//! A second thread polls `GetLastInputInfo` (system-wide input, not just input
//! to shush) for the idle timeout.
//!
//! Tauri/tao own the main window procedure, so the hidden window keeps this
//! independent of the UI event loop.

#![allow(unsafe_code)] // Win32 FFI; every block carries a SAFETY comment.

use serde::Serialize;

/// Why the vault was locked automatically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LockReason {
    /// Workstation locked (Win+L).
    SessionLocked,
    /// User logging off.
    Logoff,
    /// Remote/console session disconnected (RDP, fast user switching).
    Disconnected,
    /// System suspending / hibernating.
    Suspend,
    /// Display turned off (lid close on Modern Standby devices).
    DisplayOff,
    /// No input for the configured idle period.
    Idle,
}

impl LockReason {
    /// Whether this trigger is governed by the `auto_lock_on_sleep` setting.
    /// Session lock / log-off / disconnect always lock.
    pub fn is_sleep_related(self) -> bool {
        matches!(self, Self::Suspend | Self::DisplayOff)
    }
}

const WM_WTSSESSION_CHANGE: u32 = 0x02B1;
const WM_POWERBROADCAST: u32 = 0x0218;
const PBT_APMSUSPEND: usize = 0x0004;
const PBT_POWERSETTINGCHANGE: usize = 0x8013;
const WTS_CONSOLE_DISCONNECT: usize = 0x2;
const WTS_REMOTE_DISCONNECT: usize = 0x4;
const WTS_SESSION_LOGOFF: usize = 0x6;
const WTS_SESSION_LOCK: usize = 0x7;

/// Maps a window message to a lock trigger. `display_state` is the DWORD
/// payload of a `GUID_CONSOLE_DISPLAY_STATE` power-setting change (0 = off,
/// 1 = on, 2 = dimmed), if this message carries one.
pub fn classify(msg: u32, wparam: usize, display_state: Option<u32>) -> Option<LockReason> {
    match (msg, wparam) {
        (WM_WTSSESSION_CHANGE, WTS_SESSION_LOCK) => Some(LockReason::SessionLocked),
        (WM_WTSSESSION_CHANGE, WTS_SESSION_LOGOFF) => Some(LockReason::Logoff),
        (WM_WTSSESSION_CHANGE, WTS_CONSOLE_DISCONNECT | WTS_REMOTE_DISCONNECT) => {
            Some(LockReason::Disconnected)
        }
        (WM_POWERBROADCAST, PBT_APMSUSPEND) => Some(LockReason::Suspend),
        (WM_POWERBROADCAST, PBT_POWERSETTINGCHANGE) if display_state == Some(0) => {
            Some(LockReason::DisplayOff)
        }
        _ => None,
    }
}

/// Whether the machine has been idle for at least `minutes`. Tick counts are
/// `GetTickCount` milliseconds, which wrap every ~49.7 days, hence `wrapping_sub`.
/// `minutes == 0` disables the idle lock.
pub fn idle_exceeded(now_tick: u32, last_input_tick: u32, minutes: u32) -> bool {
    minutes > 0 && u64::from(now_tick.wrapping_sub(last_input_tick)) >= u64::from(minutes) * 60_000
}

#[cfg(windows)]
mod imp {
    use super::{classify, LockReason};
    use std::sync::OnceLock;
    use windows_sys::Win32::Foundation::{HANDLE, HWND, LPARAM, LRESULT, WPARAM};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::System::Power::{
        RegisterPowerSettingNotification, RegisterSuspendResumeNotification, POWERBROADCAST_SETTING,
    };
    use windows_sys::Win32::System::RemoteDesktop::{
        WTSRegisterSessionNotification, NOTIFY_FOR_THIS_SESSION,
    };
    use windows_sys::Win32::System::SystemInformation::GetTickCount;
    use windows_sys::Win32::System::SystemServices::GUID_CONSOLE_DISPLAY_STATE;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, RegisterClassW,
        TranslateMessage, DEVICE_NOTIFY_WINDOW_HANDLE, MSG, WNDCLASSW, WS_OVERLAPPED,
    };

    type Callback = Box<dyn Fn(LockReason) + Send + Sync>;
    static CALLBACK: OnceLock<Callback> = OnceLock::new();

    extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
        let display_state = if msg == super::WM_POWERBROADCAST
            && wparam == super::PBT_POWERSETTINGCHANGE
            && lparam != 0
        {
            // SAFETY: for PBT_POWERSETTINGCHANGE, lparam points to a
            // POWERBROADCAST_SETTING valid for the duration of this call.
            let setting = unsafe { &*(lparam as *const POWERBROADCAST_SETTING) };
            let is_display = setting.PowerSetting.data1 == GUID_CONSOLE_DISPLAY_STATE.data1
                && setting.PowerSetting.data2 == GUID_CONSOLE_DISPLAY_STATE.data2
                && setting.PowerSetting.data3 == GUID_CONSOLE_DISPLAY_STATE.data3
                && setting.PowerSetting.data4 == GUID_CONSOLE_DISPLAY_STATE.data4;
            if is_display && setting.DataLength >= 4 {
                // SAFETY: Data is a variable-length array of DataLength (>= 4)
                // bytes; read_unaligned copes with its 1-byte alignment.
                Some(unsafe { std::ptr::read_unaligned(setting.Data.as_ptr().cast::<u32>()) })
            } else {
                None
            }
        } else {
            None
        };
        if let (Some(reason), Some(cb)) = (classify(msg, wparam, display_state), CALLBACK.get()) {
            // Never let a panic unwind across the FFI boundary.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cb(reason)));
        }
        // SAFETY: forwarding the original arguments to the default procedure.
        unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub(super) fn spawn_event_window(cb: Callback) {
        if CALLBACK.set(cb).is_err() {
            return; // already running
        }
        std::thread::Builder::new()
            .name("shush-session-events".into())
            .spawn(|| {
                let class = wide("shush.session-events");
                // SAFETY: NULL module name returns the current process module.
                let hinstance = unsafe { GetModuleHandleW(std::ptr::null()) };
                let wc = WNDCLASSW {
                    style: 0,
                    lpfnWndProc: Some(wndproc),
                    cbClsExtra: 0,
                    cbWndExtra: 0,
                    hInstance: hinstance,
                    hIcon: 0,
                    hCursor: 0,
                    hbrBackground: 0,
                    lpszMenuName: std::ptr::null(),
                    lpszClassName: class.as_ptr(),
                };
                // SAFETY: wc and the class name buffer outlive the call.
                if unsafe { RegisterClassW(&wc) } == 0 {
                    return;
                }
                // A hidden top-level window (never shown). Not HWND_MESSAGE:
                // message-only windows do not receive broadcast messages.
                // SAFETY: class registered above; all pointers valid for the call.
                let hwnd = unsafe {
                    CreateWindowExW(
                        0,
                        class.as_ptr(),
                        class.as_ptr(),
                        WS_OVERLAPPED,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        hinstance,
                        std::ptr::null(),
                    )
                };
                if hwnd == 0 {
                    return;
                }
                // SAFETY: hwnd is a live window owned by this thread; the GUID is a static.
                unsafe {
                    WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION);
                    RegisterSuspendResumeNotification(hwnd as HANDLE, DEVICE_NOTIFY_WINDOW_HANDLE);
                    RegisterPowerSettingNotification(
                        hwnd as HANDLE,
                        &GUID_CONSOLE_DISPLAY_STATE,
                        DEVICE_NOTIFY_WINDOW_HANDLE,
                    );
                }
                // SAFETY: MSG is plain data; zeroed is a valid initial state.
                let mut msg: MSG = unsafe { std::mem::zeroed() };
                // SAFETY: standard message loop on the thread that owns hwnd.
                while unsafe { GetMessageW(&mut msg, 0, 0, 0) } > 0 {
                    unsafe {
                        TranslateMessage(&msg);
                        DispatchMessageW(&msg);
                    }
                }
            })
            .expect("spawn session watcher thread");
    }

    /// (`GetTickCount()`, tick of last system-wide input).
    pub(super) fn ticks() -> Option<(u32, u32)> {
        let mut info = LASTINPUTINFO {
            cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
            dwTime: 0,
        };
        // SAFETY: info is a correctly sized, writable LASTINPUTINFO.
        if unsafe { GetLastInputInfo(&mut info) } == 0 {
            return None;
        }
        // SAFETY: no preconditions.
        Some((unsafe { GetTickCount() }, info.dwTime))
    }
}

/// Starts watching for session / power events. `on_event` runs on the watcher
/// thread and must be quick (it should just lock the vault).
pub fn watch_session(on_event: impl Fn(LockReason) + Send + Sync + 'static) {
    #[cfg(windows)]
    imp::spawn_event_window(Box::new(on_event));
    #[cfg(not(windows))]
    let _ = on_event;
}

/// Starts the idle watchdog. `idle_minutes` is queried on every poll so the
/// current vault setting always applies (return 0 when locked / disabled).
pub fn watch_idle(
    idle_minutes: impl Fn() -> u32 + Send + 'static,
    on_idle: impl Fn() + Send + 'static,
) {
    #[cfg(windows)]
    std::thread::Builder::new()
        .name("shush-idle-watch".into())
        .spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(10));
            let minutes = idle_minutes();
            if let Some((now, last)) = imp::ticks() {
                if idle_exceeded(now, last, minutes) {
                    on_idle();
                }
            }
        })
        .expect("spawn idle watcher thread");
    #[cfg(not(windows))]
    let _ = (idle_minutes, on_idle);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_messages() {
        assert_eq!(
            classify(WM_WTSSESSION_CHANGE, WTS_SESSION_LOCK, None),
            Some(LockReason::SessionLocked)
        );
        assert_eq!(
            classify(WM_WTSSESSION_CHANGE, WTS_SESSION_LOGOFF, None),
            Some(LockReason::Logoff)
        );
        assert_eq!(
            classify(WM_WTSSESSION_CHANGE, WTS_REMOTE_DISCONNECT, None),
            Some(LockReason::Disconnected)
        );
        assert_eq!(
            classify(WM_WTSSESSION_CHANGE, WTS_CONSOLE_DISCONNECT, None),
            Some(LockReason::Disconnected)
        );
        // WTS_SESSION_UNLOCK (8) and logon (5) must not lock.
        assert_eq!(classify(WM_WTSSESSION_CHANGE, 0x8, None), None);
        assert_eq!(classify(WM_WTSSESSION_CHANGE, 0x5, None), None);
    }

    #[test]
    fn power_messages() {
        assert_eq!(
            classify(WM_POWERBROADCAST, PBT_APMSUSPEND, None),
            Some(LockReason::Suspend)
        );
        assert_eq!(
            classify(WM_POWERBROADCAST, PBT_POWERSETTINGCHANGE, Some(0)),
            Some(LockReason::DisplayOff)
        );
        assert_eq!(
            classify(WM_POWERBROADCAST, PBT_POWERSETTINGCHANGE, Some(1)),
            None
        ); // on
        assert_eq!(
            classify(WM_POWERBROADCAST, PBT_POWERSETTINGCHANGE, Some(2)),
            None
        ); // dimmed
        assert_eq!(
            classify(WM_POWERBROADCAST, PBT_POWERSETTINGCHANGE, None),
            None
        ); // other setting
        assert_eq!(classify(WM_POWERBROADCAST, 0x12, None), None); // resume
        assert_eq!(classify(0x0010, 0, None), None); // WM_CLOSE
    }

    #[test]
    fn sleep_related_classification() {
        assert!(LockReason::Suspend.is_sleep_related());
        assert!(LockReason::DisplayOff.is_sleep_related());
        assert!(!LockReason::SessionLocked.is_sleep_related());
        assert!(!LockReason::Idle.is_sleep_related());
    }

    #[test]
    fn idle_threshold_and_tick_wraparound() {
        assert!(!idle_exceeded(10_000, 9_000, 1));
        assert!(idle_exceeded(70_000, 10_000, 1));
        assert!(!idle_exceeded(69_999, 10_000, 1));
        assert!(
            !idle_exceeded(u32::MAX, 0, 0),
            "0 minutes disables idle lock"
        );
        // GetTickCount wrapped: last input just before wrap, now just after.
        assert!(!idle_exceeded(5_000, u32::MAX - 5_000, 1));
        assert!(idle_exceeded(60_000, u32::MAX - 5_000, 1));
    }
}
