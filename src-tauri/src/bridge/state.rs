//! Shared bridge state managed by Tauri (issue #52): the [`Bridge`] plus how
//! the pipe listener came up, so the UI can warn about a squatted pipe.
//!
//! Lock order: when both are needed, the vault state is taken first, then
//! [`BridgeState::bridge`]. Commands never hold the bridge while taking the
//! vault.

use std::sync::{Mutex, MutexGuard};

use super::protocol::Bridge;

/// Whether the pipe listener is serving.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Serving {
    /// Not started yet (or not supported on this platform).
    Starting,
    /// Accepting connections.
    Yes,
    /// Another process owns the pipe name; nothing is served.
    NameTaken,
    /// Any other failure to bind.
    Failed(String),
}

/// Bridge state for the running app.
pub struct BridgeState {
    bridge: Mutex<Bridge>,
    serving: Mutex<Serving>,
}

impl Default for BridgeState {
    fn default() -> Self {
        Self {
            bridge: Mutex::new(Bridge::sealed()),
            serving: Mutex::new(Serving::Starting),
        }
    }
}

impl BridgeState {
    /// The bridge. A panic elsewhere never bricks it.
    pub fn bridge(&self) -> MutexGuard<'_, Bridge> {
        self.bridge.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Records how the listener came up.
    pub fn set_serving(&self, s: Serving) {
        *self.serving.lock().unwrap_or_else(|e| e.into_inner()) = s;
    }

    /// How the listener came up.
    pub fn serving(&self) -> Serving {
        self.serving
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}
