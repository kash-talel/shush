//! Windows integration (spec §6): clipboard (Phase 4), auto-lock triggers
//! (Phase 5). Auto-type, window-context detection and Windows Hello follow.

pub mod browsers;
pub mod clipboard;
pub mod memory;
pub mod native_host;
pub mod pipe;
pub mod private_dir;
pub mod recycle;
pub mod replace;
pub mod session;
pub mod win_context;
