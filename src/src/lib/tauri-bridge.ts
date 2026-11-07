// Typed wrappers around Tauri `invoke()` commands.
//
// Security rule (see issue #6 / #20): commands must never return the whole
// decrypted vault or raw secrets to the WebView. Secrets are acted on in Rust
// (clipboard / auto-type) and only redacted views cross the IPC boundary.
import { invoke } from "@tauri-apps/api/core";

export type CipherSuiteId = "Aes256Gcm" | "XChaCha20Poly1305";

export interface AppInfo {
  version: string;
  supported_ciphers: CipherSuiteId[];
}

export function appInfo(): Promise<AppInfo> {
  return invoke<AppInfo>("app_info");
}
