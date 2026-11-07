// Typed wrappers around Tauri `invoke()` commands.
//
// Security rule (see issue #6 / #20): commands must never return the whole
// decrypted vault or raw secrets to the WebView. Secrets are acted on in Rust
// (clipboard / auto-type) and only redacted views cross the IPC boundary.
import { invoke } from "@tauri-apps/api/core";

export interface CipherInfo {
  id: number;
  name: string;
}

export interface KdfParams {
  mem_kib: number;
  iterations: number;
  parallelism: number;
}

export interface AppInfo {
  version: string;
  default_cipher: CipherInfo;
  supported_ciphers: CipherInfo[];
  default_kdf: KdfParams;
}

export interface VaultStatus {
  path: string;
  exists: boolean;
}

export interface KeyfileInfo {
  file_name: string;
  size_bytes: number;
}

/** Error shape returned by every Rust command. Never contains secrets. */
export interface CmdError {
  code: string;
  message: string;
}

/** Normalises anything thrown by `invoke` into a {@link CmdError}. */
export function toCmdError(e: unknown): CmdError {
  if (e && typeof e === "object" && "code" in e && "message" in e) {
    return { code: String(e.code), message: String(e.message) };
  }
  return { code: "INTERNAL", message: String(e) };
}

export const appInfo = () => invoke<AppInfo>("app_info");
export const vaultStatus = () => invoke<VaultStatus>("vault_status");
export const inspectKeyfile = (path: string) => invoke<KeyfileInfo>("inspect_keyfile", { path });
export const unlock = (password: string, keyfilePath: string | null) =>
  invoke<void>("unlock", { password, keyfilePath });
