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
  min_password_chars: number;
}

export interface VaultStatus {
  path: string;
  exists: boolean;
  unlocked: boolean;
  keyfile_required: boolean | null;
  cipher: CipherInfo | null;
  kdf: KdfParams | null;
  error: CmdError | null;
}

/** Counts only: item contents never cross the IPC boundary here. */
export interface VaultSummary {
  path: string;
  cipher: CipherInfo;
  kdf: KdfParams;
  keyfile_required: boolean;
  item_count: number;
  folder_count: number;
}

export interface KeyfileInfo {
  file_name: string;
  size_bytes: number;
}

export type KeyfileChoice =
  | { mode: "none" }
  | { mode: "existing"; path: string }
  | { mode: "generate"; path: string };

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
export const createVault = (password: string, keyfile: KeyfileChoice, cipherId: number) =>
  invoke<VaultSummary>("create_vault", { password, keyfile, cipherId });
export const unlock = (password: string, keyfilePath: string | null) =>
  invoke<VaultSummary>("unlock", { password, keyfilePath });
export const lock = () => invoke<void>("lock");

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / 1024 / 1024).toFixed(1)} MiB`;
}

export function formatKdf(k: KdfParams): string {
  return `ARGON2ID ${Math.round(k.mem_kib / 1024)}M/t${k.iterations}/p${k.parallelism}`;
}

/** Splits a path into [directory-with-separator, file name] for middle truncation. */
export function splitPath(p: string): [string, string] {
  const i = Math.max(p.lastIndexOf("\\"), p.lastIndexOf("/"));
  return [p.slice(0, i + 1), p.slice(i + 1)];
}
