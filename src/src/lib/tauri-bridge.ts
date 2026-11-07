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

/** Why the backend locked the vault on its own (session / power / idle / tray). */
export type AutoLockReason =
  | "session_locked"
  | "logoff"
  | "disconnected"
  | "suspend"
  | "display_off"
  | "idle"
  | "tray";

export const AUTO_LOCK_EVENT = "vault-auto-locked";

export function describeAutoLock(r: AutoLockReason): string {
  switch (r) {
    case "session_locked":
      return "Windows was locked";
    case "logoff":
      return "you signed out of Windows";
    case "disconnected":
      return "the session was disconnected";
    case "suspend":
      return "the PC went to sleep";
    case "display_off":
      return "the display turned off";
    case "idle":
      return "of inactivity";
    case "tray":
      return "it was locked from the tray";
  }
}

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

// ---- Items (Phase 4) --------------------------------------------------------

export type ItemKind = "login" | "secure_note";
export type SecretField = "password" | "username" | "totp";

/** List row. Never contains passwords or TOTP secrets. */
export interface ItemSummary {
  id: string;
  kind: ItemKind;
  title: string;
  subtitle: string;
  host: string;
  favorite: boolean;
  has_totp: boolean;
  updated_at: string;
}

/** Detail view. Never contains the password or TOTP secret. */
export interface ItemDetail {
  id: string;
  kind: ItemKind;
  title: string;
  username: string;
  url: string;
  notes: string;
  content: string;
  tags: string[];
  favorite: boolean;
  has_password: boolean;
  has_totp: boolean;
  history_count: number;
  created_at: string;
  updated_at: string;
}

/** Editor payload. `password` / `totp`: `null` = keep current, "" = clear. */
export interface ItemDraft {
  title: string;
  username: string;
  password: string | null;
  url: string;
  totp: string | null;
  notes: string;
  content: string;
  favorite: boolean;
  tags: string[];
}

export interface TotpCode {
  code: string;
  period: number;
  remaining: number;
}

export interface GeneratorOptions {
  length: number;
  lower: boolean;
  upper: boolean;
  digits: boolean;
  symbols: boolean;
  exclude_ambiguous: boolean;
}

export const listItems = () => invoke<ItemSummary[]>("list_items");
export const getItem = (id: string) => invoke<ItemDetail>("get_item", { id });
export const createItem = (kind: ItemKind, draft: ItemDraft) => invoke<ItemDetail>("create_item", { kind, draft });
export const updateItem = (id: string, draft: ItemDraft) => invoke<ItemDetail>("update_item", { id, draft });
export const deleteItem = (id: string) => invoke<void>("delete_item", { id });
export const setFavorite = (id: string, favorite: boolean) => invoke<void>("set_favorite", { id, favorite });
/** Copies in Rust (history/cloud-excluded); resolves to seconds until auto-clear. */
export const copyField = (id: string, field: SecretField) => invoke<number>("copy_field", { id, field });
export const revealPassword = (id: string) => invoke<string>("reveal_password", { id });
export const totpCode = (id: string) => invoke<TotpCode>("totp_code", { id });
export const generatePassword = (options: GeneratorOptions) =>
  invoke<{ password: string; entropy_bits: number }>("generate_password", { options });

// ---- Backup / import (Phase 6) ------------------------------------------------

export type BackupCredentials =
  | { mode: "same_as_vault" }
  | { mode: "dedicated"; password: string; keyfile_path: string | null };

export interface BackupInfo {
  keyfile_required: boolean;
  cipher: CipherInfo;
}

/** Counts only: what an import would do. */
export interface ImportPreview {
  exported_at: string;
  total: number;
  new_items: number;
  identical: number;
  conflicts: number;
}

export type ImportMode = "merge" | "replace";

export const exportBackup = (path: string, credentials: BackupCredentials) =>
  invoke<number>("export_backup", { path, credentials });
export const inspectBackup = (path: string) => invoke<BackupInfo>("inspect_backup", { path });
export const previewImport = (path: string, password: string, keyfilePath: string | null) =>
  invoke<ImportPreview>("preview_import", { path, password, keyfilePath });
export const applyImport = (path: string, password: string, keyfilePath: string | null, mode: ImportMode) =>
  invoke<number>("apply_import", { path, password, keyfilePath, mode });
