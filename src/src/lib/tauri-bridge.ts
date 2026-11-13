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
  /** Global Spotlight hotkey, or null if another app already owns it. */
  spotlight_hotkey: string | null;
}

export interface VaultStatus {
  /** Registry id; null on first run before any vault exists. */
  id: string | null;
  name: string | null;
  color: VaultColor;
  path: string;
  exists: boolean;
  unlocked: boolean;
  read_only: boolean;
  keyfile_required: boolean | null;
  cipher: CipherInfo | null;
  kdf: KdfParams | null;
  error: CmdError | null;
  hide_names: boolean;
  can_delete: boolean;
}

/** Counts only: item contents never cross the IPC boundary here. */
export interface VaultSummary {
  path: string;
  cipher: CipherInfo;
  kdf: KdfParams;
  keyfile_required: boolean;
  item_count: number;
  folder_count: number;
  read_only: boolean;
}

export interface KeyfileInfo {
  file_name: string;
  size_bytes: number;
  /** True for a shush-generated, checksum-verified keyfile. */
  generated: boolean;
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
export const createVault = (
  password: string,
  keyfile: KeyfileChoice,
  cipherId: number,
  target: NewVaultTarget | null = null,
) => invoke<VaultSummary>("create_vault", { password, keyfile, cipherId, target });

/**
 * Binary framing for unlock payload:
 * Byte 0: flags (bit 0 = has vaultId, bit 1 = has keyfilePath)
 * [vaultId length: u16 LE][vaultId UTF-8] (if bit 0 set)
 * [keyfilePath length: u16 LE][keyfilePath UTF-8] (if bit 1 set)
 * [password UTF-8]
 *
 * Sent as a raw byte array (Uint8Array) so Tauri receives `InvokeBody::Raw`
 * and wipes the IPC buffer immediately without intermediate JSON String copies (issue #59).
 */
export function encodeUnlockPayload(
  password: string,
  keyfilePath: string | null,
  vaultId: string | null,
): Uint8Array {
  const enc = new TextEncoder();
  const pw = enc.encode(password);
  const kf = keyfilePath ? enc.encode(keyfilePath) : null;
  const id = vaultId ? enc.encode(vaultId) : null;

  let flags = 0;
  let len = 1;
  if (id) {
    flags |= 1;
    len += 2 + id.length;
  }
  if (kf) {
    flags |= 2;
    len += 2 + kf.length;
  }
  len += pw.length;

  const buf = new Uint8Array(len);
  let off = 0;
  buf[off++] = flags;
  const view = new DataView(buf.buffer);
  if (id) {
    view.setUint16(off, id.length, true);
    off += 2;
    buf.set(id, off);
    off += id.length;
  }
  if (kf) {
    view.setUint16(off, kf.length, true);
    off += 2;
    buf.set(kf, off);
    off += kf.length;
  }
  buf.set(pw, off);
  return buf;
}

export const unlock = (password: string, keyfilePath: string | null, vaultId: string | null) =>
  invoke<VaultSummary>("unlock", encodeUnlockPayload(password, keyfilePath, vaultId));
/** Reloads the active vault from disk without locking (issue #49). */
export const reloadVault = (password?: string, keyfilePath?: string) =>
  invoke<VaultSummary>("reload_vault", { password: password ?? null, keyfilePath: keyfilePath ?? null });

// ---- Vault list (switch / add / delete) -------------------------------------

export type VaultColor = "crimson" | "amber" | "teal" | "cobalt" | "violet" | "chrome";

/** One vault on the unlock screen's shelf. No secrets. */
export interface VaultCard {
  id: string;
  name: string;
  path: string;
  color: VaultColor;
  is_default: boolean;
  selected: boolean;
  exists: boolean;
  keyfile_required: boolean | null;
  error: CmdError | null;
  can_delete: boolean;
}

export interface VaultList {
  vaults: VaultCard[];
  colors: VaultColor[];
  max_name_chars: number;
  hide_names: boolean;
}

/** Where and under which name to create an additional vault. */
export interface NewVaultTarget {
  path: string;
  name: string;
  color: VaultColor | null;
}

export const listVaults = () => invoke<VaultList>("list_vaults");
export const selectVault = (id: string) => invoke<VaultStatus>("select_vault", { id });
/** Returns the final path (".shush" added when missing). */
export const checkNewVault = (path: string, name: string) => invoke<string>("check_new_vault", { path, name });
export const addExistingVault = (path: string, name: string, color: VaultColor | null) =>
  invoke<VaultStatus>("add_existing_vault", { path, name, color });
export const updateVault = (id: string, name: string, color: VaultColor) =>
  invoke<void>("update_vault", { id, name, color });
export const forgetVault = (id: string) => invoke<void>("forget_vault", { id });
export const setHideVaultNames = (hide: boolean) =>
  invoke<VaultStatus>("set_hide_vault_names", { hide });
export const deleteVault = (id: string, password: string, keyfilePath: string | null, confirmName: string) =>
  invoke<void>("delete_vault", { id, password, keyfilePath, confirmName });
export const showInExplorer = (id: string) => invoke<void>("show_in_explorer", { id });
export const lock = () => invoke<void>("lock");
export const showSpotlight = () => invoke<void>("show_spotlight");

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
  folder_id: string | null;
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
  folder_id: string | null;
  favorite: boolean;
  has_password: boolean;
  has_totp: boolean;
  history_count: number;
  attachments: AttachmentInfo[];
  created_at: string;
  updated_at: string;
}

export interface AttachmentInfo {
  id: string;
  filename: string;
  mime_type: string;
  size_bytes: number;
  created_at: string;
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
  folder_id: string | null;
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
/** Erases a login's archived passwords (issue #19); resolves to the updated item. */
export const purgeHistory = (id: string) => invoke<ItemDetail>("purge_history", { id });
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
  /** Items deleted from this vault since; a merge does not bring them back. */
  deleted_locally: number;
}

export type ImportMode = "merge" | "replace";

export const exportBackup = (path: string, credentials: BackupCredentials) =>
  invoke<number>("export_backup", { path, credentials });
export const inspectBackup = (path: string) => invoke<BackupInfo>("inspect_backup", { path });
export const previewImport = (path: string, password: string, keyfilePath: string | null) =>
  invoke<ImportPreview>("preview_import", { path, password, keyfilePath });
export const applyImport = (path: string, password: string, keyfilePath: string | null, mode: ImportMode) =>
  invoke<number>("apply_import", { path, password, keyfilePath, mode });

// ---- CSV migration (Phase 6b) -------------------------------------------------

export type CsvFormat = "chromium" | "firefox" | "bitwarden" | "one_password" | "kee_pass" | "kee_pass_xc" | "generic";

export interface CsvSummary {
  format: CsvFormat | null;
  total: number;
  new_items: number;
  identical: number;
  conflicts: number;
  skipped: number;
  invalid_totp: number;
}

export const CSV_FORMAT_LABEL: Record<CsvFormat, string> = {
  chromium: "Chrome / Edge / Brave",
  firefox: "Firefox",
  bitwarden: "Bitwarden",
  one_password: "1Password",
  kee_pass: "KeePass",
  kee_pass_xc: "KeePassXC",
  generic: "Generic CSV",
};

export const previewCsv = (path: string) => invoke<CsvSummary>("preview_csv", { path });
export const importCsv = (path: string) => invoke<CsvSummary>("import_csv", { path });
export const shredCsv = (path: string) => invoke<void>("shred_csv", { path });

// ---- Onboarding (Phase 7a) ------------------------------------------------------

export interface Browser {
  id: string;
  name: string;
  export_url: string;
  steps: string;
}

/** Browsers whose profile folder exists. Their password stores are never read. */
export const detectBrowsers = () => invoke<Browser[]>("detect_browsers");

// ---- Folders (Phase 4b) ---------------------------------------------------------

export interface FolderInfo {
  id: string;
  name: string;
  item_count: number;
}

export const listFolders = () => invoke<FolderInfo[]>("list_folders");
export const createFolder = (name: string) => invoke<string>("create_folder", { name });
export const renameFolder = (id: string, name: string) => invoke<void>("rename_folder", { id, name });
/** Items in the folder are kept (moved to "no folder"); resolves to how many moved. */
export const deleteFolder = (id: string) => invoke<number>("delete_folder", { id });

// ---- Attachments (Phase 4c) -------------------------------------------------------

export const addAttachment = (itemId: string, path: string) => invoke<ItemDetail>("add_attachment", { itemId, path });
/** Writes the decrypted file to `dest` (an explicit, user-chosen export). */
export const saveAttachment = (attachmentId: string, dest: string) =>
  invoke<void>("save_attachment", { attachmentId, dest });
export const deleteAttachment = (itemId: string, attachmentId: string) =>
  invoke<ItemDetail>("delete_attachment", { itemId, attachmentId });

// ---- duress vault (issue #8) ----------------------------------------------------

/** Whether the unlocked vault has a duress password. A decoy always reports false. */
export const duressStatus = () => invoke<boolean>("duress_status");
/** Seals an empty decoy vault under `password`, replacing any previous decoy. */
export const setDuressPassword = (password: string, keyfilePath: string | null) =>
  invoke<void>("set_duress_password", { password, keyfilePath });
/** Destroys the decoy vault. */
export const clearDuressPassword = () => invoke<void>("clear_duress_password");

// ---- browser bridge (issue #52) -------------------------------------------------

export interface BridgePairing {
  code: string;
  seconds_left: number;
}
export interface BridgeInfo {
  /** Whether the native-messaging pipe is being served. */
  serving: boolean;
  /** Plain-words reason when it is not (e.g. the pipe name is squatted). */
  warning: string | null;
  pairings: { id: string }[];
  /** Saves offered by the extension; passwords never reach the UI. */
  pending: { origin: string; username: string }[];
  code: BridgePairing | null;
}
export const bridgeState = () => invoke<BridgeInfo>("bridge_state");
export const bridgeStartPairing = () => invoke<BridgePairing>("bridge_start_pairing");
export const bridgeCancelPairing = () => invoke<void>("bridge_cancel_pairing");
export const bridgeRevoke = (id: string) => invoke<void>("bridge_revoke", { id });
/** Writes the pending save into the vault (new login, or password update). */
export const bridgeApproveSave = (origin: string, username: string) =>
  invoke<string>("bridge_approve_save", { origin, username });
export const bridgeRejectSave = (origin: string, username: string) =>
  invoke<void>("bridge_reject_save", { origin, username });
