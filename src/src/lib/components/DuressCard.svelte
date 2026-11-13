<script lang="ts">
  import { LoaderCircle, ShieldAlert, TriangleAlert } from "@lucide/svelte";
  import PasswordField from "./PasswordField.svelte";
  import KeyfileAttach from "./KeyfileAttach.svelte";
  import {
    clearDuressPassword,
    duressStatus,
    setDuressPassword,
    toCmdError,
    vaultInSyncFolder,
    vaultStatus,
    type CmdError,
    type KeyfileInfo,
  } from "../tauri-bridge";

  // Duress password (issue #8): a second password that opens an empty decoy
  // vault stored in the same file. The text here is identical in the real
  // vault and in a decoy, so the screen itself gives nothing away.
  let enabled = $state<boolean | null>(null);
  let keyfileRequired = $state(false);
  let inSyncFolder = $state(false);
  let current = $state("");
  let password = $state("");
  let confirm = $state("");
  let keyfile = $state<{ path: string; info: KeyfileInfo } | null>(null);
  let busy = $state(false);
  let armed = $state(false);
  let result = $state<string | null>(null);
  let error = $state<CmdError | null>(null);

  const canSet = $derived(
    current.length > 0 && password.length >= 8 && password === confirm && (!keyfileRequired || keyfile !== null),
  );

  async function load() {
    try {
      enabled = await duressStatus();
      keyfileRequired = (await vaultStatus()).keyfile_required ?? false;
      inSyncFolder = await vaultInSyncFolder();
    } catch (e) {
      error = toCmdError(e);
    }
  }
  load();

  async function doSet() {
    if (!canSet) return;
    if (!armed) {
      armed = true;
      return;
    }
    busy = true;
    error = null;
    result = null;
    try {
      await setDuressPassword(current, password, keyfile?.path ?? null);
      enabled = true;
      result = "Duress password set. It opens an empty vault: add a few believable logins there.";
      current = "";
      password = "";
      confirm = "";
    } catch (e) {
      error = toCmdError(e);
    } finally {
      busy = false;
      armed = false;
    }
  }

  async function doClear() {
    busy = true;
    error = null;
    result = null;
    try {
      await clearDuressPassword();
      enabled = false;
      result = "Duress password removed. The decoy vault was destroyed.";
    } catch (e) {
      error = toCmdError(e);
    } finally {
      busy = false;
    }
  }
</script>

<div class="flex flex-col gap-3 rounded-[7px] border border-hairline bg-surface/60 p-4 shadow-[inset_0_1px_0_rgb(255_255_255/0.03)]">
  <h3 class="flex items-center gap-2 font-display text-[15px] font-bold text-zinc-50">
    <ShieldAlert class="size-4 text-caution" aria-hidden="true" /> Duress password
  </h3>
  <p class="text-xs leading-5 text-zinc-400">
    A second password that opens a separate, empty vault in the same file. If you are forced to unlock, give
    this one. The file looks the same with or without it, and both passwords take the same time to open.
  </p>

  {#if inSyncFolder}
    <p class="flex items-start gap-1.5 text-xs text-caution" role="note">
      <TriangleAlert class="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
      <span>This vault is in a cloud-sync folder. Version history there keeps old copies of the file, and comparing them can show that a second vault exists. Move the vault out of the synced folder to keep the duress password deniable.</span>
    </p>
  {/if}
  {#if enabled}
    <p class="text-xs text-uv" role="status">A duress password is set. Attachments are turned off while it is.</p>
  {/if}

  <PasswordField id="duress-current" label="Current password of this vault" autocomplete="current-password" placeholder="Required to overwrite the second vault space" bind:value={current} oninput={() => (armed = false)} />
  <PasswordField id="duress-password" label={enabled ? "New duress password" : "Duress password"} autocomplete="new-password" placeholder="8+ characters, not your master password" bind:value={password} oninput={() => (armed = false)} />
  <PasswordField id="duress-confirm" label="Confirm" autocomplete="new-password" placeholder="repeat the duress password" bind:value={confirm} oninput={() => (armed = false)} />
  {#if keyfileRequired}
    <div>
      <span class="mb-1.5 block text-xs font-medium text-caution">The duress password uses this vault's keyfile too</span>
      <KeyfileAttach bind:keyfile required acceptDrop={false} onerror={(e) => (error = e)} />
    </div>
  {/if}
  {#if confirm.length > 0 && password !== confirm}
    <p class="text-[11px] text-danger">The passwords do not match.</p>
  {/if}

  {#if error}
    <p class="flex items-start gap-1.5 text-xs text-danger" role="alert">
      <TriangleAlert class="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
      <span><span class="font-mono">[{error.code}]</span> {error.message}</span>
    </p>
  {/if}
  {#if result}<p class="text-xs text-uv" role="status">{result}</p>{/if}
  {#if armed}
    <p class="hazard rounded-[4px] border border-danger/40 bg-danger/10 px-3 py-2 text-xs text-danger" role="alert">
      This overwrites the second vault space in this file. Any vault already stored there is destroyed for good.
    </p>
  {/if}

  <div class="flex gap-2">
    <button type="button" onclick={doSet} disabled={busy || !canSet} class={["key h-9 flex-1 text-xs", armed && "hazard bg-danger! shadow-[0_2px_0_#7a2410]!"]}>
      {#if busy}<LoaderCircle class="size-3.5 animate-spin" aria-hidden="true" />{/if}
      {armed ? "CONFIRM: OVERWRITE" : enabled ? "CHANGE DURESS PASSWORD" : "SET DURESS PASSWORD"}
    </button>
    {#if enabled}
      <button type="button" onclick={doClear} disabled={busy} class="key-steel h-9 px-3 text-xs text-ruby!">REMOVE</button>
    {/if}
  </div>
</div>
