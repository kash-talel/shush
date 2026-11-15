<script lang="ts">
  import { tick } from "svelte";
  import { LoaderCircle, RotateCcw, TriangleAlert } from "@lucide/svelte";
  import Modal from "./Modal.svelte";
  import Spindle from "./Spindle.svelte";
  import PasswordField from "./PasswordField.svelte";
  import KeyfileAttach from "./KeyfileAttach.svelte";
  import { recoverVaultFromBackup, splitPath, toCmdError, type CmdError, type KeyfileInfo, type VaultCard } from "../tauri-bridge";

  // Offered only when the vault file is damaged but its backup (.bak) reads.
  // The backend decrypts the backup with these credentials first; only then is
  // the damaged file renamed aside (never deleted) and the backup restored.
  let { vault, onclose, onrecovered }: { vault: VaultCard; onclose: () => void; onrecovered: () => void } = $props();

  let password = $state("");
  let keyfile = $state<{ path: string; info: KeyfileInfo } | null>(null);
  let busy = $state(false);
  let error = $state<CmdError | null>(null);
  let passwordInput: HTMLInputElement | undefined = $state();

  const needsKeyfile = $derived(vault.keyfile_required === true);
  const canSubmit = $derived(!busy && password.length > 0 && (!needsKeyfile || keyfile !== null));
  const [dir, file] = $derived(splitPath(vault.path));

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (!canSubmit) return;
    busy = true;
    error = null;
    let done = false;
    try {
      await recoverVaultFromBackup(vault.id, password, keyfile?.path ?? null);
      done = true;
    } catch (e) {
      error = toCmdError(e);
    } finally {
      busy = false;
    }
    if (done) {
      password = "";
      onrecovered();
      return;
    }
    await tick();
    passwordInput?.select();
  }
</script>

<Modal title="Recover from backup" {busy} {onclose}>
  <form class="flex flex-col gap-4" onsubmit={submit} novalidate>
    <div class="flex items-center gap-3">
      <div class="shrink-0"><Spindle size={52} spin="off" color={vault.color} /></div>
      <div class="min-w-0">
        <p class="truncate text-[15px] font-semibold text-zinc-50">{vault.name}</p>
        <p class="flex max-w-full font-mono text-[10.5px] text-zinc-500" title={vault.path}>
          <span class="truncate">{dir}</span><span class="shrink-0 text-zinc-300">{file}</span>
        </p>
      </div>
    </div>

    <p class="text-xs leading-5 text-zinc-400">
      The vault file is damaged, but its backup copy (<span class="font-mono">.bak</span>) is intact. Enter the master
      password to check the backup. If it opens, the damaged file is renamed to
      <span class="font-mono">{file}.corrupt-…</span> (not deleted) and the backup becomes your vault. This is not an
      undo: the backup holds the same data as the vault did when you last unlocked it.
    </p>

    <PasswordField
      id="recover-password"
      label="Master password of this vault"
      bind:value={password}
      bind:input={passwordInput}
      invalid={error?.code === "WRONG_CREDENTIALS"}
      disabled={busy}
      oninput={() => (error = null)}
    />

    {#if needsKeyfile}
      <div>
        <span class="mb-1.5 flex items-baseline justify-between text-xs font-medium text-zinc-300">
          Keyfile <span class="spec text-caution!">required for this vault</span>
        </span>
        <KeyfileAttach bind:keyfile required disabled={busy} onerror={(e) => (error = e)} />
      </div>
    {/if}

    <div aria-live="polite" class="min-h-5">
      {#if error}
        <p class="flex items-start gap-1.5 text-xs leading-5 text-danger">
          <TriangleAlert class="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
          <span><span class="font-mono">[{error.code}]</span> {error.message}</span>
        </p>
      {/if}
    </div>

    <div class="flex items-center gap-2">
      <button type="button" onclick={onclose} disabled={busy} class="key-steel h-10 px-4 text-xs">Cancel</button>
      <button type="submit" disabled={!canSubmit} class="key ml-auto h-10 px-4 text-[12px]">
        {#if busy}
          <LoaderCircle class="size-4 animate-spin" aria-hidden="true" /> CHECKING BACKUP…
        {:else}
          <RotateCcw class="size-4" aria-hidden="true" /> RECOVER VAULT
        {/if}
      </button>
    </div>
  </form>
</Modal>
