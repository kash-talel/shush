<script lang="ts">
  import { tick } from "svelte";
  import { LoaderCircle, Trash2, TriangleAlert } from "@lucide/svelte";
  import Modal from "./Modal.svelte";
  import Spindle from "./Spindle.svelte";
  import PasswordField from "./PasswordField.svelte";
  import KeyfileAttach from "./KeyfileAttach.svelte";
  import { deleteVault, splitPath, toCmdError, type CmdError, type KeyfileInfo, type VaultCard } from "../tauri-bridge";

  // Deleting needs three things a passer-by does not have: the vault's exact
  // name, its master password and (if it uses one) its keyfile. The backend
  // repeats every check, throttles wrong passwords, and sends the files to
  // the Recycle Bin rather than destroying them.
  let { vault, onclose, ondeleted }: { vault: VaultCard; onclose: () => void; ondeleted: () => void } = $props();

  let typed = $state("");
  let password = $state("");
  let keyfile = $state<{ path: string; info: KeyfileInfo } | null>(null);
  let busy = $state(false);
  let error = $state<CmdError | null>(null);
  let passwordInput: HTMLInputElement | undefined = $state();

  const needsKeyfile = $derived(vault.keyfile_required === true);
  const nameOk = $derived(typed.trim() === vault.name);
  const canSubmit = $derived(!busy && nameOk && password.length > 0 && (!needsKeyfile || keyfile !== null));
  const [dir, file] = $derived(splitPath(vault.path));

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (!canSubmit) return;
    busy = true;
    error = null;
    let done = false;
    try {
      await deleteVault(vault.id, password, keyfile?.path ?? null, typed);
      done = true;
    } catch (e) {
      error = toCmdError(e);
    } finally {
      busy = false;
    }
    if (done) {
      password = "";
      ondeleted();
      return;
    }
    await tick();
    passwordInput?.select();
  }
</script>

<Modal title="Delete vault" hazard {busy} {onclose}>
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
      The vault, its backup copy and its attachments move to the Recycle Bin. Until you empty the bin you can restore
      them there; they stay encrypted.
    </p>

    <label class="flex flex-col gap-1.5 text-xs font-medium text-zinc-300">
      <span>Type <span class="font-mono text-zinc-50 select-all">{vault.name}</span> to confirm</span>
      <input
        bind:value={typed}
        disabled={busy}
        autocomplete="off"
        spellcheck="false"
        oninput={() => (error = null)}
        class={["well h-10 px-3 text-[13px] font-normal text-zinc-50", typed.length > 0 && !nameOk && "invalid"]}
      />
    </label>

    <PasswordField
      id="delete-password"
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
      <button type="button" onclick={onclose} disabled={busy} class="key-steel h-10 px-4 text-xs">Keep vault</button>
      <button type="submit" disabled={!canSubmit} class="key danger ml-auto h-10 px-4 text-[12px]">
        {#if busy}
          <LoaderCircle class="size-4 animate-spin" aria-hidden="true" /> CHECKING PASSWORD…
        {:else}
          <Trash2 class="size-4" aria-hidden="true" /> DELETE VAULT
        {/if}
      </button>
    </div>
  </form>
</Modal>

<style>
  /* Hazard vermilion instead of the disc crimson: this is the one key that destroys. */
  .danger:not(:disabled) {
    background: linear-gradient(180deg, #ff7f57, var(--color-danger) 55%, #e2501f);
    box-shadow:
      inset 0 1px 0 rgb(255 255 255 / 0.28),
      inset 0 -1px 0 rgb(0 0 0 / 0.25),
      0 2px 0 #7a2a10,
      0 6px 18px -6px rgb(255 106 61 / 0.55);
  }
</style>
