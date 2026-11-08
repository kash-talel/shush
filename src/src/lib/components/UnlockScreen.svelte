<script lang="ts">
  import { onMount, tick, untrack } from "svelte";
  import { LoaderCircle, TriangleAlert } from "@lucide/svelte";
  import Spindle from "./Spindle.svelte";
  import PasswordField from "./PasswordField.svelte";
  import KeyfileAttach from "./KeyfileAttach.svelte";
  import {
    describeAutoLock,
    formatKdf,
    toCmdError,
    unlock,
    type AutoLockReason,
    type CmdError,
    type KeyfileInfo,
    type VaultStatus,
    type VaultSummary,
  } from "../tauri-bridge";

  let {
    vault,
    autoLockReason = null,
    onunlocked,
  }: { vault: VaultStatus; autoLockReason?: AutoLockReason | null; onunlocked: (s: VaultSummary) => void } = $props();

  let password = $state("");
  let keyfile = $state<{ path: string; info: KeyfileInfo } | null>(null);
  let busy = $state(false);
  // Seeded once from the header check; the screen re-mounts after every lock.
  let error = $state<CmdError | null>(untrack(() => vault.error));
  let passwordInput: HTMLInputElement | undefined = $state();

  const keyfileRequired = $derived(vault.keyfile_required === true);
  const unreadable = $derived(vault.error !== null);
  // Keyfile problems are shown in the shared slot but must not blame the password field.
  const passwordError = $derived(
    error !== null && !error.code.startsWith("KEYFILE") && error.code !== "VAULT_UNREADABLE",
  );
  const canSubmit = $derived(
    !busy && !unreadable && password.length > 0 && (!keyfileRequired || keyfile !== null),
  );
  const cut = $derived(Math.max(vault.path.lastIndexOf("\\"), vault.path.lastIndexOf("/")));

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (!canSubmit) return;
    busy = true;
    error = null;
    let summary: VaultSummary | null = null;
    try {
      summary = await unlock(password, keyfile?.path ?? null);
    } catch (e) {
      error = toCmdError(e);
    } finally {
      busy = false;
    }
    if (summary) {
      password = "";
      onunlocked(summary);
      return;
    }
    // The input was disabled while busy; wait for Svelte to re-enable it.
    await tick();
    passwordInput?.focus();
    passwordInput?.select();
  }

  onMount(() => passwordInput?.focus());
</script>

<section class="flex flex-1 items-center justify-center overflow-y-auto px-6 py-8 [@media(max-height:640px)]:py-4">
  <div class="w-full max-w-[380px]">
    <header class="mb-7 flex flex-col items-center gap-3 text-center [@media(max-height:640px)]:mb-4">
      <div class="mb-2 [@media(max-height:640px)]:hidden">
        <Spindle spinning={busy} />
      </div>
      <h1 class="font-display text-[28px] leading-none font-bold tracking-[-0.01em] text-zinc-50">Unlock vault</h1>
      {#if autoLockReason}
        <p class="flex items-center gap-2 rounded-[3px] border border-uv/30 bg-uv/10 px-2 py-1 font-mono text-[10px] text-uv-soft" role="status">
          <span class="led text-uv"></span> AUTO-LOCKED: {describeAutoLock(autoLockReason)}
        </p>
      {/if}
      <!-- Middle-truncate: the directory may shrink, the file name never does. -->
      <p class="flex max-w-full font-mono text-[10.5px] text-zinc-500" title={vault.path}>
        <span class="truncate">{vault.path.slice(0, cut + 1)}</span>
        <span class="shrink-0 text-uv">{vault.path.slice(cut + 1)}</span>
      </p>
    </header>

    <form class="flex flex-col gap-3" onsubmit={submit} novalidate>
      <PasswordField
        id="master-password"
        label="Master password"
        bind:value={password}
        bind:input={passwordInput}
        invalid={passwordError}
        disabled={busy || unreadable}
        describedby="unlock-feedback"
        oninput={() => (error = null)}
      />

      {#if keyfileRequired}
        <div>
          <span class="mb-1.5 flex items-baseline justify-between text-xs font-medium text-zinc-300">
            Keyfile <span class="spec text-caution!">required for this vault</span>
          </span>
          <KeyfileAttach
            bind:keyfile
            required
            disabled={busy || unreadable}
            onerror={(e) => (error = e)}
            onchange={() => passwordInput?.focus()}
          />
        </div>
      {/if}

      <!-- Reserve two lines so an error never shifts the centred layout. -->
      <div id="unlock-feedback" aria-live="polite" class="min-h-10">
        {#if error}
          <p class="flex items-start gap-1.5 text-xs leading-5 text-danger">
            <TriangleAlert class="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
            <span><span class="font-mono">[{error.code}]</span> {error.message}</span>
          </p>
        {/if}
      </div>

      <button type="submit" disabled={!canSubmit} class="key h-11 text-[13px]">
        {#if busy}
          <LoaderCircle class="size-4 animate-spin" aria-hidden="true" /> DERIVING KEY…
        {:else}
          UNLOCK VAULT <span class="kbd border-white/25! bg-black/20! text-white/80!">Enter</span>
        {/if}
      </button>
    </form>

    {#if vault.kdf}
      <p class="mt-5 text-center font-mono text-[10px] text-zinc-600 [@media(max-height:640px)]:mt-3" aria-live="polite">
        {#if busy}<span class="text-ruby">reading</span>{:else}key schedule{/if}
        <span class="text-zinc-400">{formatKdf(vault.kdf).toLowerCase()}</span>
        <span class="text-zinc-700">/</span>
        <span class="text-zinc-400">{(vault.cipher?.name ?? "").toLowerCase()}</span>
      </p>
    {/if}
  </div>
</section>
