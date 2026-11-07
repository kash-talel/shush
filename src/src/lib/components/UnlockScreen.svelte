<script lang="ts">
  import { onMount, tick, untrack } from "svelte";
  import { Fingerprint, LoaderCircle, Lock, TriangleAlert } from "@lucide/svelte";
  import PasswordField from "./PasswordField.svelte";
  import KeyfileAttach from "./KeyfileAttach.svelte";
  import { toCmdError, unlock, type CmdError, type KeyfileInfo, type VaultStatus, type VaultSummary } from "../tauri-bridge";

  let { vault, onunlocked }: { vault: VaultStatus; onunlocked: (s: VaultSummary) => void } = $props();

  let password = $state("");
  let keyfile = $state<{ path: string; info: KeyfileInfo } | null>(null);
  let busy = $state(false);
  // Seeded once from the header check; the screen is re-keyed per vault path.
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

<section class="flex flex-1 items-center justify-center overflow-y-auto px-6 py-10 [@media(max-height:640px)]:py-4">
  <div class="w-full max-w-[380px]">
    <header class="mb-8 flex flex-col items-center gap-3 text-center [@media(max-height:640px)]:mb-5">
      <div class="grid size-12 place-items-center rounded-xl border border-hairline bg-surface [@media(max-height:640px)]:hidden">
        <Lock class="size-5 text-tactical" strokeWidth={1.75} aria-hidden="true" />
      </div>
      <h1 class="font-mono text-[13px] tracking-[0.18em] text-zinc-300">// SHUSH_VAULT_AUTHENTICATION</h1>
      <!-- Middle-truncate: the directory may shrink, the file name never does. -->
      <p class="flex max-w-full font-mono text-[11px] text-zinc-500" title={vault.path}>
        <span class="truncate">{vault.path.slice(0, cut + 1)}</span>
        <span class="shrink-0 text-cold/80">{vault.path.slice(cut + 1)}</span>
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

      <div>
        <span class="mb-1.5 flex items-baseline justify-between text-xs font-medium text-zinc-400">
          Keyfile
          {#if keyfileRequired}
            <span class="font-normal text-amber-300">required for this vault</span>
          {:else}
            <span class="font-normal text-zinc-500">not used by this vault</span>
          {/if}
        </span>
        {#if keyfileRequired}
          <KeyfileAttach
            bind:keyfile
            required
            disabled={busy || unreadable}
            onerror={(e) => (error = e)}
            onchange={() => passwordInput?.focus()}
          />
        {/if}
      </div>

      <!-- Reserve two lines so an error never shifts the centred layout. -->
      <div id="unlock-feedback" aria-live="polite" class="min-h-10">
        {#if error}
          <p class="flex items-start gap-1.5 text-xs leading-5 text-danger">
            <TriangleAlert class="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
            <span><span class="font-mono">[{error.code}]</span> {error.message}</span>
          </p>
        {/if}
      </div>

      <button
        type="submit"
        disabled={!canSubmit}
        class="flex h-11 items-center justify-center gap-2 rounded-lg bg-tactical font-mono text-sm font-semibold tracking-wider text-obsidian transition
          hover:bg-emerald-400 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-tactical
          disabled:cursor-not-allowed disabled:bg-hairline disabled:text-zinc-500"
      >
        {#if busy}
          <LoaderCircle class="size-4 animate-spin" aria-hidden="true" /> DERIVING KEY…
        {:else}
          UNLOCK VAULT <kbd class="rounded border border-current/30 px-1 text-[10px] font-normal opacity-70">↵</kbd>
        {/if}
      </button>
    </form>

    <p class="mt-6 flex items-center justify-center gap-1.5 font-mono text-[11px] text-zinc-500 [@media(max-height:640px)]:mt-3">
      <Fingerprint class="size-3.5" aria-hidden="true" />
      Windows Hello can be enabled after first unlock
    </p>
  </div>
</section>
