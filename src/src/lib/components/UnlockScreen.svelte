<script lang="ts">
  import { onMount, tick, untrack } from "svelte";
  import { ArrowLeft, LoaderCircle, TriangleAlert } from "@lucide/svelte";
  import Spindle from "./Spindle.svelte";
  import PasswordField from "./PasswordField.svelte";
  import KeyfileAttach from "./KeyfileAttach.svelte";
  import VaultShelf from "./VaultShelf.svelte";
  import {
    describeAutoLock,
    formatKdf,
    toCmdError,
    unlock,
    type AutoLockReason,
    type CmdError,
    type KeyfileInfo,
    type NewVaultTarget,
    type VaultStatus,
    type VaultSummary,
  } from "../tauri-bridge";

  let {
    vault,
    autoLockReason = null,
    onunlocked,
    onswitch,
    onnew,
  }: {
    vault: VaultStatus;
    autoLockReason?: AutoLockReason | null;
    onunlocked: (s: VaultSummary) => void;
    /** Another vault was picked (or the list changed) on the shelf. */
    onswitch: (s: VaultStatus) => void;
    /** "New vault" on the shelf: set its password next. */
    onnew: (t: NewVaultTarget) => void;
  } = $props();

  let password = $state("");
  let keyfile = $state<{ path: string; info: KeyfileInfo } | null>(null);
  let busy = $state(false);
  // Seeded once from the header check; the screen re-mounts after every lock.
  let error = $state<CmdError | null>(untrack(() => vault.error));
  let passwordInput: HTMLInputElement | undefined = $state();
  let caseButton: HTMLElement | undefined = $state();

  // The unlock ritual: the vault starts sealed (lid shut, disc still). Opening
  // the case reveals the credentials; the screen re-mounts sealed after every lock.
  let unsealed = $state(false);
  let shudder = $state(false);
  const spin = $derived(busy ? "fast" : unsealed ? "idle" : "off");

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

  async function unseal() {
    unsealed = true;
    // The form stops being inert on the next render; then type straight away.
    await tick();
    passwordInput?.focus({ preventScroll: true });
  }

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (!canSubmit) return;
    busy = true;
    error = null;
    let summary: VaultSummary | null = null;
    try {
      summary = await unlock(password, keyfile?.path ?? null, vault.id);
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
    // Failed: shake the case (restarting the animation if it is mid-shudder).
    shudder = false;
    // The input was disabled while busy; wait for Svelte to re-enable it.
    await tick();
    shudder = true;
    passwordInput?.focus();
    passwordInput?.select();
  }

  async function reseal() {
    if (busy) return;
    unsealed = false;
    shudder = false;
    password = "";
    keyfile = null;
    if (error?.code !== "VAULT_UNREADABLE") {
      error = null;
    }
    await tick();
    caseButton?.focus({ preventScroll: true });
  }

  function onkeydown(e: KeyboardEvent) {
    if (e.key === "Escape" && unsealed && !busy) {
      e.preventDefault();
      void reseal();
    }
  }

  // Enter or Space on the focused case unseals it, so the keyboard path is one key.
  onMount(() => caseButton?.focus());
</script>

<svelte:window {onkeydown} />

<section class="flex flex-1 items-center justify-center overflow-y-auto px-6 py-8 [@media(max-height:640px)]:py-4">
  <div class="flex w-full max-w-[380px] flex-col items-center">
    <!-- The case glides up as the credentials unfold beneath it. -->
    <div class={["transition-transform duration-700 ease-out", unsealed && "-translate-y-2"]}>
      <Spindle
        id="unseal"
        bind:element={caseButton}
        open={unsealed}
        {spin}
        {shudder}
        color={vault.color}
        size="clamp(128px, 29vh, 212px)"
        label={unsealed ? "Vault case (open)" : `Unseal the vault${vault.name && !vault.hide_names ? ` ${vault.name}` : ""}`}
        expanded={unsealed}
        controls="unlock-form"
        onclick={unsealed ? () => passwordInput?.focus() : unseal}
        onshudderend={() => (shudder = false)}
      />
    </div>

    <!-- Sealed: only the case and the prompt. -->
    <div class={["unfold w-full", !unsealed && "open"]} aria-hidden={unsealed} inert={unsealed}>
      <div class="flex flex-col items-center gap-3 pt-7 [@media(max-height:640px)]:pt-4">
        {#if vault.name && !vault.hide_names}
          <p class="font-display text-[17px] leading-none font-bold text-zinc-100">{vault.name}</p>
        {/if}
        <p class="font-mono text-[11px] tracking-[0.08em] text-zinc-400">[ CLICK DISC TO UNSEAL VAULT ]</p>
        <div class="mt-3 w-full [@media(max-height:640px)]:mt-1">
          <VaultShelf current={vault} {onswitch} {onnew} />
        </div>
      </div>
    </div>

    <!-- Status that matters even while sealed. -->
    {#if autoLockReason || (!unsealed && unreadable && error)}
      <div class="mt-4 flex flex-col items-center gap-2 text-center">
        {#if autoLockReason}
          <p class="flex items-center gap-2 rounded-[3px] border border-uv/30 bg-uv/10 px-2 py-1 font-mono text-[10px] text-uv-soft" role="status">
            <span class="led text-uv"></span> AUTO-LOCKED: {describeAutoLock(autoLockReason)}
          </p>
        {/if}
        {#if !unsealed && unreadable && error}
          <p class="text-xs text-danger" role="alert"><span class="font-mono">[{error.code}]</span> {error.message}</p>
        {/if}
      </div>
    {/if}

    <!-- Unsealed: the credentials slide and fade in. Inert until then. -->
    <div id="unlock-form" class={["unfold w-full", unsealed && "open"]} inert={!unsealed}>
      <div>
        <header class="mt-6 mb-5 flex flex-col items-center gap-2 text-center [@media(max-height:640px)]:mt-3 [@media(max-height:640px)]:mb-3">
          <h1 class="font-display text-[26px] leading-none font-bold tracking-[-0.01em] text-zinc-50">{vault.name && !vault.hide_names ? `Unlock ${vault.name}` : "Unlock vault"}</h1>
          {#if !vault.hide_names}
            <!-- Middle-truncate: the directory may shrink, the file name never does. -->
            <p class="flex max-w-full items-center gap-1.5 font-mono text-[10.5px] text-zinc-500" title={vault.path}>
              <span class="truncate">{vault.path.slice(0, cut + 1)}</span>
              <span class="shrink-0 text-uv">{vault.path.slice(cut + 1)}</span>
              {#if vault.read_only}
                <span class="rounded border border-caution/40 bg-caution/10 px-1 py-0.2 font-mono text-[9px] font-bold uppercase tracking-wider text-caution" role="status">
                  read-only
                </span>
              {/if}
            </p>
          {/if}
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
                acceptDrop={unsealed}
                onerror={(e) => (error = e)}
                onchange={() => passwordInput?.focus()}
              />
            </div>
          {/if}

          <!-- Reserve two lines so an error never shifts the layout. -->
          <div id="unlock-feedback" aria-live="polite" class="min-h-10">
            {#if error}
              <p class="flex items-start gap-1.5 rounded-[3px] border border-danger/40 bg-danger/10 px-2 py-1.5 text-xs leading-5 text-danger">
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

          <button
            type="button"
            onclick={reseal}
            disabled={busy}
            class="key-steel h-9 font-mono text-xs tracking-[0.06em]"
            aria-label="Choose another vault"
          >
            <ArrowLeft class="size-3.5" aria-hidden="true" /> CHOOSE ANOTHER VAULT <span class="kbd">Esc</span>
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
    </div>
  </div>
</section>

<style>
  /* Height-animating reveal: grid rows go 0fr → 1fr, so the centred column
     (and the case above it) glide smoothly as the content grows. */
  .unfold {
    display: grid;
    /* minmax(0, …): long vault paths must truncate, not widen the column. */
    grid-template-columns: minmax(0, 1fr);
    grid-template-rows: 0fr;
    opacity: 0;
    translate: 0 10px;
    transition:
      grid-template-rows 0.6s cubic-bezier(0.2, 0.9, 0.2, 1),
      opacity 0.45s ease,
      translate 0.6s cubic-bezier(0.2, 0.9, 0.2, 1);
  }
  .unfold.open {
    grid-template-rows: 1fr;
    opacity: 1;
    translate: 0 0;
  }
  /* The credentials wait for the lid to swing before they arrive. */
  #unlock-form.open {
    transition-delay: 0.18s;
  }
  .unfold > :global(*) {
    min-height: 0;
    min-width: 0;
    /* Clip during the reveal without cutting off focus rings. */
    overflow: clip;
    overflow-clip-margin: 8px;
  }
  @media (prefers-reduced-motion: reduce) {
    .unfold {
      transition: none;
    }
  }
</style>
