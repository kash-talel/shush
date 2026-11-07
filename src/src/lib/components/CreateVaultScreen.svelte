<script lang="ts">
  import { onMount, tick } from "svelte";
  import { save } from "@tauri-apps/plugin-dialog";
  import { ChevronRight, FileKey2, KeyRound, LoaderCircle, ShieldPlus, TriangleAlert } from "@lucide/svelte";
  import PasswordField from "./PasswordField.svelte";
  import KeyfileAttach from "./KeyfileAttach.svelte";
  import {
    createVault,
    formatKdf,
    splitPath,
    toCmdError,
    type AppInfo,
    type CmdError,
    type KeyfileChoice,
    type KeyfileInfo,
    type VaultStatus,
    type VaultSummary,
  } from "../tauri-bridge";

  let {
    vault,
    info,
    oncreated,
  }: { vault: VaultStatus; info: AppInfo | null; oncreated: (s: VaultSummary) => void } = $props();

  type Mode = KeyfileChoice["mode"];

  let password = $state("");
  let confirm = $state("");
  let mode = $state<Mode>("none");
  let generatePath = $state<string | null>(null);
  let existing = $state<{ path: string; info: KeyfileInfo } | null>(null);
  let cipherId = $state(0x01);
  let acknowledged = $state(false);
  let busy = $state(false);
  let error = $state<CmdError | null>(null);
  let passwordInput: HTMLInputElement | undefined = $state();

  const minChars = $derived(info?.min_password_chars ?? 8);
  const length = $derived([...password.normalize("NFC")].length);
  const mismatch = $derived(confirm.length > 0 && confirm !== password);

  // Rough entropy estimate for feedback only (zxcvbn arrives with the
  // generator in Phase 4). Never used as a security decision.
  const strength = $derived.by(() => {
    let pool = 0;
    if (/[a-z]/.test(password)) pool += 26;
    if (/[A-Z]/.test(password)) pool += 26;
    if (/[0-9]/.test(password)) pool += 10;
    if (/[^A-Za-z0-9]/.test(password)) pool += 33;
    const bits = Math.round(length * Math.log2(Math.max(pool, 1)));
    if (length === 0) return { bits: 0, label: "", tone: "bg-hairline", pct: 0 };
    if (length < minChars || bits < 50) return { bits, label: "WEAK", tone: "bg-danger", pct: 25 };
    if (bits < 80) return { bits, label: "FAIR", tone: "bg-amber-400", pct: 60 };
    return { bits, label: "STRONG", tone: "bg-tactical", pct: 100 };
  });

  const keyfileReady = $derived(
    mode === "none" || (mode === "generate" && generatePath !== null) || (mode === "existing" && existing !== null),
  );
  const canSubmit = $derived(
    !busy && length >= minChars && confirm === password && keyfileReady && acknowledged,
  );
  const cut = $derived(Math.max(vault.path.lastIndexOf("\\"), vault.path.lastIndexOf("/")));
  const vaultDir = $derived(vault.path.slice(0, cut).toLowerCase());
  const keyfileNextToVault = $derived.by(() => {
    const p = mode === "generate" ? generatePath : mode === "existing" ? existing?.path : null;
    if (!p) return false;
    const i = Math.max(p.lastIndexOf("\\"), p.lastIndexOf("/"));
    return p.slice(0, i).toLowerCase() === vaultDir;
  });

  async function chooseGeneratePath() {
    const picked = await save({
      title: "Save new keyfile",
      defaultPath: "vault.key",
      filters: [{ name: "shush keyfile", extensions: ["key"] }],
    });
    if (picked) generatePath = picked;
  }

  function keyfileChoice(): KeyfileChoice {
    if (mode === "generate" && generatePath) return { mode, path: generatePath };
    if (mode === "existing" && existing) return { mode, path: existing.path };
    return { mode: "none" };
  }

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (!canSubmit) return;
    busy = true;
    error = null;
    let summary: VaultSummary | null = null;
    try {
      summary = await createVault(password, keyfileChoice(), cipherId);
    } catch (e) {
      error = toCmdError(e);
    } finally {
      busy = false;
    }
    if (summary) {
      password = confirm = "";
      oncreated(summary);
      return;
    }
    await tick();
    passwordInput?.focus();
  }

  onMount(() => passwordInput?.focus());

  const modes: { id: Mode; label: string }[] = [
    { id: "none", label: "None" },
    { id: "generate", label: "Generate new" },
    { id: "existing", label: "Use existing file" },
  ];
</script>

<section class="flex flex-1 justify-center overflow-y-auto px-6 py-8">
  <div class="my-auto w-full max-w-[420px]">
    <header class="mb-6 flex flex-col items-center gap-3 text-center">
      <div class="grid size-12 place-items-center rounded-xl border border-hairline bg-surface [@media(max-height:700px)]:hidden">
        <ShieldPlus class="size-5 text-tactical" strokeWidth={1.75} aria-hidden="true" />
      </div>
      <h1 class="font-mono text-[13px] tracking-[0.18em] text-zinc-300">// SHUSH_VAULT_INITIALIZATION</h1>
      <p class="text-xs text-zinc-400">No vault found. Create one to get started.</p>
      <p class="flex max-w-full font-mono text-[11px] text-zinc-500" title={vault.path}>
        <span class="truncate">{vault.path.slice(0, cut + 1)}</span>
        <span class="shrink-0 text-cold/80">{vault.path.slice(cut + 1)}</span>
      </p>
    </header>

    <form class="flex flex-col gap-4" onsubmit={submit} novalidate>
      <div>
        <PasswordField
          id="new-password"
          label="Master password"
          autocomplete="new-password"
          placeholder="choose a master password"
          bind:value={password}
          bind:input={passwordInput}
          disabled={busy}
          describedby="strength"
          oninput={() => (error = null)}
        />
        <div id="strength" class="mt-2 flex items-center gap-2" aria-live="polite">
          <div class="h-1 flex-1 overflow-hidden rounded-full bg-hairline">
            <div class="h-full rounded-full transition-all {strength.tone}" style="width: {strength.pct}%"></div>
          </div>
          <span class="w-28 text-right font-mono text-[10px] text-zinc-500">
            {#if length === 0}
              min {minChars} chars
            {:else if length < minChars}
              {length}/{minChars} chars
            {:else}
              {strength.label} · ~{strength.bits} bits
            {/if}
          </span>
        </div>
      </div>

      <PasswordField
        id="confirm-password"
        label="Confirm master password"
        autocomplete="new-password"
        placeholder="type it again"
        bind:value={confirm}
        invalid={mismatch}
        disabled={busy}
      />
      {#if mismatch}
        <p class="-mt-2 text-xs text-danger">Passwords do not match.</p>
      {/if}

      <!-- fieldset defaults to min-width:min-content; min-w-0 lets long paths truncate. -->
      <fieldset class="min-w-0">
        <legend class="mb-1.5 flex w-full items-baseline justify-between text-xs font-medium text-zinc-400">
          Keyfile <span class="font-normal text-zinc-500">second factor, optional</span>
        </legend>
        <div class="mb-2 grid grid-cols-3 gap-1 rounded-lg border border-hairline bg-surface p-1" role="radiogroup">
          {#each modes as m (m.id)}
            <button
              type="button"
              role="radio"
              aria-checked={mode === m.id}
              disabled={busy}
              onclick={() => {
                mode = m.id;
                error = null;
              }}
              class="rounded-md px-2 py-1.5 text-xs transition focus-visible:outline-2 focus-visible:outline-tactical
                {mode === m.id ? 'bg-hairline text-zinc-100' : 'text-zinc-500 hover:text-zinc-300'}"
            >
              {m.label}
            </button>
          {/each}
        </div>

        {#if mode === "generate"}
          <button
            type="button"
            onclick={chooseGeneratePath}
            disabled={busy}
            class="flex h-14 w-full items-center gap-2.5 rounded-lg border px-3 text-left text-xs transition focus-visible:outline-2 focus-visible:outline-tactical
              {generatePath ? 'border-tactical/40 bg-tactical/5' : 'border-dashed border-hairline text-zinc-400 hover:border-zinc-600 hover:text-zinc-200'}"
          >
            <KeyRound class="size-4 shrink-0 {generatePath ? 'text-tactical' : ''}" aria-hidden="true" />
            {#if generatePath}
              {@const [dir, file] = splitPath(generatePath)}
              <span class="min-w-0 flex-1 font-mono">
                <span class="flex text-tactical" title={generatePath}>
                  <span class="truncate">{dir}</span><span class="shrink-0">{file}</span>
                </span>
                <span class="block truncate text-zinc-500">new 32-byte keyfile · click to change</span>
              </span>
            {:else}
              Choose where to save the new keyfile…
            {/if}
          </button>
        {:else if mode === "existing"}
          <KeyfileAttach bind:keyfile={existing} disabled={busy} onerror={(e) => (error = e)} />
        {/if}

        {#if mode !== "none"}
          <p class="mt-2 flex items-start gap-1.5 text-[11px] leading-4 {keyfileNextToVault ? 'text-amber-300' : 'text-zinc-500'}">
            <FileKey2 class="mt-px size-3.5 shrink-0" aria-hidden="true" />
            {#if keyfileNextToVault}
              The keyfile is in the same folder as the vault, which defeats its purpose. Store it on a USB drive.
            {:else}
              Keep the keyfile on a USB drive, away from the vault. Without it the vault cannot be opened.
            {/if}
          </p>
        {/if}
      </fieldset>

      <details class="group rounded-lg border border-hairline">
        <summary class="flex cursor-pointer list-none items-center gap-1.5 px-3 py-2 text-xs text-zinc-400 select-none hover:text-zinc-200">
          <ChevronRight class="size-3.5 transition group-open:rotate-90" aria-hidden="true" />
          Advanced cryptography
        </summary>
        <div class="flex flex-col gap-2 border-t border-hairline px-3 py-3">
          {#each info?.supported_ciphers ?? [] as c (c.id)}
            <label class="flex cursor-pointer items-center gap-2 text-xs text-zinc-300">
              <input type="radio" name="cipher" value={c.id} bind:group={cipherId} disabled={busy} class="accent-emerald-500" />
              <span class="font-mono">{c.name}</span>
              {#if c.id === 0x01}<span class="text-zinc-500">default · hardware-accelerated</span>{/if}
              {#if c.id === 0x02}<span class="text-zinc-500">192-bit nonce · constant-time</span>{/if}
            </label>
          {/each}
          {#if info}
            <p class="font-mono text-[11px] text-zinc-500">KDF: <span class="text-cold">{formatKdf(info.default_kdf)}</span></p>
          {/if}
        </div>
      </details>

      <label class="flex cursor-pointer items-start gap-2 text-xs leading-5 text-zinc-400">
        <input type="checkbox" bind:checked={acknowledged} disabled={busy} class="mt-1 accent-emerald-500" />
        <span>
          I understand shush has <span class="text-zinc-200">no recovery</span>: if I forget the master
          password{#if mode !== "none"}&nbsp;or lose the keyfile{/if}, the vault cannot be opened by anyone.
        </span>
      </label>

      <div aria-live="polite" class="min-h-5">
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
          <LoaderCircle class="size-4 animate-spin" aria-hidden="true" /> DERIVING KEY & ENCRYPTING…
        {:else}
          CREATE VAULT
        {/if}
      </button>
    </form>
  </div>
</section>
