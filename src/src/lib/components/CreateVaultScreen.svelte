<script lang="ts">
  import { onMount, tick } from "svelte";
  import { save } from "@tauri-apps/plugin-dialog";
  import { ChevronRight, FileKey2, KeyRound, LoaderCircle, TriangleAlert } from "@lucide/svelte";
  import Spindle from "./Spindle.svelte";
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
    if (bits < 80) return { bits, label: "FAIR", tone: "bg-caution", pct: 60 };
    return { bits, label: "STRONG", tone: "bg-uv", pct: 100 };
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

<section class="flex flex-1 justify-center overflow-y-auto px-6 py-6">
  <div class="my-auto w-full max-w-[440px]">
    <header class="mb-5 flex items-center gap-4">
      <div class="shrink-0 [@media(max-height:620px)]:hidden">
        <Spindle spinning={busy} size={76} />
      </div>
      <div class="min-w-0 flex-1">
        <h1 class="font-display text-[26px] leading-tight font-bold tracking-[-0.01em] text-zinc-50">New vault</h1>
        <p class="mt-0.5 text-xs text-zinc-400">No vault found here yet. Set a master password to create one.</p>
        <p class="mt-1.5 flex max-w-full font-mono text-[10.5px] text-zinc-500" title={vault.path}>
          <span class="truncate">{vault.path.slice(0, cut + 1)}</span>
          <span class="shrink-0 text-uv">{vault.path.slice(cut + 1)}</span>
        </p>
      </div>
    </header>

    <form class="flex flex-col gap-3.5" onsubmit={submit} novalidate>
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
          <!-- Segmented meter: 12 cells lit to the strength level. -->
          <div class="flex h-1.5 flex-1 gap-[3px]" aria-hidden="true">
            {#each { length: 12 } as _, i (i)}
              <span class={["flex-1 rounded-[1px] transition-colors", i < Math.round((strength.pct / 100) * 12) ? strength.tone : "bg-hairline"]}></span>
            {/each}
          </div>
          <span class="w-32 text-right font-mono text-[10px] text-zinc-500">
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

      <div>
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
          <p class="mt-1.5 text-xs text-danger">Passwords do not match.</p>
        {/if}
      </div>

      <!-- fieldset defaults to min-width:min-content; min-w-0 lets long paths truncate. -->
      <fieldset class="min-w-0">
        <legend class="mb-1.5 flex w-full items-baseline justify-between text-xs font-medium text-zinc-300">
          Keyfile <span class="spec">second factor, optional</span>
        </legend>
        <div class="mb-2 grid grid-cols-3 gap-1 rounded-[5px] border border-hairline bg-[#09090e] p-1" role="radiogroup">
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
              class={[
                "h-8 rounded-[3px] px-2 text-xs transition",
                mode === m.id ? "key-steel w-full text-zinc-50" : "text-zinc-500 hover:text-zinc-200",
              ]}
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
            class={[
              "flex h-14 w-full items-center gap-2.5 rounded-[4px] border px-3 text-left text-xs transition",
              generatePath ? "border-crimson/40 bg-crimson/5" : "border-dashed border-edge text-zinc-400 hover:border-zinc-500 hover:text-zinc-200",
            ]}
          >
            <KeyRound class={["size-4 shrink-0", generatePath && "text-ruby"]} aria-hidden="true" />
            {#if generatePath}
              {@const [dir, file] = splitPath(generatePath)}
              <span class="min-w-0 flex-1 font-mono">
                <span class="flex text-ruby" title={generatePath}>
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
          <p class={["mt-2 flex items-start gap-1.5 text-[11px] leading-4", keyfileNextToVault ? "text-caution" : "text-zinc-500"]}>
            <FileKey2 class="mt-px size-3.5 shrink-0" aria-hidden="true" />
            {#if keyfileNextToVault}
              The keyfile is in the same folder as the vault, which defeats its purpose. Store it on a USB drive.
            {:else}
              Keep the keyfile on a USB drive, away from the vault. Without it the vault cannot be opened.
            {/if}
          </p>
        {/if}
      </fieldset>

      <details class="group rounded-[5px] border border-hairline bg-surface/50">
        <summary class="flex cursor-pointer list-none items-center gap-1.5 px-3 py-2 text-xs text-zinc-400 select-none hover:text-zinc-200">
          <ChevronRight class="size-3.5 transition group-open:rotate-90" aria-hidden="true" />
          Advanced cryptography
          <span class="ml-auto font-mono text-[10px] text-zinc-600">
            {(info?.supported_ciphers.find((c) => c.id === cipherId)?.name ?? "").toLowerCase()}
          </span>
        </summary>
        <div class="flex flex-col gap-2 border-t border-hairline px-3 py-3">
          {#each info?.supported_ciphers ?? [] as c (c.id)}
            <label class="flex cursor-pointer items-center gap-2 text-xs text-zinc-300">
              <input type="radio" name="cipher" value={c.id} bind:group={cipherId} disabled={busy} class="accent-crimson" />
              <span class="font-mono text-[11px]">{c.name}</span>
              {#if c.id === 0x01}<span class="text-zinc-500">default, hardware-accelerated</span>{/if}
              {#if c.id === 0x02}<span class="text-zinc-500">192-bit nonce, constant-time</span>{/if}
            </label>
          {/each}
          {#if info}
            <p class="font-mono text-[10.5px] text-zinc-500">kdf <span class="text-uv">{formatKdf(info.default_kdf).toLowerCase()}</span></p>
          {/if}
        </div>
      </details>

      <label class="flex cursor-pointer items-start gap-2 text-xs leading-5 text-zinc-400">
        <input type="checkbox" bind:checked={acknowledged} disabled={busy} class="mt-1 accent-crimson" />
        <span>
          I understand shush has <span class="text-zinc-100">no recovery</span>: if I forget the master
          password{#if mode !== "none"}&nbsp;or lose the keyfile{/if}, the vault cannot be opened by anyone.
        </span>
      </label>

      {#if error}
        <p class="flex items-start gap-1.5 text-xs leading-5 text-danger" role="alert">
          <TriangleAlert class="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
          <span><span class="font-mono">[{error.code}]</span> {error.message}</span>
        </p>
      {/if}

      <button type="submit" disabled={!canSubmit} class="key mt-1 h-11 text-[13px]">
        {#if busy}
          <LoaderCircle class="size-4 animate-spin" aria-hidden="true" /> DERIVING KEY & ENCRYPTING…
        {:else}
          CREATE VAULT
        {/if}
      </button>
    </form>
  </div>
</section>
