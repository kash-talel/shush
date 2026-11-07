<script lang="ts">
  import { onMount, tick } from "svelte";
  import { getCurrentWebview } from "@tauri-apps/api/webview";
  import { open } from "@tauri-apps/plugin-dialog";
  import { Eye, EyeOff, FileKey2, Fingerprint, LoaderCircle, Lock, TriangleAlert, X } from "@lucide/svelte";
  import {
    inspectKeyfile,
    toCmdError,
    unlock,
    type CmdError,
    type KeyfileInfo,
    type VaultStatus,
  } from "../tauri-bridge";

  let { vault }: { vault: VaultStatus | null } = $props();

  let password = $state("");
  let reveal = $state(false);
  let capsLock = $state(false);
  let busy = $state(false);
  let error = $state<CmdError | null>(null);

  let keyfile = $state<{ path: string; info: KeyfileInfo } | null>(null);
  let keyfileBusy = $state(false);
  let dragging = $state(false);

  let passwordInput: HTMLInputElement | undefined = $state();

  // Keyfile problems are reported in the shared slot but must not blame the password field.
  const passwordError = $derived(error !== null && !error.code.startsWith("KEYFILE"));
  const canSubmit = $derived(!busy && (password.length > 0 || keyfile !== null));

  async function attachKeyfile(path: string) {
    keyfileBusy = true;
    error = null;
    try {
      keyfile = { path, info: await inspectKeyfile(path) };
    } catch (e) {
      keyfile = null;
      error = toCmdError(e);
    } finally {
      keyfileBusy = false;
      passwordInput?.focus();
    }
  }

  async function browseKeyfile() {
    const picked = await open({ multiple: false, directory: false, title: "Select keyfile" });
    if (typeof picked === "string") await attachKeyfile(picked);
  }

  function detachKeyfile() {
    keyfile = null;
    error = null;
    passwordInput?.focus();
  }

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (!canSubmit) return;
    busy = true;
    error = null;
    try {
      await unlock(password, keyfile?.path ?? null);
    } catch (e) {
      error = toCmdError(e);
    } finally {
      busy = false;
      // The input is disabled while busy; wait for Svelte to re-enable it,
      // otherwise focus() is silently ignored.
      await tick();
      passwordInput?.focus();
      if (error) passwordInput?.select();
    }
  }

  function trackCapsLock(e: KeyboardEvent) {
    capsLock = e.getModifierState?.("CapsLock") ?? false;
  }

  function formatBytes(n: number): string {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
    return `${(n / 1024 / 1024).toFixed(1)} MiB`;
  }

  onMount(() => {
    passwordInput?.focus();
    // Tauri intercepts OS file drops; HTML5 drop events never carry paths.
    const unlisten = getCurrentWebview().onDragDropEvent((event) => {
      const p = event.payload;
      if (p.type === "enter" || p.type === "over") dragging = true;
      else if (p.type === "leave") dragging = false;
      else if (p.type === "drop") {
        dragging = false;
        const first = p.paths[0];
        if (first) void attachKeyfile(first);
      }
    });
    return () => void unlisten.then((f) => f());
  });
</script>

<section class="flex flex-1 items-center justify-center overflow-y-auto px-6 py-10 [@media(max-height:640px)]:py-4">
  <div class="w-full max-w-[380px]">
    <header class="mb-8 flex flex-col items-center gap-3 text-center [@media(max-height:640px)]:mb-5">
      <div class="grid size-12 place-items-center rounded-xl border border-hairline bg-surface [@media(max-height:640px)]:hidden">
        <Lock class="size-5 text-tactical" strokeWidth={1.75} aria-hidden="true" />
      </div>
      <h1 class="font-mono text-[13px] tracking-[0.18em] text-zinc-300">// SHUSH_VAULT_AUTHENTICATION</h1>
      {#if vault}
        {@const cut = Math.max(vault.path.lastIndexOf("\\"), vault.path.lastIndexOf("/"))}
        {#if !vault.exists}
          <p class="rounded-full border border-amber-400/30 bg-amber-400/10 px-2.5 py-0.5 font-mono text-[10px] tracking-wider text-amber-300">
            NO VAULT FOUND · creation ships in Phase 3
          </p>
        {/if}
        <!-- Middle-truncate: the directory may shrink, the file name never does. -->
        <p class="flex max-w-full font-mono text-[11px] text-zinc-500" title={vault.path}>
          <span class="truncate">{vault.path.slice(0, cut + 1)}</span>
          <span class="shrink-0 text-cold/80">{vault.path.slice(cut + 1)}</span>
        </p>
      {/if}
    </header>

    <form class="flex flex-col gap-3" onsubmit={submit} novalidate>
      <!-- Master password -->
      <div>
        <label for="master-password" class="mb-1.5 block text-xs font-medium text-zinc-400">Master password</label>
        <div
          class="group flex items-center rounded-lg border bg-surface transition
            {passwordError
            ? 'border-danger/70 focus-within:shadow-[0_0_0_3px_rgb(239_68_68/0.14)]'
            : 'border-hairline focus-within:border-tactical/60 focus-within:shadow-[0_0_0_3px_rgb(16_185_129/0.12)]'}"
        >
          <span class="pl-3 font-mono text-sm text-tactical/70 select-none" aria-hidden="true">&gt;</span>
          <input
            id="master-password"
            bind:this={passwordInput}
            bind:value={password}
            type={reveal ? "text" : "password"}
            autocomplete="current-password"
            spellcheck="false"
            disabled={busy}
            aria-invalid={passwordError ? "true" : undefined}
            aria-describedby="unlock-feedback"
            onkeydown={trackCapsLock}
            onkeyup={trackCapsLock}
            oninput={() => (error = null)}
            class="h-11 min-w-0 flex-1 bg-transparent px-2.5 font-mono text-sm tracking-wide text-zinc-100 outline-none placeholder:text-zinc-600 disabled:opacity-60"
            placeholder="enter master password"
          />
          <button
            type="button"
            class="mr-1 grid size-9 place-items-center rounded-md text-zinc-500 transition hover:bg-hairline hover:text-zinc-200 focus-visible:outline-2 focus-visible:outline-tactical"
            onclick={() => (reveal = !reveal)}
            aria-label={reveal ? "Hide password" : "Show password"}
            aria-pressed={reveal}
          >
            {#if reveal}<EyeOff class="size-4" />{:else}<Eye class="size-4" />{/if}
          </button>
        </div>
        {#if capsLock}
          <p class="mt-1.5 flex items-center gap-1.5 text-xs text-amber-400">
            <TriangleAlert class="size-3.5" aria-hidden="true" /> Caps Lock is on
          </p>
        {/if}
      </div>

      <!-- Keyfile -->
      <div>
        <span class="mb-1.5 flex items-baseline justify-between text-xs font-medium text-zinc-400">
          Keyfile <span class="font-normal text-zinc-500">optional</span>
        </span>
        {#if keyfile}
          <div class="flex h-14 items-center gap-2.5 rounded-lg border border-tactical/40 bg-tactical/5 px-3">
            <FileKey2 class="size-4 shrink-0 text-tactical" aria-hidden="true" />
            <div class="min-w-0 flex-1 font-mono text-xs">
              <p class="truncate text-tactical" title={keyfile.path}>[KEYFILE ATTACHED: {keyfile.info.file_name}]</p>
              <p class="text-zinc-500">{formatBytes(keyfile.info.size_bytes)} · read &amp; hashed (SHA-256)</p>
            </div>
            <button
              type="button"
              onclick={detachKeyfile}
              class="grid size-8 place-items-center rounded-md text-zinc-500 hover:bg-hairline hover:text-zinc-200 focus-visible:outline-2 focus-visible:outline-tactical"
              aria-label="Remove keyfile"
            >
              <X class="size-4" />
            </button>
          </div>
        {:else}
          <button
            type="button"
            onclick={browseKeyfile}
            disabled={busy || keyfileBusy}
            class="flex h-14 w-full items-center justify-center gap-2 rounded-lg border border-dashed px-3 text-xs transition
              focus-visible:outline-2 focus-visible:outline-tactical
              {dragging
              ? 'border-tactical bg-tactical/10 text-tactical'
              : 'border-hairline text-zinc-400 hover:border-zinc-600 hover:text-zinc-200'}"
          >
            {#if keyfileBusy}
              <LoaderCircle class="size-4 animate-spin" aria-hidden="true" /> Reading keyfile…
            {:else if dragging}
              <FileKey2 class="size-4" aria-hidden="true" /> Drop to attach keyfile
            {:else}
              <FileKey2 class="size-4" aria-hidden="true" /> Drop keyfile here or <span class="text-zinc-200 underline decoration-zinc-600 underline-offset-2">browse</span>
            {/if}
          </button>
        {/if}
      </div>

      <!-- Feedback -->
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

    <p class="mt-6 flex items-center justify-center gap-1.5 [@media(max-height:640px)]:mt-3 font-mono text-[11px] text-zinc-500">
      <Fingerprint class="size-3.5" aria-hidden="true" />
      Windows Hello can be enabled after first unlock
    </p>
  </div>
</section>
