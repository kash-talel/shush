<script lang="ts">
  import { onMount } from "svelte";
  import { LockKeyhole, LockOpen } from "@lucide/svelte";
  import { formatKdf, type VaultSummary } from "../tauri-bridge";

  // Placeholder for the Phase 4 dashboard: proves the vault is really open
  // and gives the user a way to lock it again.
  let { summary, onlock }: { summary: VaultSummary; onlock: () => void } = $props();

  let lockButton: HTMLButtonElement | undefined = $state();

  onMount(() => lockButton?.focus());

  function onKey(e: KeyboardEvent) {
    if (e.ctrlKey && !e.shiftKey && !e.altKey && e.key.toLowerCase() === "l") {
      e.preventDefault();
      onlock();
    }
  }

  const rows = $derived([
    ["Items", String(summary.item_count)],
    ["Folders", String(summary.folder_count)],
    ["Cipher", summary.cipher.name],
    ["KDF", formatKdf(summary.kdf)],
    ["Keyfile", summary.keyfile_required ? "required" : "not used"],
  ]);
</script>

<svelte:window onkeydown={onKey} />

<section class="flex flex-1 items-center justify-center overflow-y-auto px-6 py-10">
  <div class="w-full max-w-[380px] text-center">
    <div class="mx-auto mb-4 grid size-12 place-items-center rounded-xl border border-tactical/40 bg-tactical/10">
      <LockOpen class="size-5 text-tactical" strokeWidth={1.75} aria-hidden="true" />
    </div>
    <h1 class="font-mono text-[13px] tracking-[0.18em] text-tactical">// VAULT_UNLOCKED</h1>
    <p class="mt-2 text-xs text-zinc-400">
      Your vault is decrypted in memory. The item list, editor and TOTP arrive in Phase 4.
    </p>

    <dl class="mt-6 divide-y divide-hairline rounded-lg border border-hairline bg-surface text-left font-mono text-xs">
      {#each rows as [k, v] (k)}
        <div class="flex justify-between gap-4 px-3 py-2">
          <dt class="text-zinc-500">{k}</dt>
          <dd class="truncate text-zinc-200">{v}</dd>
        </div>
      {/each}
    </dl>

    <button
      bind:this={lockButton}
      type="button"
      onclick={onlock}
      class="mt-6 flex h-11 w-full items-center justify-center gap-2 rounded-lg border border-danger/40 font-mono text-sm tracking-wider text-danger transition
        hover:bg-danger/10 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-danger"
    >
      <LockKeyhole class="size-4" aria-hidden="true" /> LOCK VAULT
      <kbd class="rounded border border-current/30 px-1 text-[10px] opacity-70">CTRL+L</kbd>
    </button>
  </div>
</section>
