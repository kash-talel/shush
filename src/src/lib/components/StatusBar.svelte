<script lang="ts">
  import { onMount } from "svelte";
  import { formatKdf, type AppInfo, type CipherInfo, type KdfParams } from "../tauri-bridge";

  // Tactical footer status bar (spec §7.1). Shows the *vault's* cipher/KDF
  // when one exists, otherwise the defaults for a new vault. Clipboard / TPM
  // segments arrive with their features.
  let {
    info,
    locked = true,
    cipher = null,
    kdf = null,
    clipboardUntil = 0,
  }: {
    info: AppInfo | null;
    locked?: boolean;
    cipher?: CipherInfo | null;
    kdf?: KdfParams | null;
    /** Epoch ms at which the copied secret is auto-cleared (0 = nothing copied). */
    clipboardUntil?: number;
  } = $props();

  // External clock for the clipboard countdown.
  let now = $state(Date.now());
  onMount(() => {
    const t = setInterval(() => (now = Date.now()), 500);
    return () => clearInterval(t);
  });
  const clipboardSecs = $derived(Math.max(0, Math.ceil((clipboardUntil - now) / 1000)));

  const cipherName = $derived(cipher?.name ?? info?.default_cipher.name ?? "…");
  const kdfLabel = $derived(kdf ? formatKdf(kdf) : info ? formatKdf(info.default_kdf) : "…");
</script>

<footer
  class="steel flex h-7 shrink-0 items-center gap-3 overflow-hidden border-t border-hairline px-3 font-mono text-[10px] whitespace-nowrap text-zinc-600"
  aria-label="Vault status"
>
  <span class="flex items-center gap-1.5">
    <span class={["led", locked ? "text-ruby" : "text-uv"]} aria-hidden="true"></span>
    vault <span class={locked ? "text-ruby" : "text-uv"}>{locked ? "LOCKED" : "UNLOCKED"}</span>
  </span>
  <span aria-hidden="true" class="h-3 w-px bg-hairline"></span>
  <span>cipher <span class="text-zinc-300">{cipherName.toLowerCase()}</span></span>
  <span aria-hidden="true" class="h-3 w-px bg-hairline max-sm:hidden"></span>
  <span class="max-sm:hidden">kdf <span class="text-zinc-300">{kdfLabel.toLowerCase()}</span></span>
  {#if clipboardSecs > 0}
    <span aria-hidden="true" class="h-3 w-px bg-hairline"></span>
    <span class="flex items-center gap-1.5" aria-live="polite">
      <span class="led animate-pulse text-caution" aria-hidden="true"></span>
      clipboard clears in <span class="text-caution tabular-nums">{clipboardSecs}s</span>
    </span>
  {/if}
  <span class="ml-auto text-zinc-700">shush v{info?.version ?? "?"}</span>
</footer>
