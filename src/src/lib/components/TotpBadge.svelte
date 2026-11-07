<script lang="ts">
  import { onMount } from "svelte";
  import { Copy } from "@lucide/svelte";
  import { totpCode, toCmdError, type TotpCode } from "../tauri-bridge";

  // Live 2FA code with a circular countdown ring (spec §7.2.2).
  // The code is short-lived by design; the secret never leaves Rust.
  let { id, oncopy }: { id: string; oncopy: () => void } = $props();

  // Each fetched code remembers which item it belongs to, so switching items
  // never shows the previous item's code (no $effect needed).
  let fetched = $state.raw<(TotpCode & { for: string }) | null>(null);
  const current = $derived(fetched?.for === id ? fetched : null);
  let error = $state<string | null>(null);

  const R = 14;
  const C = 2 * Math.PI * R;
  const fraction = $derived(current ? current.remaining / current.period : 0);
  const urgent = $derived(current !== null && current.remaining <= 5);
  const pretty = $derived(
    current ? current.code.replace(/^(\d{3,4})(\d{3,4})$/, (_, a, b) => `${a} ${b}`) : "••• •••",
  );

  async function tick() {
    try {
      // Reads the latest `id` prop on every tick.
      const forId = id;
      fetched = { ...(await totpCode(forId)), for: forId };
      error = null;
    } catch (e) {
      error = toCmdError(e).message;
    }
  }

  onMount(() => {
    void tick();
    // External clock: poll once per second (cheap IPC, no secret crosses).
    const timer = setInterval(tick, 1000);
    return () => clearInterval(timer);
  });
</script>

<div class="flex items-center gap-3">
  <svg width="36" height="36" viewBox="0 0 36 36" class="shrink-0 -rotate-90" aria-hidden="true">
    <circle cx="18" cy="18" r={R} fill="none" stroke="var(--color-hairline)" stroke-width="3" />
    <circle
      cx="18"
      cy="18"
      r={R}
      fill="none"
      stroke={urgent ? "var(--color-danger)" : "var(--color-tactical)"}
      stroke-width="3"
      stroke-linecap="round"
      stroke-dasharray={C}
      stroke-dashoffset={C * (1 - fraction)}
      class="transition-[stroke-dashoffset] duration-1000 ease-linear"
    />
  </svg>
  {#if error}
    <span class="text-xs text-danger">{error}</span>
  {:else}
    <button
      type="button"
      onclick={oncopy}
      class={["group flex items-baseline gap-2 rounded-md px-1 font-mono text-xl tracking-[0.2em] transition hover:bg-hairline", urgent ? "text-danger" : "text-tactical"]}
      aria-label="Copy one-time code"
    >
      {pretty}
      <span class="text-[10px] tracking-normal text-zinc-500">{current?.remaining ?? "–"}s</span>
      <Copy class="size-3.5 self-center text-zinc-500 opacity-0 transition group-hover:opacity-100" aria-hidden="true" />
    </button>
  {/if}
</div>
