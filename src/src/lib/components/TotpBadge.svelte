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

  // One tick per second of the period, clockwise from 12 o'clock.
  const period = $derived(current?.period ?? 30);
  const ticks = $derived(
    Array.from({ length: period }, (_, i) => {
      const a = (i / period) * 2 * Math.PI - Math.PI / 2;
      const [cos, sin] = [Math.cos(a), Math.sin(a)];
      return { i, x1: 22 + 16 * cos, y1: 22 + 16 * sin, x2: 22 + 21 * cos, y2: 22 + 21 * sin };
    }),
  );
  const lit = $derived(current ? current.remaining : 0);
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

<div class="flex items-center gap-3.5">
  <!-- Tachometer: one tick per second of the period; lit ticks are the seconds left. -->
  <svg width="44" height="44" viewBox="0 0 44 44" class="shrink-0" aria-hidden="true">
    <circle cx="22" cy="22" r="13" fill="#09090e" stroke="var(--color-hairline)" />
    {#each ticks as t (t.i)}
      <line
        x1={t.x1}
        y1={t.y1}
        x2={t.x2}
        y2={t.y2}
        stroke-width="2"
        stroke-linecap="butt"
        stroke={t.i < lit ? (urgent ? "var(--color-danger)" : "var(--color-crimson)") : "var(--color-hairline)"}
      />
    {/each}
    <text x="22" y="25.5" text-anchor="middle" class="fill-zinc-400 font-mono text-[9px] tabular-nums">{current?.remaining ?? "–"}</text>
  </svg>
  {#if error}
    <span class="text-xs text-danger">{error}</span>
  {:else}
    <button
      type="button"
      onclick={oncopy}
      class={[
        "group flex items-center gap-2 rounded-[3px] px-1.5 py-0.5 font-mono text-[22px] font-medium tracking-[0.14em] tabular-nums transition hover:bg-raised",
        urgent ? "text-danger" : "text-zinc-50",
      ]}
      aria-label="Copy one-time code"
    >
      {pretty}
      <span class="sr-only">{current?.remaining ?? "–"}s left</span>
      <Copy class="size-3.5 text-zinc-500 opacity-0 transition group-hover:opacity-100 group-focus-visible:opacity-100" aria-hidden="true" />
    </button>
  {/if}
</div>
