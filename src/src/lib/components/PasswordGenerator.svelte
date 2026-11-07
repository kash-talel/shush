<script lang="ts">
  import { onMount } from "svelte";
  import { RefreshCw } from "@lucide/svelte";
  import { generatePassword, toCmdError, type GeneratorOptions } from "../tauri-bridge";

  // Password generator (spec §7.2.4). Generation uses the OS CSPRNG in Rust.
  let { onuse }: { onuse: (password: string) => void } = $props();

  let options = $state<GeneratorOptions>({
    length: 24,
    lower: true,
    upper: true,
    digits: true,
    symbols: true,
    exclude_ambiguous: false,
  });
  let result = $state.raw<{ password: string; entropy_bits: number } | null>(null);
  let error = $state<string | null>(null);

  const strength = $derived.by(() => {
    const bits = result?.entropy_bits ?? 0;
    if (bits < 60) return { label: "WEAK", tone: "bg-danger", pct: 30 };
    if (bits < 90) return { label: "FAIR", tone: "bg-amber-400", pct: 65 };
    return { label: "STRONG", tone: "bg-tactical", pct: 100 };
  });

  async function regenerate() {
    try {
      result = await generatePassword(options);
      error = null;
    } catch (e) {
      result = null;
      error = toCmdError(e).message;
    }
  }

  onMount(regenerate);

  const sets: { key: "upper" | "lower" | "digits" | "symbols"; label: string }[] = [
    { key: "upper", label: "A-Z" },
    { key: "lower", label: "a-z" },
    { key: "digits", label: "0-9" },
    { key: "symbols", label: "!@#" },
  ];
</script>

<div class="flex flex-col gap-3 rounded-lg border border-hairline bg-obsidian p-3">
  <div class="flex items-center gap-2">
    <output class="min-w-0 flex-1 truncate font-mono text-sm text-zinc-100 select-text" aria-live="polite">
      {result?.password ?? error ?? "…"}
    </output>
    <button
      type="button"
      onclick={regenerate}
      class="grid size-8 place-items-center rounded-md text-zinc-400 hover:bg-hairline hover:text-zinc-100"
      aria-label="Generate another"
    >
      <RefreshCw class="size-4" />
    </button>
  </div>

  <div class="flex items-center gap-2">
    <div class="h-1 flex-1 overflow-hidden rounded-full bg-hairline">
      <div class={["h-full rounded-full transition-all", strength.tone]} style:width="{strength.pct}%"></div>
    </div>
    <span class="font-mono text-[10px] text-zinc-500">
      {strength.label} · {Math.round(result?.entropy_bits ?? 0)} bits
    </span>
  </div>

  <label class="flex items-center gap-3 text-xs text-zinc-400">
    Length
    <input type="range" min="8" max="64" bind:value={options.length} oninput={regenerate} class="flex-1 accent-emerald-500" />
    <span class="w-6 text-right font-mono text-zinc-200">{options.length}</span>
  </label>

  <div class="flex flex-wrap gap-1.5">
    {#each sets as s (s.key)}
      <label
        class={[
          "cursor-pointer rounded-md border px-2 py-1 font-mono text-[11px] transition select-none",
          options[s.key] ? "border-tactical/50 bg-tactical/10 text-tactical" : "border-hairline text-zinc-500",
        ]}
      >
        <input type="checkbox" class="sr-only" bind:checked={options[s.key]} onchange={regenerate} />
        [{s.label}]
      </label>
    {/each}
    <label
      class={[
        "cursor-pointer rounded-md border px-2 py-1 text-[11px] transition select-none",
        options.exclude_ambiguous ? "border-cold/50 bg-cold/10 text-cold" : "border-hairline text-zinc-500",
      ]}
    >
      <input type="checkbox" class="sr-only" bind:checked={options.exclude_ambiguous} onchange={regenerate} />
      no look-alikes
    </label>
  </div>

  <button
    type="button"
    disabled={!result}
    onclick={() => result && onuse(result.password)}
    class="h-8 rounded-md bg-tactical font-mono text-xs font-semibold tracking-wider text-obsidian hover:bg-emerald-400 disabled:bg-hairline disabled:text-zinc-500"
  >
    USE THIS PASSWORD
  </button>
</div>
