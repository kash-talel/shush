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
    if (bits < 90) return { label: "FAIR", tone: "bg-caution", pct: 65 };
    return { label: "STRONG", tone: "bg-uv", pct: 100 };
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

<div class="acrylic flex flex-col gap-3 rounded-[8px] p-3">
  <div class="well flex items-center gap-2 pl-3">
    <output class="min-w-0 flex-1 truncate font-mono text-[13px] text-uv-soft select-text" aria-live="polite">
      {result?.password ?? error ?? "…"}
    </output>
    <button
      type="button"
      onclick={regenerate}
      class="grid size-9 place-items-center rounded-[3px] text-zinc-400 hover:bg-raised hover:text-zinc-50 active:rotate-90"
      aria-label="Generate another"
    >
      <RefreshCw class="size-4" />
    </button>
  </div>

  <div class="flex items-center gap-2">
    <div class="flex h-1.5 flex-1 gap-[3px]" aria-hidden="true">
      {#each { length: 16 } as _, i (i)}
        <span class={["flex-1 rounded-[1px] transition-colors", i < Math.round((strength.pct / 100) * 16) ? strength.tone : "bg-hairline"]}></span>
      {/each}
    </div>
    <span class="font-mono text-[10px] text-zinc-500 tabular-nums">
      {strength.label} · {Math.round(result?.entropy_bits ?? 0)} bits
    </span>
  </div>

  <label class="flex items-center gap-3 text-xs text-zinc-300">
    Length
    <input type="range" min="8" max="64" bind:value={options.length} oninput={regenerate} class="flex-1 accent-crimson" />
    <span class="w-6 text-right font-mono text-[12px] text-zinc-50 tabular-nums">{options.length}</span>
  </label>

  <div class="flex flex-wrap gap-1.5">
    {#each sets as s (s.key)}
      <label
        class={[
          "cursor-pointer rounded-[3px] border px-2 py-1 font-mono text-[10.5px] transition select-none has-focus-visible:outline-2 has-focus-visible:outline-ruby",
          options[s.key] ? "border-crimson/60 bg-crimson/15 text-ruby shadow-[inset_0_-2px_0_var(--color-crimson)]" : "border-hairline bg-raised text-zinc-500",
        ]}
      >
        <input type="checkbox" class="sr-only" bind:checked={options[s.key]} onchange={regenerate} />
        {s.label}
      </label>
    {/each}
    <label
      class={[
        "cursor-pointer rounded-[3px] border px-2 py-1 text-[11px] transition select-none has-focus-visible:outline-2 has-focus-visible:outline-ruby",
        options.exclude_ambiguous ? "border-uv/50 bg-uv/10 text-uv" : "border-hairline bg-raised text-zinc-500",
      ]}
    >
      <input type="checkbox" class="sr-only" bind:checked={options.exclude_ambiguous} onchange={regenerate} />
      no look-alikes
    </label>
  </div>

  <button type="button" disabled={!result} onclick={() => result && onuse(result.password)} class="key h-9 text-[11px]">
    USE THIS PASSWORD
  </button>
</div>
