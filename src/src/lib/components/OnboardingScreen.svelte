<script lang="ts">
  import { onMount } from "svelte";
  import { ArrowRight, Check, Copy, Globe, PackageOpen } from "@lucide/svelte";
  import CsvImport from "./CsvImport.svelte";
  import { detectBrowsers, type Browser } from "../tauri-bridge";

  // First-run "bring your passwords" step (spec §10.1). Detection only checks
  // that a browser's profile folder exists; its password store is never read (#17).
  let { ondone }: { ondone: () => void } = $props();

  let browsers = $state.raw<Browser[] | null>(null);
  let copied = $state<string | null>(null);
  let imported = $state(0);

  async function copyUrl(b: Browser) {
    // Not a secret: just the browser's settings address.
    await navigator.clipboard.writeText(b.export_url);
    copied = b.id;
  }

  onMount(async () => {
    browsers = await detectBrowsers();
  });
</script>

<section class="flex flex-1 justify-center overflow-y-auto px-6 py-8">
  <div class="my-auto flex w-full max-w-[560px] flex-col gap-5">
    <header class="flex flex-col items-center gap-2 text-center">
      <div class="grid size-12 place-items-center rounded-xl border border-tactical/40 bg-tactical/10">
        <PackageOpen class="size-5 text-tactical" strokeWidth={1.75} aria-hidden="true" />
      </div>
      <h1 class="font-mono text-[13px] tracking-[0.18em] text-zinc-300">// BRING_YOUR_PASSWORDS</h1>
      <p class="max-w-md text-xs leading-5 text-zinc-400">
        Your vault is ready. Move your saved passwords in from your browser or old password manager: export a
        CSV there, then import it below. You can also do this later from <span class="text-zinc-200">Backup &amp; import</span>.
      </p>
    </header>

    {#if browsers && browsers.length}
      <ol class="flex flex-col gap-2" aria-label="Browsers found on this PC">
        {#each browsers as b (b.id)}
          <li class="flex items-center gap-3 rounded-lg border border-hairline bg-surface px-3 py-2.5">
            <Globe class="size-4 shrink-0 text-cold" aria-hidden="true" />
            <div class="min-w-0 flex-1">
              <p class="text-sm text-zinc-100">{b.name}</p>
              <p class="text-[11px] text-zinc-500">
                Open <span class="font-mono text-zinc-300">{b.export_url}</span> → {b.steps}
              </p>
            </div>
            <button
              type="button"
              onclick={() => copyUrl(b)}
              class="flex h-7 shrink-0 items-center gap-1 rounded-md border border-hairline px-2 text-[11px] text-zinc-400 hover:bg-hairline hover:text-zinc-100"
              aria-label="Copy {b.name} export address"
            >
              {#if copied === b.id}<Check class="size-3 text-tactical" aria-hidden="true" /> copied{:else}<Copy class="size-3" aria-hidden="true" /> address{/if}
            </button>
          </li>
        {/each}
      </ol>
    {:else if browsers}
      <p class="rounded-lg border border-hairline bg-surface px-3 py-2.5 text-xs text-zinc-400">
        No supported browser was found. Export a CSV from Bitwarden, 1Password, KeePass or KeePassXC instead.
      </p>
    {/if}

    <CsvImport onimported={() => (imported += 1)} />

    <button
      type="button"
      onclick={ondone}
      class={[
        "flex h-11 items-center justify-center gap-2 rounded-lg font-mono text-sm font-semibold tracking-wider transition",
        imported ? "bg-tactical text-obsidian hover:bg-emerald-400" : "border border-hairline text-zinc-300 hover:bg-hairline",
      ]}
    >
      {imported ? "OPEN MY VAULT" : "SKIP FOR NOW"} <ArrowRight class="size-4" aria-hidden="true" />
    </button>
  </div>
</section>
