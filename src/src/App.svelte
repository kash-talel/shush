<script lang="ts">
  import { onMount } from "svelte";
  import { ShieldCheck } from "@lucide/svelte";
  import { appInfo, type AppInfo } from "./lib/tauri-bridge";

  // Phase 1 placeholder. The Unlock / Dashboard / Spotlight router lands in Phase 4.
  let info = $state<AppInfo | null>(null);
  let error = $state<string | null>(null);

  onMount(async () => {
    try {
      info = await appInfo();
    } catch (e) {
      error = String(e);
    }
  });
</script>

<main class="flex h-full flex-col">
  <section class="flex flex-1 flex-col items-center justify-center gap-4">
    <ShieldCheck class="size-10 text-tactical" strokeWidth={1.5} />
    <p class="font-mono text-sm tracking-widest text-zinc-400">// SHUSH_VAULT_AUTHENTICATION</p>
    <p class="font-mono text-xs text-zinc-600">phase 1 · crypto engine</p>
  </section>

  <footer
    class="flex gap-3 border-t border-hairline bg-surface px-4 py-1.5 font-mono text-[11px] text-zinc-500"
  >
    <span>[VAULT: <span class="text-danger">LOCKED</span>]</span>
    <span>│</span>
    <span>
      [CIPHERS:
      <span class="text-cold">{info ? info.supported_ciphers.join(" / ") : error ? "ERR" : "…"}</span>]
    </span>
    <span>│</span>
    <span>[v{info?.version ?? "?"}]</span>
  </footer>
</main>
