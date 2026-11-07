<script lang="ts">
  import type { AppInfo } from "../tauri-bridge";

  // Tactical footer status bar (spec §7.1). Only shows facts the backend
  // actually reports; clipboard/TPM segments arrive with their features.
  let { info, locked = true }: { info: AppInfo | null; locked?: boolean } = $props();

  const kdf = $derived(
    info
      ? `ARGON2ID ${Math.round(info.default_kdf.mem_kib / 1024)}M/t${info.default_kdf.iterations}/p${info.default_kdf.parallelism}`
      : "…",
  );
</script>

<footer
  class="flex h-7 shrink-0 items-center gap-2 overflow-hidden border-t border-hairline bg-surface px-3 font-mono text-[11px] whitespace-nowrap text-zinc-500"
  aria-label="Vault status"
>
  <span>
    [VAULT: <span class={locked ? "text-danger" : "text-tactical"}>{locked ? "LOCKED" : "UNLOCKED"}</span>]
  </span>
  <span aria-hidden="true" class="text-hairline">│</span>
  <span>[CIPHER: <span class="text-cold">{info?.default_cipher.name ?? "…"}</span>]</span>
  <span aria-hidden="true" class="text-hairline max-sm:hidden">│</span>
  <span class="max-sm:hidden">[KDF: <span class="text-cold">{kdf}</span>]</span>
  <span class="ml-auto text-zinc-600">v{info?.version ?? "?"}</span>
</footer>
