<script lang="ts">
  import { formatKdf, type AppInfo, type CipherInfo, type KdfParams } from "../tauri-bridge";

  // Tactical footer status bar (spec §7.1). Shows the *vault's* cipher/KDF
  // when one exists, otherwise the defaults for a new vault. Clipboard / TPM
  // segments arrive with their features.
  let {
    info,
    locked = true,
    cipher = null,
    kdf = null,
  }: { info: AppInfo | null; locked?: boolean; cipher?: CipherInfo | null; kdf?: KdfParams | null } = $props();

  const cipherName = $derived(cipher?.name ?? info?.default_cipher.name ?? "…");
  const kdfLabel = $derived(kdf ? formatKdf(kdf) : info ? formatKdf(info.default_kdf) : "…");
</script>

<footer
  class="flex h-7 shrink-0 items-center gap-2 overflow-hidden border-t border-hairline bg-surface px-3 font-mono text-[11px] whitespace-nowrap text-zinc-500"
  aria-label="Vault status"
>
  <span>
    [VAULT: <span class={locked ? "text-danger" : "text-tactical"}>{locked ? "LOCKED" : "UNLOCKED"}</span>]
  </span>
  <span aria-hidden="true" class="text-hairline">│</span>
  <span>[CIPHER: <span class="text-cold">{cipherName}</span>]</span>
  <span aria-hidden="true" class="text-hairline max-sm:hidden">│</span>
  <span class="max-sm:hidden">[KDF: <span class="text-cold">{kdfLabel}</span>]</span>
  <span class="ml-auto text-zinc-600">v{info?.version ?? "?"}</span>
</footer>
