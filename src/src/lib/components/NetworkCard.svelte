<script lang="ts">
  import { TriangleAlert, WifiOff } from "@lucide/svelte";
  import { networkStatus, setAirGapped, toCmdError, type CmdError, type NetworkStatus } from "../tauri-bridge";

  // Settings -> Network (issue #157). Air-gapped is the default: shush opens no
  // network socket until this is turned off. Native messaging to the browser
  // extension is local and is not affected.
  let status = $state<NetworkStatus | null>(null);
  let error = $state<CmdError | null>(null);
  let busy = $state(false);

  async function refresh() {
    try {
      status = await networkStatus();
    } catch (e) {
      error = toCmdError(e);
    }
  }

  $effect(() => {
    refresh();
  });

  async function toggle(on: boolean) {
    busy = true;
    error = null;
    try {
      status = await setAirGapped(on);
    } catch (e) {
      error = toCmdError(e);
    } finally {
      busy = false;
      await refresh();
    }
  }
</script>

<div class="flex flex-col gap-3 rounded-[7px] border border-hairline bg-surface/60 p-4 shadow-[inset_0_1px_0_rgb(255_255_255/0.03)]">
  <h3 class="flex items-center gap-2 font-display text-[15px] font-bold text-zinc-50">
    <WifiOff class="size-4 text-emerald" aria-hidden="true" /> Network
  </h3>
  <p class="text-xs leading-5 text-zinc-400">
    Air-gapped mode keeps shush off the network. While it is on, sync and every other network feature are
    disabled. Browser pairing is local and keeps working.
  </p>

  <label class="flex items-start gap-2 text-xs text-zinc-300">
    <input
      type="checkbox"
      class="mt-0.5"
      checked={status?.air_gapped ?? true}
      disabled={busy || status === null || !status.available}
      onchange={(e) => toggle(e.currentTarget.checked)}
    />
    <span>Air-gapped mode (recommended)</span>
  </label>

  {#if status && !status.available}
    <p class="text-xs text-zinc-400" role="status">This build of shush was made without network support, so it is always air-gapped.</p>
  {:else if status?.air_gapped}
    <p class="text-xs text-zinc-400" role="status">Network features are disabled. Turn air-gapped mode off to allow them.</p>
  {:else if status}
    <p class="flex items-start gap-1.5 text-xs text-caution" role="status">
      <TriangleAlert class="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
      <span>Air-gapped mode is off. Network features may connect when you use them.</span>
    </p>
  {/if}

  {#if error}
    <p class="flex items-start gap-1.5 text-xs text-danger" role="alert">
      <TriangleAlert class="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
      <span><span class="font-mono">[{error.code}]</span> {error.message}</span>
    </p>
  {/if}
</div>
