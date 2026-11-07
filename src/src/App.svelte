<script lang="ts">
  import { onMount } from "svelte";
  import StatusBar from "./lib/components/StatusBar.svelte";
  import UnlockScreen from "./lib/components/UnlockScreen.svelte";
  import { appInfo, vaultStatus, type AppInfo, type VaultStatus } from "./lib/tauri-bridge";

  // Router (spec §8): Unlock vs Main View vs Spotlight. Only Unlock exists in Phase 1.
  let info = $state<AppInfo | null>(null);
  let vault = $state<VaultStatus | null>(null);

  onMount(async () => {
    [info, vault] = await Promise.all([appInfo(), vaultStatus()]);
  });
</script>

<div class="flex h-full flex-col">
  <UnlockScreen {vault} />
  <StatusBar {info} />
</div>
