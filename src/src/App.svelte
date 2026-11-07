<script lang="ts">
  import { onMount } from "svelte";
  import { listen } from "@tauri-apps/api/event";
  import StatusBar from "./lib/components/StatusBar.svelte";
  import UnlockScreen from "./lib/components/UnlockScreen.svelte";
  import CreateVaultScreen from "./lib/components/CreateVaultScreen.svelte";
  import Dashboard from "./lib/components/Dashboard.svelte";
  import {
    appInfo,
    lock,
    vaultStatus,
    AUTO_LOCK_EVENT,
    type AppInfo,
    type AutoLockReason,
    type VaultStatus,
    type VaultSummary,
  } from "./lib/tauri-bridge";

  // Router (spec §8): Create → Unlock → Vault. Spotlight arrives in Phase 5.
  let info = $state<AppInfo | null>(null);
  let status = $state<VaultStatus | null>(null);
  let summary = $state<VaultSummary | null>(null);
  let clipboardUntil = $state(0);
  let autoLockReason = $state<AutoLockReason | null>(null);

  async function refresh() {
    status = await vaultStatus();
  }

  async function doLock() {
    await lock();
    summary = null;
    clipboardUntil = 0; // lock also clears shush's clipboard content
    await refresh();
  }

  async function init() {
    [info] = await Promise.all([appInfo(), refresh()]);
    // A reload of the WebView must not show stale unlocked UI: the Rust side
    // may still hold the vault, so lock to get back to a known state.
    if (status?.unlocked) await doLock();
  }

  onMount(() => {
    // The backend already locked and wiped the vault; just follow it.
    const unlisten = listen<AutoLockReason>(AUTO_LOCK_EVENT, async (e) => {
      summary = null;
      clipboardUntil = 0;
      autoLockReason = e.payload;
      await refresh();
    });
    void init();
    return () => void unlisten.then((f) => f());
  });
</script>

<div class="flex h-full flex-col">
  {#if summary}
    <Dashboard onlock={doLock} oncopied={(secs) => (clipboardUntil = Date.now() + secs * 1000)} />
  {:else if status && !status.exists}
    <CreateVaultScreen vault={status} {info} oncreated={(s) => (summary = s)} />
  {:else if status}
    <UnlockScreen
      vault={status}
      {autoLockReason}
      onunlocked={(s) => {
        summary = s;
        autoLockReason = null;
      }}
    />
  {:else}
    <div class="flex-1"></div>
  {/if}
  <StatusBar
    {info}
    locked={summary === null}
    cipher={summary?.cipher ?? status?.cipher ?? null}
    kdf={summary?.kdf ?? status?.kdf ?? null}
    {clipboardUntil}
  />
</div>
