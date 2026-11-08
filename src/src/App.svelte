<script lang="ts">
  import { onMount } from "svelte";
  import { listen } from "@tauri-apps/api/event";
  import StatusBar from "./lib/components/StatusBar.svelte";
  import UnlockScreen from "./lib/components/UnlockScreen.svelte";
  import CreateVaultScreen from "./lib/components/CreateVaultScreen.svelte";
  import Dashboard from "./lib/components/Dashboard.svelte";
  import OnboardingScreen from "./lib/components/OnboardingScreen.svelte";
  import {
    appInfo,
    lock,
    vaultStatus,
    AUTO_LOCK_EVENT,
    type AppInfo,
    type AutoLockReason,
    type NewVaultTarget,
    type VaultStatus,
    type VaultSummary,
  } from "./lib/tauri-bridge";

  // Router (spec §8): Create → Unlock → Vault. Spotlight arrives in Phase 5.
  let info = $state<AppInfo | null>(null);
  let status = $state<VaultStatus | null>(null);
  let summary = $state<VaultSummary | null>(null);
  let clipboardUntil = $state(0);
  let autoLockReason = $state<AutoLockReason | null>(null);
  // First run: show the import step once, right after the vault is created.
  let onboarding = $state(false);
  // "New vault" from the shelf: the create screen for a chosen location.
  let newTarget = $state<NewVaultTarget | null>(null);
  const targetStatus = $derived<VaultStatus | null>(
    newTarget && {
      id: null,
      name: newTarget.name,
      color: newTarget.color ?? "crimson",
      path: newTarget.path,
      exists: false,
      unlocked: false,
      keyfile_required: null,
      cipher: null,
      kdf: null,
      error: null,
      hide_names: status?.hide_names ?? false,
    },
  );

  async function refresh() {
    status = await vaultStatus();
  }

  async function doLock() {
    await lock();
    summary = null;
    onboarding = false;
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
    // Copies from Spotlight (another window) also drive the countdown.
    const unlistenCopy = listen<number>("clipboard-copied", (e) => {
      clipboardUntil = Date.now() + e.payload * 1000;
    });
    const unlisten = listen<AutoLockReason>(AUTO_LOCK_EVENT, async (e) => {
      summary = null;
      onboarding = false;
      clipboardUntil = 0;
      autoLockReason = e.payload;
      await refresh();
    });
    void init();
    return () => {
      void unlisten.then((f) => f());
      void unlistenCopy.then((f) => f());
    };
  });
</script>

<div class="flex h-full flex-col">
  {#if summary && onboarding}
    <OnboardingScreen ondone={() => (onboarding = false)} />
  {:else if summary}
    <Dashboard hotkey={info?.spotlight_hotkey ?? null} onlock={doLock} oncopied={(secs) => (clipboardUntil = Date.now() + secs * 1000)} />
  {:else if newTarget && targetStatus}
    <CreateVaultScreen
      vault={targetStatus}
      {info}
      target={newTarget}
      oncancel={() => (newTarget = null)}
      oncreated={(s) => {
        newTarget = null;
        summary = s;
        onboarding = true;
      }}
    />
  {:else if status && !status.exists && status.id === null}
    <!-- First run: no vault anywhere yet. -->
    <CreateVaultScreen
      vault={status}
      {info}
      oncreated={(s) => {
        summary = s;
        onboarding = true;
      }}
    />
  {:else if status}
    <!-- Re-mount per vault: a switched-to vault starts sealed with a clean form. -->
    {#key status.id}
      <UnlockScreen
        vault={status}
        {autoLockReason}
        onunlocked={(s) => {
          summary = s;
          autoLockReason = null;
        }}
        onswitch={(s) => {
          status = s;
          autoLockReason = null;
        }}
        onnew={(t) => (newTarget = t)}
      />
    {/key}
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
