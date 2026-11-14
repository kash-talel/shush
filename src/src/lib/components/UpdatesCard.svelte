<script lang="ts">
  import { Download, LoaderCircle, RefreshCw, TriangleAlert } from "@lucide/svelte";
  import {
    checkForUpdate,
    downloadUpdate,
    installUpdate,
    NETWORK_CHANGED_EVENT,
    setUpdateMode,
    toCmdError,
    updateStatus,
    type CmdError,
    type UpdateInfo,
    type UpdateMode,
  } from "../tauri-bridge";

  // Settings -> Updates (issue #78). Checks only run while the network is allowed (air-gapped
  // mode off). Downloading and installing happen only on the user's click (#197): Download
  // fetches and verifies the installer; Install asks first, locks the vault, then restarts.
  let info = $state<UpdateInfo | null>(null);
  let error = $state<CmdError | null>(null);
  let busy = $state(false);
  /** Version awaiting the "Update to X?" confirmation, if the prompt is open. */
  let confirming = $state<string | null>(null);
  let installing = $state(false);

  async function refresh() {
    try {
      info = await updateStatus();
    } catch (e) {
      error = toCmdError(e);
    }
  }

  $effect(() => {
    refresh();
    // The Network card above can open or close the gate; re-read so this card never shows a
    // stale "air-gapped" note or a wrongly disabled "Check now".
    const onNetwork = () => void refresh();
    window.addEventListener(NETWORK_CHANGED_EVENT, onNetwork);
    // Background checks record results on their own; pick them up while the card is open.
    const timer = setInterval(() => {
      if (!busy) void refresh();
    }, 30_000);
    return () => {
      window.removeEventListener(NETWORK_CHANGED_EVENT, onNetwork);
      clearInterval(timer);
    };
  });

  async function changeMode(select: HTMLSelectElement) {
    await run(() => setUpdateMode(select.value as UpdateMode));
    // A failed save leaves `info` unchanged, so Svelte would not reset the select: show the
    // mode that is really in effect, not the click.
    select.value = info?.mode ?? "notify";
  }

  async function run(action: () => Promise<UpdateInfo>) {
    busy = true;
    error = null;
    try {
      info = await action();
    } catch (e) {
      error = toCmdError(e);
    } finally {
      busy = false;
    }
  }

  async function install(version: string) {
    busy = true;
    error = null;
    try {
      await installUpdate(version);
      // The app quits in a moment and the installer relaunches it, locked.
      installing = true;
      confirming = null;
    } catch (e) {
      error = toCmdError(e);
      confirming = null;
      await refresh();
    } finally {
      busy = false;
    }
  }

  const date = (unix: number) => new Date(unix * 1000).toLocaleDateString();
  const canCheck = $derived(info !== null && info.mode === "notify" && !info.air_gapped && !busy);
  /** A newer version the user can download (not the one already staged). */
  const offered = $derived(
    info?.status.state === "available" && info.status.version !== info.staged ? info.status.version : null,
  );
  let fetching = $state(false);
  const downloading = $derived(info?.downloading === true || fetching);

  async function download(version: string) {
    fetching = true;
    try {
      await run(() => downloadUpdate(version));
      // A refused download may have recorded a newer check result (feed moved, up to date):
      // show it instead of offering the old version again. The error stays visible.
      if (error) {
        const shown = error;
        await refresh();
        error = shown;
      }
    } finally {
      fetching = false;
    }
  }
</script>

<div class="flex flex-col gap-3 rounded-[7px] border border-hairline bg-surface/60 p-4 shadow-[inset_0_1px_0_rgb(255_255_255/0.03)]">
  <h3 class="flex items-center gap-2 font-display text-[15px] font-bold text-zinc-50">
    <RefreshCw class="size-4 text-emerald" aria-hidden="true" /> Updates
  </h3>
  <p class="text-xs leading-5 text-zinc-400">
    shush can check for new versions and tell you. Nothing is downloaded or installed until you click, and
    the check sends no identifiers. The feed and the installer are signature-checked, so a tampered or
    replayed one is ignored.
  </p>

  <label class="flex items-center gap-2 text-xs text-zinc-300">
    <span>Update checks</span>
    <select
      class="rounded border border-hairline bg-surface px-2 py-1 text-xs text-zinc-200"
      value={info?.mode ?? "notify"}
      disabled={busy || info === null}
      onchange={(e) => changeMode(e.currentTarget)}
    >
      <option value="notify">Notify only</option>
      <option value="off">Off</option>
    </select>
  </label>

  {#if info?.air_gapped}
    <p class="text-xs text-zinc-400" role="status">
      Air-gapped mode is on, so shush will not check for updates. Turn it off under Network to allow checks.
    </p>
  {:else if info?.mode === "off"}
    <p class="text-xs text-zinc-400" role="status">Update checks are off.</p>
  {:else if info}
    {@const s = info.status}
    <div role="status" class="text-xs leading-5">
      {#if s.state === "unchecked"}
        <p class="text-zinc-400">Not checked yet. shush checks at start and about once a day.</p>
      {:else if s.state === "up_to_date"}
        <p class="text-zinc-300">
          You are up to date ({info.installed}). Verified {date(info.checked_at ?? s.verified_until)}.
        </p>
      {:else if s.state === "available"}
        <p class={s.security ? "font-bold text-caution" : "text-zinc-200"}>
          {s.security ? "Security update available" : "Update available"}: {s.version} (you have {info.installed}).
        </p>
        {#if s.below_min_supported}
          <p class="text-caution">Your version is no longer supported. Please update.</p>
        {/if}
        {#if info.staged !== s.version}
          <p class="text-zinc-400">Download it here, or from the shush website. Nothing is installed until you confirm.</p>
        {/if}
      {:else if s.state === "stale"}
        <p class="flex items-start gap-1.5 text-caution">
          <TriangleAlert class="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
          <span>Can't confirm you're up to date: the update feed is out of date.</span>
        </p>
      {:else}
        <p class="flex items-start gap-1.5 text-caution">
          <TriangleAlert class="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
          <span><span class="font-mono">[{s.code}]</span> {s.message}</span>
        </p>
      {/if}
    </div>
  {/if}

  {#if installing}
    <p class="text-xs text-zinc-300" role="status">Installing. shush will close and reopen locked.</p>
  {:else if info?.staged && confirming === info.staged}
    <div class="flex flex-col gap-2 rounded border border-caution/40 p-3" role="alertdialog" aria-label="Confirm update">
      <p class="text-xs text-zinc-200">Update to {info.staged}? Your vault will lock first.</p>
      <div class="flex gap-2">
        <button
          type="button"
          class="inline-flex items-center gap-1.5 rounded border border-hairline bg-white/5 px-3 py-1.5 text-xs text-zinc-50 hover:bg-white/10 disabled:opacity-50"
          disabled={busy}
          onclick={() => info?.staged && install(info.staged)}
        >
          {#if busy}<LoaderCircle class="size-3.5 animate-spin" aria-hidden="true" />{/if}
          Lock and install
        </button>
        <button
          type="button"
          class="rounded border border-hairline px-3 py-1.5 text-xs text-zinc-300 hover:bg-white/5 disabled:opacity-50"
          disabled={busy}
          onclick={() => (confirming = null)}
        >
          Cancel
        </button>
      </div>
    </div>
  {:else if info?.staged}
    <p class="text-xs text-zinc-300" role="status">Version {info.staged} is downloaded and verified.</p>
  {/if}

  <div class="flex flex-wrap gap-2">
    <button
      type="button"
      class="inline-flex items-center gap-1.5 rounded border border-hairline px-3 py-1.5 text-xs text-zinc-200 hover:bg-white/5 disabled:opacity-50"
      disabled={!canCheck}
      onclick={() => run(checkForUpdate)}
    >
      {#if busy && !downloading}<LoaderCircle class="size-3.5 animate-spin" aria-hidden="true" />{/if}
      Check now
    </button>
    {#if offered && !info?.air_gapped && info?.mode === "notify"}
      {@const version = offered}
      <button
        type="button"
        class="inline-flex items-center gap-1.5 rounded border border-hairline px-3 py-1.5 text-xs text-zinc-200 hover:bg-white/5 disabled:opacity-50"
        disabled={busy || info?.downloading}
        onclick={() => download(version)}
      >
        {#if downloading}
          <LoaderCircle class="size-3.5 animate-spin" aria-hidden="true" /> Downloading and verifying
        {:else}
          <Download class="size-3.5" aria-hidden="true" /> Download {version}
        {/if}
      </button>
    {/if}
    {#if info?.staged && confirming === null && !installing}
      <button
        type="button"
        class="inline-flex items-center gap-1.5 rounded border border-emerald/50 px-3 py-1.5 text-xs text-zinc-50 hover:bg-white/5 disabled:opacity-50"
        disabled={busy}
        onclick={() => (confirming = info?.staged ?? null)}
      >
        Install and restart
      </button>
    {/if}
  </div>

  {#if error}
    <p class="flex items-start gap-1.5 text-xs text-danger" role="alert">
      <TriangleAlert class="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
      <span><span class="font-mono">[{error.code}]</span> {error.message}</span>
    </p>
  {/if}
</div>
