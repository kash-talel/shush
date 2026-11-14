<script lang="ts">
  import { LoaderCircle, RefreshCw, TriangleAlert } from "@lucide/svelte";
  import {
    checkForUpdate,
    setUpdateMode,
    toCmdError,
    updateStatus,
    type CmdError,
    type UpdateInfo,
    type UpdateMode,
  } from "../tauri-bridge";

  // Settings -> Updates (issue #78, notify-only). Checks only run while the network is allowed
  // (air-gapped mode off). Nothing is downloaded or installed; this card only reports.
  let info = $state<UpdateInfo | null>(null);
  let error = $state<CmdError | null>(null);
  let busy = $state(false);

  async function refresh() {
    try {
      info = await updateStatus();
    } catch (e) {
      error = toCmdError(e);
    }
  }

  $effect(() => {
    refresh();
  });

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

  const date = (unix: number) => new Date(unix * 1000).toLocaleDateString();
  const canCheck = $derived(info !== null && info.mode === "notify" && !info.air_gapped && !busy);
</script>

<div class="flex flex-col gap-3 rounded-[7px] border border-hairline bg-surface/60 p-4 shadow-[inset_0_1px_0_rgb(255_255_255/0.03)]">
  <h3 class="flex items-center gap-2 font-display text-[15px] font-bold text-zinc-50">
    <RefreshCw class="size-4 text-emerald" aria-hidden="true" /> Updates
  </h3>
  <p class="text-xs leading-5 text-zinc-400">
    shush can check for new versions and tell you. Nothing is downloaded or installed automatically, and
    the check sends no identifiers. The feed is signature-checked, so a tampered or replayed one is ignored.
  </p>

  <label class="flex items-center gap-2 text-xs text-zinc-300">
    <span>Update checks</span>
    <select
      class="rounded border border-hairline bg-surface px-2 py-1 text-xs text-zinc-200"
      value={info?.mode ?? "notify"}
      disabled={busy || info === null}
      onchange={(e) => run(() => setUpdateMode(e.currentTarget.value as UpdateMode))}
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
        <p class="text-zinc-400">Download it from the shush website. It is not installed for you.</p>
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

  <div>
    <button
      type="button"
      class="inline-flex items-center gap-1.5 rounded border border-hairline px-3 py-1.5 text-xs text-zinc-200 hover:bg-white/5 disabled:opacity-50"
      disabled={!canCheck}
      onclick={() => run(checkForUpdate)}
    >
      {#if busy}<LoaderCircle class="size-3.5 animate-spin" aria-hidden="true" />{/if}
      Check now
    </button>
  </div>

  {#if error}
    <p class="flex items-start gap-1.5 text-xs text-danger" role="alert">
      <TriangleAlert class="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
      <span><span class="font-mono">[{error.code}]</span> {error.message}</span>
    </p>
  {/if}
</div>
