<script lang="ts">
  import { ArrowLeftRight, TriangleAlert } from "@lucide/svelte";
  import {
    NETWORK_CHANGED_EVENT,
    syncCancelPairing,
    syncDiscover,
    syncForget,
    syncJoin,
    syncResetIdentity,
    syncSetAdvertise,
    syncStartPairing,
    syncStatus,
    toCmdError,
    type CmdError,
    type SyncFound,
    type SyncStatus,
  } from "../tauri-bridge";

  // Settings -> LAN sync (issue #156, docs/spec/lan-sync.md). Pair device opens a
  // 2-minute window showing a one-time code; Join device dials one and types it.
  // Nothing listens or is advertised outside that window. Merging over a sync
  // session is a later step.
  let status = $state.raw<SyncStatus | null>(null);
  let error = $state<CmdError | null>(null);
  let notice = $state("");
  let busy = $state(false);
  let secondsLeft = $state(0);
  let joining = $state(false);
  let address = $state("");
  let code = $state("");
  let found = $state.raw<SyncFound[]>([]);
  let searched = $state(false);
  let confirmForget = $state<string | null>(null);
  let confirmReset = $state(false);

  async function refresh() {
    try {
      status = await syncStatus();
      secondsLeft = status.window?.seconds_left ?? 0;
    } catch (e) {
      error = toCmdError(e);
    }
  }

  $effect(() => {
    refresh();
    const tick = setInterval(() => (secondsLeft = Math.max(0, secondsLeft - 1)), 1000);
    window.addEventListener(NETWORK_CHANGED_EVENT, refresh);
    return () => {
      clearInterval(tick);
      window.removeEventListener(NETWORK_CHANGED_EVENT, refresh);
    };
  });

  // Poll only while a window is open, so its result shows up promptly.
  const windowOpen = $derived(status?.window?.state === "open");
  $effect(() => {
    if (!windowOpen) return;
    const poll = setInterval(refresh, 1000);
    return () => clearInterval(poll);
  });

  async function run(f: () => Promise<unknown>) {
    busy = true;
    error = null;
    notice = "";
    try {
      await f();
    } catch (e) {
      error = toCmdError(e);
    } finally {
      busy = false;
      await refresh();
    }
  }

  async function discover() {
    await run(async () => {
      found = await syncDiscover();
      searched = true;
    });
  }

  async function join() {
    await run(async () => {
      const r = await syncJoin(address, code);
      notice = `Paired with ${r.name} (${r.fingerprint}).`;
      code = "";
      joining = false;
    });
  }

  const disabled = $derived(!status || !status.available || status.air_gapped || status.read_only);
  const countdown = $derived(`${Math.floor(secondsLeft / 60)}:${String(secondsLeft % 60).padStart(2, "0")}`);
  const windowMessage = $derived.by(() => {
    const w = status?.window;
    if (!w) return "";
    switch (w.state) {
      case "paired":
        return `Paired with ${w.peer_name} (${w.peer_fingerprint}).`;
      case "too_many_failures":
        return "Three wrong codes: the pairing window closed. Open a new one to try again.";
      case "expired":
        return "The pairing window expired.";
      case "failed":
        return `The pairing window failed: ${w.error ?? "unknown error"}`;
      default:
        return "";
    }
  });
</script>

<div class="flex flex-col gap-3 rounded-[7px] border border-hairline bg-surface/60 p-4 shadow-[inset_0_1px_0_rgb(255_255_255/0.03)]">
  <h3 class="flex items-center gap-2 font-display text-[15px] font-bold text-zinc-50">
    <ArrowLeftRight class="size-4 text-emerald" aria-hidden="true" /> LAN sync devices
  </h3>
  <p class="text-xs leading-5 text-zinc-400">
    Pair another computer running shush on the same network. One device shows a code for two minutes; the other
    types it. Nothing listens or is announced on the network outside that window.
  </p>

  {#if status && !status.available}
    <p class="text-xs text-zinc-400" role="status">This build of shush was made without network support.</p>
  {:else if status?.air_gapped}
    <p class="text-xs text-zinc-400" role="status">
      Air-gapped mode is on, so pairing is disabled. Turn it off under Network to pair a device.
    </p>
  {:else if status?.read_only}
    <p class="text-xs text-zinc-400" role="status">This vault is read-only, so it cannot remember paired devices.</p>
  {/if}

  {#if status?.fingerprint}
    <p class="text-xs text-zinc-400">
      This device: <span class="text-zinc-200">{status.device_name}</span>,
      fingerprint <span class="font-mono text-zinc-200">{status.fingerprint}</span>
    </p>
  {/if}

  {#if windowOpen && status?.window?.code}
    <div class="flex flex-col gap-1.5 rounded-[4px] border border-hairline bg-black/30 px-3 py-2" role="status">
      <div class="flex items-center justify-between">
        <span class="font-mono text-lg tracking-[0.2em] text-zinc-50" aria-label="Pairing code">{status.window.code}</span>
        <span class="font-mono text-xs text-zinc-400">closes in {countdown}</span>
      </div>
      <span class="text-xs text-zinc-400">
        On the other device choose Join device and type this code.
        {#if status.window.addresses.length > 0}
          Address: <span class="font-mono text-zinc-200">{status.window.addresses.join(", ")}</span>
        {/if}
        {#if status.window.failures > 0}
          <span class="text-caution">{status.window.failures} wrong {status.window.failures === 1 ? "code" : "codes"} so far (3 close the window).</span>
        {/if}
      </span>
    </div>
    <button type="button" class="key-steel h-9 text-xs" disabled={busy} onclick={() => run(syncCancelPairing)}>CANCEL</button>
  {:else}
    {#if windowMessage}
      <p class="text-xs text-zinc-300" role="status">{windowMessage}</p>
    {/if}
    <div class="flex gap-2">
      <button type="button" class="key h-9 flex-1 text-xs" disabled={busy || disabled} onclick={() => run(syncStartPairing)}>PAIR DEVICE</button>
      <button type="button" class="key-steel h-9 flex-1 text-xs" disabled={busy || disabled} onclick={() => (joining = !joining)} aria-expanded={joining}>JOIN DEVICE</button>
    </div>
  {/if}

  {#if joining && !disabled}
    <form class="flex flex-col gap-2" onsubmit={(e) => { e.preventDefault(); join(); }}>
      <button type="button" class="key-steel h-8 text-[11px]" disabled={busy || !status?.advertise} onclick={discover}>
        FIND DEVICES (3 S)
      </button>
      {#if found.length > 0}
        <ul class="flex flex-col gap-1">
          {#each found as f (f.address)}
            <li>
              <button type="button" class="w-full rounded-[4px] border border-hairline px-2 py-1 text-left font-mono text-xs text-zinc-300 hover:border-emerald" onclick={() => (address = f.address)}>
                {f.address}
              </button>
            </li>
          {/each}
        </ul>
      {:else if searched}
        <p class="text-xs text-zinc-400">No pairing window found. Type the address shown on the other device.</p>
      {/if}
      <label class="flex flex-col gap-1 text-xs text-zinc-300">
        Address
        <input class="rounded-[4px] border border-hairline bg-black/30 px-2 py-1 font-mono text-zinc-50" placeholder="192.168.1.20:53124" autocomplete="off" spellcheck="false" bind:value={address} />
      </label>
      <label class="flex flex-col gap-1 text-xs text-zinc-300">
        Code
        <input class="rounded-[4px] border border-hairline bg-black/30 px-2 py-1 font-mono uppercase tracking-[0.2em] text-zinc-50" placeholder="XXXX-XXXX" autocomplete="off" spellcheck="false" maxlength="12" bind:value={code} />
      </label>
      <button type="submit" class="key h-9 text-xs" disabled={busy || !address.trim() || !code.trim()}>PAIR</button>
    </form>
  {/if}

  {#if notice}
    <p class="text-xs text-emerald" role="status">{notice}</p>
  {/if}

  <label class="flex items-start gap-2 text-xs text-zinc-300">
    <input
      type="checkbox"
      class="mt-0.5"
      checked={status?.advertise ?? true}
      disabled={busy || !status}
      onchange={(e) => run(() => syncSetAdvertise(e.currentTarget.checked))}
    />
    <span>Announce pairing windows on the local network. Off means you always type the address.</span>
  </label>

  {#if status && status.peers.length > 0}
    <h4 class="text-xs font-semibold text-zinc-300">Paired devices</h4>
    <ul class="flex flex-col gap-1.5">
      {#each status.peers as p (p.id)}
        <li class="flex flex-col gap-1.5 text-xs text-zinc-300">
          <span class="flex items-center justify-between gap-2">
            <span><span class="text-zinc-50">{p.name}</span> <span class="font-mono text-zinc-400">{p.id}</span></span>
            {#if confirmForget !== p.id}
              <button type="button" class="key-steel h-7 px-2 text-[11px] text-ruby!" disabled={busy} onclick={() => (confirmForget = p.id)}>FORGET</button>
            {/if}
          </span>
          {#if confirmForget === p.id}
            <span class="flex flex-col gap-1.5 rounded-[4px] border border-hairline p-2">
              <span class="text-caution">
                Forgetting stops this device from syncing with this vault. It does not take back the vault copy already on
                it. If it was lost or stolen, forget it on every device and consider changing your master password.
              </span>
              <span class="flex gap-2">
                <button type="button" class="key h-7 flex-1 text-[11px]" disabled={busy} onclick={() => run(async () => { await syncForget(p.id); confirmForget = null; })}>FORGET DEVICE</button>
                <button type="button" class="key-steel h-7 flex-1 text-[11px]" disabled={busy} onclick={() => (confirmForget = null)}>KEEP</button>
              </span>
            </span>
          {/if}
        </li>
      {/each}
    </ul>
  {/if}

  {#if status?.fingerprint}
    {#if confirmReset}
      <div class="flex flex-col gap-1.5 rounded-[4px] border border-hairline p-2 text-xs">
        <span class="text-caution">Reset cuts off every paired device at once. You will need to pair them again.</span>
        <span class="flex gap-2">
          <button type="button" class="key h-7 flex-1 text-[11px]" disabled={busy} onclick={() => run(async () => { await syncResetIdentity(); confirmReset = false; })}>RESET SYNC IDENTITY</button>
          <button type="button" class="key-steel h-7 flex-1 text-[11px]" disabled={busy} onclick={() => (confirmReset = false)}>CANCEL</button>
        </span>
      </div>
    {:else}
      <button type="button" class="key-steel h-8 text-[11px]" disabled={busy || status.read_only} onclick={() => (confirmReset = true)}>RESET SYNC IDENTITY</button>
    {/if}
  {/if}

  {#if error}
    <p class="flex items-start gap-1.5 text-xs text-danger" role="alert">
      <TriangleAlert class="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
      <span><span class="font-mono">[{error.code}]</span> {error.message}</span>
    </p>
  {/if}
</div>
