<script lang="ts">
  import { Globe, TriangleAlert } from "@lucide/svelte";
  import {
    bridgeApproveSave,
    bridgeRejectSave,
    bridgeRevoke,
    bridgeStartPairing,
    bridgeState,
    toCmdError,
    type BridgeInfo,
    type CmdError,
  } from "../tauri-bridge";

  // Settings → Pair browser (issue #52): pair the companion extension, list and
  // revoke paired browsers, approve or reject logins the extension offers to
  // save. Passwords of pending saves never reach this window.
  let { onchanged = () => {} }: { onchanged?: () => void } = $props();

  let info = $state<BridgeInfo | null>(null);
  let error = $state<CmdError | null>(null);
  let busy = $state(false);
  // Counted down locally between polls so the countdown is smooth.
  let secondsLeft = $state(0);

  async function refresh() {
    try {
      info = await bridgeState();
      secondsLeft = info.code?.seconds_left ?? 0;
    } catch (e) {
      error = toCmdError(e);
    }
  }

  $effect(() => {
    refresh();
    const poll = setInterval(refresh, 2000);
    const tick = setInterval(() => (secondsLeft = Math.max(0, secondsLeft - 1)), 1000);
    return () => {
      clearInterval(poll);
      clearInterval(tick);
    };
  });

  async function run(f: () => Promise<unknown>) {
    busy = true;
    error = null;
    try {
      await f();
    } catch (e) {
      error = toCmdError(e);
    } finally {
      busy = false;
      await refresh();
    }
  }

  const showCode = $derived(info?.code != null && secondsLeft > 0);
  const countdown = $derived(`${Math.floor(secondsLeft / 60)}:${String(secondsLeft % 60).padStart(2, "0")}`);
</script>

<div class="flex flex-col gap-3 rounded-[7px] border border-hairline bg-surface/60 p-4 shadow-[inset_0_1px_0_rgb(255_255_255/0.03)]">
  <h3 class="flex items-center gap-2 font-display text-[15px] font-bold text-zinc-50">
    <Globe class="size-4 text-emerald" aria-hidden="true" /> Pair browser
  </h3>
  <p class="text-xs leading-5 text-zinc-400">
    Connect the shush browser extension. Enter the code in the extension within two minutes. Logins are only
    filled on an exact site match, and saves wait here for your approval.
  </p>

  {#if info?.warning}
    <p class="flex items-start gap-1.5 text-xs text-caution" role="alert">
      <TriangleAlert class="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
      <span>{info.warning}</span>
    </p>
  {/if}

  {#if showCode && info?.code}
    <div class="flex items-center justify-between rounded-[4px] border border-hairline bg-black/30 px-3 py-2" role="status">
      <span class="font-mono text-lg tracking-[0.2em] text-zinc-50" aria-label="Pairing code">{info.code.code}</span>
      <span class="font-mono text-xs text-zinc-400">expires in {countdown}</span>
    </div>
  {/if}
  <button type="button" class="key h-9 text-xs" disabled={busy || !info?.serving} onclick={() => run(bridgeStartPairing)}>
    {showCode ? "NEW CODE" : "SHOW PAIRING CODE"}
  </button>

  {#if info && info.pairings.length > 0}
    <h4 class="text-xs font-semibold text-zinc-300">Paired browsers</h4>
    <ul class="flex flex-col gap-1.5">
      {#each info.pairings as p (p.id)}
        <li class="flex items-center justify-between gap-2 text-xs text-zinc-300">
          <span class="font-mono">{p.id.slice(0, 8)}…</span>
          <button type="button" class="key-steel h-7 px-2 text-[11px] text-ruby!" disabled={busy} onclick={() => run(() => bridgeRevoke(p.id))}>REVOKE</button>
        </li>
      {/each}
    </ul>
  {/if}

  {#if info && info.pending.length > 0}
    <h4 class="text-xs font-semibold text-zinc-300">Waiting for approval</h4>
    <ul class="flex flex-col gap-2">
      {#each info.pending as s (s.origin + "\n" + s.username)}
        <li class="flex flex-col gap-1.5 rounded-[4px] border border-hairline p-2 text-xs text-zinc-300">
          <span class="break-all">Save login for <span class="font-mono text-zinc-50">{s.origin}</span> as <span class="font-mono text-zinc-50">{s.username || "(no username)"}</span>?</span>
          <span class="flex gap-2">
            <button type="button" class="key h-7 flex-1 text-[11px]" disabled={busy} onclick={() => run(async () => { await bridgeApproveSave(s.origin, s.username); onchanged(); })}>APPROVE</button>
            <button type="button" class="key-steel h-7 flex-1 text-[11px]" disabled={busy} onclick={() => run(() => bridgeRejectSave(s.origin, s.username))}>REJECT</button>
          </span>
        </li>
      {/each}
    </ul>
  {/if}

  {#if error}
    <p class="flex items-start gap-1.5 text-xs text-danger" role="alert">
      <TriangleAlert class="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
      <span><span class="font-mono">[{error.code}]</span> {error.message}</span>
    </p>
  {/if}
</div>
