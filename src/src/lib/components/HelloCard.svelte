<script lang="ts">
  import { Fingerprint, TriangleAlert } from "@lucide/svelte";
  import {
    helloSetEnabled,
    helloSetMaxHours,
    helloStatus,
    toCmdError,
    type CmdError,
    type HelloStatus,
  } from "../tauri-bridge";

  // Settings -> Windows Hello (docs/spec/windows-hello.md, issue #66). Hello reopens
  // the vault after a password unlock for a limited time; it never survives the app.
  let status = $state<HelloStatus | null>(null);
  let error = $state<CmdError | null>(null);
  let busy = $state(false);

  async function refresh() {
    try {
      status = await helloStatus();
    } catch (e) {
      error = toCmdError(e);
    }
  }

  $effect(() => {
    refresh();
  });

  async function toggle(box: HTMLInputElement) {
    busy = true;
    error = null;
    try {
      await helloSetEnabled(box.checked);
    } catch (e) {
      error = toCmdError(e);
    } finally {
      busy = false;
      await refresh();
      box.checked = status?.enabled ?? false;
    }
  }

  async function setHours(select: HTMLSelectElement) {
    error = null;
    try {
      await helloSetMaxHours(Number(select.value));
    } catch (e) {
      error = toCmdError(e);
    } finally {
      await refresh();
      select.value = String(status?.max_hours ?? 8);
    }
  }
</script>

{#if status?.supported}
  <div class="flex flex-col gap-3 rounded-[7px] border border-hairline bg-surface/60 p-4 shadow-[inset_0_1px_0_rgb(255_255_255/0.03)]">
    <h3 class="flex items-center gap-2 font-display text-[15px] font-bold text-zinc-50">
      <Fingerprint class="size-4 text-emerald" aria-hidden="true" /> Windows Hello
    </h3>
    <p class="text-xs leading-5 text-zinc-400">
      After you unlock with your password, Windows Hello can reopen this vault for a limited time. For a vault with a
      keyfile, Hello skips the keyfile during that time. The session lives only in memory: quitting shush, restarting
      Windows, sleeping or signing out ends it, and then the password (and keyfile) is required again.
    </p>

    <label class="flex items-start gap-2 text-xs text-zinc-300">
      <input
        type="checkbox"
        class="mt-0.5"
        checked={status.enabled ?? false}
        disabled={busy || status.enabled === null}
        onchange={(e) => toggle(e.currentTarget)}
      />
      <span>Unlock with Windows Hello</span>
    </label>

    {#if status.enabled}
      <label class="flex items-center gap-2 text-xs text-zinc-300">
        Session length
        <select
          class="rounded border border-hairline bg-transparent px-1 py-0.5"
          value={String(status.max_hours ?? 8)}
          onchange={(e) => setHours(e.currentTarget)}
        >
          {#each [1, 2, 4, 8] as h (h)}
            <option value={String(h)}>{h} {h === 1 ? "hour" : "hours"}</option>
          {/each}
        </select>
      </label>
      <p class="text-xs text-zinc-400" role="status">Hello is armed the next time you unlock with your password.</p>
    {/if}

    {#if error}
      <p class="flex items-start gap-1.5 text-xs text-danger" role="alert">
        <TriangleAlert class="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
        <span><span class="font-mono">[{error.code}]</span> {error.message}</span>
      </p>
    {/if}
  </div>
{/if}
