<script lang="ts">
  import { open } from "@tauri-apps/plugin-dialog";
  import { FileSpreadsheet, LoaderCircle, ShieldAlert, Trash2, TriangleAlert } from "@lucide/svelte";
  import {
    CSV_FORMAT_LABEL,
    importCsv,
    previewCsv,
    shredCsv,
    splitPath,
    toCmdError,
    type CmdError,
    type CsvSummary,
  } from "../tauri-bridge";

  // Migration from other password managers / browsers (spec §9.3, #17).
  let { onimported }: { onimported: () => void } = $props();

  let path = $state<string | null>(null);
  let preview = $state.raw<CsvSummary | null>(null);
  let done = $state.raw<CsvSummary | null>(null);
  let shredded = $state(false);
  let busy = $state(false);
  let error = $state<CmdError | null>(null);

  async function pick() {
    const picked = await open({
      multiple: false,
      directory: false,
      title: "Choose a password export (CSV)",
      filters: [{ name: "CSV export", extensions: ["csv"] }],
    });
    if (typeof picked !== "string") return;
    path = picked;
    preview = done = null;
    shredded = false;
    error = null;
    busy = true;
    try {
      preview = await previewCsv(picked);
    } catch (e) {
      error = toCmdError(e);
    } finally {
      busy = false;
    }
  }

  async function run() {
    if (!path) return;
    busy = true;
    error = null;
    try {
      done = await importCsv(path);
      preview = null;
      onimported();
    } catch (e) {
      error = toCmdError(e);
    } finally {
      busy = false;
    }
  }

  async function shred() {
    if (!path) return;
    busy = true;
    try {
      await shredCsv(path);
      shredded = true;
    } catch (e) {
      error = toCmdError(e);
    } finally {
      busy = false;
    }
  }

  const stats = $derived(
    preview
      ? [
          ["rows", preview.total, "text-zinc-200"],
          ["new", preview.new_items, "text-tactical"],
          ["already saved", preview.identical, "text-zinc-400"],
          ["conflicts", preview.conflicts, "text-amber-300"],
        ]
      : [],
  );
</script>

<div class="flex flex-col gap-3 rounded-lg border border-hairline p-4">
  <h3 class="flex items-center gap-2 text-sm font-medium text-zinc-100">
    <FileSpreadsheet class="size-4 text-amber-300" aria-hidden="true" /> Import from another password manager
  </h3>
  <p class="text-xs leading-5 text-zinc-400">
    Export a CSV from Chrome, Edge, Brave, Firefox, Bitwarden, 1Password, KeePass or KeePassXC, then pick it
    here. Existing logins are never overwritten: a different password is kept in that login's history.
  </p>

  <button
    type="button"
    onclick={pick}
    disabled={busy}
    class={[
      "flex h-12 items-center gap-2.5 rounded-lg border px-3 text-left text-xs transition",
      path ? "border-amber-300/40 bg-amber-300/5" : "border-dashed border-hairline text-zinc-400 hover:border-zinc-600",
    ]}
  >
    <FileSpreadsheet class="size-4 shrink-0" aria-hidden="true" />
    {#if path}
      {@const [dir, file] = splitPath(path)}
      <span class="flex min-w-0 flex-1 font-mono text-amber-200" title={path}>
        <span class="truncate">{dir}</span><span class="shrink-0">{file}</span>
      </span>
    {:else}
      Choose a .csv export…
    {/if}
  </button>

  {#if preview}
    <p class="font-mono text-[11px] text-zinc-500">
      Detected: <span class="text-cold">{preview.format ? CSV_FORMAT_LABEL[preview.format] : "?"}</span>
      {#if preview.skipped}· {preview.skipped} incomplete row{preview.skipped === 1 ? "" : "s"} will be skipped{/if}
    </p>
    <dl class="grid grid-cols-4 divide-x divide-hairline rounded-lg border border-hairline bg-surface text-center font-mono" aria-label="CSV preview">
      {#each stats as [label, n, tone] (label)}
        <div class="px-2 py-2">
          <dd class={["text-lg", tone]}>{n}</dd>
          <dt class="text-[10px] text-zinc-500 uppercase">{label}</dt>
        </div>
      {/each}
    </dl>
    <button
      type="button"
      onclick={run}
      disabled={busy || preview.new_items + preview.conflicts === 0}
      class="flex h-9 items-center justify-center gap-2 rounded-lg bg-amber-300 font-mono text-xs font-semibold tracking-wider text-obsidian hover:bg-amber-200 disabled:bg-hairline disabled:text-zinc-500"
    >
      {#if busy}<LoaderCircle class="size-3.5 animate-spin" aria-hidden="true" />{/if}
      {preview.new_items + preview.conflicts === 0 ? "NOTHING NEW TO IMPORT" : `IMPORT ${preview.new_items} NEW`}
    </button>
  {/if}

  {#if done}
    <p class="text-xs text-tactical" role="status">
      Imported {done.new_items} item{done.new_items === 1 ? "" : "s"}{done.conflicts
        ? `; ${done.conflicts} different password${done.conflicts === 1 ? "" : "s"} archived in history`
        : ""}{done.invalid_totp ? `; ${done.invalid_totp} invalid 2FA secret${done.invalid_totp === 1 ? "" : "s"} dropped` : ""}.
    </p>
    {#if shredded}
      <p class="text-xs text-tactical" role="status">The CSV file was overwritten and deleted.</p>
    {:else}
      <div class="flex flex-col gap-2 rounded-lg border border-danger/30 bg-danger/5 p-3">
        <p class="flex items-start gap-1.5 text-xs leading-5 text-zinc-300">
          <ShieldAlert class="mt-0.5 size-3.5 shrink-0 text-danger" aria-hidden="true" />
          The CSV still contains every password in plain text. Delete it now, then empty the browser's own
          password store and the Recycle Bin.
        </p>
        <button
          type="button"
          onclick={shred}
          disabled={busy}
          class="flex h-8 items-center justify-center gap-1.5 rounded-md border border-danger/50 text-xs text-danger hover:bg-danger/10"
        >
          <Trash2 class="size-3.5" aria-hidden="true" /> Overwrite &amp; delete the CSV
        </button>
        <p class="text-[10px] leading-4 text-zinc-500">
          Best effort: on SSDs, with cloud sync or shadow copies, old copies may survive elsewhere.
        </p>
      </div>
    {/if}
  {/if}

  {#if error}
    <p class="flex items-start gap-1.5 text-xs text-danger" role="alert">
      <TriangleAlert class="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
      <span><span class="font-mono">[{error.code}]</span> {error.message}</span>
    </p>
  {/if}
</div>
