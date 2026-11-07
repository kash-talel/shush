<script lang="ts">
  import { open, save } from "@tauri-apps/plugin-dialog";
  import { ArchiveRestore, DatabaseBackup, FileArchive, LoaderCircle, TriangleAlert } from "@lucide/svelte";
  import PasswordField from "./PasswordField.svelte";
  import KeyfileAttach from "./KeyfileAttach.svelte";
  import CsvImport from "./CsvImport.svelte";
  import {
    applyImport,
    exportBackup,
    inspectBackup,
    previewImport,
    splitPath,
    toCmdError,
    type BackupInfo,
    type CmdError,
    type ImportMode,
    type ImportPreview,
    type KeyfileInfo,
  } from "../tauri-bridge";

  // Settings → Backup & Export (spec §9.1) and backup import.
  let { onimported }: { onimported: () => void } = $props();

  // ---- export ----
  let exportMode = $state<"same_as_vault" | "dedicated">("same_as_vault");
  let exportPassword = $state("");
  let exportKeyfile = $state<{ path: string; info: KeyfileInfo } | null>(null);
  let exporting = $state(false);
  let exportResult = $state<string | null>(null);
  let exportError = $state<CmdError | null>(null);

  async function doExport() {
    exportError = null;
    exportResult = null;
    const date = new Date().toISOString().slice(0, 10);
    const path = await save({
      title: "Save encrypted backup",
      defaultPath: `shush-${date}.shushbackup`,
      filters: [{ name: "shush backup", extensions: ["shushbackup"] }],
    });
    if (!path) return;
    exporting = true;
    try {
      const n = await exportBackup(
        path,
        exportMode === "same_as_vault"
          ? { mode: "same_as_vault" }
          : { mode: "dedicated", password: exportPassword, keyfile_path: exportKeyfile?.path ?? null },
      );
      exportResult = `${n} item${n === 1 ? "" : "s"} saved to ${splitPath(path)[1]}`;
      exportPassword = "";
    } catch (e) {
      exportError = toCmdError(e);
    } finally {
      exporting = false;
    }
  }

  // ---- import ----
  let importPath = $state<string | null>(null);
  let importInfo = $state.raw<BackupInfo | null>(null);
  let importPassword = $state("");
  let importKeyfile = $state<{ path: string; info: KeyfileInfo } | null>(null);
  let preview = $state.raw<ImportPreview | null>(null);
  let importMode = $state<ImportMode>("merge");
  let confirmReplace = $state(false);
  let importing = $state(false);
  let importResult = $state<string | null>(null);
  let importError = $state<CmdError | null>(null);

  const canPreview = $derived(
    importPath !== null && importPassword.length > 0 && (!importInfo?.keyfile_required || importKeyfile !== null),
  );

  function resetImport() {
    preview = null;
    importResult = null;
    importError = null;
    confirmReplace = false;
  }

  async function pickBackup() {
    const picked = await open({
      multiple: false,
      directory: false,
      title: "Choose a backup to import",
      filters: [{ name: "shush backup", extensions: ["shushbackup"] }],
    });
    if (typeof picked !== "string") return;
    resetImport();
    importKeyfile = null;
    try {
      importInfo = await inspectBackup(picked);
      importPath = picked;
    } catch (e) {
      importPath = null;
      importInfo = null;
      importError = toCmdError(e);
    }
  }

  async function doPreview() {
    if (!importPath || !canPreview) return;
    importing = true;
    resetImport();
    try {
      preview = await previewImport(importPath, importPassword, importKeyfile?.path ?? null);
    } catch (e) {
      importError = toCmdError(e);
    } finally {
      importing = false;
    }
  }

  async function doImport() {
    if (!importPath || !preview) return;
    if (importMode === "replace" && !confirmReplace) {
      confirmReplace = true;
      return;
    }
    importing = true;
    importError = null;
    try {
      const n = await applyImport(importPath, importPassword, importKeyfile?.path ?? null, importMode);
      importResult =
        importMode === "replace"
          ? `Vault restored from backup (${n} items). The previous vault was kept as vault.shush.bak.`
          : `${n} new item${n === 1 ? "" : "s"} added.${preview.conflicts ? ` ${preview.conflicts} conflicting password${preview.conflicts === 1 ? "" : "s"} archived in history.` : ""}`;
      preview = null;
      importPassword = "";
      confirmReplace = false;
      onimported();
    } catch (e) {
      importError = toCmdError(e);
    } finally {
      importing = false;
    }
  }
</script>

{#snippet errorLine(e: CmdError | null)}
  {#if e}
    <p class="flex items-start gap-1.5 text-xs text-danger" role="alert">
      <TriangleAlert class="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
      <span><span class="font-mono">[{e.code}]</span> {e.message}</span>
    </p>
  {/if}
{/snippet}

<section class="flex min-h-0 min-w-0 flex-1 flex-col">
  <header class="flex h-12 shrink-0 items-center border-b border-hairline px-4">
    <h2 class="font-mono text-xs tracking-[0.15em] text-zinc-400">// BACKUP_AND_RESTORE</h2>
  </header>

  <div class="flex min-h-0 flex-1 flex-col gap-6 overflow-y-auto p-4">
    <!-- Export -->
    <div class="flex flex-col gap-3 rounded-lg border border-hairline p-4">
      <h3 class="flex items-center gap-2 text-sm font-medium text-zinc-100">
        <DatabaseBackup class="size-4 text-tactical" aria-hidden="true" /> Create encrypted backup
      </h3>
      <p class="text-xs leading-5 text-zinc-400">
        Writes a <span class="font-mono text-cold">.shushbackup</span> file: the whole vault, encrypted and
        tamper-proof. Store it on an external drive.
      </p>
      <div class="grid grid-cols-2 gap-1 rounded-lg border border-hairline bg-surface p-1" role="radiogroup" aria-label="Backup credentials">
        {#each [{ id: "same_as_vault", label: "Vault password" }, { id: "dedicated", label: "Separate password" }] as m (m.id)}
          <button
            type="button"
            role="radio"
            aria-checked={exportMode === m.id}
            onclick={() => (exportMode = m.id as typeof exportMode)}
            class={["rounded-md px-2 py-1.5 text-xs transition", exportMode === m.id ? "bg-hairline text-zinc-100" : "text-zinc-500 hover:text-zinc-300"]}
          >
            {m.label}
          </button>
        {/each}
      </div>
      {#if exportMode === "dedicated"}
        <PasswordField id="backup-password" label="Backup password" autocomplete="new-password" placeholder="at least 8 characters" bind:value={exportPassword} />
        <div>
          <span class="mb-1.5 flex justify-between text-xs font-medium text-zinc-400">Backup keyfile <span class="font-normal text-zinc-500">optional</span></span>
          <KeyfileAttach bind:keyfile={exportKeyfile} acceptDrop={false} onerror={(e) => (exportError = e)} />
        </div>
      {:else}
        <p class="text-[11px] text-zinc-500">Opens with the same master password and keyfile as this vault.</p>
      {/if}
      {@render errorLine(exportError)}
      {#if exportResult}<p class="text-xs text-tactical" role="status">{exportResult}</p>{/if}
      <button
        type="button"
        onclick={doExport}
        disabled={exporting || (exportMode === "dedicated" && exportPassword.length < 8)}
        class="flex h-9 items-center justify-center gap-2 rounded-lg bg-tactical font-mono text-xs font-semibold tracking-wider text-obsidian hover:bg-emerald-400 disabled:bg-hairline disabled:text-zinc-500"
      >
        {#if exporting}<LoaderCircle class="size-3.5 animate-spin" aria-hidden="true" />{/if}
        EXPORT BACKUP…
      </button>
    </div>

    <!-- Import -->
    <div class="flex flex-col gap-3 rounded-lg border border-hairline p-4">
      <h3 class="flex items-center gap-2 text-sm font-medium text-zinc-100">
        <ArchiveRestore class="size-4 text-cold" aria-hidden="true" /> Import from backup
      </h3>
      <button
        type="button"
        onclick={pickBackup}
        class={[
          "flex h-12 items-center gap-2.5 rounded-lg border px-3 text-left text-xs transition",
          importPath ? "border-cold/40 bg-cold/5" : "border-dashed border-hairline text-zinc-400 hover:border-zinc-600",
        ]}
      >
        <FileArchive class="size-4 shrink-0" aria-hidden="true" />
        {#if importPath}
          {@const [dir, file] = splitPath(importPath)}
          <span class="flex min-w-0 flex-1 font-mono text-cold" title={importPath}>
            <span class="truncate">{dir}</span><span class="shrink-0">{file}</span>
          </span>
        {:else}
          Choose a .shushbackup file…
        {/if}
      </button>

      {#if importPath}
        <PasswordField
          id="import-password"
          label="Backup password"
          bind:value={importPassword}
          oninput={() => resetImport()}
        />
        {#if importInfo?.keyfile_required}
          <div>
            <span class="mb-1.5 block text-xs font-medium text-amber-300">This backup requires its keyfile</span>
            <KeyfileAttach bind:keyfile={importKeyfile} required onerror={(e) => (importError = e)} onchange={resetImport} />
          </div>
        {/if}

        {#if preview}
          <dl class="grid grid-cols-4 divide-x divide-hairline rounded-lg border border-hairline bg-surface text-center font-mono" aria-label="Import preview">
            {#each [["in backup", preview.total, "text-zinc-200"], ["new", preview.new_items, "text-tactical"], ["identical", preview.identical, "text-zinc-400"], ["conflicts", preview.conflicts, "text-amber-300"]] as [label, n, tone] (label)}
              <div class="px-2 py-2">
                <dd class={["text-lg", tone]}>{n}</dd>
                <dt class="text-[10px] text-zinc-500 uppercase">{label}</dt>
              </div>
            {/each}
          </dl>
          <fieldset class="flex flex-col gap-2 text-xs text-zinc-300">
            <legend class="sr-only">Import mode</legend>
            <label class="flex items-start gap-2">
              <input type="radio" bind:group={importMode} value="merge" onchange={() => (confirmReplace = false)} class="mt-0.5 accent-emerald-500" />
              <span><span class="text-zinc-100">Merge</span>: add new items. For conflicts your current password stays active; the backup's is archived in history.</span>
            </label>
            <label class="flex items-start gap-2">
              <input type="radio" bind:group={importMode} value="replace" class="mt-0.5 accent-emerald-500" />
              <span><span class="text-zinc-100">Clean restore</span>: replace the vault's contents with the backup.</span>
            </label>
          </fieldset>
        {/if}

        {@render errorLine(importError)}
        {#if importResult}<p class="text-xs text-tactical" role="status">{importResult}</p>{/if}

        <button
          type="button"
          onclick={preview ? doImport : doPreview}
          disabled={importing || !canPreview}
          class={[
            "flex h-9 items-center justify-center gap-2 rounded-lg font-mono text-xs font-semibold tracking-wider disabled:bg-hairline disabled:text-zinc-500",
            confirmReplace ? "bg-danger text-white hover:bg-red-400" : "bg-cold text-obsidian hover:bg-cyan-400",
          ]}
        >
          {#if importing}<LoaderCircle class="size-3.5 animate-spin" aria-hidden="true" />{/if}
          {#if !preview}
            DECRYPT &amp; PREVIEW
          {:else if confirmReplace}
            CONFIRM: REPLACE VAULT CONTENTS
          {:else}
            {importMode === "merge" ? "MERGE INTO VAULT" : "RESTORE BACKUP"}
          {/if}
        </button>
      {/if}
      {#if !importPath}{@render errorLine(importError)}{/if}
    </div>
    <CsvImport {onimported} />
  </div>
</section>
