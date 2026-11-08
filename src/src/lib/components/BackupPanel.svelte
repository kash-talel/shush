<script lang="ts">
  import { open, save } from "@tauri-apps/plugin-dialog";
  import { ArchiveRestore, DatabaseBackup, FileArchive, FileKey, LoaderCircle, TriangleAlert } from "@lucide/svelte";
  import PasswordField from "./PasswordField.svelte";
  import KeyfileAttach from "./KeyfileAttach.svelte";
  import CsvImport from "./CsvImport.svelte";
  import DuressCard from "./DuressCard.svelte";
  import EmergencyKitModal from "./EmergencyKitModal.svelte";
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
  let showRecoveryKit = $state(false);

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
  <header class="flex h-12 shrink-0 items-center border-b border-hairline px-5">
    <h2 class="font-display text-[17px] font-bold text-zinc-50">Backup &amp; restore</h2>
  </header>

  <div class="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto p-5 max-[1000px]:p-3">
    <!-- Export -->
    <div class="flex flex-col gap-3 rounded-[7px] border border-hairline bg-surface/60 p-4 shadow-[inset_0_1px_0_rgb(255_255_255/0.03)]">
      <h3 class="flex items-center gap-2 font-display text-[15px] font-bold text-zinc-50">
        <DatabaseBackup class="size-4 text-ruby" aria-hidden="true" /> Create encrypted backup
      </h3>
      <p class="text-xs leading-5 text-zinc-400">
        Writes a <span class="font-mono text-uv">.shushbackup</span> file: the whole vault, encrypted and
        tamper-proof. Store it on an external drive.
      </p>
      <div class="grid grid-cols-2 gap-1 rounded-[5px] border border-hairline bg-[#09090e] p-1" role="radiogroup" aria-label="Backup credentials">
        {#each [{ id: "same_as_vault", label: "Vault password" }, { id: "dedicated", label: "Separate password" }] as m (m.id)}
          <button
            type="button"
            role="radio"
            aria-checked={exportMode === m.id}
            onclick={() => (exportMode = m.id as typeof exportMode)}
            class={["h-8 truncate rounded-[3px] px-2 text-xs whitespace-nowrap transition", exportMode === m.id ? "key-steel w-full text-zinc-50" : "text-zinc-500 hover:text-zinc-200"]}
          >
            {m.label}
          </button>
        {/each}
      </div>
      {#if exportMode === "dedicated"}
        <PasswordField id="backup-password" label="Backup password" autocomplete="new-password" placeholder="8+ characters" bind:value={exportPassword} />
        <div>
          <span class="mb-1.5 flex items-baseline justify-between text-xs font-medium text-zinc-300">Backup keyfile <span class="spec">optional</span></span>
          <KeyfileAttach bind:keyfile={exportKeyfile} acceptDrop={false} onerror={(e) => (exportError = e)} />
        </div>
      {:else}
        <p class="text-[11px] text-zinc-500">Opens with the same master password and keyfile as this vault.</p>
      {/if}
      {@render errorLine(exportError)}
      {#if exportResult}<p class="text-xs text-uv" role="status">{exportResult}</p>{/if}
      <button
        type="button"
        onclick={doExport}
        disabled={exporting || (exportMode === "dedicated" && exportPassword.length < 8)}
        class="key h-9 text-xs"
      >
        {#if exporting}<LoaderCircle class="size-3.5 animate-spin" aria-hidden="true" />{/if}
        EXPORT BACKUP…
      </button>
    </div>

    <!-- Import -->
    <div class="flex flex-col gap-3 rounded-[7px] border border-hairline bg-surface/60 p-4 shadow-[inset_0_1px_0_rgb(255_255_255/0.03)]">
      <h3 class="flex items-center gap-2 font-display text-[15px] font-bold text-zinc-50">
        <ArchiveRestore class="size-4 text-uv" aria-hidden="true" /> Import from backup
      </h3>
      <button
        type="button"
        onclick={pickBackup}
        class={[
          "flex h-12 items-center gap-2.5 rounded-[5px] border px-3 text-left text-xs transition",
          importPath ? "border-uv/40 bg-uv/5" : "border-dashed border-edge text-zinc-400 hover:border-zinc-500",
        ]}
      >
        <FileArchive class="size-4 shrink-0" aria-hidden="true" />
        {#if importPath}
          {@const [dir, file] = splitPath(importPath)}
          <span class="flex min-w-0 flex-1 font-mono text-[11px] text-uv" title={importPath}>
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
            <span class="mb-1.5 block text-xs font-medium text-caution">This backup requires its keyfile</span>
            <KeyfileAttach bind:keyfile={importKeyfile} required onerror={(e) => (importError = e)} onchange={resetImport} />
          </div>
        {/if}

        {#if preview}
          <dl class="grid grid-cols-4 divide-x divide-hairline rounded-[4px] border border-hairline bg-[#09090e] text-center font-mono shadow-[inset_0_1px_2px_rgb(0_0_0/0.6)]" aria-label="Import preview">
            {#each [["in backup", preview.total, "text-zinc-200"], ["new", preview.new_items, "text-uv"], ["identical", preview.identical, "text-zinc-400"], ["conflicts", preview.conflicts, "text-caution"]] as [label, n, tone] (label)}
              <div class="px-2 py-2">
                <dd class={["text-lg tabular-nums", tone]}>{n}</dd>
                <dt class="text-[9.5px] text-zinc-500">{label}</dt>
              </div>
            {/each}
          </dl>
          <fieldset class="flex flex-col gap-2 text-xs text-zinc-300">
            <legend class="sr-only">Import mode</legend>
            <label class="flex items-start gap-2">
              <input type="radio" bind:group={importMode} value="merge" onchange={() => (confirmReplace = false)} class="mt-0.5 accent-crimson" />
              <span><span class="text-zinc-100">Merge</span>: add new items. For conflicts your current password stays active; the backup's is archived in history.</span>
            </label>
            <label class="flex items-start gap-2">
              <input type="radio" bind:group={importMode} value="replace" class="mt-0.5 accent-crimson" />
              <span><span class="text-zinc-100">Clean restore</span>: replace the vault's contents with the backup.</span>
            </label>
          </fieldset>
        {/if}

        {@render errorLine(importError)}
        {#if importResult}<p class="text-xs text-uv" role="status">{importResult}</p>{/if}

        <button
          type="button"
          onclick={preview ? doImport : doPreview}
          disabled={importing || !canPreview}
          class={[
            "key h-9 text-xs",
            confirmReplace && "hazard bg-danger! shadow-[0_2px_0_#7a2410]!",
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
    <DuressCard />

    <!-- Emergency Recovery Kit (spec §7.2 item 6, issue #27) -->
    <div class="flex flex-col gap-3 rounded-[7px] border border-hairline bg-surface/60 p-4 shadow-[inset_0_1px_0_rgb(255_255_255/0.03)]">
      <h3 class="flex items-center gap-2 font-display text-[15px] font-bold text-zinc-50">
        <FileKey class="size-4 text-emerald" aria-hidden="true" /> Emergency recovery kit
      </h3>
      <p class="text-xs leading-5 text-zinc-400">
        Print a 1-page offline recovery sheet with envelope metadata and disaster instructions. Rendered directly in-window with <span class="font-semibold text-emerald">zero temporary files</span> written to disk.
      </p>
      <button
        type="button"
        onclick={() => (showRecoveryKit = true)}
        class="key-steel h-9 text-xs font-semibold text-zinc-200 hover:text-white"
      >
        VIEW &amp; PRINT RECOVERY KIT…
      </button>
    </div>
  </div>

  {#if showRecoveryKit}
    <EmergencyKitModal onclose={() => (showRecoveryKit = false)} />
  {/if}
</section>
