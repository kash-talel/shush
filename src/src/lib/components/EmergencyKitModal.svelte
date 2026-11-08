<script lang="ts">
  import { onMount } from "svelte";
  import { Printer, ShieldCheck, TriangleAlert, X, FileKey, CheckSquare, Square } from "@lucide/svelte";
  import { vaultStatus, toCmdError, type CmdError, type VaultStatus } from "../tauri-bridge";

  let { onclose }: { onclose: () => void } = $props();

  let status = $state<VaultStatus | null>(null);
  let loading = $state(true);
  let error = $state<CmdError | null>(null);
  let includePasswordBox = $state(false);

  onMount(() => {
    vaultStatus()
      .then((s) => {
        status = s;
      })
      .catch((e) => {
        error = toCmdError(e);
      })
      .finally(() => {
        loading = false;
      });
  });

  function show(d: HTMLDialogElement) {
    d.showModal();
    return () => d.close();
  }

  function doPrint() {
    window.print();
  }

  const currentDate = new Date().toISOString().slice(0, 10);
</script>

<dialog
  {@attach show}
  aria-labelledby="recovery-kit-title"
  class="acrylic m-auto max-h-[92vh] w-[min(640px,calc(100vw-32px))] overflow-y-auto rounded-[6px] border border-hairline p-0 text-zinc-200 backdrop:bg-black/75 backdrop:backdrop-blur-[2px]"
  oncancel={(e) => {
    e.preventDefault();
    onclose();
  }}
>
  <!-- Screen Header -->
  <div class="no-print flex items-center justify-between border-b border-hairline px-5 py-4">
    <div class="flex items-center gap-2.5">
      <div class="flex size-7 items-center justify-center rounded border border-uv/30 bg-uv/10 text-uv">
        <FileKey class="size-4" aria-hidden="true" />
      </div>
      <div>
        <h2 id="recovery-kit-title" class="font-display text-[17px] font-bold tracking-[-0.01em] text-zinc-50">
          Emergency Recovery Kit
        </h2>
        <p class="text-[11px] text-zinc-400">Offline vault parameters and disaster recovery instructions</p>
      </div>
    </div>
    <button type="button" onclick={onclose} class="rounded p-1 text-zinc-500 hover:text-zinc-200" aria-label="Close">
      <X class="size-4" aria-hidden="true" />
    </button>
  </div>

  <!-- Screen Notice: Zero Disk Residue -->
  <div class="no-print mx-5 mt-4 flex items-start gap-2.5 rounded-[5px] border border-emerald/30 bg-emerald/10 p-3 text-xs text-zinc-300">
    <ShieldCheck class="mt-0.5 size-4 shrink-0 text-emerald" aria-hidden="true" />
    <div class="leading-relaxed">
      <strong class="font-semibold text-emerald">Zero Disk Residue:</strong> This kit is rendered purely in memory and printed directly to your printer. No intermediate PDF or HTML files are written to disk, preventing residue in unallocated disk space, Volume Shadow Copies, or cloud-synced folders.
    </div>
  </div>

  <!-- Screen Option: Opt-in Master Password Field (Issue #27) -->
  <div class="no-print mx-5 mt-3 rounded-[5px] border border-hairline bg-[#09090e] p-3 text-xs">
    <label class="flex cursor-pointer items-start gap-2.5 text-zinc-300">
      <input
        type="checkbox"
        bind:checked={includePasswordBox}
        class="mt-0.5 accent-crimson"
      />
      <div>
        <span class="font-medium text-zinc-100">Include Master Password handwriting box</span>
        <span class="ml-1 text-[11px] text-zinc-500">(Optional &mdash; safe-deposit box storage only)</span>
        {#if includePasswordBox}
          <p class="mt-2 flex items-start gap-1.5 rounded border border-danger/30 bg-danger/10 p-2 text-[11px] leading-relaxed text-danger">
            <TriangleAlert class="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
            <span>
              <strong>Warning: Single Point of Compromise.</strong> Writing your master password on the same sheet that identifies your vault creates a single point of failure if discovered. Only use this if storing this sheet in an access-controlled physical safe or bank safe-deposit box.
            </span>
          </p>
        {/if}
      </div>
    </label>
  </div>

  <!-- Printable Area (Formatted for both screen preview and print) -->
  <div class="print-area p-5 text-xs">
    <!-- Sheet Header -->
    <div class="border-b-2 border-hairline pb-3 print-border">
      <div class="flex items-baseline justify-between">
        <h1 class="font-mono text-base font-bold tracking-wider uppercase text-zinc-100 print:text-black">
          SHUSH // EMERGENCY RECOVERY KIT
        </h1>
        <span class="font-mono text-[10.5px] text-zinc-400 print:text-black">
          DATE: {currentDate}
        </span>
      </div>
      <p class="mt-0.5 font-mono text-[10.5px] text-uv print:text-black">
        OFFLINE ZERO-KNOWLEDGE ENVELOPE PARAMETERS &bull; NO ENCRYPTION KEYS EMBEDDED
      </p>
    </div>

    <!-- Vault Identification -->
    <div class="mt-4">
      <h2 class="font-mono text-[11px] font-bold tracking-wider uppercase text-zinc-400 print:text-black">
        1. VAULT IDENTIFICATION
      </h2>
      <div class="mt-1.5 grid grid-cols-2 gap-2 rounded border border-hairline bg-surface/40 p-2.5 font-mono text-[11px] print-box print-border">
        <div>
          <span class="text-zinc-500 print:text-zinc-700">Vault Name:</span>
          <span class="ml-1 text-zinc-200 font-semibold print:text-black">{status?.name ?? "Primary Vault"}</span>
        </div>
        <div>
          <span class="text-zinc-500 print:text-zinc-700">Vault ID:</span>
          <span class="ml-1 text-zinc-200 print:text-black">{status?.id ?? "default"}</span>
        </div>
        <div class="col-span-2 truncate">
          <span class="text-zinc-500 print:text-zinc-700">File Path:</span>
          <span class="ml-1 text-zinc-300 print:text-black" title={status?.path}>{status?.path ?? "vault.shush"}</span>
        </div>
        <div>
          <span class="text-zinc-500 print:text-zinc-700">Format:</span>
          <span class="ml-1 text-zinc-300 print:text-black">Format v3 (Dual Padded Slots)</span>
        </div>
        <div>
          <span class="text-zinc-500 print:text-zinc-700">Cipher Suite:</span>
          <span class="ml-1 text-zinc-300 print:text-black">{status?.cipher?.name ?? "AES-256-GCM"} (0x{status?.cipher?.id ? status.cipher.id.toString(16).padStart(2, "0") : "01"})</span>
        </div>
      </div>
    </div>

    <!-- Cryptographic KDF Specifications -->
    <div class="mt-4">
      <h2 class="font-mono text-[11px] font-bold tracking-wider uppercase text-zinc-400 print:text-black">
        2. KEY DERIVATION PARAMETERS (ARGON2ID RFC 9106)
      </h2>
      <div class="mt-1.5 grid grid-cols-3 gap-2 rounded border border-hairline bg-surface/40 p-2.5 font-mono text-[11px] print-box print-border">
        <div>
          <span class="text-zinc-500 print:text-zinc-700">Memory (m):</span>
          <div class="text-zinc-200 font-semibold print:text-black">
            {status?.kdf?.mem_kib ?? 65536} KiB ({Math.round((status?.kdf?.mem_kib ?? 65536) / 1024)} MiB)
          </div>
        </div>
        <div>
          <span class="text-zinc-500 print:text-zinc-700">Iterations (t):</span>
          <div class="text-zinc-200 font-semibold print:text-black">{status?.kdf?.iterations ?? 3} passes</div>
        </div>
        <div>
          <span class="text-zinc-500 print:text-zinc-700">Parallelism (p):</span>
          <div class="text-zinc-200 font-semibold print:text-black">{status?.kdf?.parallelism ?? 4} threads</div>
        </div>
        <div class="col-span-3 pt-1 border-t border-hairline/60 print:border-black/20 text-[10px] text-zinc-400 print:text-black">
          Composite Secret: UTF-8(NFC(MasterPassword)) + (SHA-256(KeyfileBytes) if enabled)
        </div>
      </div>
    </div>

    <!-- Authentication Factors -->
    <div class="mt-4">
      <h2 class="font-mono text-[11px] font-bold tracking-wider uppercase text-zinc-400 print:text-black">
        3. REQUIRED AUTHENTICATION FACTORS
      </h2>
      <div class="mt-1.5 space-y-1 rounded border border-hairline bg-surface/40 p-2.5 font-mono text-[11px] print-box print-border">
        <div class="flex items-center gap-2">
          <span class="text-emerald print:text-black font-bold">[&#10003;] Factor 1 (Knowledge):</span>
          <span class="text-zinc-200 print:text-black">Master Password (Normalized Unicode NFC)</span>
        </div>
        <div class="flex items-center gap-2">
          {#if status?.keyfile_required}
            <span class="text-emerald print:text-black font-bold">[&#10003;] Factor 2 (Physical):</span>
            <span class="text-zinc-200 print:text-black">External Keyfile (Required &mdash; stored on external USB drive)</span>
          {:else}
            <span class="text-zinc-500 print:text-zinc-600">[&nbsp;] Factor 2 (Physical):</span>
            <span class="text-zinc-400 print:text-zinc-600">Keyfile not enabled for this vault</span>
          {/if}
        </div>
      </div>
    </div>

    <!-- Optional Handwriting Box (Issue #27) -->
    {#if includePasswordBox}
      <div class="mt-4 rounded border-2 border-dashed border-danger/60 p-3 print-border print-box">
        <div class="font-mono text-[10.5px] font-bold uppercase text-danger print:text-black">
          OPTIONAL SAFE-DEPOSIT BOX HANDWRITTEN MASTER PASSWORD
        </div>
        <p class="mt-0.5 text-[9.5px] text-zinc-400 print:text-zinc-700">
          CAUTION: Single point of compromise. Keep this document strictly in a locked, tamper-evident physical safe.
        </p>
        <div class="mt-3 flex items-baseline gap-2 font-mono text-xs">
          <span class="font-bold print:text-black">MASTER PASSWORD:</span>
          <span class="flex-1 border-b-2 border-dotted border-zinc-500 print:border-black h-5"></span>
        </div>
      </div>
    {/if}

    <!-- Offline Recovery Checklist -->
    <div class="mt-4">
      <h2 class="font-mono text-[11px] font-bold tracking-wider uppercase text-zinc-400 print:text-black">
        4. OFFLINE DISASTER RECOVERY PROCEDURE
      </h2>
      <ol class="mt-1.5 list-decimal space-y-1.5 pl-4 font-mono text-[10.5px] text-zinc-300 print:text-black">
        <li>
          <strong>Obtain Vault Binary:</strong> Locate the encrypted <span class="text-uv print:text-black font-semibold">vault.shush</span> file or an encrypted <span class="text-uv print:text-black font-semibold">.shushbackup</span> export.
        </li>
        <li>
          <strong>Retrieve Keyfile (if enabled):</strong> If factor 2 was required, insert the USB flash drive holding your 32-byte keyfile.
        </li>
        <li>
          <strong>Run shush.exe:</strong> Execute the standalone <span class="font-semibold">shush.exe</span> binary on any Windows 10/11 x64 machine. No internet access or installer is required.
        </li>
        <li>
          <strong>Authenticate:</strong> Choose "Open Existing Vault" (or "Import from backup"), enter your master password, and point to the keyfile.
        </li>
        <li>
          <strong>Tamper-Proof Decryption:</strong> The Argon2id KDF derives the sub-keys and validates the 33-byte canary block in memory. All decryption occurs strictly offline.
        </li>
      </ol>
    </div>

    <!-- Security Guarantee Badge -->
    <div class="mt-4 border-t border-hairline/80 pt-2 text-center font-mono text-[9px] text-zinc-500 print:text-zinc-600 print-border">
      CONFIDENTIAL &bull; ZERO PLAIN-TEXT CREDENTIALS STORED ON THIS SHEET &bull; RENDERED DIRECTLY TO PRINT SPOOLER
    </div>
  </div>

  <!-- Screen Footer / Action Buttons -->
  <div class="no-print flex items-center justify-between border-t border-hairline px-5 py-3">
    <span class="text-[11px] text-zinc-500">
      Prints standard 1-page portrait
    </span>
    <div class="flex items-center gap-2">
      <button
        type="button"
        onclick={onclose}
        class="key-steel h-9 px-4 text-xs"
      >
        CANCEL
      </button>
      <button
        type="button"
        onclick={doPrint}
        class="key flex h-9 items-center gap-1.5 px-4 text-xs font-semibold"
      >
        <Printer class="size-3.5" aria-hidden="true" />
        PRINT RECOVERY KIT
      </button>
    </div>
  </div>
</dialog>

<style>
  @media print {
    :global(body) {
      background: #ffffff !important;
      color: #000000 !important;
    }
    :global(body *) {
      visibility: hidden;
    }
    .print-area,
    .print-area * {
      visibility: visible;
    }
    .print-area {
      position: fixed;
      left: 0;
      top: 0;
      width: 100%;
      height: 100%;
      margin: 0;
      padding: 32px 40px !important;
      background: #ffffff !important;
      color: #000000 !important;
      border: none !important;
      box-shadow: none !important;
      z-index: 99999;
    }
    .no-print {
      display: none !important;
    }
    .print-border {
      border-color: #000000 !important;
    }
    .print-box {
      border: 1px solid #333333 !important;
      background: #fafafa !important;
    }
  }
</style>
