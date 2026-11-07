<script lang="ts">
  import { open, save } from "@tauri-apps/plugin-dialog";
  import { Download, FileText, LoaderCircle, Paperclip, Trash2 } from "@lucide/svelte";
  import {
    addAttachment,
    deleteAttachment,
    formatBytes,
    saveAttachment,
    toCmdError,
    type CmdError,
    type ItemDetail,
  } from "../tauri-bridge";

  // Encrypted file attachments (spec §5, #5). Files are stored as separately
  // sealed blobs; contents only leave Rust when the user saves one to disk.
  let { item, onchange }: { item: ItemDetail; onchange: (updated: ItemDetail) => void } = $props();

  let busy = $state(false);
  let error = $state<CmdError | null>(null);
  let saved = $state<string | null>(null);
  let confirmDelete = $state<string | null>(null);

  async function add() {
    const picked = await open({ multiple: false, directory: false, title: "Attach a file (max 10 MB)" });
    if (typeof picked !== "string") return;
    busy = true;
    error = null;
    saved = null;
    try {
      onchange(await addAttachment(item.id, picked));
    } catch (e) {
      error = toCmdError(e);
    } finally {
      busy = false;
    }
  }

  async function download(id: string, filename: string) {
    const dest = await save({ title: "Save attachment", defaultPath: filename });
    if (!dest) return;
    error = null;
    try {
      await saveAttachment(id, dest);
      saved = filename;
    } catch (e) {
      error = toCmdError(e);
    }
  }

  async function remove(id: string) {
    if (confirmDelete !== id) {
      confirmDelete = id;
      return;
    }
    try {
      onchange(await deleteAttachment(item.id, id));
      confirmDelete = null;
    } catch (e) {
      error = toCmdError(e);
    }
  }
</script>

<div class="border-b border-hairline px-4 py-3" aria-label="Attachments">
  <div class="mb-2 flex items-center justify-between">
    <dt class="text-[11px] tracking-wider text-zinc-500 uppercase">Attachments</dt>
    <button
      type="button"
      onclick={add}
      disabled={busy}
      class="flex h-7 items-center gap-1.5 rounded-md border border-hairline px-2 text-xs text-zinc-300 hover:bg-hairline disabled:opacity-50"
    >
      {#if busy}<LoaderCircle class="size-3.5 animate-spin" aria-hidden="true" />{:else}<Paperclip class="size-3.5" aria-hidden="true" />{/if}
      Add file
    </button>
  </div>
  <dd>
    {#if item.attachments.length === 0}
      <p class="text-xs text-zinc-600">No files. Attach scans, recovery codes or keys (encrypted, up to 10 MB each).</p>
    {:else}
      <ul class="flex flex-col gap-1">
        {#each item.attachments as a (a.id)}
          <li class="group flex items-center gap-2 rounded-md bg-surface px-2 py-1.5">
            <FileText class="size-4 shrink-0 text-cold" aria-hidden="true" />
            <span class="min-w-0 flex-1 truncate text-sm text-zinc-200" title={a.filename}>{a.filename}</span>
            <span class="font-mono text-[11px] text-zinc-500">{formatBytes(a.size_bytes)}</span>
            <button
              type="button"
              onclick={() => download(a.id, a.filename)}
              class="grid size-7 place-items-center rounded text-zinc-500 hover:bg-hairline hover:text-zinc-100"
              aria-label="Save {a.filename}"
            >
              <Download class="size-3.5" />
            </button>
            <button
              type="button"
              onclick={() => remove(a.id)}
              onblur={() => (confirmDelete = null)}
              class={["grid size-7 place-items-center rounded hover:bg-hairline", confirmDelete === a.id ? "text-danger" : "text-zinc-500 hover:text-danger"]}
              aria-label={confirmDelete === a.id ? `Click again to delete ${a.filename}` : `Delete ${a.filename}`}
            >
              <Trash2 class="size-3.5" />
            </button>
          </li>
        {/each}
      </ul>
    {/if}
    {#if saved}<p class="mt-1.5 text-xs text-tactical" role="status">Saved {saved}. It is no longer encrypted on disk.</p>{/if}
    {#if error}<p class="mt-1.5 text-xs text-danger" role="alert"><span class="font-mono">[{error.code}]</span> {error.message}</p>{/if}
  </dd>
</div>
