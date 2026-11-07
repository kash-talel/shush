<script lang="ts">
  import { tick } from "svelte";
  import { Check, Folder, FolderPlus, Pencil, Trash2, X } from "@lucide/svelte";
  import { createFolder, deleteFolder, renameFolder, toCmdError, type CmdError, type FolderInfo } from "../tauri-bridge";

  // Sidebar folder section: filter, create inline, rename, two-step delete.
  let {
    folders,
    activeId,
    onselect,
    onchanged,
  }: {
    folders: FolderInfo[];
    activeId: string | null;
    onselect: (id: string) => void;
    onchanged: (removedId?: string) => void;
  } = $props();

  // `editing`: null = idle, "" = creating a new folder, otherwise the id being renamed.
  let editing = $state<string | null>(null);
  let name = $state("");
  let confirmDelete = $state<string | null>(null);
  let error = $state<CmdError | null>(null);
  let input: HTMLInputElement | undefined = $state();

  async function startEdit(id: string, current: string) {
    editing = id;
    name = current;
    error = null;
    await tick();
    input?.focus();
    input?.select();
  }

  async function commit() {
    if (editing === null) return;
    try {
      if (editing === "") await createFolder(name);
      else await renameFolder(editing, name);
      editing = null;
      onchanged();
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
      await deleteFolder(id);
      confirmDelete = null;
      onchanged(id);
    } catch (e) {
      error = toCmdError(e);
    }
  }

  function onkeydown(e: KeyboardEvent) {
    if (e.key === "Enter") {
      e.preventDefault();
      void commit();
    } else if (e.key === "Escape") {
      e.stopPropagation();
      editing = null;
    }
  }
</script>

{#snippet editor()}
  <div class="flex h-8 items-center gap-1 rounded-md border border-tactical/50 bg-surface pr-1 pl-2">
    <Folder class="size-3.5 shrink-0 text-zinc-500" aria-hidden="true" />
    <input
      bind:this={input}
      bind:value={name}
      {onkeydown}
      maxlength="64"
      placeholder="Folder name"
      aria-label="Folder name"
      class="min-w-0 flex-1 bg-transparent text-sm text-zinc-100 outline-none placeholder:text-zinc-600"
    />
    <button type="button" onclick={commit} class="grid size-6 place-items-center rounded text-tactical hover:bg-hairline" aria-label="Save folder">
      <Check class="size-3.5" />
    </button>
    <button type="button" onclick={() => (editing = null)} class="grid size-6 place-items-center rounded text-zinc-500 hover:bg-hairline" aria-label="Cancel">
      <X class="size-3.5" />
    </button>
  </div>
{/snippet}

<div class="mt-4 flex min-h-0 flex-col gap-0.5 border-t border-hairline pt-3" aria-label="Folders">
  <div class="flex items-center justify-between px-2 pb-1">
    <span class="text-[11px] tracking-wider text-zinc-500 uppercase">Folders</span>
    <button
      type="button"
      onclick={() => startEdit("", "")}
      class="grid size-6 place-items-center rounded text-zinc-500 hover:bg-hairline hover:text-zinc-200"
      aria-label="New folder"
    >
      <FolderPlus class="size-3.5" />
    </button>
  </div>

  <div class="flex min-h-0 flex-col gap-0.5 overflow-y-auto">
    {#each folders as f (f.id)}
      {#if editing === f.id}
        {@render editor()}
      {:else}
        <div class="group flex items-center">
          <button
            type="button"
            onclick={() => onselect(f.id)}
            aria-current={activeId === f.id ? "page" : undefined}
            class={[
              "flex h-8 min-w-0 flex-1 items-center gap-2 rounded-md px-2 text-sm transition",
              activeId === f.id ? "bg-hairline text-zinc-100" : "text-zinc-400 hover:bg-hairline/60 hover:text-zinc-200",
            ]}
          >
            <Folder class="size-4 shrink-0" aria-hidden="true" />
            <span class="min-w-0 flex-1 truncate text-left">{f.name}</span>
            <span class="font-mono text-[11px] text-zinc-500 group-hover:hidden">{f.item_count}</span>
          </button>
          <span class="hidden items-center group-hover:flex group-focus-within:flex">
            <button
              type="button"
              onclick={() => startEdit(f.id, f.name)}
              class="grid size-6 place-items-center rounded text-zinc-500 hover:bg-hairline hover:text-zinc-200"
              aria-label="Rename {f.name}"
            >
              <Pencil class="size-3" />
            </button>
            <button
              type="button"
              onclick={() => remove(f.id)}
              onblur={() => (confirmDelete = null)}
              class={["grid size-6 place-items-center rounded hover:bg-hairline", confirmDelete === f.id ? "text-danger" : "text-zinc-500 hover:text-danger"]}
              aria-label={confirmDelete === f.id ? `Click again to delete ${f.name} (items are kept)` : `Delete ${f.name}`}
              title={confirmDelete === f.id ? "Click again: delete folder, keep its items" : "Delete folder"}
            >
              <Trash2 class="size-3" />
            </button>
          </span>
        </div>
      {/if}
    {/each}
    {#if editing === ""}
      {@render editor()}
    {:else if folders.length === 0}
      <p class="px-2 py-1 text-[11px] text-zinc-600">No folders yet.</p>
    {/if}
  </div>
  {#if error}<p class="px-2 pt-1 text-[11px] text-danger" role="alert">{error.message}</p>{/if}
</div>
