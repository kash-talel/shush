<script lang="ts">
  import { onMount } from "svelte";
  import { DatabaseBackup, KeyRound, Layers, LockKeyhole, NotebookText, Plus, Search, Star, TriangleAlert } from "@lucide/svelte";
  import ItemList from "./ItemList.svelte";
  import ItemDetailView from "./ItemDetail.svelte";
  import ItemEditor from "./ItemEditor.svelte";
  import BackupPanel from "./BackupPanel.svelte";
  import FolderList from "./FolderList.svelte";
  import {
    copyField,
    createItem,
    deleteItem,
    getItem,
    listFolders,
    listItems,
    reloadVault,
    setFavorite,
    showSpotlight,
    toCmdError,
    updateItem,
    type CmdError,
    type FolderInfo,
    type ItemDetail,
    type ItemDraft,
    type ItemKind,
    type ItemSummary,
    type SecretField,
    type VaultSummary,
  } from "../tauri-bridge";

  // Main vault dashboard (spec §7.2.2): sidebar · list · detail/editor.
  let {
    summary = null,
    onlock,
    oncopied,
    hotkey = null,
  }: {
    summary?: VaultSummary | null;
    onlock: () => void;
    oncopied: (seconds: number) => void;
    hotkey?: string | null;
  } = $props();

  const readOnly = $derived(summary?.read_only ?? false);

  type Filter = "all" | "favorites" | ItemKind;
  type Mode = { kind: "view" } | { kind: "create"; itemKind: ItemKind } | { kind: "edit" } | { kind: "backup" };

  let items = $state.raw<ItemSummary[]>([]);
  let detail = $state.raw<ItemDetail | null>(null);
  let filter = $state<Filter>("all");
  let folderFilter = $state<string | null>(null);
  let folders = $state.raw<FolderInfo[]>([]);
  let query = $state("");
  let mode = $state<Mode>({ kind: "view" });
  let error = $state<CmdError | null>(null);
  let searchInput: HTMLInputElement | undefined = $state();

  const visible = $derived.by(() => {
    const q = query.trim().toLowerCase();
    return items.filter((i) => {
      if (folderFilter !== null && i.folder_id !== folderFilter) return false;
      if (filter === "favorites" && !i.favorite) return false;
      if ((filter === "login" || filter === "secure_note") && i.kind !== filter) return false;
      if (!q) return true;
      return [i.title, i.subtitle, i.host].some((f) => f.toLowerCase().includes(q));
    });
  });

  const counts = $derived({
    all: items.length,
    favorites: items.filter((i) => i.favorite).length,
    login: items.filter((i) => i.kind === "login").length,
    secure_note: items.filter((i) => i.kind === "secure_note").length,
  });

  async function run<T>(op: () => Promise<T>): Promise<T | undefined> {
    try {
      error = null;
      return await op();
    } catch (e) {
      error = toCmdError(e);
      return undefined;
    }
  }

  async function refresh() {
    items = (await run(listItems)) ?? items;
    folders = (await run(listFolders)) ?? folders;
    if (detail) {
      // Keep the open item in sync (e.g. its folder was deleted).
      const id = detail.id;
      const d = await run(() => getItem(id));
      if (d) detail = d;
    }
  }

  async function reloadAndRefresh() {
    try {
      await reloadVault();
      error = null;
      await refresh();
    } catch (e) {
      error = toCmdError(e);
    }
  }

  const folderName = (id: string | null) => folders.find((f) => f.id === id)?.name ?? null;

  async function select(id: string) {
    mode = { kind: "view" };
    const d = await run(() => getItem(id));
    if (d) detail = d;
  }

  async function save(draft: ItemDraft) {
    // Errors propagate to the editor, which shows them inline.
    const saved =
      mode.kind === "create"
        ? await createItem(mode.itemKind, draft)
        : await updateItem((detail as ItemDetail).id, draft);
    detail = saved;
    mode = { kind: "view" };
    await refresh();
  }

  async function remove() {
    if (!detail) return;
    const id = detail.id;
    const ok = await run(async () => (await deleteItem(id), true));
    if (ok) {
      detail = null;
      await refresh();
    }
  }

  async function toggleFavorite() {
    if (!detail) return;
    const { id, favorite } = detail;
    const ok = await run(async () => (await setFavorite(id, !favorite), true));
    if (ok && detail?.id === id) {
      detail = { ...detail, favorite: !favorite };
      await refresh();
    }
  }

  async function copy(field: SecretField) {
    if (!detail) return;
    const id = detail.id;
    const secs = await run(() => copyField(id, field));
    if (secs !== undefined) oncopied(secs);
  }

  function onkeydown(e: KeyboardEvent) {
    if (!e.ctrlKey || e.altKey || e.shiftKey) return;
    const k = e.key.toLowerCase();
    if (k === "l") {
      e.preventDefault();
      onlock();
    } else if (k === "f") {
      e.preventDefault();
      searchInput?.focus();
      searchInput?.select();
    } else if (k === "n" && mode.kind === "view" && !readOnly) {
      e.preventDefault();
      mode = { kind: "create", itemKind: "login" };
    }
  }

  onMount(refresh);

  const filters: { id: Filter; label: string; icon: typeof Layers }[] = [
    { id: "all", label: "All items", icon: Layers },
    { id: "favorites", label: "Favorites", icon: Star },
    { id: "login", label: "Logins", icon: KeyRound },
    { id: "secure_note", label: "Secure notes", icon: NotebookText },
  ];
</script>

<svelte:window {onkeydown} />

<div class="flex min-h-0 flex-1">
  <!-- Sidebar -->
  <nav class="steel flex w-52 shrink-0 flex-col border-r border-hairline p-2 max-[1000px]:w-44" aria-label="Vault sections">
    <p class="flex items-center gap-2 px-2 pt-1.5 pb-3">
      <span class="font-display text-[19px] leading-none font-extrabold tracking-[-0.02em] text-zinc-50">shush</span>
      <span class="led text-ruby" aria-hidden="true"></span>
      {#if readOnly}
        <span class="ml-auto rounded border border-caution/40 bg-caution/10 px-1.5 py-0.5 font-mono text-[9.5px] font-bold uppercase tracking-wider text-caution" role="status">
          read-only
        </span>
      {/if}
    </p>
    {#each filters as f (f.id)}
      {@const on = filter === f.id && folderFilter === null}
      <button
        type="button"
        onclick={() => {
          filter = f.id;
          folderFilter = null;
        }}
        aria-current={on ? "page" : undefined}
        class={[
          "flex h-8 items-center gap-2 rounded-[3px] px-2 text-[13px] transition",
          on ? "rail-on bg-raised text-zinc-50" : "text-zinc-400 hover:bg-raised hover:text-zinc-200",
        ]}
      >
        <f.icon class={["size-4", on && "text-ruby"]} aria-hidden="true" />
        <span class="flex-1 text-left">{f.label}</span>
        <span class="font-mono text-[10px] text-zinc-500 tabular-nums">{counts[f.id]}</span>
      </button>
    {/each}

    <FolderList
      {folders}
      activeId={folderFilter}
      onselect={(id) => {
        filter = "all";
        folderFilter = id;
      }}
      onchanged={(removedId) => {
        if (removedId && folderFilter === removedId) folderFilter = null;
        void refresh();
      }}
    />

    <div class="mt-3 flex flex-col gap-0.5 border-t border-hairline pt-3">
      <button
        type="button"
        onclick={() => (mode = { kind: "create", itemKind: "login" })}
        disabled={readOnly}
        title={readOnly ? "Vault is read-only" : undefined}
        class={[
          "flex h-8 items-center gap-2 rounded-[3px] px-2 text-[13px]",
          readOnly ? "cursor-not-allowed text-zinc-500 opacity-50" : "text-ruby hover:bg-crimson/10",
        ]}
      >
        <Plus class="size-4" aria-hidden="true" /> New login
        <kbd class="kbd ml-auto max-[1000px]:hidden">Ctrl N</kbd>
      </button>
      <button
        type="button"
        onclick={() => (mode = { kind: "create", itemKind: "secure_note" })}
        disabled={readOnly}
        title={readOnly ? "Vault is read-only" : undefined}
        class={[
          "flex h-8 items-center gap-2 rounded-[3px] px-2 text-[13px]",
          readOnly ? "cursor-not-allowed text-zinc-500 opacity-50" : "text-zinc-300 hover:bg-raised",
        ]}
      >
        <Plus class="size-4" aria-hidden="true" /> New secure note
      </button>
      <button
        type="button"
        onclick={() => (mode = { kind: "backup" })}
        aria-current={mode.kind === "backup" ? "page" : undefined}
        class={[
          "flex h-8 items-center gap-2 rounded-[3px] px-2 text-[13px] hover:bg-raised",
          mode.kind === "backup" ? "rail-on bg-raised text-zinc-50" : "text-zinc-300",
        ]}
      >
        <DatabaseBackup class="size-4" aria-hidden="true" /> Backup &amp; import
      </button>
    </div>

    <button
      type="button"
      onclick={() => showSpotlight()}
      class="mt-auto flex items-start gap-2 rounded-[3px] px-2 py-1.5 text-left text-[13px] text-zinc-400 hover:bg-raised hover:text-zinc-200"
      title={hotkey ? `Quick search from anywhere: ${hotkey}` : "Quick search (global hotkey unavailable: another app uses it)"}
    >
      <Search class="mt-0.5 size-4 shrink-0" aria-hidden="true" />
      <span class="flex min-w-0 flex-col gap-1">
        Quick search
        <span class="flex gap-1">
          {#each hotkey ? hotkey.split("+") : ["Tray"] as k (k)}<kbd class="kbd">{k}</kbd>{/each}
        </span>
      </span>
    </button>
    <button type="button" onclick={onlock} class="key-steel mt-2 h-9 justify-start! gap-2 px-2 text-[13px] text-ruby! hover:border-crimson/50!">
      <LockKeyhole class="size-4" aria-hidden="true" /> Lock vault
      <kbd class="kbd ml-auto">Ctrl L</kbd>
    </button>
  </nav>

  <ItemList items={visible} selectedId={detail?.id ?? null} bind:query bind:searchInput onselect={select} />

  <!-- Detail / editor -->
  <div class="flex min-h-0 min-w-0 flex-1 flex-col">
    {#if readOnly}
      <div class="flex items-center gap-2 border-b border-caution/30 bg-caution/10 px-4 py-1.5 text-xs text-caution" role="status">
        <LockKeyhole class="size-3.5 shrink-0" aria-hidden="true" />
        <span>Vault is opened in read-only mode (media or file is write-protected). Changes cannot be saved.</span>
      </div>
    {/if}
    {#if error}
      <div class="hazard flex items-center justify-between border-b border-danger/40 bg-danger/10 px-4 py-2 text-xs text-danger" role="alert">
        <span class="flex items-center gap-1.5">
          <TriangleAlert class="size-3.5 shrink-0" aria-hidden="true" />
          <span><span class="font-mono">[{error.code}]</span> {error.message}</span>
        </span>
        {#if error.code === "VAULT_CHANGED_ON_DISK"}
          <button
            type="button"
            onclick={reloadAndRefresh}
            class="key-steel h-6 shrink-0 px-2 text-[11px]"
          >
            Reload Vault
          </button>
        {/if}
      </div>
    {/if}
    {#if mode.kind === "backup"}
      <BackupPanel {readOnly} onimported={refresh} />
    {:else if mode.kind === "create"}
      <ItemEditor kind={mode.itemKind} {folders} defaultFolderId={folderFilter} onsave={save} oncancel={() => (mode = { kind: "view" })} onrefresh={refresh} />
    {:else if mode.kind === "edit" && detail}
      <ItemEditor kind={detail.kind} existing={detail} {folders} onsave={save} oncancel={() => (mode = { kind: "view" })} onrefresh={refresh} />
    {:else if detail}
      <ItemDetailView
        item={detail}
        {readOnly}
        folderName={folderName(detail.folder_id)}
        onupdated={(d) => (detail = d)}
        oncopy={copy}
        onedit={() => (mode = { kind: "edit" })}
        ondelete={remove}
        onfavorite={toggleFavorite}
      />
    {:else}
      <div class="flex flex-1 flex-col items-center justify-center gap-3 px-6 text-center">
        {#if items.length === 0}
          <h2 class="font-display text-[22px] font-bold text-zinc-100">Empty vault</h2>
          <p class="max-w-64 text-xs leading-5 text-zinc-500">Add your first login, or bring passwords over from Backup &amp; import.</p>
          <button
            type="button"
            onclick={() => (mode = { kind: "create", itemKind: "login" })}
            disabled={readOnly}
            title={readOnly ? "Vault is read-only" : undefined}
            class={["key mt-1 h-9 px-4 text-[11px]", readOnly && "cursor-not-allowed opacity-50"]}
          >
            NEW LOGIN <span class="kbd border-white/25! bg-black/20! text-white/80!">Ctrl N</span>
          </button>
        {:else}
          <p class="font-display text-[15px] font-semibold text-zinc-500">Nothing selected</p>
          <p class="max-w-64 text-xs text-zinc-600">Pick an item, or search with <kbd class="kbd">Ctrl F</kbd></p>
        {/if}
      </div>
    {/if}
  </div>
</div>
