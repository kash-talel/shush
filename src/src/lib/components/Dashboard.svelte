<script lang="ts">
  import { onMount } from "svelte";
  import { KeyRound, Layers, LockKeyhole, NotebookText, Plus, Star } from "@lucide/svelte";
  import ItemList from "./ItemList.svelte";
  import ItemDetailView from "./ItemDetail.svelte";
  import ItemEditor from "./ItemEditor.svelte";
  import {
    copyField,
    createItem,
    deleteItem,
    getItem,
    listItems,
    setFavorite,
    toCmdError,
    updateItem,
    type CmdError,
    type ItemDetail,
    type ItemDraft,
    type ItemKind,
    type ItemSummary,
    type SecretField,
  } from "../tauri-bridge";

  // Main vault dashboard (spec §7.2.2): sidebar · list · detail/editor.
  let { onlock, oncopied }: { onlock: () => void; oncopied: (seconds: number) => void } = $props();

  type Filter = "all" | "favorites" | ItemKind;
  type Mode = { kind: "view" } | { kind: "create"; itemKind: ItemKind } | { kind: "edit" };

  let items = $state.raw<ItemSummary[]>([]);
  let detail = $state.raw<ItemDetail | null>(null);
  let filter = $state<Filter>("all");
  let query = $state("");
  let mode = $state<Mode>({ kind: "view" });
  let error = $state<CmdError | null>(null);
  let searchInput: HTMLInputElement | undefined = $state();

  const visible = $derived.by(() => {
    const q = query.trim().toLowerCase();
    return items.filter((i) => {
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
  }

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
    } else if (k === "n" && mode.kind === "view") {
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
  <nav class="flex w-52 shrink-0 flex-col border-r border-hairline bg-surface/40 p-2" aria-label="Vault sections">
    <p class="px-2 pt-1 pb-3 font-mono text-[11px] tracking-[0.18em] text-tactical">// SHUSH</p>
    {#each filters as f (f.id)}
      <button
        type="button"
        onclick={() => (filter = f.id)}
        aria-current={filter === f.id ? "page" : undefined}
        class={[
          "flex h-8 items-center gap-2 rounded-md px-2 text-sm transition",
          filter === f.id ? "bg-hairline text-zinc-100" : "text-zinc-400 hover:bg-hairline/60 hover:text-zinc-200",
        ]}
      >
        <f.icon class="size-4" aria-hidden="true" />
        <span class="flex-1 text-left">{f.label}</span>
        <span class="font-mono text-[11px] text-zinc-500">{counts[f.id]}</span>
      </button>
    {/each}

    <div class="mt-4 flex flex-col gap-1 border-t border-hairline pt-3">
      <button
        type="button"
        onclick={() => (mode = { kind: "create", itemKind: "login" })}
        class="flex h-8 items-center gap-2 rounded-md px-2 text-sm text-tactical hover:bg-tactical/10"
      >
        <Plus class="size-4" aria-hidden="true" /> New login
        <kbd class="ml-auto font-mono text-[10px] text-zinc-600">CTRL+N</kbd>
      </button>
      <button
        type="button"
        onclick={() => (mode = { kind: "create", itemKind: "secure_note" })}
        class="flex h-8 items-center gap-2 rounded-md px-2 text-sm text-zinc-300 hover:bg-hairline/60"
      >
        <Plus class="size-4" aria-hidden="true" /> New secure note
      </button>
    </div>

    <button
      type="button"
      onclick={onlock}
      class="mt-auto flex h-9 items-center gap-2 rounded-md border border-danger/30 px-2 text-sm text-danger hover:bg-danger/10"
    >
      <LockKeyhole class="size-4" aria-hidden="true" /> Lock vault
      <kbd class="ml-auto font-mono text-[10px] opacity-70">CTRL+L</kbd>
    </button>
  </nav>

  <ItemList items={visible} selectedId={detail?.id ?? null} bind:query bind:searchInput onselect={select} />

  <!-- Detail / editor -->
  <div class="flex min-h-0 min-w-0 flex-1 flex-col">
    {#if error}
      <p class="border-b border-danger/30 bg-danger/10 px-4 py-2 text-xs text-danger" role="alert">
        <span class="font-mono">[{error.code}]</span> {error.message}
      </p>
    {/if}
    {#if mode.kind === "create"}
      <ItemEditor kind={mode.itemKind} onsave={save} oncancel={() => (mode = { kind: "view" })} />
    {:else if mode.kind === "edit" && detail}
      <ItemEditor kind={detail.kind} existing={detail} onsave={save} oncancel={() => (mode = { kind: "view" })} />
    {:else if detail}
      <ItemDetailView
        item={detail}
        oncopy={copy}
        onedit={() => (mode = { kind: "edit" })}
        ondelete={remove}
        onfavorite={toggleFavorite}
      />
    {:else}
      <div class="flex flex-1 flex-col items-center justify-center gap-2 text-center">
        <p class="font-mono text-xs tracking-[0.18em] text-zinc-500">
          {items.length === 0 ? "// VAULT_EMPTY" : "// NO_ITEM_SELECTED"}
        </p>
        <p class="max-w-64 text-xs text-zinc-500">
          {items.length === 0
            ? "Add your first login with Ctrl+N."
            : "Select an item, or search with Ctrl+F."}
        </p>
      </div>
    {/if}
  </div>
</div>
