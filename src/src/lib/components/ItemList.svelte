<script lang="ts">
  import { KeyRound, NotebookText, Search, ShieldCheck, Star } from "@lucide/svelte";
  import type { ItemSummary } from "../tauri-bridge";

  // Middle pane (spec §7.2.2): terminal-style search + item rows.
  let {
    items,
    selectedId,
    query = $bindable(""),
    searchInput = $bindable(),
    onselect,
  }: {
    items: ItemSummary[];
    selectedId: string | null;
    query?: string;
    searchInput?: HTMLInputElement;
    onselect: (id: string) => void;
  } = $props();

  function onkeydown(e: KeyboardEvent) {
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    e.preventDefault();
    const i = items.findIndex((it) => it.id === selectedId);
    const next = e.key === "ArrowDown" ? Math.min(i + 1, items.length - 1) : Math.max(i - 1, 0);
    const target = items[next];
    if (target) onselect(target.id);
  }
</script>

<section class="flex min-h-0 w-72 shrink-0 flex-col border-r border-hairline">
  <label class="flex h-12 items-center gap-2 border-b border-hairline px-3 focus-within:bg-surface">
    <Search class="size-4 text-zinc-500" aria-hidden="true" />
    <span class="font-mono text-sm text-tactical/70" aria-hidden="true">&gt;</span>
    <input
      bind:this={searchInput}
      bind:value={query}
      {onkeydown}
      type="search"
      spellcheck="false"
      placeholder="search vault…"
      aria-label="Search vault"
      class="min-w-0 flex-1 bg-transparent font-mono text-sm text-zinc-100 outline-none placeholder:text-zinc-600"
    />
    <kbd class="rounded border border-hairline px-1 font-mono text-[10px] text-zinc-600">CTRL+F</kbd>
  </label>

  <ul class="min-h-0 flex-1 overflow-y-auto py-1" role="listbox" aria-label="Items">
    {#each items as item (item.id)}
      <li role="option" aria-selected={item.id === selectedId}>
        <button
          type="button"
          onclick={() => onselect(item.id)}
          class={[
            "flex w-full items-center gap-3 px-3 py-2 text-left transition",
            item.id === selectedId ? "bg-surface shadow-[inset_2px_0_0_var(--color-tactical)]" : "hover:bg-surface/60",
          ]}
        >
          <span class="grid size-8 shrink-0 place-items-center rounded-md border border-hairline bg-obsidian font-mono text-xs text-zinc-400 uppercase">
            {#if item.kind === "secure_note"}
              <NotebookText class="size-4" aria-hidden="true" />
            {:else if item.host}
              {item.host.slice(0, 2)}
            {:else}
              <KeyRound class="size-4" aria-hidden="true" />
            {/if}
          </span>
          <span class="min-w-0 flex-1">
            <span class="flex items-center gap-1.5">
              <span class="truncate text-sm text-zinc-100">{item.title}</span>
              {#if item.favorite}<Star class="size-3 shrink-0 fill-amber-300 text-amber-300" aria-label="Favorite" />{/if}
              {#if item.has_totp}<ShieldCheck class="size-3 shrink-0 text-tactical" aria-label="Has 2FA" />{/if}
            </span>
            <span class="block truncate font-mono text-[11px] text-zinc-500">
              {item.kind === "secure_note" ? "secure note" : item.subtitle || item.host || "—"}
            </span>
          </span>
        </button>
      </li>
    {:else}
      <li class="px-4 py-10 text-center text-xs text-zinc-500">
        {query ? "No matches." : "Nothing here yet."}
      </li>
    {/each}
  </ul>
</section>
