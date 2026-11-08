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

<section class="flex min-h-0 w-72 shrink-0 flex-col border-r border-hairline bg-obsidian/60 max-[1000px]:w-60">
  <label class="flex h-12 items-center gap-2 border-b border-hairline px-3 transition-colors focus-within:bg-surface">
    <Search class="size-4 text-zinc-500" aria-hidden="true" />
    <span class="font-mono text-sm text-ruby" aria-hidden="true">›</span>
    <input
      bind:this={searchInput}
      bind:value={query}
      {onkeydown}
      type="search"
      spellcheck="false"
      placeholder="search vault"
      aria-label="Search vault"
      class="min-w-0 flex-1 bg-transparent font-mono text-[12px] text-zinc-100 caret-ruby outline-none placeholder:text-zinc-600"
    />
    <kbd class="kbd">Ctrl F</kbd>
  </label>

  <ul class="min-h-0 flex-1 overflow-y-auto py-1" role="listbox" aria-label="Items">
    {#each items as item (item.id)}
      {@const on = item.id === selectedId}
      <li role="option" aria-selected={on}>
        <button
          type="button"
          onclick={() => onselect(item.id)}
          class={["flex w-full items-center gap-3 px-3 py-2 text-left transition-colors", on ? "rail-on bg-surface" : "hover:bg-surface/70"]}
        >
          <!-- Stamped-steel monogram plate -->
          <span
            class={[
              "grid size-8 shrink-0 place-items-center rounded-[3px] border font-mono text-[10.5px] font-semibold uppercase",
              on ? "border-crimson/50 bg-crimson/10 text-ruby" : "border-hairline bg-raised text-zinc-400",
            ]}
          >
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
              <span class={["truncate text-[13px]", on ? "text-zinc-50" : "text-zinc-200"]}>{item.title}</span>
              {#if item.favorite}<Star class="size-3 shrink-0 fill-caution text-caution" aria-label="Favorite" />{/if}
              {#if item.has_totp}<ShieldCheck class="size-3 shrink-0 text-uv" aria-label="Has 2FA" />{/if}
            </span>
            <span class="block truncate font-mono text-[10.5px] text-zinc-500">
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
