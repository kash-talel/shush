<script lang="ts">
  import { onMount, tick } from "svelte";
  import { listen } from "@tauri-apps/api/event";
  import { invoke } from "@tauri-apps/api/core";
  import { KeyRound, LockKeyhole, ShieldCheck, Sparkles } from "@lucide/svelte";
  import {
    AUTO_LOCK_EVENT,
    copyField,
    listItems,
    toCmdError,
    vaultStatus,
    type ItemSummary,
    type SecretField,
  } from "../tauri-bridge";

  // Spotlight quick search (spec §7.2.3), shown with Ctrl+Alt+Space.
  // Enter copies through the Rust clipboard (history/cloud excluded); the
  // active window's title only pre-selects a result and never auto-types (#14).
  let unlocked = $state<boolean | null>(null);
  let items = $state.raw<ItemSummary[]>([]);
  let query = $state("");
  let selected = $state(0);
  let contextMatch = $state<string | null>(null);
  let message = $state<string | null>(null);
  let input: HTMLInputElement | undefined = $state();

  /** Subsequence fuzzy score; higher is better, null = no match. */
  function score(item: ItemSummary, q: string): number | null {
    const hay = `${item.title} ${item.subtitle} ${item.host}`.toLowerCase();
    const at = hay.indexOf(q);
    if (at === 0) return 1000;
    if (at > 0) return 500 - at;
    let i = 0;
    for (const ch of hay) if (ch === q[i] && ++i === q.length) return 100;
    return null;
  }

  const logins = $derived(items.filter((i) => i.kind === "login"));
  const results = $derived.by(() => {
    const q = query.trim().toLowerCase();
    if (!q) return logins;
    return logins
      .map((i) => [i, score(i, q)] as const)
      .filter((x): x is readonly [ItemSummary, number] => x[1] !== null)
      .sort((a, b) => b[1] - a[1])
      .map(([i]) => i);
  });
  const current = $derived(results[Math.min(selected, results.length - 1)] ?? null);

  /** Best item for the active window's title: longest host/title key it contains. */
  function preselect(context: string | null): number {
    if (!context) return -1;
    const ctx = context.toLowerCase();
    let best = -1;
    let bestLen = 0;
    logins.forEach((item, idx) => {
      const keys = [item.title.toLowerCase(), item.host.split(".").slice(-2, -1)[0] ?? "", item.host];
      for (const k of keys) {
        if (k.length >= 3 && ctx.includes(k) && k.length > bestLen) {
          best = idx;
          bestLen = k.length;
        }
      }
    });
    return best;
  }

  async function open(context: string | null) {
    query = "";
    message = null;
    contextMatch = null;
    selected = 0;
    try {
      unlocked = (await vaultStatus()).unlocked;
      items = unlocked ? await listItems() : [];
    } catch (e) {
      unlocked = false;
      message = toCmdError(e).message;
    }
    const idx = preselect(context);
    if (idx >= 0) {
      selected = idx;
      contextMatch = context;
    }
    await tick();
    input?.focus();
  }

  const hide = () => invoke("hide_spotlight");

  async function copy(field: SecretField) {
    if (!current) return;
    if (field === "totp" && !current.has_totp) {
      message = "This login has no 2FA code.";
      return;
    }
    try {
      await copyField(current.id, field);
      await hide();
    } catch (e) {
      message = toCmdError(e).message;
    }
  }

  function onkeydown(e: KeyboardEvent) {
    const next = e.key === "ArrowDown" || (e.ctrlKey && e.key.toLowerCase() === "j");
    const prev = e.key === "ArrowUp" || (e.ctrlKey && e.key.toLowerCase() === "k");
    if (e.key === "Escape") {
      e.preventDefault();
      void hide();
    } else if (next || prev) {
      e.preventDefault();
      const n = results.length;
      if (n) selected = (Math.min(selected, n - 1) + (next ? 1 : n - 1)) % n;
    } else if (e.key === "Enter") {
      e.preventDefault();
      if (!unlocked) void invoke("open_main_window");
      else void copy(e.ctrlKey ? "username" : e.altKey ? "totp" : "password");
    }
  }

  onMount(() => {
    const offOpen = listen<{ context: string | null }>("spotlight-open", (e) => open(e.payload.context));
    const offLock = listen(AUTO_LOCK_EVENT, () => {
      unlocked = false;
      items = [];
    });
    document.title = "shush quick search";
    void open(null);
    return () => {
      void offOpen.then((f) => f());
      void offLock.then((f) => f());
    };
  });
</script>

<svelte:window {onkeydown} />

<div class="acrylic flex h-full flex-col overflow-hidden">
  <label class="flex h-14 shrink-0 items-center gap-3 border-b border-hairline px-4">
    <span class="flex items-center gap-2 select-none" aria-hidden="true">
      <span class={["led", unlocked ? "text-ruby" : "text-zinc-600"]}></span>
      <span class="font-display text-[17px] font-extrabold tracking-[-0.02em] text-zinc-50">shush</span>
      <span class="font-mono text-base text-ruby">›</span>
    </span>
    <input
      bind:this={input}
      bind:value={query}
      oninput={() => {
        selected = 0;
        contextMatch = null;
      }}
      disabled={!unlocked}
      spellcheck="false"
      autocomplete="off"
      placeholder={unlocked ? "search logins" : "vault locked"}
      aria-label="Search logins"
      class="min-w-0 flex-1 bg-transparent font-mono text-[15px] text-zinc-50 caret-ruby outline-none placeholder:text-zinc-600"
    />
    <kbd class="kbd">Esc</kbd>
  </label>

  {#if unlocked === false}
    <div class="flex flex-1 flex-col items-center justify-center gap-2 text-center">
      <LockKeyhole class="size-6 text-ruby" aria-hidden="true" />
      <p class="font-display text-[17px] font-bold text-zinc-100">Vault locked</p>
      <p class="text-xs text-zinc-500">Press <kbd class="kbd">Enter</kbd> to open shush and unlock.</p>
    </div>
  {:else}
    {#if contextMatch}
      <p class="flex items-center gap-1.5 border-b border-hairline bg-uv/5 px-4 py-1.5 text-[11px] text-uv" role="status">
        <Sparkles class="size-3 shrink-0" aria-hidden="true" /> Matched the active window:
        <span class="truncate font-mono text-[10.5px] text-zinc-400">{contextMatch}</span>
      </p>
    {/if}
    <ul class="min-h-0 flex-1 overflow-y-auto py-1" role="listbox" aria-label="Results">
      {#each results as item, i (item.id)}
        {@const on = item === current}
        <li role="option" aria-selected={on}>
          <button
            type="button"
            tabindex="-1"
            onclick={() => {
              selected = i;
              void copy("password");
            }}
            onmousemove={() => (selected = i)}
            class={["flex w-full items-center gap-3 px-4 py-2 text-left", on && "rail-on bg-white/[0.03]"]}
          >
            <span
              class={[
                "grid size-8 shrink-0 place-items-center rounded-[3px] border font-mono text-[10.5px] font-semibold uppercase",
                on ? "border-crimson/50 bg-crimson/10 text-ruby" : "border-hairline bg-raised text-zinc-400",
              ]}
            >
              {#if item.host}{item.host.slice(0, 2)}{:else}<KeyRound class="size-4" aria-hidden="true" />{/if}
            </span>
            <span class="min-w-0 flex-1">
              <span class="flex items-center gap-1.5 truncate text-[13px] text-zinc-50">
                {item.title}
                {#if item.has_totp}<ShieldCheck class="size-3 shrink-0 text-uv" aria-label="Has 2FA" />{/if}
              </span>
              <span class="block truncate font-mono text-[10.5px] text-zinc-500">{item.subtitle || item.host || "—"}</span>
            </span>
            {#if on}<span class="kbd">Enter</span>{/if}
          </button>
        </li>
      {:else}
        <li class="px-4 py-10 text-center text-xs text-zinc-500">{query ? "No matching logins." : "No logins yet."}</li>
      {/each}
    </ul>
  {/if}

  <footer class="flex h-9 shrink-0 items-center gap-4 border-t border-hairline px-4 text-[11px] text-zinc-500">
    {#if message}
      <span class="text-danger" role="alert">{message}</span>
    {:else if unlocked}
      <span class="flex items-center gap-1.5"><kbd class="kbd">Enter</kbd> password</span>
      <span class="flex items-center gap-1.5"><kbd class="kbd">Ctrl Enter</kbd> username</span>
      <span class="flex items-center gap-1.5"><kbd class="kbd">Alt Enter</kbd> 2FA code</span>
    {/if}
  </footer>
</div>
