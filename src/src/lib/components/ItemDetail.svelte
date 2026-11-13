<script lang="ts">
  import { Copy, Eye, EyeOff, Folder, History, Pencil, Star, Trash2 } from "@lucide/svelte";
  import TotpBadge from "./TotpBadge.svelte";
  import AttachmentList from "./AttachmentList.svelte";
  import { purgeHistory, revealPassword, toCmdError, type ItemDetail, type SecretField } from "../tauri-bridge";

  // Right pane (spec §7.2.2): click-to-copy fields, concealed password with
  // explicit reveal, live TOTP, edit / delete / favorite.
  let {
    item,
    folderName = null,
    readOnly = false,
    onupdated,
    oncopy,
    onedit,
    ondelete,
    onfavorite,
  }: {
    item: ItemDetail;
    folderName?: string | null;
    readOnly?: boolean;
    onupdated: (updated: ItemDetail) => void;
    oncopy: (field: SecretField) => void;
    onedit: () => void;
    ondelete: () => void;
    onfavorite: () => void;
  } = $props();

  // Revealed password is tied to the item it came from, so selecting another
  // item hides it automatically (no $effect).
  let revealed = $state.raw<{ for: string; value: string } | null>(null);
  const shown = $derived(revealed?.for === item.id ? revealed.value : null);
  let revealError = $state<string | null>(null);
  let confirmDelete = $state<string | null>(null);

  async function toggleReveal() {
    if (shown !== null) {
      revealed = null;
      return;
    }
    try {
      revealed = { for: item.id, value: await revealPassword(item.id) };
      revealError = null;
    } catch (e) {
      revealError = toCmdError(e).message;
    }
  }

  // Explicit purge of archived passwords (issue #19), two-step like delete.
  let confirmPurge = $state<string | null>(null);
  let purgeError = $state<string | null>(null);
  async function purge() {
    if (confirmPurge !== item.id) {
      confirmPurge = item.id;
      return;
    }
    confirmPurge = null;
    try {
      onupdated(await purgeHistory(item.id));
      purgeError = null;
    } catch (e) {
      purgeError = toCmdError(e).message;
    }
  }

  function remove() {
    if (confirmDelete === item.id) ondelete();
    else confirmDelete = item.id;
  }

  const created = $derived(item.created_at.replace("T", " ").replace("Z", " UTC"));
  const updated = $derived(item.updated_at.replace("T", " ").replace("Z", " UTC"));
</script>

{#snippet field(label: string, value: string, copyAs: SecretField | null, mono = false)}
  <div class="group border-b border-hairline px-5 py-3">
    <dt class="spec mb-1">{label.toLowerCase()}</dt>
    <dd class="flex items-center gap-2">
      <span class={["min-w-0 flex-1 truncate text-zinc-50 select-text", mono ? "font-mono text-[12.5px]" : "text-sm"]}>{value || "—"}</span>
      {#if copyAs && value}
        <button
          type="button"
          onclick={() => oncopy(copyAs)}
          class="grid size-7 place-items-center rounded-[3px] text-zinc-500 opacity-60 transition group-hover:opacity-100 hover:bg-raised hover:text-zinc-50 focus-visible:opacity-100"
          aria-label="Copy {label.toLowerCase()}"
        >
          <Copy class="size-3.5" />
        </button>
      {/if}
    </dd>
  </div>
{/snippet}

<article class="flex min-h-0 min-w-0 flex-1 flex-col">
  <header class="flex h-12 shrink-0 items-center gap-2 border-b border-hairline px-5">
    <h2 class="min-w-0 truncate font-display text-[17px] font-bold text-zinc-50">{item.title}</h2>
    <span class="min-w-0 flex-1">
      {#if folderName}
        <span class="inline-flex max-w-full items-center gap-1 rounded-[2px] border border-hairline bg-raised px-1.5 py-0.5 font-mono text-[10px] text-zinc-400" aria-label="Folder">
          <Folder class="size-3 shrink-0" aria-hidden="true" /> <span class="truncate">{folderName}</span>
        </span>
      {/if}
    </span>
    <button
      type="button"
      onclick={onfavorite}
      disabled={readOnly}
      title={readOnly ? "Vault is read-only" : undefined}
      class={["grid size-8 place-items-center rounded-[3px]", readOnly ? "cursor-not-allowed opacity-50" : "hover:bg-raised"]}
      aria-label={item.favorite ? "Remove from favorites" : "Add to favorites"}
      aria-pressed={item.favorite}
    >
      <Star class={["size-4", item.favorite ? "fill-caution text-caution" : "text-zinc-500"]} />
    </button>
    <button
      type="button"
      onclick={onedit}
      disabled={readOnly}
      title={readOnly ? "Vault is read-only" : undefined}
      class={["key-steel h-8 px-2.5 text-xs", readOnly && "cursor-not-allowed opacity-50"]}
    >
      <Pencil class="size-3.5" aria-hidden="true" /> Edit
    </button>
    <button
      type="button"
      onclick={remove}
      disabled={readOnly}
      title={readOnly ? "Vault is read-only" : undefined}
      onblur={() => (confirmDelete = null)}
      class={["key-steel h-8 px-2.5 text-xs", readOnly ? "cursor-not-allowed opacity-50" : confirmDelete === item.id ? "hazard border-danger! text-danger!" : "hover:text-danger!"]}
    >
      <Trash2 class="size-3.5" aria-hidden="true" />
      {confirmDelete === item.id ? "Click again to delete" : "Delete"}
    </button>
  </header>

  <dl class="min-h-0 flex-1 overflow-y-auto">
    {#if item.kind === "login"}
      {@render field("Username", item.username, "username")}

      <div class="group border-b border-hairline px-5 py-3">
        <dt class="spec mb-1">password</dt>
        <dd class="flex items-center gap-2">
          <span class={["min-w-0 flex-1 truncate font-mono text-[12.5px] select-text", shown !== null ? "text-uv-soft" : "text-zinc-50"]}>
            {#if !item.has_password}—{:else if shown !== null}{shown}{:else}••••••••••••{/if}
          </span>
          {#if item.has_password}
            <button
              type="button"
              onclick={toggleReveal}
              class="grid size-7 place-items-center rounded-[3px] text-zinc-500 hover:bg-raised hover:text-zinc-50"
              aria-label={shown !== null ? "Hide password" : "Reveal password"}
              aria-pressed={shown !== null}
            >
              {#if shown !== null}<EyeOff class="size-3.5" />{:else}<Eye class="size-3.5" />{/if}
            </button>
            <button
              type="button"
              onclick={() => oncopy("password")}
              class="grid size-7 place-items-center rounded-[3px] text-zinc-500 hover:bg-raised hover:text-zinc-50"
              aria-label="Copy password"
            >
              <Copy class="size-3.5" />
            </button>
          {/if}
        </dd>
        {#if revealError}<p class="mt-1 text-xs text-danger">{revealError}</p>{/if}
        {#if item.history_count > 0}
          <p class="mt-1.5 flex items-center gap-1 font-mono text-[10.5px] text-zinc-500">
            <History class="size-3" aria-hidden="true" /> {item.history_count} previous password{item.history_count === 1 ? "" : "s"} archived
            {#if !readOnly}
              <button
                type="button"
                onclick={purge}
                onblur={() => (confirmPurge = null)}
                class={["ml-1 rounded-[2px] px-1 underline-offset-2 hover:underline", confirmPurge === item.id ? "text-danger" : "text-zinc-400 hover:text-danger"]}
              >
                {confirmPurge === item.id ? "click again to erase" : "purge"}
              </button>
            {/if}
          </p>
        {/if}
        {#if purgeError}<p class="mt-1 text-xs text-danger">{purgeError}</p>{/if}
      </div>

      {#if item.has_totp}
        <div class="border-b border-hairline px-5 py-3">
          <dt class="spec mb-1.5">one-time code</dt>
          <dd><TotpBadge id={item.id} oncopy={() => oncopy("totp")} /></dd>
        </div>
      {/if}

      {@render field("Website", item.url, null, true)}
    {:else}
      <div class="border-b border-hairline px-5 py-3">
        <dt class="spec mb-1">note</dt>
        <!-- Plain text only: never render stored content as HTML (issue #20). -->
        <dd class="font-mono text-[12.5px] leading-6 whitespace-pre-wrap text-zinc-200 select-text">{item.content || "—"}</dd>
      </div>
    {/if}

    {#if item.notes}
      <div class="border-b border-hairline px-5 py-3">
        <dt class="spec mb-1">notes</dt>
        <dd class="text-sm whitespace-pre-wrap text-zinc-300 select-text">{item.notes}</dd>
      </div>
    {/if}

    <AttachmentList {item} {readOnly} onchange={onupdated} />

    {#if item.tags.length}
      <div class="flex flex-wrap gap-1.5 border-b border-hairline px-5 py-3">
        {#each item.tags as tag (tag)}
          <span class="rounded-[2px] border border-uv/30 bg-uv/5 px-1.5 py-0.5 font-mono text-[10.5px] text-uv">#{tag}</span>
        {/each}
      </div>
    {/if}

    <p class="px-5 py-3 font-mono text-[10px] leading-4 text-zinc-600">
      created {created}<br />updated {updated}
    </p>
  </dl>
</article>
