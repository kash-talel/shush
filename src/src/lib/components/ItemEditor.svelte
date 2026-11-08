<script lang="ts">
  import { onMount, tick } from "svelte";
  import { LoaderCircle, Sparkles, TriangleAlert } from "@lucide/svelte";
  import PasswordField from "./PasswordField.svelte";
  import PasswordGenerator from "./PasswordGenerator.svelte";
  import {
    createItem,
    getItem,
    reloadVault,
    toCmdError,
    type CmdError,
    type FolderInfo,
    type ItemDetail,
    type ItemDraft,
    type ItemKind,
  } from "../tauri-bridge";

  // Create / edit form. Secrets follow "keep unless changed": when editing,
  // the existing password and TOTP secret are never loaded into the UI.
  let {
    kind,
    existing = null,
    folders = [],
    defaultFolderId = null,
    onsave,
    oncancel,
    onrefresh,
  }: {
    kind: ItemKind;
    existing?: ItemDetail | null;
    folders?: FolderInfo[];
    defaultFolderId?: string | null;
    onsave: (draft: ItemDraft) => Promise<void>;
    oncancel: () => void;
    onrefresh?: () => Promise<void>;
  } = $props();

  // The form copies the item once on mount; it is remounted per edit session.
  // svelte-ignore state_referenced_locally
  const initial = existing;
  let title = $state(initial?.title ?? "");
  let username = $state(initial?.username ?? "");
  let url = $state(initial?.url ?? "");
  let notes = $state(initial?.notes ?? "");
  let content = $state(initial?.content ?? "");
  let tags = $state(initial?.tags.join(", ") ?? "");
  let favorite = $state(initial?.favorite ?? false);
  // svelte-ignore state_referenced_locally
  let folderId = $state<string | null>(initial ? initial.folder_id : defaultFolderId);

  let password = $state("");
  let passwordTouched = $state(initial === null);
  let totp = $state("");
  let totpTouched = $state(initial === null);
  let showGenerator = $state(false);

  let busy = $state(false);
  let error = $state<CmdError | null>(null);
  let titleInput: HTMLInputElement | undefined = $state();

  // Recovery state for VAULT_CHANGED_ON_DISK (issue #49)
  let conflictFields = $state<string[]>([]);
  let conflictItem = $state<ItemDetail | null>(null);
  let itemDeletedOnDisk = $state(false);
  let requirePassword = $state(false);
  let masterPassword = $state("");

  const isLogin = $derived(kind === "login");
  const canSave = $derived(!busy && title.trim().length > 0);

  function buildDraft(): ItemDraft {
    return {
      title,
      username,
      url,
      notes,
      content,
      favorite,
      tags: tags.split(",").map((t) => t.trim()).filter(Boolean),
      folder_id: folderId,
      password: isLogin && passwordTouched ? password : null,
      totp: isLogin && totpTouched ? totp : null,
    };
  }

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    if (!canSave) return;
    busy = true;
    error = null;
    conflictItem = null;
    conflictFields = [];
    itemDeletedOnDisk = false;
    try {
      await onsave(buildDraft());
    } catch (err) {
      const cmdErr = toCmdError(err);
      if (cmdErr.code === "PASSWORD_REQUIRED") {
        requirePassword = true;
      }
      error = cmdErr;
      busy = false;
      await tick();
    }
  }

  async function reloadAndReapply(force = false) {
    busy = true;
    error = null;
    try {
      await reloadVault(requirePassword ? masterPassword : undefined);
      requirePassword = false;
      masterPassword = "";

      // If updating an existing item and not forced: check if disk changed
      if (initial && !force) {
        try {
          const diskItem = await getItem(initial.id);
          const diffs: string[] = [];
          if (diskItem.title !== initial.title) diffs.push("title");
          if (diskItem.username !== initial.username) diffs.push("username");
          if (diskItem.url !== initial.url) diffs.push("URL");
          if (diskItem.notes !== initial.notes) diffs.push("notes");
          if (diskItem.content !== initial.content) diffs.push("content");
          if (diskItem.folder_id !== initial.folder_id) diffs.push("folder");
          if (diskItem.favorite !== initial.favorite) diffs.push("favorite");
          if (diskItem.tags.join(",") !== initial.tags.join(",")) diffs.push("tags");

          if (diffs.length > 0) {
            conflictItem = diskItem;
            conflictFields = diffs;
            busy = false;
            return;
          }
        } catch (e) {
          const err = toCmdError(e);
          if (err.code === "ITEM_NOT_FOUND") {
            itemDeletedOnDisk = true;
            busy = false;
            return;
          }
          throw e;
        }
      }

      conflictItem = null;
      conflictFields = [];
      itemDeletedOnDisk = false;
      await onsave(buildDraft());
    } catch (err) {
      const cmdErr = toCmdError(err);
      if (cmdErr.code === "PASSWORD_REQUIRED") {
        requirePassword = true;
      }
      error = cmdErr;
      busy = false;
      await tick();
    }
  }

  function applyDiskVersion() {
    if (!conflictItem) return;
    title = conflictItem.title;
    username = conflictItem.username;
    url = conflictItem.url;
    notes = conflictItem.notes;
    content = conflictItem.content;
    tags = conflictItem.tags.join(", ");
    favorite = conflictItem.favorite;
    folderId = conflictItem.folder_id;
    password = "";
    passwordTouched = false;
    totp = "";
    totpTouched = false;
    conflictItem = null;
    conflictFields = [];
  }

  async function reloadAndDiscard() {
    busy = true;
    error = null;
    try {
      await reloadVault(requirePassword ? masterPassword : undefined);
      await onrefresh?.();
      oncancel();
    } catch (err) {
      const cmdErr = toCmdError(err);
      if (cmdErr.code === "PASSWORD_REQUIRED") {
        requirePassword = true;
      }
      error = cmdErr;
      busy = false;
    }
  }

  async function saveAsNew() {
    itemDeletedOnDisk = false;
    busy = true;
    error = null;
    try {
      await createItem(kind, buildDraft());
      await onrefresh?.();
      oncancel();
    } catch (err) {
      error = toCmdError(err);
      busy = false;
    }
  }

  onMount(() => titleInput?.focus());
</script>

<svelte:window onkeydown={(e) => e.key === "Escape" && !busy && oncancel()} />

<form class="flex min-h-0 min-w-0 flex-1 flex-col" onsubmit={submit} novalidate>
  <header class="flex h-12 shrink-0 items-center gap-2 border-b border-hairline px-4">
    <h2 class="flex-1 font-display text-[17px] font-bold text-zinc-50">
      {existing ? "Edit" : "New"} {isLogin ? "login" : "secure note"}
    </h2>
    <button type="button" onclick={oncancel} disabled={busy} class="key-steel h-8 px-2.5 text-xs">
      Cancel <kbd class="kbd">Esc</kbd>
    </button>
    <button
      type="submit"
      disabled={!canSave}
      class="key h-8 px-3.5 text-[11px]"
    >
      {#if busy}<LoaderCircle class="size-3.5 animate-spin" aria-hidden="true" />{/if}
      SAVE
    </button>
  </header>

  <div class="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto p-4">
    {#snippet label(id: string, text: string)}
      <label for={id} class="mb-1.5 block text-xs font-medium text-zinc-300">{text}</label>
    {/snippet}

    <div>
      {@render label("f-title", "Title")}
      <input
        id="f-title"
        bind:this={titleInput}
        bind:value={title}
        maxlength="256"
        class="well h-10 w-full px-3 text-sm text-zinc-100 outline-none"
        placeholder={isLogin ? "e.g. GitHub" : "e.g. Wi-Fi recovery codes"}
      />
    </div>

    {#if isLogin}
      <div>
        {@render label("f-username", "Username / e-mail")}
        <input
          id="f-username"
          bind:value={username}
          autocomplete="off"
          spellcheck="false"
          class="well h-10 w-full px-3 font-mono text-[13px] text-zinc-100 outline-none"
        />
      </div>

      <div>
        {#if passwordTouched}
          <PasswordField
            id="f-password"
            label="Password"
            autocomplete="new-password"
            placeholder="enter or generate a password"
            bind:value={password}
          />
        {:else}
          <span class="mb-1.5 block text-xs font-medium text-zinc-300">Password</span>
          <button
            type="button"
            onclick={() => (passwordTouched = true)}
            class="flex h-11 w-full items-center rounded-[5px] border border-dashed border-edge px-3 font-mono text-sm text-zinc-500 hover:border-zinc-600 hover:text-zinc-300"
          >
            •••••••••• <span class="ml-auto text-xs">unchanged · click to replace</span>
          </button>
        {/if}
        <button
          type="button"
          onclick={() => (showGenerator = !showGenerator)}
          aria-expanded={showGenerator}
          class="mt-2 flex items-center gap-1.5 text-xs text-ruby hover:text-zinc-100"
        >
          <Sparkles class="size-3.5" aria-hidden="true" /> {showGenerator ? "Hide generator" : "Generate password"}
        </button>
        {#if showGenerator}
          <div class="mt-2">
            <PasswordGenerator
              onuse={(p) => {
                password = p;
                passwordTouched = true;
                showGenerator = false;
              }}
            />
          </div>
        {/if}
      </div>

      <div>
        {@render label("f-url", "Website")}
        <input
          id="f-url"
          bind:value={url}
          spellcheck="false"
          placeholder="https://"
          class="well h-10 w-full px-3 font-mono text-[13px] text-zinc-100 outline-none"
        />
      </div>

      <div>
        {@render label("f-totp", "2FA secret (Base32 or otpauth:// link)")}
        {#if totpTouched}
          <input
            id="f-totp"
            bind:value={totp}
            spellcheck="false"
            autocomplete="off"
            placeholder={existing?.has_totp ? "leave empty to remove" : "optional"}
            class="well h-10 w-full px-3 font-mono text-[13px] text-zinc-100 outline-none"
          />
        {:else}
          <button
            id="f-totp"
            type="button"
            onclick={() => (totpTouched = true)}
            class="flex h-10 w-full items-center rounded-[5px] border border-dashed border-edge px-3 text-left text-sm text-zinc-500 hover:border-zinc-600 hover:text-zinc-300"
          >
            {existing?.has_totp ? "configured · click to replace or remove" : "none · click to add"}
          </button>
        {/if}
      </div>
    {:else}
      <div class="flex min-h-48 flex-1 flex-col">
        {@render label("f-content", "Note")}
        <textarea
          id="f-content"
          bind:value={content}
          spellcheck="false"
          class="well min-h-48 w-full flex-1 resize-none p-3 font-mono text-sm leading-6 text-zinc-100 outline-none"
        ></textarea>
      </div>
    {/if}

    <div>
      {@render label("f-notes", "Notes")}
      <textarea
        id="f-notes"
        bind:value={notes}
        rows="3"
        class="well w-full resize-y p-3 text-sm text-zinc-100 outline-none"
      ></textarea>
    </div>

    <div class="flex items-end gap-4">
      <div class="flex-1">
        {@render label("f-tags", "Tags (comma separated)")}
        <input
          id="f-tags"
          bind:value={tags}
          spellcheck="false"
          class="well h-10 w-full px-3 font-mono text-sm text-uv outline-none"
        />
      </div>
      <div>
        {@render label("f-folder", "Folder")}
        <select
          id="f-folder"
          bind:value={folderId}
          class="well h-10 px-2 text-sm text-zinc-100 outline-none"
        >
          <option value={null}>No folder</option>
          {#each folders as f (f.id)}
            <option value={f.id}>{f.name}</option>
          {/each}
        </select>
      </div>
      <label class="flex h-10 items-center gap-2 text-xs text-zinc-400">
        <input type="checkbox" bind:checked={favorite} class="accent-crimson" /> Favorite
      </label>
    </div>

    <div aria-live="polite" class="min-h-5 space-y-3">
      {#if error}
        <div class="rounded border border-danger/40 bg-danger/10 p-3 text-xs text-danger">
          <p class="flex items-start gap-1.5">
            <TriangleAlert class="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
            <span><span class="font-mono">[{error.code}]</span> {error.message}</span>
          </p>

          {#if error.code === "VAULT_CHANGED_ON_DISK" || error.code === "PASSWORD_REQUIRED"}
            <div class="mt-2.5 flex flex-col gap-2 border-t border-danger/20 pt-2.5">
              {#if requirePassword}
                <div>
                  <label for="f-reload-pw" class="mb-1 block text-[11px] font-medium text-zinc-300">
                    Master password changed on disk. Enter new master password to reload:
                  </label>
                  <input
                    id="f-reload-pw"
                    type="password"
                    bind:value={masterPassword}
                    placeholder="New master password"
                    class="well h-8 w-full px-2 text-xs text-zinc-100 outline-none"
                  />
                </div>
              {/if}

              <div class="flex items-center gap-2">
                <button
                  type="button"
                  disabled={busy || (requirePassword && !masterPassword)}
                  onclick={() => reloadAndReapply(false)}
                  class="key h-7 px-2.5 text-[11px]"
                >
                  {#if busy}<LoaderCircle class="size-3 animate-spin" aria-hidden="true" />{/if}
                  Reload & Save
                </button>
                <button
                  type="button"
                  disabled={busy}
                  onclick={reloadAndDiscard}
                  class="key-steel h-7 px-2 text-[11px]"
                >
                  Discard & Reload
                </button>
              </div>
            </div>
          {/if}
        </div>
      {/if}

      {#if conflictItem}
        <div class="rounded border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-200" role="alert">
          <p class="font-semibold text-amber-100">
            Conflict detected: this item was also modified on disk.
          </p>
          <p class="mt-1 text-[11px] text-zinc-300">
            Conflicting fields: <span class="font-mono text-amber-300">{conflictFields.join(", ")}</span>.
          </p>
          <div class="mt-2.5 flex items-center gap-2">
            <button
              type="button"
              disabled={busy}
              onclick={() => reloadAndReapply(true)}
              class="key h-7 px-2.5 text-[11px]"
            >
              Overwrite with my edits
            </button>
            <button
              type="button"
              disabled={busy}
              onclick={applyDiskVersion}
              class="key-steel h-7 px-2 text-[11px]"
            >
              Keep disk version
            </button>
          </div>
        </div>
      {/if}

      {#if itemDeletedOnDisk}
        <div class="rounded border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-200" role="alert">
          <p class="font-semibold text-amber-100">
            This item was deleted on disk by another program.
          </p>
          <div class="mt-2.5 flex items-center gap-2">
            <button
              type="button"
              disabled={busy}
              onclick={saveAsNew}
              class="key h-7 px-2.5 text-[11px]"
            >
              Save as new item
            </button>
            <button
              type="button"
              disabled={busy}
              onclick={oncancel}
              class="key-steel h-7 px-2 text-[11px]"
            >
              Discard
            </button>
          </div>
        </div>
      {/if}
    </div>
  </div>
</form>
