<script lang="ts">
  import { onMount, tick } from "svelte";
  import { LoaderCircle, Sparkles, TriangleAlert } from "@lucide/svelte";
  import PasswordField from "./PasswordField.svelte";
  import PasswordGenerator from "./PasswordGenerator.svelte";
  import { toCmdError, type CmdError, type FolderInfo, type ItemDetail, type ItemDraft, type ItemKind } from "../tauri-bridge";

  // Create / edit form. Secrets follow "keep unless changed": when editing,
  // the existing password and TOTP secret are never loaded into the UI.
  let {
    kind,
    existing = null,
    folders = [],
    defaultFolderId = null,
    onsave,
    oncancel,
  }: {
    kind: ItemKind;
    existing?: ItemDetail | null;
    folders?: FolderInfo[];
    defaultFolderId?: string | null;
    onsave: (draft: ItemDraft) => Promise<void>;
    oncancel: () => void;
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

  const isLogin = $derived(kind === "login");
  const canSave = $derived(!busy && title.trim().length > 0);

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    if (!canSave) return;
    busy = true;
    error = null;
    try {
      await onsave({
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
      });
    } catch (err) {
      error = toCmdError(err);
      busy = false;
      await tick();
    }
  }

  onMount(() => titleInput?.focus());
</script>

<svelte:window onkeydown={(e) => e.key === "Escape" && !busy && oncancel()} />

<form class="flex min-h-0 min-w-0 flex-1 flex-col" onsubmit={submit} novalidate>
  <header class="flex h-12 shrink-0 items-center gap-2 border-b border-hairline px-4">
    <h2 class="flex-1 font-mono text-xs tracking-[0.15em] text-zinc-400">
      // {existing ? "EDIT" : "NEW"}_{isLogin ? "LOGIN" : "SECURE_NOTE"}
    </h2>
    <button type="button" onclick={oncancel} disabled={busy} class="h-8 rounded-md px-3 text-xs text-zinc-400 hover:bg-hairline">
      Cancel <kbd class="ml-1 font-mono text-[10px] text-zinc-600">ESC</kbd>
    </button>
    <button
      type="submit"
      disabled={!canSave}
      class="flex h-8 items-center gap-1.5 rounded-md bg-tactical px-3 font-mono text-xs font-semibold tracking-wider text-obsidian hover:bg-emerald-400 disabled:bg-hairline disabled:text-zinc-500"
    >
      {#if busy}<LoaderCircle class="size-3.5 animate-spin" aria-hidden="true" />{/if}
      SAVE
    </button>
  </header>

  <div class="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto p-4">
    {#snippet label(id: string, text: string)}
      <label for={id} class="mb-1.5 block text-xs font-medium text-zinc-400">{text}</label>
    {/snippet}

    <div>
      {@render label("f-title", "Title")}
      <input
        id="f-title"
        bind:this={titleInput}
        bind:value={title}
        maxlength="256"
        class="h-10 w-full rounded-lg border border-hairline bg-surface px-3 text-sm text-zinc-100 outline-none focus:border-tactical/60"
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
          class="h-10 w-full rounded-lg border border-hairline bg-surface px-3 font-mono text-sm text-zinc-100 outline-none focus:border-tactical/60"
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
          <span class="mb-1.5 block text-xs font-medium text-zinc-400">Password</span>
          <button
            type="button"
            onclick={() => (passwordTouched = true)}
            class="flex h-11 w-full items-center rounded-lg border border-dashed border-hairline px-3 font-mono text-sm text-zinc-500 hover:border-zinc-600 hover:text-zinc-300"
          >
            •••••••••• <span class="ml-auto text-xs">unchanged · click to replace</span>
          </button>
        {/if}
        <button
          type="button"
          onclick={() => (showGenerator = !showGenerator)}
          aria-expanded={showGenerator}
          class="mt-2 flex items-center gap-1.5 text-xs text-tactical hover:text-emerald-300"
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
          class="h-10 w-full rounded-lg border border-hairline bg-surface px-3 font-mono text-sm text-zinc-100 outline-none focus:border-tactical/60"
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
            class="h-10 w-full rounded-lg border border-hairline bg-surface px-3 font-mono text-sm text-zinc-100 outline-none focus:border-tactical/60"
          />
        {:else}
          <button
            id="f-totp"
            type="button"
            onclick={() => (totpTouched = true)}
            class="flex h-10 w-full items-center rounded-lg border border-dashed border-hairline px-3 text-left text-sm text-zinc-500 hover:border-zinc-600 hover:text-zinc-300"
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
          class="min-h-48 w-full flex-1 resize-none rounded-lg border border-hairline bg-surface p-3 font-mono text-sm leading-6 text-zinc-100 outline-none focus:border-tactical/60"
        ></textarea>
      </div>
    {/if}

    <div>
      {@render label("f-notes", "Notes")}
      <textarea
        id="f-notes"
        bind:value={notes}
        rows="3"
        class="w-full resize-y rounded-lg border border-hairline bg-surface p-3 text-sm text-zinc-100 outline-none focus:border-tactical/60"
      ></textarea>
    </div>

    <div class="flex items-end gap-4">
      <div class="flex-1">
        {@render label("f-tags", "Tags (comma separated)")}
        <input
          id="f-tags"
          bind:value={tags}
          spellcheck="false"
          class="h-10 w-full rounded-lg border border-hairline bg-surface px-3 font-mono text-sm text-cold outline-none focus:border-tactical/60"
        />
      </div>
      <div>
        {@render label("f-folder", "Folder")}
        <select
          id="f-folder"
          bind:value={folderId}
          class="h-10 rounded-lg border border-hairline bg-surface px-2 text-sm text-zinc-100 outline-none focus:border-tactical/60"
        >
          <option value={null}>No folder</option>
          {#each folders as f (f.id)}
            <option value={f.id}>{f.name}</option>
          {/each}
        </select>
      </div>
      <label class="flex h-10 items-center gap-2 text-xs text-zinc-400">
        <input type="checkbox" bind:checked={favorite} class="accent-emerald-500" /> Favorite
      </label>
    </div>

    <div aria-live="polite" class="min-h-5">
      {#if error}
        <p class="flex items-start gap-1.5 text-xs text-danger">
          <TriangleAlert class="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
          <span><span class="font-mono">[{error.code}]</span> {error.message}</span>
        </p>
      {/if}
    </div>
  </div>
</form>
