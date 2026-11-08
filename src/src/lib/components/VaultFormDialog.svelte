<script lang="ts">
  import { untrack } from "svelte";
  import { open, save } from "@tauri-apps/plugin-dialog";
  import { FolderOpen, LoaderCircle, TriangleAlert } from "@lucide/svelte";
  import Modal from "./Modal.svelte";
  import {
    addExistingVault,
    checkNewVault,
    forgetVault,
    splitPath,
    toCmdError,
    updateVault,
    type CmdError,
    type NewVaultTarget,
    type VaultCard,
    type VaultColor,
    type VaultList,
    type VaultStatus,
  } from "../tauri-bridge";
  import { VAULT_COLORS } from "../vault-colors";

  // One form for the three non-destructive vault-list actions:
  // "new" picks a name, colour and location, then hands over to the create
  // screen; "existing" adds a .shush file from elsewhere; "edit" renames,
  // recolours or removes a vault from the list (its file is kept).
  type Mode = "new" | "existing" | "edit";
  let {
    mode,
    list,
    vault = null,
    onclose,
    onnew,
    onadded,
    onchanged,
  }: {
    mode: Mode;
    list: VaultList;
    /** The vault being edited ("edit" mode). */
    vault?: VaultCard | null;
    onclose: () => void;
    /** "new": location and name are valid; set the password next. */
    onnew?: (t: NewVaultTarget) => void;
    /** "existing": the vault was added and selected. */
    onadded?: (s: VaultStatus) => void;
    /** "edit": renamed, recoloured or removed. */
    onchanged?: () => void;
  } = $props();

  // Seeded once when the dialog opens. A new vault gets the first colour no
  // vault uses yet, like the backend picks.
  let name = $state(untrack(() => vault?.name ?? ""));
  let color = $state<VaultColor>(
    untrack(() => vault?.color ?? list.colors.find((c) => !list.vaults.some((v) => v.color === c)) ?? list.colors[0] ?? "crimson"),
  );
  let path = $state<string | null>(null);
  let busy = $state(false);
  let error = $state<CmdError | null>(null);
  let confirmForget = $state(false);

  const title = $derived(mode === "new" ? "New vault" : mode === "existing" ? "Open a vault file" : "Edit vault");
  const nameTaken = $derived(
    list.vaults.some((v) => v.id !== vault?.id && v.name.toLowerCase() === name.trim().toLowerCase()),
  );
  const canSubmit = $derived(
    !busy && name.trim().length > 0 && !nameTaken && (mode === "edit" || path !== null),
  );
  // The default vault keeps showing while its file exists, so it cannot be removed.
  const canForget = $derived(mode === "edit" && vault !== null && !(vault.is_default && vault.exists));

  async function pick() {
    error = null;
    if (mode === "new") {
      const picked = await save({
        title: "Where to save the new vault",
        defaultPath: `${name.trim() || "vault"}.shush`,
        filters: [{ name: "shush vault", extensions: ["shush"] }],
      });
      if (picked) path = picked;
    } else {
      const picked = await open({
        title: "Open a shush vault",
        multiple: false,
        directory: false,
        filters: [{ name: "shush vault", extensions: ["shush"] }],
      });
      if (typeof picked === "string") {
        path = picked;
        if (!name.trim()) name = splitPath(picked)[1].replace(/\.shush$/i, "");
      }
    }
  }

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (!canSubmit) return;
    busy = true;
    error = null;
    try {
      if (mode === "new" && path) {
        const final = await checkNewVault(path, name);
        onnew?.({ path: final, name: name.trim(), color });
      } else if (mode === "existing" && path) {
        onadded?.(await addExistingVault(path, name, color));
      } else if (mode === "edit" && vault) {
        await updateVault(vault.id, name, color);
        onchanged?.();
      }
    } catch (e) {
      error = toCmdError(e);
    } finally {
      busy = false;
    }
  }

  async function forget() {
    if (!vault) return;
    if (!confirmForget) {
      confirmForget = true;
      return;
    }
    busy = true;
    try {
      await forgetVault(vault.id);
      onchanged?.();
    } catch (e) {
      error = toCmdError(e);
    } finally {
      busy = false;
    }
  }
</script>

<Modal {title} {busy} {onclose}>
  <form class="flex flex-col gap-4" onsubmit={submit} novalidate>
    <label class="flex flex-col gap-1.5 text-xs font-medium text-zinc-300">
      Name
      <input
        bind:value={name}
        maxlength={list.max_name_chars}
        placeholder="Work, Family, USB…"
        disabled={busy}
        aria-invalid={nameTaken}
        oninput={() => (error = null)}
        class="well h-10 px-3 text-[13px] font-normal text-zinc-50 placeholder:text-zinc-600"
      />
      {#if nameTaken}<span class="text-[11px] font-normal text-danger">Another vault already has this name.</span>{/if}
    </label>

    <fieldset class="min-w-0">
      <legend class="mb-1.5 text-xs font-medium text-zinc-300">Disc colour</legend>
      <div class="flex flex-wrap gap-2" role="radiogroup" aria-label="Disc colour">
        {#each list.colors as c (c)}
          <button
            type="button"
            role="radio"
            aria-checked={color === c}
            aria-label={VAULT_COLORS[c].label}
            title={VAULT_COLORS[c].label}
            disabled={busy}
            onclick={() => (color = c)}
            class={["swatch", color === c && "on"]}
            style:--glow={VAULT_COLORS[c].glow}
          >
            <img src={VAULT_COLORS[c].disc} alt="" draggable="false" />
          </button>
        {/each}
      </div>
    </fieldset>

    {#if mode === "edit" && vault}
      {@const [dir, file] = splitPath(vault.path)}
      <p class="flex max-w-full font-mono text-[10.5px] text-zinc-500" title={vault.path}>
        <span class="truncate">{dir}</span><span class="shrink-0 text-zinc-300">{file}</span>
      </p>
    {:else}
      <div>
        <span class="mb-1.5 block text-xs font-medium text-zinc-300">{mode === "new" ? "Location" : "Vault file"}</span>
        <button
          type="button"
          onclick={pick}
          disabled={busy}
          class={[
            "flex min-h-11 w-full items-center gap-2.5 rounded-[4px] border px-3 py-2 text-left text-xs transition",
            path ? "border-edge bg-surface" : "border-dashed border-edge text-zinc-400 hover:border-zinc-500 hover:text-zinc-200",
          ]}
        >
          <FolderOpen class="size-4 shrink-0" aria-hidden="true" />
          {#if path}
            {@const [dir, file] = splitPath(path)}
            <span class="flex min-w-0 flex-1 font-mono text-[11px]" title={path}>
              <span class="truncate text-zinc-500">{dir}</span><span class="shrink-0 text-zinc-100">{file}</span>
            </span>
          {:else if mode === "new"}
            Choose a folder and file name. A USB drive works too.
          {:else}
            Choose a .shush file
          {/if}
        </button>
        {#if mode === "new"}
          <p class="mt-1.5 text-[11px] leading-4 text-zinc-500">You set its master password on the next screen.</p>
        {/if}
      </div>
    {/if}

    {#if error}
      <p class="flex items-start gap-1.5 text-xs leading-5 text-danger" role="alert">
        <TriangleAlert class="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
        <span><span class="font-mono">[{error.code}]</span> {error.message}</span>
      </p>
    {/if}

    <div class="flex items-center gap-2 pt-1">
      {#if canForget}
        <button
          type="button"
          onclick={forget}
          disabled={busy}
          class={["key-steel h-10 px-3 text-xs", confirmForget && "border-caution/60! text-caution!"]}
        >
          {confirmForget ? "Click again to remove" : "Remove from list"}
        </button>
      {/if}
      <button type="submit" disabled={!canSubmit} class="key ml-auto h-10 px-4 text-[12px]">
        {#if busy}<LoaderCircle class="size-4 animate-spin" aria-hidden="true" />{/if}
        {mode === "new" ? "SET PASSWORD" : mode === "existing" ? "ADD VAULT" : "SAVE"}
      </button>
    </div>
    {#if confirmForget}
      <p class="-mt-2 text-[11px] leading-4 text-zinc-500">
        The vault file stays where it is. You can add it again with Open vault file.
      </p>
    {/if}
  </form>
</Modal>

<style>
  .swatch {
    width: 34px;
    height: 34px;
    padding: 2px;
    border-radius: 9999px;
    border: 1px solid var(--color-hairline);
    background: #09090e;
    transition:
      border-color 120ms,
      box-shadow 120ms;
  }
  .swatch img {
    width: 100%;
    height: 100%;
    border-radius: 9999px;
  }
  .swatch:hover:not(:disabled) {
    border-color: var(--color-edge);
  }
  .swatch.on {
    border-color: rgb(var(--glow));
    box-shadow: 0 0 0 2px rgb(var(--glow) / 0.35), 0 0 14px rgb(var(--glow) / 0.45);
  }
</style>
