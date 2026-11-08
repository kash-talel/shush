<script lang="ts">
  import { onMount } from "svelte";
  import { Eye, EyeOff, FolderOpen, Pencil, Plus, Trash2 } from "@lucide/svelte";
  import Spindle from "./Spindle.svelte";
  import VaultFormDialog from "./VaultFormDialog.svelte";
  import DeleteVaultDialog from "./DeleteVaultDialog.svelte";
  import { vaultColor } from "../vault-colors";
  import {
    listVaults,
    selectVault,
    setHideVaultNames,
    toCmdError,
    vaultStatus,
    type CmdError,
    type NewVaultTarget,
    type VaultList,
    type VaultStatus,
  } from "../tauri-bridge";

  // The rack under the sealed case: every known vault as a small jewel case in
  // its own disc colour, plus the vault-list actions. Shown only while locked.
  let {
    current,
    onswitch,
    onnew,
  }: {
    /** The vault the big case shows. */
    current: VaultStatus;
    /** The shown vault changed (switched, edited, deleted). */
    onswitch: (s: VaultStatus) => void;
    /** "New vault": go set the password for this target. */
    onnew: (t: NewVaultTarget) => void;
  } = $props();

  let list = $state.raw<VaultList | null>(null);
  let dialog = $state<"new" | "existing" | "edit" | "delete" | null>(null);
  let error = $state<CmdError | null>(null);

  const selected = $derived(list?.vaults.find((v) => v.id === current.id) ?? null);
  const showRack = $derived((list?.vaults.length ?? 0) > 1);

  async function reload() {
    list = await listVaults();
  }

  async function pick(id: string) {
    if (id === current.id) return;
    error = null;
    try {
      onswitch(await selectVault(id));
    } catch (e) {
      error = toCmdError(e);
    }
  }

  async function changed() {
    dialog = null;
    await reload();
    onswitch(await vaultStatus());
  }

  async function toggleHideNames() {
    if (!list) return;
    error = null;
    try {
      const next = !list.hide_names;
      const status = await setHideVaultNames(next);
      await reload();
      onswitch(status);
    } catch (e) {
      error = toCmdError(e);
    }
  }

  onMount(reload);
</script>

{#if list}
  <div class="flex w-full flex-col items-center gap-3">
    {#if showRack}
      <div class="rack" role="radiogroup" aria-label="Vaults">
        {#each list.vaults as v (v.id)}
          {@const on = v.id === current.id}
          <button
            type="button"
            role="radio"
            aria-checked={on}
            aria-label={list.hide_names ? `Vault (${v.color})` : v.name}
            title={list.hide_names ? `Vault (${v.color})` : (v.error ? `${v.name}: ${v.error.message}` : v.path)}
            onclick={() => pick(v.id)}
            class={["slot", on && "on", !v.exists && "missing"]}
            style:--glow={vaultColor(v.color).glow}
            {@attach (el) => {
              if (on) el.scrollIntoView({ block: "nearest", inline: "center" });
            }}
          >
            <Spindle size={56} spin="off" color={v.color} />
            {#if !list.hide_names}
              <span class="max-w-[84px] truncate text-[11px] leading-4">{v.name}</span>
            {/if}
          </button>
        {/each}
        <button type="button" class="slot add" onclick={() => (dialog = "new")} title="New vault">
          <span class="grid size-14 place-items-center rounded-[4px] border border-dashed border-edge">
            <Plus class="size-4" aria-hidden="true" />
          </span>
          {#if !list.hide_names}
            <span class="text-[11px] leading-4">New</span>
          {/if}
        </button>
      </div>
    {/if}

    <div class="flex flex-wrap items-center justify-center gap-x-1 gap-y-1">
      {#if !showRack}
        <button type="button" class="act" onclick={() => (dialog = "new")}><Plus aria-hidden="true" /> New vault</button>
      {/if}
      <button type="button" class="act" onclick={() => (dialog = "existing")}><FolderOpen aria-hidden="true" /> Open vault file</button>
      {#if selected}
        <button type="button" class="act" onclick={() => (dialog = "edit")}><Pencil aria-hidden="true" /> Edit</button>
        {#if selected.exists && !selected.error}
          <button type="button" class="act hazardous" onclick={() => (dialog = "delete")}><Trash2 aria-hidden="true" /> Delete</button>
        {/if}
      {/if}
      <button
        type="button"
        class="act"
        onclick={toggleHideNames}
        title={list.hide_names ? "Show vault names and paths on lock screen" : "Hide vault names and paths on lock screen"}
      >
        {#if list.hide_names}
          <Eye aria-hidden="true" /> Show names
        {:else}
          <EyeOff aria-hidden="true" /> Hide names
        {/if}
      </button>
    </div>

    {#if error}
      <p class="text-xs text-danger" role="alert"><span class="font-mono">[{error.code}]</span> {error.message}</p>
    {/if}
  </div>

  {#if dialog === "new" || dialog === "existing"}
    <VaultFormDialog
      mode={dialog}
      {list}
      onclose={() => (dialog = null)}
      onnew={(t) => {
        dialog = null;
        onnew(t);
      }}
      onadded={async (s) => {
        dialog = null;
        await reload();
        onswitch(s);
      }}
    />
  {:else if dialog === "edit" && selected}
    <VaultFormDialog mode="edit" {list} vault={selected} onclose={() => (dialog = null)} onchanged={changed} />
  {:else if dialog === "delete" && selected}
    <DeleteVaultDialog vault={selected} onclose={() => (dialog = null)} ondeleted={changed} />
  {/if}
{/if}

<style>
  /* One strip; scrolls sideways past five cases instead of wrapping. */
  .rack {
    display: flex;
    gap: 2px;
    max-width: 100%;
    overflow-x: auto;
    scrollbar-width: thin;
    scrollbar-color: var(--color-edge) transparent;
    padding: 10px 8px 6px;
    border-radius: 6px;
    border: 1px solid var(--color-hairline);
    background: linear-gradient(180deg, rgb(255 255 255 / 0.02), transparent), #09090e;
    box-shadow: inset 0 1px 3px rgb(0 0 0 / 0.7);
  }
  .slot {
    flex: none;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 6px;
    padding: 4px 6px 2px;
    border-radius: 4px;
    color: #8a8a96;
    opacity: 0.72;
    transition:
      opacity 160ms,
      color 160ms,
      translate 160ms;
  }
  .slot:hover {
    opacity: 1;
    color: #e4e4e7;
    translate: 0 -2px;
  }
  /* The shown vault: full brightness and an LED in its disc colour. */
  .slot.on {
    opacity: 1;
    color: #fafafa;
    box-shadow: inset 0 -2px 0 rgb(var(--glow));
  }
  .slot.missing {
    filter: grayscale(1);
  }
  .slot.add {
    opacity: 0.8;
  }
  .act {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    height: 26px;
    padding: 0 8px;
    border-radius: 3px;
    font-size: 11.5px;
    color: #8a8a96;
    transition:
      color 120ms,
      background-color 120ms;
  }
  .act :global(svg) {
    width: 13px;
    height: 13px;
  }
  .act:hover {
    color: #f4f4f5;
    background: rgb(255 255 255 / 0.04);
  }
  .act.hazardous:hover {
    color: var(--color-danger);
  }
  @media (prefers-reduced-motion: reduce) {
    .slot:hover {
      translate: none;
    }
  }
</style>
