<script lang="ts">
  import { onMount } from "svelte";
  import { getCurrentWebview } from "@tauri-apps/api/webview";
  import { open } from "@tauri-apps/plugin-dialog";
  import { FileKey2, LoaderCircle, X } from "@lucide/svelte";
  import { formatBytes, inspectKeyfile, toCmdError, type CmdError, type KeyfileInfo } from "../tauri-bridge";

  // Attach an existing keyfile by OS drag-and-drop or the native picker.
  // Rust reads + hashes it immediately; only name/size come back.
  let {
    keyfile = $bindable(null),
    disabled = false,
    required = false,
    acceptDrop = true,
    onerror,
    onchange,
  }: {
    keyfile?: { path: string; info: KeyfileInfo } | null;
    disabled?: boolean;
    required?: boolean;
    /** Only one visible picker should claim OS file drops. */
    acceptDrop?: boolean;
    onerror?: (e: CmdError | null) => void;
    onchange?: () => void;
  } = $props();

  let busy = $state(false);
  let dragging = $state(false);

  async function attach(path: string) {
    busy = true;
    onerror?.(null);
    try {
      keyfile = { path, info: await inspectKeyfile(path) };
    } catch (e) {
      keyfile = null;
      onerror?.(toCmdError(e));
    } finally {
      busy = false;
      onchange?.();
    }
  }

  async function browse() {
    const picked = await open({ multiple: false, directory: false, title: "Select keyfile" });
    if (typeof picked === "string") await attach(picked);
  }

  function detach() {
    keyfile = null;
    onerror?.(null);
    onchange?.();
  }

  onMount(() => {
    // Tauri intercepts OS file drops; HTML5 drop events never carry paths.
    const unlisten = getCurrentWebview().onDragDropEvent((event) => {
      if (disabled || !acceptDrop) return;
      const p = event.payload;
      if (p.type === "enter" || p.type === "over") dragging = true;
      else if (p.type === "leave") dragging = false;
      else if (p.type === "drop") {
        dragging = false;
        const first = p.paths[0];
        if (first) void attach(first);
      }
    });
    return () => void unlisten.then((f) => f());
  });
</script>

{#if keyfile}
  <div class="flex h-14 items-center gap-2.5 rounded-lg border border-tactical/40 bg-tactical/5 px-3">
    <FileKey2 class="size-4 shrink-0 text-tactical" aria-hidden="true" />
    <div class="min-w-0 flex-1 font-mono text-xs">
      <p class="truncate text-tactical" title={keyfile.path}>[KEYFILE ATTACHED: {keyfile.info.file_name}]</p>
      <p class="text-zinc-500">{formatBytes(keyfile.info.size_bytes)} · read &amp; hashed (SHA-256)</p>
    </div>
    <button
      type="button"
      onclick={detach}
      {disabled}
      class="grid size-8 place-items-center rounded-md text-zinc-500 hover:bg-hairline hover:text-zinc-200 focus-visible:outline-2 focus-visible:outline-tactical"
      aria-label="Remove keyfile"
    >
      <X class="size-4" />
    </button>
  </div>
{:else}
  <button
    type="button"
    onclick={browse}
    disabled={disabled || busy}
    class="flex h-14 w-full items-center justify-center gap-2 rounded-lg border border-dashed px-3 text-xs transition
      focus-visible:outline-2 focus-visible:outline-tactical
      {dragging
      ? 'border-tactical bg-tactical/10 text-tactical'
      : required
        ? 'border-amber-400/40 text-zinc-300 hover:border-amber-300/60'
        : 'border-hairline text-zinc-400 hover:border-zinc-600 hover:text-zinc-200'}"
  >
    {#if busy}
      <LoaderCircle class="size-4 animate-spin" aria-hidden="true" /> Reading keyfile…
    {:else if dragging}
      <FileKey2 class="size-4" aria-hidden="true" /> Drop to attach keyfile
    {:else}
      <FileKey2 class="size-4" aria-hidden="true" /> Drop keyfile here or
      <span class="text-zinc-200 underline decoration-zinc-600 underline-offset-2">browse</span>
    {/if}
  </button>
{/if}
