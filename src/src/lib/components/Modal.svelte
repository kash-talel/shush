<script lang="ts">
  import type { Snippet } from "svelte";
  import { X } from "@lucide/svelte";

  // Native <dialog>: focus trap, Esc to close and inert background for free.
  let {
    title,
    hazard = false,
    busy = false,
    onclose,
    children,
  }: {
    title: string;
    /** Destructive dialogs carry the hazard stripe. */
    hazard?: boolean;
    /** While true, Esc and the close button do nothing. */
    busy?: boolean;
    onclose: () => void;
    children: Snippet;
  } = $props();

  function show(d: HTMLDialogElement) {
    d.showModal();
    return () => d.close();
  }
</script>

<dialog
  {@attach show}
  aria-labelledby="modal-title"
  class="acrylic m-auto w-[min(440px,calc(100vw-32px))] rounded-[6px] p-0 text-zinc-200 backdrop:bg-black/70 backdrop:backdrop-blur-[2px]"
  oncancel={(e) => {
    e.preventDefault();
    if (!busy) onclose();
  }}
>
  {#if hazard}<div class="hazard h-1.5 rounded-t-[6px]" aria-hidden="true"></div>{/if}
  <div class="flex items-center justify-between px-5 pt-4">
    <h2 id="modal-title" class="font-display text-[19px] font-bold tracking-[-0.01em] text-zinc-50">{title}</h2>
    <button type="button" onclick={onclose} disabled={busy} class="rounded p-1 text-zinc-500 hover:text-zinc-200" aria-label="Close">
      <X class="size-4" aria-hidden="true" />
    </button>
  </div>
  <div class="px-5 pt-3 pb-5">
    {@render children()}
  </div>
</dialog>
