<script lang="ts">
  import { Eye, EyeOff, TriangleAlert } from "@lucide/svelte";

  // Shared master-password input: terminal prompt glyph, reveal toggle,
  // Caps Lock warning, error state. Used by Unlock and Create screens.
  let {
    id,
    label,
    value = $bindable(""),
    invalid = false,
    disabled = false,
    autocomplete = "current-password",
    placeholder = "enter master password",
    describedby,
    input = $bindable(),
    oninput,
  }: {
    id: string;
    label: string;
    value?: string;
    invalid?: boolean;
    disabled?: boolean;
    autocomplete?: "current-password" | "new-password";
    placeholder?: string;
    describedby?: string;
    input?: HTMLInputElement;
    oninput?: () => void;
  } = $props();

  let reveal = $state(false);
  let capsLock = $state(false);

  function trackCapsLock(e: KeyboardEvent) {
    capsLock = e.getModifierState?.("CapsLock") ?? false;
  }
</script>

<div>
  <label for={id} class="mb-1.5 block text-xs font-medium text-zinc-400">{label}</label>
  <div
    class="flex items-center rounded-lg border bg-surface transition
      {invalid
      ? 'border-danger/70 focus-within:shadow-[0_0_0_3px_rgb(239_68_68/0.14)]'
      : 'border-hairline focus-within:border-tactical/60 focus-within:shadow-[0_0_0_3px_rgb(16_185_129/0.12)]'}"
  >
    <span class="pl-3 font-mono text-sm text-tactical/70 select-none" aria-hidden="true">&gt;</span>
    <input
      {id}
      bind:this={input}
      bind:value
      type={reveal ? "text" : "password"}
      {autocomplete}
      spellcheck="false"
      {disabled}
      aria-invalid={invalid ? "true" : undefined}
      aria-describedby={describedby}
      onkeydown={trackCapsLock}
      onkeyup={trackCapsLock}
      {oninput}
      class="h-11 min-w-0 flex-1 bg-transparent px-2.5 font-mono text-sm tracking-wide text-zinc-100 outline-none placeholder:text-zinc-600 disabled:opacity-60"
      {placeholder}
    />
    <button
      type="button"
      class="mr-1 grid size-9 place-items-center rounded-md text-zinc-500 transition hover:bg-hairline hover:text-zinc-200 focus-visible:outline-2 focus-visible:outline-tactical"
      onclick={() => (reveal = !reveal)}
      aria-label={reveal ? "Hide password" : "Show password"}
      aria-pressed={reveal}
    >
      {#if reveal}<EyeOff class="size-4" />{:else}<Eye class="size-4" />{/if}
    </button>
  </div>
  {#if capsLock}
    <p class="mt-1.5 flex items-center gap-1.5 text-xs text-amber-400">
      <TriangleAlert class="size-3.5" aria-hidden="true" /> Caps Lock is on
    </p>
  {/if}
</div>
