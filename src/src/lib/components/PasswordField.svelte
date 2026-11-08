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
  <label for={id} class="mb-1.5 block text-xs font-medium text-zinc-300">{label}</label>
  <div class={["well flex items-center", invalid && "invalid"]}>
    <span class="pl-3 font-mono text-sm text-ruby select-none" aria-hidden="true">›</span>
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
      class="h-11 min-w-0 flex-1 bg-transparent px-2.5 font-mono text-[13px] tracking-wide text-zinc-50 caret-ruby outline-none placeholder:text-zinc-600 disabled:opacity-60"
      {placeholder}
    />
    <button
      type="button"
      class="mr-1 grid size-9 place-items-center rounded-[3px] text-zinc-500 transition hover:bg-raised hover:text-zinc-100"
      onclick={() => (reveal = !reveal)}
      aria-label={reveal ? "Hide password" : "Show password"}
      aria-pressed={reveal}
    >
      {#if reveal}<EyeOff class="size-4" />{:else}<Eye class="size-4" />{/if}
    </button>
  </div>
  {#if capsLock}
    <p class="mt-1.5 flex items-center gap-1.5 text-xs text-caution">
      <TriangleAlert class="size-3.5" aria-hidden="true" /> Caps Lock is on
    </p>
  {/if}
</div>
