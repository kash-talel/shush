<script lang="ts">
  import disc from "../assets/disc.png";

  // The brand disc seated in an acrylic tray. It idles slowly and spins up
  // while Argon2id derives the key, like a drive reading the vault.
  let { spinning = false, size = 168 }: { spinning?: boolean; size?: number } = $props();

  // Change speed without restarting the rotation, so the disc never jumps.
  function drive(node: HTMLImageElement) {
    const rate = spinning ? 34 : 1;
    for (const a of node.getAnimations()) a.updatePlaybackRate(rate);
  }
</script>

<div class="tray" style:--size="{size}px" aria-hidden="true">
  <img src={disc} alt="" class={["disc", spinning && "fast"]} draggable="false" {@attach drive} />
  <span class="glint"></span>
</div>

<style>
  .tray {
    position: relative;
    width: var(--size);
    height: var(--size);
    border-radius: 14px;
    padding: 9px;
    /* Smoked acrylic case: ultraviolet edge light on top, crimson bleed below. */
    background:
      linear-gradient(135deg, rgb(255 255 255 / 0.07), transparent 38%),
      rgb(12 12 18 / 0.9);
    border: 1px solid rgb(255 255 255 / 0.08);
    box-shadow:
      inset 0 1px 0 rgb(192 132 252 / 0.35),
      inset 0 0 0 1px rgb(0 0 0 / 0.6),
      0 30px 60px -30px rgb(225 29 72 / 0.55),
      0 18px 40px -20px rgb(0 0 0 / 0.95);
  }
  .disc {
    display: block;
    width: 100%;
    height: 100%;
    border-radius: 50%;
    filter: drop-shadow(0 6px 14px rgb(0 0 0 / 0.8));
    animation: spin 24s linear infinite;
  }
  .disc.fast {
    filter: drop-shadow(0 6px 14px rgb(0 0 0 / 0.8)) drop-shadow(0 0 18px rgb(225 29 72 / 0.45));
  }
  /* Crystal lid reflection sweeping over the disc. */
  .glint {
    position: absolute;
    inset: 0;
    border-radius: inherit;
    background: linear-gradient(118deg, rgb(255 255 255 / 0.14) 0%, transparent 30%, transparent 64%, rgb(192 132 252 / 0.08) 78%, transparent 92%);
    pointer-events: none;
  }
  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
  @media (prefers-reduced-motion: reduce) {
    .disc,
    .disc.fast {
      animation: none;
    }
  }
</style>
