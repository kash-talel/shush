<script lang="ts">
  import tray from "../assets/case-tray.png";
  import lid from "../assets/case-lid.png";
  import { vaultColor } from "../vault-colors";

  // The shush jewel case, built from the same three layers as the website:
  // back tray, the embroidered disc, and the crystal lid hinged on the left.
  // `open` swings the lid; `spin` drives the disc (off / idle / fast while
  // Argon2id runs); `shudder` plays the failed-unlock shake and crimson flash.
  type Spin = "off" | "idle" | "fast";
  let {
    open = false,
    spin = "idle",
    size = 168,
    shudder = false,
    color = "crimson",
    id,
    label,
    expanded,
    controls,
    element = $bindable(),
    onclick,
    onshudderend,
  }: {
    open?: boolean;
    spin?: Spin;
    /** px, or any CSS length such as clamp(…) */
    size?: number | string;
    shudder?: boolean;
    /** Vault disc colour (see vault-colors.ts). */
    color?: string;
    id?: string;
    /** Accessible name; only used when the case is clickable. */
    label?: string;
    expanded?: boolean;
    controls?: string;
    element?: HTMLElement;
    onclick?: () => void;
    onshudderend?: () => void;
  } = $props();

  const tint = $derived(vaultColor(color));

  // 1 = 18 s per turn. With Windows animation effects off (prefers-reduced-motion)
  // the disc only turns while the key is derived, where it is the progress indicator.
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const RATE: Record<Spin, number> = reduce ? { off: 0, idle: 0, fast: 30 } : { off: 0, idle: 1, fast: 30 };

  // The rotation is a Web Animation whose playbackRate is eased toward the
  // target, so the disc spins up and winds down instead of jumping speed.
  let anim: Animation | null = null;
  let rate = 0;
  let target = 0;
  let frame = 0;

  function drive() {
    cancelAnimationFrame(frame);
    const step = () => {
      if (!anim) return;
      // Spin-up is a little quicker than the wind-down.
      rate += (target - rate) * (target > rate ? 0.05 : 0.03);
      if (Math.abs(target - rate) < 0.005) rate = target;
      anim.playbackRate = rate; // keeps the current angle
      if (rate !== target) frame = requestAnimationFrame(step);
    };
    frame = requestAnimationFrame(step);
  }

  function motor(img: HTMLImageElement) {
    anim = img.animate([{ transform: "rotate(0deg)" }, { transform: "rotate(360deg)" }], {
      duration: 18000,
      iterations: Infinity,
    });
    anim.playbackRate = rate;
    drive();
    return () => {
      cancelAnimationFrame(frame);
      anim?.cancel();
      anim = null;
    };
  }

  // Sync the external animation with the `spin` prop.
  $effect(() => {
    target = RATE[spin];
    drive();
  });
</script>

<svelte:element
  this={onclick ? "button" : "div"}
  bind:this={element}
  {id}
  type={onclick ? "button" : undefined}
  aria-label={onclick ? label : undefined}
  aria-hidden={onclick ? undefined : "true"}
  aria-expanded={onclick ? expanded : undefined}
  aria-controls={onclick ? controls : undefined}
  class={["stage", onclick && "interactive", open ? "open" : "sealed", shudder && "shudder"]}
  style:--size={typeof size === "number" ? `${size}px` : size}
  style:--tray="url({tray})"
  style:--lid="url({lid})"
  style:--glow={tint.glow}
  {onclick}
  onanimationend={(e: AnimationEvent) => e.animationName.endsWith("flash") && onshudderend?.()}
>
  <span class="box">
    <span class="tray"></span>
    <img src={tint.disc} alt="" class="disc" draggable="false" {@attach motor} />
    <span class="lid"><span class="sheen"></span></span>
    <span class="flash"></span>
  </span>
</svelte:element>

<style>
  .stage {
    position: relative;
    display: block;
    width: var(--size);
    height: var(--size);
    padding: 0;
    border: 0;
    background: none;
    perspective: 1200px;
    -webkit-tap-highlight-color: transparent;
  }
  .interactive {
    cursor: pointer;
  }
  .interactive:focus-visible {
    outline: 2px solid rgb(var(--glow));
    outline-offset: 14px;
    border-radius: 8px;
  }

  .box {
    position: absolute;
    inset: 0;
    transform-style: preserve-3d;
    transform: rotateX(8deg) rotateY(-4deg);
    transition: transform 0.8s cubic-bezier(0.16, 1, 0.3, 1);
  }
  .interactive:hover .box {
    transform: rotateX(4deg) rotateY(0deg) scale(1.03);
  }

  .tray {
    position: absolute;
    inset: 0;
    border-radius: 5px;
    background: var(--tray) center / cover;
    box-shadow:
      0 22px 50px rgb(0 0 0 / 0.85),
      0 0 46px rgb(var(--glow) / 0.2);
  }
  .disc {
    position: absolute;
    width: 84.5%;
    height: 84.5%;
    top: 7.75%;
    left: 7.75%;
    border-radius: 50%;
    filter: drop-shadow(0 4px 16px rgb(0 0 0 / 0.8));
    transition: filter 0.4s;
  }

  /* Crystal lid, hinged on the left. Closed = sealed; open swings to -65deg
     on a damped spring (about 10% overshoot, as if the hinge had give). */
  .lid {
    position: absolute;
    inset: 0;
    overflow: hidden;
    border-radius: 5px;
    background: var(--lid) center / cover;
    transform-origin: 0% 50%;
    transform: rotateY(0deg);
    box-shadow: 0 10px 25px rgb(0 0 0 / 0.5);
    transition:
      transform 1.05s
        linear(0, 0.03, 0.109, 0.218, 0.344, 0.475, 0.603, 0.72, 0.823, 0.909, 0.979, 1.031, 1.068, 1.092, 1.104, 1.107, 1.103, 1.094, 1.082, 1.068, 1.054, 1.041, 1.028, 1.018, 1.009, 1.002, 0.996, 0.992, 0.99, 0.989, 0.989, 0.989, 1),
      box-shadow 0.9s ease;
  }
  /* Specular reflections on the acrylic. */
  .lid::after {
    content: "";
    position: absolute;
    inset: 0;
    background: linear-gradient(135deg, rgb(255 255 255 / 0.24) 0%, transparent 42%, rgb(255 255 255 / 0.09) 58%, transparent 100%);
    pointer-events: none;
  }
  .open .lid {
    transform: rotateY(-65deg);
    box-shadow: 18px 24px 50px rgb(0 0 0 / 0.75);
  }
  /* Sealed and clickable: the lid gives a little under the cursor. */
  .interactive.sealed:hover .lid {
    transform: rotateY(-9deg);
  }

  /* A light sweep across the sealed lid, inviting the click. */
  .sheen {
    position: absolute;
    inset: -20% auto -20% -60%;
    width: 45%;
    background: linear-gradient(100deg, transparent, rgb(255 255 255 / 0.16) 45%, rgb(221 196 254 / 0.12) 55%, transparent);
    transform: skewX(-12deg);
    opacity: 0;
    pointer-events: none;
  }
  .sealed .sheen {
    animation: sheen 4.8s ease-in-out 1.2s infinite;
  }
  @keyframes sheen {
    0% {
      left: -60%;
      opacity: 0;
    }
    8% {
      opacity: 1;
    }
    32%,
    100% {
      left: 120%;
      opacity: 0;
    }
  }

  /* Failed unlock: the case shudders and flashes crimson. `translate` is
     separate from `transform`, so it never fights the 3D tilt or the lid. */
  .shudder {
    animation: shudder 0.52s cubic-bezier(0.36, 0.07, 0.19, 0.97);
  }
  @keyframes shudder {
    10%,
    90% {
      translate: -2px 0;
    }
    20%,
    80% {
      translate: 4px 0;
    }
    30%,
    50%,
    70% {
      translate: -7px 0;
    }
    40%,
    60% {
      translate: 7px 0;
    }
  }
  .flash {
    position: absolute;
    inset: -2px;
    border-radius: 6px;
    pointer-events: none;
    opacity: 0;
    box-shadow:
      0 0 0 2px var(--color-crimson),
      0 0 46px 6px rgb(225 29 72 / 0.75),
      inset 0 0 60px rgb(225 29 72 / 0.55);
  }
  .shudder .flash {
    animation: flash 0.7s ease-out;
  }
  @keyframes flash {
    0% {
      opacity: 0;
    }
    15% {
      opacity: 1;
    }
    100% {
      opacity: 0;
    }
  }

  /* Animation effects off: no spring, sweep, tilt or shake. The lid still
     opens (briefly eased, so the change is legible) and the error still flashes.
     These override the app-wide reduced-motion rule in app.css. */
  @media (prefers-reduced-motion: reduce) {
    .sealed .sheen,
    .shudder {
      animation: none !important;
    }
    .box {
      transition: none !important;
    }
    .lid {
      transition: transform 0.25s ease-out !important;
    }
    .interactive:hover .box {
      transform: rotateX(8deg) rotateY(-4deg);
    }
    .interactive.sealed:hover .lid {
      transform: rotateY(0deg);
    }
    .shudder .flash {
      animation: flash 0.7s ease-out !important;
    }
  }
</style>
