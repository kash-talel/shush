// Jewel case behaviour shared by the preview variants.
// Markup: <button class="jc" aria-pressed="true" aria-label="…">
//           <span class="jc-box"><span class="jc-tray"></span><img class="jc-disc"><span class="jc-lid"></span></span>
//         </button>
// aria-pressed="true" means open. Variants listen for the "jewelcase" event
// ({ detail: { open } }) and may call shushCase.spin(rate) to drive the disc.
(() => {
  const cases = [...document.querySelectorAll(".jc")];
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;

  for (const el of cases) {
    el.addEventListener("click", () => {
      const open = el.getAttribute("aria-pressed") !== "true";
      el.setAttribute("aria-pressed", String(open));
      el.dispatchEvent(new CustomEvent("jewelcase", { bubbles: true, detail: { open } }));
    });
  }

  // Changes speed without restarting the rotation, so the disc never jumps.
  function spin(rate) {
    if (reduce) return;
    for (const el of cases) {
      const disc = el.querySelector(".jc-disc");
      for (const a of disc?.getAnimations() ?? []) a.updatePlaybackRate(rate);
    }
  }

  window.shushCase = { spin, cases };
})();
