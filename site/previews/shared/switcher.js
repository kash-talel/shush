// Sticky preview switch bar: compare the design directions live.
// Keys 1–3 switch variants; the current one is marked. Not part of any final design.
(() => {
  const variants = [
    { file: "variant-industrial-raw.html", key: "1", name: "A · Industrial raw", note: "spec sheet + live crypto bench" },
    { file: "variant-cyber-acrylic.html", key: "2", name: "B · Cyber acrylic", note: "liner notes + tactile audio" },
    { file: "variant-terminal-telemetry.html", key: "3", name: "C · Terminal telemetry", note: "rack panel + live Spotlight" },
  ];
  const here = location.pathname.split("/").pop();

  const css = `
  .pv-bar{position:sticky;top:0;z-index:1000;display:flex;align-items:center;gap:6px;flex-wrap:wrap;
    padding:8px 16px;background:#000;border-bottom:1px dashed #f43f5e;font:500 12px/1.2 ui-monospace,Consolas,monospace;color:#a1a1aa}
  .pv-bar b{color:#fafafa;font-weight:600;margin-right:6px}
  .pv-bar a{display:inline-flex;gap:8px;align-items:center;padding:6px 10px;border:1px solid #27272a;border-radius:3px;color:#d4d4d8;text-decoration:none}
  .pv-bar a:hover{border-color:#52525b;color:#fff}
  .pv-bar a[aria-current=page]{background:#e11d48;border-color:#e11d48;color:#fff}
  .pv-bar kbd{all:unset;font:inherit;font-size:10px;opacity:.7;border:1px solid currentColor;border-radius:2px;padding:0 4px}
  .pv-bar .pv-note{margin-left:auto;opacity:.8}
  .pv-bar a:focus-visible{outline:2px solid #c084fc;outline-offset:2px}
  @media (max-width:720px){.pv-bar .pv-note,.pv-bar .pv-sub{display:none}}`;
  const style = document.createElement("style");
  style.textContent = css;
  document.head.append(style);

  const bar = document.createElement("nav");
  bar.className = "pv-bar";
  bar.setAttribute("aria-label", "Design preview switcher");
  bar.innerHTML =
    `<b>shush previews</b>` +
    variants
      .map(
        (v) =>
          `<a href="${v.file}"${v.file === here ? ' aria-current="page"' : ""}><kbd>${v.key}</kbd>${v.name}<span class="pv-sub" style="opacity:.6">${v.note}</span></a>`,
      )
      .join("") +
    `<a href="../index.html">current site</a><span class="pv-note">pick one and tell Claude: A, B or C</span>`;
  document.body.prepend(bar);

  addEventListener("keydown", (e) => {
    if (e.ctrlKey || e.altKey || e.metaKey) return;
    if (e.target instanceof HTMLElement && e.target.closest("input,textarea,[contenteditable]")) return;
    const v = variants.find((x) => x.key === e.key);
    if (v && v.file !== here) location.href = v.file;
  });
})();
