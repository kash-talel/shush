// node emu.mjs <w> <h> <out.png> : screenshot the main window at an emulated viewport size
import { writeFileSync } from "node:fs";
const [w, h, out] = process.argv.slice(2);
const t = await (await fetch(`http://127.0.0.1:${process.env.CDP_PORT ?? "9222"}/json`)).json();
const p = t.find((x) => x.type === "page" && /localhost:1420|tauri\.localhost/.test(x.url) && x.title !== "shush quick search");
const ws = new WebSocket(p.webSocketDebuggerUrl); await new Promise((r) => (ws.onopen = r));
let i = 0; const send = (m, pa = {}) => new Promise((r) => { const id = ++i; ws.addEventListener("message", (e) => { const d = JSON.parse(e.data); if (d.id === id) r(d); }); ws.send(JSON.stringify({ id, method: m, params: pa })); });
await send("Emulation.setDeviceMetricsOverride", { width: +w, height: +h, deviceScaleFactor: 1, mobile: false });
await new Promise((r) => setTimeout(r, 500));
const s = await send("Page.captureScreenshot", { format: "png" }); writeFileSync(out, Buffer.from(s.result.data, "base64"));
await send("Emulation.clearDeviceMetricsOverride"); ws.close(); console.log("saved " + out);
