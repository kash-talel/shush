// Holds a CDP session that emulates prefers-reduced-motion: no-preference on the main shush window.
const t = await (await fetch(`http://127.0.0.1:${process.env.CDP_PORT ?? "9222"}/json`)).json();
const p = t.find((x) => x.type === "page" && /localhost:1420/.test(x.url) && x.title !== "shush quick search");
const ws = new WebSocket(p.webSocketDebuggerUrl); await new Promise((r) => (ws.onopen = r));
ws.send(JSON.stringify({ id: 1, method: "Emulation.setEmulatedMedia", params: { features: [{ name: "prefers-reduced-motion", value: "no-preference" }] } }));
console.log("holding full-motion emulation for", process.argv[2] ?? 240, "s");
setTimeout(() => { ws.close(); process.exit(0); }, (+(process.argv[2] ?? 240)) * 1000);
