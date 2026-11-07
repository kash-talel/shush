// Minimal, dependency-free Chrome DevTools Protocol driver for the shush WebView2.
// Never touches the mouse/keyboard/focus: everything goes through CDP.
//
//   node cdp.mjs eval "<js expression>"        -> prints JSON result
//   node cdp.mjs shot <out.png>                -> off-screen screenshot of the page
//   node cdp.mjs fill "<css>" "<value>"        -> sets an input's value + fires input event
//   node cdp.mjs click "<css or text:Label>"   -> element.click()
//   node cdp.mjs wait "<js predicate>" [ms]    -> polls until truthy
//
// Port: CDP_PORT env (default 9222). Target: first page whose URL is the app.
import { writeFileSync } from "node:fs";

const port = process.env.CDP_PORT ?? "9222";
const [cmd, a, b] = process.argv.slice(2);

const targets = await (await fetch(`http://127.0.0.1:${port}/json`)).json();
// CDP_WINDOW=spotlight selects the quick-search window; default is the main window.
const wantSpotlight = process.env.CDP_WINDOW === "spotlight";
const page = targets.find(
  (t) =>
    t.type === "page" &&
    /localhost:1420|tauri\.localhost/.test(t.url) &&
    (t.title === "shush quick search") === wantSpotlight,
);
if (!page) throw new Error("app page not found: " + JSON.stringify(targets.map((t) => t.url)));

const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
let id = 0;
const pending = new Map();
ws.onmessage = (m) => {
  const msg = JSON.parse(m.data);
  if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); }
};
const send = (method, params = {}) =>
  new Promise((res) => { const i = ++id; pending.set(i, res); ws.send(JSON.stringify({ id: i, method, params })); });

async function evaluate(expression) {
  const r = await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
  if (r.result?.exceptionDetails) throw new Error(r.result.exceptionDetails.exception?.description ?? "eval failed");
  return r.result?.result?.value;
}

// Finds by CSS, or by visible text with "text:" prefix (buttons/labels/radios).
const finder = (sel) => `(() => {
  const s = ${JSON.stringify(sel)};
  if (s.startsWith("text:")) {
    const t = s.slice(5).trim();
    return [...document.querySelectorAll("button,label,summary,[role=radio],a")]
      .find((e) => e.textContent.replace(/\\s+/g, " ").trim().includes(t));
  }
  return document.querySelector(s);
})()`;

try {
  if (cmd === "eval") {
    console.log(JSON.stringify(await evaluate(a)));
  } else if (cmd === "shot") {
    const r = await send("Page.captureScreenshot", { format: "png" });
    writeFileSync(a, Buffer.from(r.result.data, "base64"));
    console.log("saved " + a);
  } else if (cmd === "fill") {
    console.log(await evaluate(`(() => {
      const el = ${finder(a)}; if (!el) return "NOT FOUND: " + ${JSON.stringify(a)};
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
      el.focus(); setter.call(el, ${JSON.stringify(b ?? "")});
      el.dispatchEvent(new Event("input", { bubbles: true }));
      return "filled";
    })()`));
  } else if (cmd === "click") {
    console.log(await evaluate(`(() => {
      const el = ${finder(a)}; if (!el) return "NOT FOUND: " + ${JSON.stringify(a)};
      if (el.disabled) return "DISABLED: " + ${JSON.stringify(a)};
      el.click(); return "clicked";
    })()`));
  } else if (cmd === "wait") {
    const deadline = Date.now() + Number(b ?? 15000);
    for (;;) {
      if (await evaluate(`!!(${a})`)) { console.log("ok"); break; }
      if (Date.now() > deadline) { console.log("TIMEOUT: " + a); process.exitCode = 1; break; }
      await new Promise((r) => setTimeout(r, 200));
    }
  } else {
    throw new Error("unknown command " + cmd);
  }
} finally {
  ws.close();
}
