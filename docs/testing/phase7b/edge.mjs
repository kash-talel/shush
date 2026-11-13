// Dependency-free CDP driver for a headless Edge running the shush extension (Node 22).
//
//   node edge.mjs list                     every target: "<type> <url>"
//   node edge.mjs open <url>               new tab
//   node edge.mjs eval <url-part> <expr>   evaluate in the first target whose URL contains <url-part>
//                                          (page, popup or the extension service worker); prints JSON
//   node edge.mjs fill <url-part>          click the shush inline button, then the last entry in its
//                                          list, with trusted CDP mouse events (the content script
//                                          ignores untrusted clicks). Exit 2: no button, 3: no entry.
//
// Port: EDGE_PORT env (default 9333). Input events stay inside the browser: nothing reaches the
// desktop's keyboard or mouse.

const port = process.env.EDGE_PORT ?? "9333";
const [cmd, a, b] = process.argv.slice(2);

const ver = await (await fetch(`http://127.0.0.1:${port}/json/version`)).json();
const ws = new WebSocket(ver.webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener("open", r, { once: true }));
let seq = 0;
const waiters = new Map();
ws.addEventListener("message", (e) => {
  const m = JSON.parse(e.data);
  if (m.id && waiters.has(m.id)) {
    waiters.get(m.id)(m);
    waiters.delete(m.id);
  }
});
const send = (method, params = {}, sessionId) =>
  new Promise((r) => {
    const id = ++seq;
    waiters.set(id, r);
    ws.send(JSON.stringify({ id, method, params, sessionId }));
  });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const targets = async () => (await send("Target.getTargets")).result.targetInfos;

async function attach(part) {
  const t = (await targets()).find((t) => t.url.includes(part));
  if (!t) throw new Error(`no target matching ${part}`);
  return (await send("Target.attachToTarget", { targetId: t.targetId, flatten: true })).result.sessionId;
}

async function evaluate(s, expression) {
  // userGesture: chrome.action.openPopup() needs one.
  const r = await send(
    "Runtime.evaluate",
    { expression, awaitPromise: true, returnByValue: true, userGesture: true },
    s,
  );
  if (r.result?.exceptionDetails) {
    throw new Error(r.result.exceptionDetails.exception?.description ?? "eval failed");
  }
  return r.result?.result?.value;
}

// Buttons inside shadow roots (the content script's UI uses a closed one).
async function shadowButtons(s) {
  const root = (await send("DOM.getDocument", { depth: -1, pierce: true }, s)).result.root;
  const out = [];
  const walk = (n, inShadow) => {
    if (inShadow && n.nodeName === "BUTTON") out.push(n);
    for (const c of n.children ?? []) walk(c, inShadow);
    for (const sr of n.shadowRoots ?? []) walk(sr, true);
  };
  walk(root, false);
  return out;
}

async function click(s, node) {
  const q = (await send("DOM.getBoxModel", { backendNodeId: node.backendNodeId }, s)).result?.model?.content;
  if (!q) throw new Error("button has no box");
  const x = (q[0] + q[4]) / 2;
  const y = (q[1] + q[5]) / 2;
  for (const type of ["mousePressed", "mouseReleased"]) {
    await send("Input.dispatchMouseEvent", { type, x, y, button: "left", clickCount: 1 }, s);
  }
}

let code = 0;
try {
  if (cmd === "list") {
    for (const t of await targets()) console.log(t.type, t.url);
  } else if (cmd === "open") {
    await send("Target.createTarget", { url: a });
  } else if (cmd === "eval") {
    console.log(JSON.stringify(await evaluate(await attach(a), b)));
  } else if (cmd === "fill") {
    const s = await attach(a);
    await send("Page.bringToFront", {}, s);
    await evaluate(s, "document.querySelector('input[type=password]')?.focus()");
    await sleep(800);
    let buttons = await shadowButtons(s);
    if (!buttons.length) code = 2;
    else {
      await click(s, buttons[0]);
      await sleep(2000);
      buttons = await shadowButtons(s);
      if (buttons.length < 2) code = 3;
      else {
        await click(s, buttons.at(-1));
        await sleep(2000);
      }
    }
  } else {
    throw new Error(`unknown command ${cmd}`);
  }
} catch (e) {
  console.error(e.message);
  code = 1;
}
ws.close();
process.exit(code);
