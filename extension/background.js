// shush extension service worker (issue #53, protocol v1 in
// src-tauri/src/bridge/protocol.rs).
//
// Owns the native-messaging port, the pairing key and the request counter.
// Content scripts and the popup never see the key. Every answer to an
// authenticated request is checked against its MAC; the origin of a fill is
// always the tab's URL as the browser reports it, never a value a page or
// content script supplies. Whether a login may be filled is decided by shush.

import { pairWithCode } from "./pairing.js";
import { concat, hmac } from "./spake2.js";

const HOST = "com.shush.vault";
const VERSION = 1;
const TIMEOUT_MS = 15000;
const enc = new TextEncoder();

// ---- encoding helpers ---------------------------------------------------------

const toB64 = (u8) => btoa(String.fromCharCode(...u8));
const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

function counterBytes(n) {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), true);
  return b;
}

function macOf(key, counter, bodyString) {
  return hmac(key, concat(counterBytes(counter), enc.encode(bodyString)));
}

function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

class BridgeError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

// ---- native port --------------------------------------------------------------

let port = null;
let nextRid = 1;
const pending = new Map();

function failAll(code) {
  for (const p of pending.values()) {
    clearTimeout(p.timer);
    p.reject(new BridgeError(code));
  }
  pending.clear();
}

function connect() {
  if (port) return port;
  port = chrome.runtime.connectNative(HOST);
  port.onMessage.addListener((msg) => {
    const p = msg && pending.get(msg.rid);
    if (!p) return;
    pending.delete(msg.rid);
    clearTimeout(p.timer);
    p.resolve(msg);
  });
  port.onDisconnect.addListener(() => {
    port = null;
    void chrome.runtime.lastError; // read it so the browser does not log it
    failAll("NOT_CONNECTED");
  });
  return port;
}

function roundtrip(envelope) {
  return new Promise((resolve, reject) => {
    let p;
    try {
      p = connect();
    } catch {
      reject(new BridgeError("NOT_CONNECTED"));
      return;
    }
    const timer = setTimeout(() => {
      pending.delete(envelope.rid);
      reject(new BridgeError("TIMEOUT"));
    }, TIMEOUT_MS);
    pending.set(envelope.rid, { resolve, reject, timer });
    try {
      p.postMessage(envelope);
    } catch {
      pending.delete(envelope.rid);
      clearTimeout(timer);
      reject(new BridgeError("NOT_CONNECTED"));
    }
  });
}

// ---- pairing state ------------------------------------------------------------

// One request at a time: the counter must strictly increase on the wire.
let chain = Promise.resolve();
function serialized(fn) {
  const run = chain.then(fn, fn);
  chain = run.catch(() => {});
  return run;
}

async function loadPairing() {
  const { pairing } = await chrome.storage.local.get("pairing");
  return pairing ? { id: pairing.id, key: fromB64(pairing.key), counter: pairing.counter } : null;
}

async function savePairing(p) {
  await chrome.storage.local.set({
    pairing: { id: p.id, key: toB64(p.key), counter: p.counter },
  });
}

async function clearPairing() {
  await chrome.storage.local.remove("pairing");
}

/**
 * Sends one request. Authenticated when paired (unless `open`); the answer's
 * MAC is verified, and an unsigned success for a signed request is refused.
 * Resolves to `result`, rejects with a BridgeError.
 */
function call(type, fields = {}, { open = false } = {}) {
  return serialized(async () => {
    const pairing = open ? null : await loadPairing();
    const body = JSON.stringify({ type, ...fields });
    const rid = nextRid++;
    const envelope = { v: VERSION, rid, body };
    if (pairing) {
      pairing.counter += 1;
      // Persist before sending: a counter must never be reused.
      await savePairing(pairing);
      envelope.pair_id = pairing.id;
      envelope.counter = pairing.counter;
      envelope.mac = toB64(await macOf(pairing.key, pairing.counter, body));
    } else if (!open) {
      throw new BridgeError("NOT_PAIRED");
    }
    const reply = await roundtrip(envelope);
    let answer;
    try {
      answer = JSON.parse(reply.body);
    } catch {
      throw new BridgeError("BAD_ANSWER");
    }
    let authentic = false;
    if (pairing && typeof reply.mac === "string") {
      const expect = await macOf(pairing.key, pairing.counter, reply.body);
      authentic = reply.counter === pairing.counter && equalBytes(expect, fromB64(reply.mac));
      if (!authentic) throw new BridgeError("BAD_ANSWER_MAC");
    }
    if (!answer.ok) {
      if (answer.error === "NOT_PAIRED") await clearPairing();
      throw new BridgeError(String(answer.error));
    }
    if (pairing && !authentic && type !== "revoke") {
      // Success data only counts when shush proved it holds the key.
      throw new BridgeError("BAD_ANSWER_MAC");
    }
    return answer.result;
  });
}

// ---- operations ---------------------------------------------------------------

async function status() {
  const paired = (await loadPairing()) !== null;
  try {
    const hello = await call("hello", {}, { open: !paired });
    return {
      connected: true,
      locked: hello.locked,
      paired: paired && hello.paired,
      canPair: hello.pairing_nonce != null,
    };
  } catch (e) {
    if (e.code === "NOT_PAIRED") return status();
    return { connected: e.code !== "NOT_CONNECTED", error: e.code, paired: false };
  }
}

async function pair(code) {
  const hello = await call("hello", {}, { open: true });
  if (!hello.pairing_nonce) throw new BridgeError("NO_PAIRING_CODE");
  const { extMsg, proof, pairKey } = await pairWithCode(code, fromB64(hello.pairing_nonce));
  const result = await call(
    "pair",
    { ext_nonce: toB64(extMsg), proof: toB64(proof) },
    { open: true },
  );
  await savePairing({ id: result.pair_id, key: pairKey, counter: 0 });
}

async function unpair() {
  try {
    await call("revoke");
  } finally {
    await clearPairing();
  }
}

/** Origin of an http(s) tab as the browser reports it, else null. */
function tabOrigin(tab) {
  try {
    const u = new URL(tab?.url ?? "");
    return u.protocol === "https:" || u.protocol === "http:" ? u.origin : null;
  } catch {
    return null;
  }
}

async function activeTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function matches(tab) {
  const origin = tabOrigin(tab);
  if (!origin) return [];
  return call("match", { tab_origin: origin });
}

async function fill(tab, id) {
  const origin = tabOrigin(tab);
  if (!origin) throw new BridgeError("BAD_ORIGIN");
  return call("fill", { id, tab_origin: origin });
}

// ---- messages from the popup and content scripts -------------------------------

async function handle(msg, sender) {
  const fromContent = sender.tab != null;
  // Content scripts: top frame only, so an iframe cannot stand in for the page.
  if (fromContent && sender.frameId !== 0) throw new BridgeError("FORBIDDEN");
  const tab = fromContent ? sender.tab : await activeTab();

  switch (msg?.cmd) {
    case "status":
      return status();
    case "pair":
      if (fromContent) throw new BridgeError("FORBIDDEN");
      return pair(String(msg.code ?? ""));
    case "unpair":
      if (fromContent) throw new BridgeError("FORBIDDEN");
      return unpair();
    case "matches":
      return matches(tab);
    case "fill": {
      const secrets = await fill(tab, String(msg.id));
      if (fromContent) return secrets;
      // Popup: the click was the user gesture; deliver to the tab's top frame.
      await chrome.tabs.sendMessage(tab.id, { cmd: "shush-fill", secrets }, { frameId: 0 });
      return {};
    }
    case "save": {
      if (!fromContent) throw new BridgeError("FORBIDDEN");
      const origin = tabOrigin(tab);
      if (!origin) throw new BridgeError("BAD_ORIGIN");
      return call("save", {
        tab_origin: origin,
        username: String(msg.username ?? ""),
        password: String(msg.password ?? ""),
      });
    }
    default:
      throw new BridgeError("BAD_REQUEST");
  }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id) return false;
  handle(msg, sender).then(
    (result) => sendResponse({ ok: true, result }),
    (e) => sendResponse({ ok: false, error: e instanceof BridgeError ? e.code : "INTERNAL" }),
  );
  return true; // answered asynchronously
});
