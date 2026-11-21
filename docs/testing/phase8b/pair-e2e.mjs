// Phase 8b LAN sync pairing E2E (issue #156). Launch two debug builds beside each
// other, each with its own scratch vault, SHUSH_NO_SINGLE_INSTANCE=1 and its own CDP
// port (A: 10156, B: 10157), plus `npx vite --port 1420` in src/. Create a vault in
// each instance with the passwords below (through the create screen; `create_vault`
// takes only the binary frame from `encodeSecretFrame`, not JSON args), then run
// `node docs/testing/phase8b/pair-e2e.mjs`.
//
// Two debug instances over CDP (A: CDP 10156, B: CDP 10157). Drives Tauri IPC
// through each window's own invoke, as the UI does. The machine is idle (no
// synthetic input allowed), so idle auto-lock fires every ~10 s: each scenario
// unlocks first and is retried if a lock interrupted it.
const ports = { A: 10156, B: 10157 };
let fails = 0;
const ok = (c, m) => { console.log((c ? "PASS " : "FAIL ") + m); if (!c) fails++; };

async function conn(port) {
  const targets = await (await fetch(`http://127.0.0.1:${port}/json`)).json();
  const page = targets.find((t) => t.type === "page" && t.title !== "shush quick search");
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((r, j) => { ws.onopen = r; ws.onerror = j; });
  let id = 0; const pending = new Map();
  ws.onmessage = (m) => { const x = JSON.parse(m.data); if (pending.has(x.id)) { pending.get(x.id)(x); pending.delete(x.id); } };
  const send = (method, params = {}) => new Promise((r) => { const i = ++id; pending.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
  const ev = async (expr) => {
    const r = await send("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true });
    if (r.result?.exceptionDetails) throw new Error(JSON.stringify(r.result.exceptionDetails));
    return r.result.result.value;
  };
  const call = (cmd, args = {}) => ev(`window.__TAURI_INTERNALS__.invoke(${JSON.stringify(cmd)}, ${JSON.stringify(args)}).then(v => ({ok: v}), e => ({err: e}))`);
  return { ev, call, close: () => ws.close() };
}

const A = await conn(ports.A);
const B = await conn(ports.B);
A.pw = "correct horse battery A";
B.pw = "correct horse battery B";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
class Locked extends Error {}

async function unlockBoth() {
  for (const X of [A, B]) {
    const s = await X.call("sync_status");
    if (s.err?.code === "VAULT_LOCKED") {
      const r = await X.call("unlock", { password: X.pw, keyfilePath: null });
      if (r.err) throw new Error("unlock failed " + JSON.stringify(r.err));
    }
  }
}
// A step result that shows an auto-lock interrupted the scenario.
const guard = (r) => {
  if (r.err?.code === "VAULT_LOCKED" || r.err?.code === "PAIR_NOT_SAVED") throw new Locked();
  return r;
};
async function scenario(name, f) {
  for (let i = 0; i < 6; i++) {
    await unlockBoth();
    try {
      const checks = [];
      await f((c, m) => checks.push([c, m]));
      for (const [c, m] of checks) ok(c, `${name}: ${m}`);
      return;
    } catch (e) {
      if (!(e instanceof Locked)) throw e;
      console.log(`  (${name}: idle auto-lock interrupted, retrying)`);
      await A.call("sync_cancel_pairing");
      await B.call("sync_cancel_pairing");
    }
  }
  ok(false, `${name}: never ran without an auto-lock`);
}

await scenario("air-gapped", async (check) => {
  for (const X of [A, B]) await X.call("set_air_gapped", { enabled: true });
  const r1 = guard(await A.call("sync_start_pairing"));
  check(r1.err?.code === "SYNC_AIR_GAPPED", "pairing refused while air-gapped");
  const r2 = guard(await B.call("sync_discover"));
  check(r2.err?.code === "SYNC_AIR_GAPPED", "discovery refused while air-gapped");
  const r3 = guard(await B.call("sync_join", { address: "127.0.0.1:9", code: "ABCD-EFGH" }));
  check(r3.err?.code === "SYNC_AIR_GAPPED", "join refused while air-gapped");
  for (const X of [A, B]) await X.call("set_air_gapped", { enabled: false });
});

// Clean slate: forget any earlier pairing.
for (const X of [A, B]) { await unlockBoth(); await X.call("sync_reset_identity"); }

let fpA, fpB;
await scenario("pair", async (check) => {
  const r = guard(await A.call("sync_start_pairing"));
  const w = r.ok.window;
  check(w.state === "open" && /^[A-Z2-7]{4}-[A-Z2-7]{4}$/.test(w.code), "window open with XXXX-XXXX code");
  check(/^([A-Z2-7]{4}-){3}[A-Z2-7]{4}$/.test(r.ok.fingerprint), "identity created, fingerprint shown");
  check(w.advertised, "window advertised (setting on)");
  const port = w.addresses[0].split(":")[1];
  const addr = `127.0.0.1:${port}`;
  const wrong = w.code.startsWith("A") ? "BBBB-BBBB" : "AAAA-AAAA";
  const j1 = guard(await B.call("sync_join", { address: addr, code: wrong }));
  check(j1.err?.code === "WRONG_CODE", "wrong code reported as WRONG_CODE " + JSON.stringify(j1.err));
  const s1 = guard(await A.call("sync_status")).ok;
  if (s1.window?.state !== "open") throw new Locked();
  check(s1.window.failures === 1 && s1.peers.length === 0, "responder counted 1 failure, stored nothing");
  check(guard(await B.call("sync_status")).ok.peers.length === 0, "initiator stored nothing");
  const j2 = guard(await B.call("sync_join", { address: addr, code: w.code.toLowerCase() }));
  if (j2.err?.code === "SYNC_CONNECT_FAILED") throw new Locked();
  check(!j2.err, "right code (typed lowercase) pairs " + JSON.stringify(j2));
  const sa = guard(await A.call("sync_status")).ok;
  const sb = guard(await B.call("sync_status")).ok;
  check(sa.window.state === "paired" && sa.window.code === null, "window closed as paired, code wiped");
  check(sa.peers.length === 1 && sa.peers[0].id === sb.fingerprint, "A pinned B's fingerprint");
  check(sb.peers.length === 1 && sb.peers[0].id === sa.fingerprint, "B pinned A's fingerprint");
  check(sb.peers[0].name.length > 0, "peer name received: " + sb.peers[0].name);
  const j3 = guard(await B.call("sync_join", { address: addr, code: w.code }));
  check(j3.err?.code === "SYNC_CONNECT_FAILED", "code cannot be reused: listener gone");
  fpA = sa.fingerprint; fpB = sb.fingerprint;
});

await scenario("discovery", async (check) => {
  const r = guard(await A.call("sync_start_pairing"));
  const port = r.ok.window.addresses[0].split(":")[1];
  const d = guard(await B.call("sync_discover"));
  check(!d.err && d.ok.some((x) => x.address.endsWith(":" + port)), "B finds A's open window " + JSON.stringify(d));
  check(!d.err && d.ok.every((x) => /^[a-z2-7]{8}$/.test(x.instance)), "instance name random, no device name");
  await A.call("sync_cancel_pairing");
  await sleep(1500);
  const d2 = guard(await B.call("sync_discover"));
  check(!d2.err && !d2.ok.some((x) => x.address.endsWith(":" + port)), "cancelled window no longer found " + JSON.stringify(d2));
});

await scenario("advertise off", async (check) => {
  guard(await A.call("sync_set_advertise", { enabled: false }));
  const r = guard(await A.call("sync_start_pairing"));
  check(r.ok.window.advertised === false, "window not advertised");
  const port = r.ok.window.addresses[0].split(":")[1];
  const d = guard(await B.call("sync_discover"));
  check(!d.err && !d.ok.some((x) => x.address.endsWith(":" + port)), "not discoverable " + JSON.stringify(d));
  await A.call("sync_cancel_pairing");
  guard(await A.call("sync_set_advertise", { enabled: true }));
});

await scenario("lock closes window", async (check) => {
  const r = guard(await A.call("sync_start_pairing"));
  const port = r.ok.window.addresses[0].split(":")[1];
  await A.call("lock");
  await sleep(500);
  const j = await B.call("sync_join", { address: `127.0.0.1:${port}`, code: "ABCD-EFGH" });
  check(j.err?.code === "SYNC_CONNECT_FAILED" || j.err?.code === "VAULT_LOCKED", "listener closed on vault lock " + JSON.stringify(j.err));
});

await scenario("forget + reset", async (check) => {
  const r = guard(await B.call("sync_forget", { id: fpA }));
  check(!r.err && r.ok.peers.length === 0, "B forgets A");
  const r2 = guard(await A.call("sync_reset_identity"));
  check(r2.ok.peers.length === 0 && r2.ok.fingerprint === null, "A reset identity clears peers");
  const r3 = guard(await A.call("sync_start_pairing"));
  check(r3.ok.fingerprint !== fpA, "A has a new identity after reset");
  await A.call("sync_cancel_pairing");
  check(guard(await A.call("sync_status")).ok.window === null, "cancel drops the window");
});

await A.close(); await B.close();
console.log(fails ? `${fails} FAILED` : "ALL PASSED");
process.exit(fails ? 1 : 0);
