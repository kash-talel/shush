// Pipe-side probes for issue #153 (used by e2e-pipe.sh). Talks to the running shush pipe
// with Node's net module and the real shush-host.exe; no desktop input.
//
//   node pipe-probe.mjs serve <shush-host.exe>   non-host rejected, host works, rate limit, cap
//   node pipe-probe.mjs squat                    create the pipe name first and hold it
//   node pipe-probe.mjs refuse <shush-host.exe>  the host refuses a server that is not shush.exe
//
// Prints PASS/FAIL lines; the exit code is the number of failures.
import net from "node:net";
import { spawn, execFileSync } from "node:child_process";

const [mode, hostExe] = process.argv.slice(2);
const csv = execFileSync(`${process.env.SystemRoot ?? "C:/Windows"}/System32/whoami.exe`, ["/user", "/fo", "csv", "/nh"], { encoding: "utf8" });
const sid = csv.trim().split(",")[1].replaceAll('"', "");
const PIPE = String.raw`\\.\pipe\shush-` + sid;

let failures = 0;
const report = (ok, what) => { console.log(`${ok ? "PASS" : "FAIL"}  ${what}`); if (!ok) failures++; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const frame = (obj) => {
  const body = Buffer.from(JSON.stringify(obj));
  const head = Buffer.alloc(4);
  head.writeUInt32LE(body.length);
  return Buffer.concat([head, body]);
};
const HELLO = frame({ v: 1, rid: 1, body: JSON.stringify({ type: "hello" }) });

/** Reads length-prefixed frames from a stream; `next()` resolves null when it ends. */
function reader(stream) {
  let buf = Buffer.alloc(0);
  let ended = false;
  const waiters = [];
  const pump = () => {
    while (waiters.length) {
      if (buf.length >= 4 && buf.length >= 4 + buf.readUInt32LE(0)) {
        const n = buf.readUInt32LE(0);
        const out = buf.subarray(4, 4 + n);
        buf = buf.subarray(4 + n);
        waiters.shift()(out);
      } else if (ended) waiters.shift()(null);
      else break;
    }
  };
  stream.on("data", (d) => { buf = Buffer.concat([buf, d]); pump(); });
  stream.on("end", () => { ended = true; pump(); });
  stream.on("close", () => { ended = true; pump(); });
  stream.on("error", () => { ended = true; pump(); });
  return { next: (ms = 4000) => new Promise((res) => {
    const t = setTimeout(() => res(undefined), ms);
    waiters.push((v) => { clearTimeout(t); res(v); });
    pump();
  }) };
}

/** A shush-host.exe child: send() writes one frame and waits for its reply. */
function host() {
  // Node is not a browser: the ancestry check (#159) is skipped only in debug builds,
  // so these probes need a debug shush-host.exe.
  const p = spawn(hostExe, ["chrome-extension://kmcbplfcpijmfohfojkajnmejadkcipe/"], { stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, SHUSH_HOST_SKIP_ANCESTRY: "1" } });
  const r = reader(p.stdout);
  let stderr = "";
  p.stderr.on("data", (d) => (stderr += d));
  p.stdin.on("error", () => {});
  const exited = new Promise((res) => { p.on("exit", (c) => res(c)); p.on("error", () => res("spawn-error")); });
  return {
    p, exited, r, err: () => stderr,
    async send() { p.stdin.write(HELLO); return r.next(); },
  };
}
/** True only for a real hello answer: an error reply also echoes rid, so check the inner body
 *  (a JSON string `{"ok":true,"result":{version,…}}`). */
const isHello = (b) => {
  if (!b || b.length === 0) return false;
  try {
    const m = JSON.parse(b.toString());
    const inner = JSON.parse(m.body);
    return m.rid === 1 && inner.ok === true && inner.result?.version !== undefined;
  } catch {
    return false;
  }
};

if (mode === "serve") {
  // 1. Not shush-host.exe: the image check closes the pipe before reading a byte.
  const c = net.connect(PIPE);
  await new Promise((res, rej) => { c.once("connect", res); c.once("error", rej); });
  const r = reader(c);
  c.write(HELLO);
  const got = await r.next(3000);
  report(got === null, "non-host client (node.exe) is closed without an answer");
  c.destroy();

  // 2. The real host passes the image check and gets answers.
  const h = host();
  report(isHello(await h.send()), "shush-host.exe gets an answer through the pipe");
  h.p.stdin.end();
  await h.exited;

  // 3. Rate limit: 30 requests per second per connection, then it hangs up. All 45 frames are
  // written at once so the 30 allowed ones land well inside the 1 s window even on a slow build.
  const rl = host();
  rl.p.stdin.write(Buffer.concat(Array.from({ length: 45 }, () => HELLO)));
  let replies = 0;
  for (let i = 0; i < 45; i++) {
    if (!isHello(await rl.r.next())) break;
    replies++;
  }
  const code = await Promise.race([rl.exited, sleep(5000).then(() => "timeout")]);
  report(replies === 30, `rate limit: ${replies} answers then the connection is cut (want 30)`);
  report(code !== 0 && code !== "timeout", `rate limit: host exits with an error (code ${code})`);
  await sleep(300);

  // 4. Connection cap: 8 live connections, the 9th is dropped unread.
  const held = [];
  for (let i = 0; i < 8; i++) {
    const x = host();
    if (isHello(await x.send())) held.push(x); else x.p.kill();
  }
  report(held.length === 8, `connection cap: ${held.length} of 8 connections served`);
  const ninth = host();
  const ans = await ninth.send();
  const c9 = await Promise.race([ninth.exited, sleep(5000).then(() => "timeout")]);
  report(!isHello(ans) && c9 !== 0 && c9 !== "timeout", `connection cap: 9th connection dropped (code ${c9})`);
  const freed = held.pop();
  freed.p.stdin.end();
  await Promise.race([freed.exited, sleep(5000)]);
  await sleep(500); // let the server thread see the close and free its slot
  const again = host();
  report(isHello(await again.send()), "connection cap: a slot frees up when one connection closes");
  again.p.stdin.end();
  for (const x of held) x.p.stdin.end();
  await sleep(300);
} else if (mode === "squat") {
  const s = net.createServer((sock) => sock.on("error", () => {}));
  s.on("error", (e) => { console.log("squat failed: " + e.message); process.exit(2); });
  s.listen(PIPE, () => console.log("squatting " + PIPE));
  await new Promise(() => {}); // until killed
} else if (mode === "refuse") {
  const h = host();
  const ans = await h.send();
  const code = await Promise.race([h.exited, sleep(5000).then(() => "timeout")]);
  report(!isHello(ans) && code !== 0 && code !== "timeout" && /unexpected peer/i.test(h.err()),
    `shush-host.exe refuses a pipe not served by shush.exe (code ${code}, ${h.err().trim()})`);
} else {
  console.error("usage: pipe-probe.mjs serve|squat|refuse <shush-host.exe>");
  process.exit(64);
}
process.exit(failures);
