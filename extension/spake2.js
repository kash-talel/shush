// SPAKE2 (Ed25519 group, role A) compatible with the Rust `spake2` 0.4 crate
// that shush uses for browser pairing (src-tauri/src/bridge/pairing.rs, #54).
// Self-contained: BigInt Edwards25519 arithmetic plus WebCrypto for hashing.
// Not constant-time. The code is short-lived (2 minutes, 3 attempts) and the
// extension runs on the user's own machine, so timing leaks are out of scope.

const P = (1n << 255n) - 19n;
const L = (1n << 252n) + 27742317777372353535851937790883648493n;
const enc = new TextEncoder();

function mod(a, m = P) {
  const r = a % m;
  return r >= 0n ? r : r + m;
}
function pow(b, e, m = P) {
  let r = 1n;
  b = mod(b, m);
  while (e > 0n) {
    if (e & 1n) r = (r * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return r;
}
function inv(a) {
  return pow(a, P - 2n);
}

const D = mod(-121665n * inv(121666n));
const SQRT_M1 = pow(2n, (P - 1n) / 4n);

// Extended coordinates [X, Y, Z, T].
const IDENTITY = [0n, 1n, 1n, 0n];

function add(p, q) {
  const [x1, y1, z1, t1] = p;
  const [x2, y2, z2, t2] = q;
  const a = mod((y1 - x1) * (y2 - x2));
  const b = mod((y1 + x1) * (y2 + x2));
  const c = mod(2n * D * t1 * t2);
  const d = mod(2n * z1 * z2);
  const e = b - a;
  const f = d - c;
  const g = d + c;
  const h = b + a;
  return [mod(e * f), mod(g * h), mod(f * g), mod(e * h)];
}

function mul(p, k) {
  let r = IDENTITY;
  let q = p;
  while (k > 0n) {
    if (k & 1n) r = add(r, q);
    q = add(q, q);
    k >>= 1n;
  }
  return r;
}

export function decompress(bytes) {
  if (bytes.length !== 32) return null;
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(bytes[i]);
  const sign = y >> 255n;
  y &= (1n << 255n) - 1n;
  if (y >= P) return null;
  const y2 = mod(y * y);
  const u = mod(y2 - 1n);
  const v = mod(D * y2 + 1n);
  let x = mod(u * pow(v, 3n) * pow(u * pow(v, 7n), (P - 5n) / 8n));
  const vx2 = mod(v * x * x);
  if (vx2 !== u) {
    if (vx2 !== mod(-u)) return null;
    x = mod(x * SQRT_M1);
  }
  if (x === 0n && sign === 1n) return null;
  if ((x & 1n) !== sign) x = mod(-x);
  return [x, y, 1n, mod(x * y)];
}

export function compress(p) {
  const zi = inv(p[2]);
  const x = mod(p[0] * zi);
  let y = mod(p[1] * zi);
  if (x & 1n) y |= 1n << 255n;
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(y & 0xffn);
    y >>= 8n;
  }
  return out;
}

const fromHex = (h) => Uint8Array.from(h.match(/../g), (b) => parseInt(b, 16));
// Ed25519 base point: y = 4/5, x even.
const BASEPOINT = decompress(fromHex("5866666666666666666666666666666666666666666666666666666666666666"));
const M = decompress(fromHex("15cfd18e385952982b6a8f8c7854963b58e34388c8e6dae891db756481a02312"));
const N = decompress(fromHex("f04f2e7eb734b2a8f8b472eaf9c3c632576ac64aea650b496a8a20ff00e583c3"));

function bytesToBigBE(b) {
  let r = 0n;
  for (const x of b) r = (r << 8n) | BigInt(x);
  return r;
}
function bytesToBigLE(b) {
  let r = 0n;
  for (let i = b.length - 1; i >= 0; i--) r = (r << 8n) | BigInt(b[i]);
  return r;
}

export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

async function sha256(...parts) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", concat(...parts)));
}

export async function hkdf(ikm, salt, info, len) {
  const key = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(
    await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, key, len * 8),
  );
}

export async function hmac(keyBytes, data) {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, data));
}

async function passwordScalar(pw) {
  const okm = await hkdf(pw, new Uint8Array(0), enc.encode("SPAKE2 pw"), 48);
  return bytesToBigBE(okm) % L;
}

/**
 * Role A. Returns `{ msg, finish(hostMsg) }`; `msg` is the 33-byte `ext_msg`
 * (0x41 side byte + point) and `finish` returns the 32-byte shared secret.
 * `scalarBytes` is for tests only.
 */
export async function startA(password, idA, idB, scalarBytes) {
  const pw = await passwordScalar(password);
  const x = bytesToBigLE(scalarBytes ?? crypto.getRandomValues(new Uint8Array(64))) % L;
  const X = add(mul(BASEPOINT, x), mul(M, pw));
  const msg1 = compress(X);
  return {
    msg: concat(Uint8Array.of(0x41), msg1),
    async finish(msg2) {
      if (msg2.length !== 33 || msg2[0] !== 0x42) throw new Error("BAD_SIDE");
      const Y = decompress(msg2.subarray(1));
      if (!Y) throw new Error("CORRUPT_MESSAGE");
      const unblind = mul(N, mod(-pw, L));
      const K = mul(add(Y, unblind), x);
      return sha256(
        await sha256(password),
        await sha256(idA),
        await sha256(idB),
        msg1,
        msg2.subarray(1),
        compress(K),
      );
    },
  };
}
