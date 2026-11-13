/**
 * Pairing code utilities for companion extension popup input and pairing (issue #114).
 * Conforms to RFC 4648 Base32 pairing code specifications in docs/spec/lan-sync.md §3.
 */

import { startA, concat, hkdf, hmac } from "./spake2.js";

export const CODE_LEN = 8;

/**
 * Normalizes pairing code input per docs/spec/lan-sync.md §3:
 * - Strips whitespace and all punctuation
 * - Converts lowercase to uppercase
 * - Maps visual lookalikes: '0' -> 'O', '1' -> 'I', '8' -> 'B'
 * - Truncates to at most CODE_LEN (8) characters
 *
 * @param {string} raw
 * @returns {string}
 */
export function normalizeCode(raw) {
  if (!raw) return "";
  let out = "";
  for (const ch of raw) {
    if (/\s|[!"#$%&'()*+,\-./:;<=>?@[\\\]^_`{|}~]/.test(ch)) {
      continue;
    }
    const upper = ch.toUpperCase();
    if (upper === "0") {
      out += "O";
    } else if (upper === "1") {
      out += "I";
    } else if (upper === "8") {
      out += "B";
    } else {
      out += upper;
    }
    if (out.length === CODE_LEN) {
      break;
    }
  }
  return out;
}

/**
 * Formats pairing code dynamically as 'XXXX-XXXX' for input fields (issue #114):
 * - Automatically normalizes input (stripping whitespace/punctuation, lookalike substitution)
 * - Inserts a hyphen after the 4th character
 *
 * @param {string} raw
 * @returns {string}
 */
export function formatCode(raw) {
  const norm = normalizeCode(raw);
  if (norm.length <= 4) {
    return norm;
  }
  return `${norm.slice(0, 4)}-${norm.slice(4)}`;
}

const ID_EXTENSION = new TextEncoder().encode("shush-bridge-v1/extension");
const ID_SHUSH = new TextEncoder().encode("shush-bridge-v1/shush");
const PAIR_INFO = new TextEncoder().encode("shush-pair-v2");
const CONFIRM_INFO = new TextEncoder().encode("shush-pair-v2-confirm");

/**
 * Extension side of pairing (mirrors `extension_pair` in bridge/pairing.rs).
 * Returns `{ extMsg, proof, pairKey }` as Uint8Arrays.
 *
 * @param {string} code pairing code as typed
 * @param {Uint8Array} hostMsg the `pairing_nonce` from `hello`
 */
export async function pairWithCode(code, hostMsg, scalarBytes) {
  const pw = new TextEncoder().encode(normalizeCode(code));
  const a = await startA(pw, ID_EXTENSION, ID_SHUSH, scalarBytes);
  const k = await a.finish(hostMsg);
  const transcript = concat(a.msg, hostMsg);
  const confirmKey = await hkdf(k, transcript, CONFIRM_INFO, 32);
  const pairKey = await hkdf(k, transcript, PAIR_INFO, 32);
  return { extMsg: a.msg, proof: await hmac(confirmKey, transcript), pairKey };
}
