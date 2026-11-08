/**
 * Pairing code utilities for companion extension and shush pairing UI (issue #114).
 * Conforms to RFC 4648 Base32 pairing code specifications in docs/spec/lan-sync.md §3.
 */

export const CODE_LEN = 8;

/**
 * Normalizes pairing code input per docs/spec/lan-sync.md §3:
 * - Strips whitespace and all punctuation
 * - Converts lowercase to uppercase
 * - Maps visual lookalikes: '0' -> 'O', '1' -> 'I', '8' -> 'B'
 * - Truncates to at most CODE_LEN (8) characters
 */
export function normalizeCode(raw: string): string {
  if (!raw) return "";
  let out = "";
  for (const ch of raw) {
    // Skip whitespace and ASCII punctuation
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
 */
export function formatCode(raw: string): string {
  const norm = normalizeCode(raw);
  if (norm.length <= 4) {
    return norm;
  }
  return `${norm.slice(0, 4)}-${norm.slice(4)}`;
}
