import assert from "node:assert/strict";
import { normalizeCode as normalizeTs, formatCode as formatTs } from "../src/lib/pairing.ts";
import { normalizeCode as normalizeJs, formatCode as formatJs } from "../../extension/pairing.js";

for (const [name, normalizeCode, formatCode] of [
  ["TypeScript (src/lib/pairing.ts)", normalizeTs, formatTs],
  ["JavaScript (extension/pairing.js)", normalizeJs, formatJs],
]) {
  // Empty input
  assert.equal(normalizeCode(""), "");
  assert.equal(formatCode(""), "");

  // Basic normalization
  assert.equal(normalizeCode("ABCD-EFGH"), "ABCDEFGH");
  assert.equal(normalizeCode("abcd efgh"), "ABCDEFGH");
  assert.equal(normalizeCode("018X_yz"), "OIBXYZ");

  // Punctuation and symbol stripping
  assert.equal(normalizeCode("a.b:c/d,e!f?g"), "ABCDEFG");
  assert.equal(normalizeCode("018x.yz23extra"), "OIBXYZ23");
  assert.equal(normalizeCode("~`@#$%^&*()_+=[]{}|\\;:'\",.<>/?"), "");

  // Visual lookalikes: 0 -> O, 1 -> I, 8 -> B
  assert.equal(normalizeCode("00001111"), "OOOOIIII");
  assert.equal(normalizeCode("88888888"), "BBBBBBBB");
  assert.equal(normalizeCode("018oib"), "OIBOIB");

  // Length truncation to 8
  assert.equal(normalizeCode("ABCDEFGHIJKL"), "ABCDEFGH");
  assert.equal(normalizeCode("018x yz23 extra chars"), "OIBXYZ23");

  // Dynamic formatting
  assert.equal(formatCode("a"), "A");
  assert.equal(formatCode("ab"), "AB");
  assert.equal(formatCode("abc"), "ABC");
  assert.equal(formatCode("abcd"), "ABCD");
  assert.equal(formatCode("abcde"), "ABCD-E");
  assert.equal(formatCode("abcdef"), "ABCD-EF");
  assert.equal(formatCode("abcdefg"), "ABCD-EFG");
  assert.equal(formatCode("abcdefgh"), "ABCD-EFGH");

  // Format with lookalikes, spaces, punctuation
  assert.equal(formatCode("018x yz23"), "OIBX-YZ23");
  assert.equal(formatCode("a.b:c-d/e_f!g?h"), "ABCD-EFGH");
  assert.equal(formatCode("ABCD-EFGH"), "ABCD-EFGH");
  assert.equal(formatCode("abcdefghijklmnop"), "ABCD-EFGH");

  // Idempotence
  assert.equal(formatCode(formatCode("018x.yz23")), "OIBX-YZ23");
  assert.equal(normalizeCode(normalizeCode("018x.yz23")), "OIBXYZ23");

  console.log(`[PASS] ${name}: all pairing tests passed.`);
}
