// Test helper: `node pairing-cli.mjs <code> <host_msg_base64>` prints
// {ext_nonce, proof, pair_key} (base64). Used by the Rust interop test.
import { pairWithCode } from "./pairing.js";

const [code, host] = process.argv.slice(2);
const b64 = (u) => Buffer.from(u).toString("base64");
const r = await pairWithCode(code, new Uint8Array(Buffer.from(host, "base64")));
console.log(JSON.stringify({ ext_nonce: b64(r.extMsg), proof: b64(r.proof), pair_key: b64(r.pairKey) }));
