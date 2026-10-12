// Runs the extension's fill crypto (extension/fillcrypto.js) under Node: opens what the daemon
// sealed (cmd/assentd/fill_test.go) with a non-extractable key, as the extension would.
import { fingerprint, openFill, openProof, unb64u } from "../extension/fillcrypto.js";

const input = JSON.parse(process.argv[2]);
const priv = await crypto.subtle.importKey("pkcs8", unb64u(input.pkcs8), { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
const out = { value: await openFill(priv, input.msg), fingerprint: await fingerprint(unb64u(input.pub)),
  proof: await openProof(priv, input.proof) };
// The AAD binds the value to its request, site and tab: change any and it doesn't open.
for (const [k, v] of [["id", "other"], ["origin", "https://evil.example"], ["tabId", input.msg.tabId + 1]]) {
  try {
    await openFill(priv, { ...input.msg, [k]: v });
    out[`opened_with_other_${k}`] = true;
  } catch { /* expected */ }
}
// A proof is bound to its connection, and a fill box is not a proof (different key derivation).
try { await openProof(priv, { ...input.proof, id: "other" }); out.opened_with_other_proof_id = true; } catch { /* expected */ }
try { await openProof(priv, { ...input.msg }); out.opened_with_other_fill_as_proof = true; } catch { /* expected */ }
console.log(JSON.stringify(out));
