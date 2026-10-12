// The extension's half of the fill format (the daemon's half is sealTo in cmd/assentd/fill.go;
// docs/crypto.md describes both). Kept separate from background.js so tests can run it under node.
//
//   box = AES-256-GCM(HKDF-SHA256(ECDH(eph, extension key), salt="", info), plaintext, aad)
//   fill:  info = FILL_INFO,  aad = "<request id>\n<origin>\n<tab id>", plaintext = the value
//   proof: info = PROOF_INFO, aad = "proof\n<connection id>",          plaintext = a random nonce
// The fill AAD binds the value to the request, the site and the tab it was approved for. The
// proof shows the daemon that this extension holds the private key for the public key it sent,
// so nothing can claim a paired key it doesn't have.

export const FILL_INFO = "assentd/fill/v1";
export const PROOF_INFO = "assentd/fill-proof/v1";

const enc = new TextEncoder();

export const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
export const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));

export const fillAAD = (id, origin, tabId) => enc.encode(`${id}\n${origin}\n${tabId}`);
export const proofAAD = (id) => enc.encode(`proof\n${id}`);

// openSealed(priv, info, aad, {eph, iv, ct}) -> the plaintext bytes. priv: the extension's ECDH key.
async function openSealed(priv, info, aad, m) {
  const eph = await crypto.subtle.importKey("raw", unb64u(m.eph), { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = await crypto.subtle.deriveBits({ name: "ECDH", public: eph }, priv, 256);
  const hk = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  const aes = await crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(), info: enc.encode(info) },
    hk, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64u(m.iv), additionalData: aad }, aes, unb64u(m.ct)));
}

// openFill(priv, {id, origin, tabId, eph, iv, ct}) -> the value.
export async function openFill(priv, m) {
  return new TextDecoder().decode(await openSealed(priv, FILL_INFO, fillAAD(m.id, m.origin, m.tabId), m));
}

// openProof(priv, {id, eph, iv, ct}) -> the nonce (base64url), to send back to the daemon.
export async function openProof(priv, m) {
  return b64u(await openSealed(priv, PROOF_INFO, proofAAD(m.id), m));
}

// What the popup and the phone show to compare when pairing: the first 8 bytes of
// SHA-256(raw public key), as hex in groups of 4.
export async function fingerprint(pubRaw) {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", pubRaw));
  return [...d.slice(0, 8)].map((b) => b.toString(16).padStart(2, "0")).join("").match(/..../g).join("-");
}
