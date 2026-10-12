// Phone-side crypto. The vault master key (VMK) only ever exists here, in
// memory, for the length of one approval. Format is documented in
// assentd/vcrypto.py; keep both files in lockstep.

const te = new TextEncoder();
const td = new TextDecoder();

// WebAuthn hashes the PRF input with its own domain separator, so a plain label is fine.
export const PRF_SALT = te.encode("assentd/prf/v1");
const KEK_INFO_PRF = "assentd/kek/prf/v1";
const KEK_INFO_RECOVERY = "assentd/kek/recovery/v1";
const VMK_AAD = "assentd/vmk/v1";
const SECRET_AAD_PREFIX = "assentd/secret/v1\n";

export function b64u(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function unb64u(s) {
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

async function kek(ikm, info) {
  const base = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: te.encode(info) },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

export const kekFromPrf = (prfOutput) => kek(new Uint8Array(prfOutput), KEK_INFO_PRF);
export const kekFromRecovery = (codeBytes) => kek(codeBytes, KEK_INFO_RECOVERY);

async function seal(key, plaintext, aad) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: te.encode(aad) }, key, plaintext);
  return { nonce: b64u(nonce), ct: b64u(ct) };
}

async function open(key, box, aad) {
  return new Uint8Array(await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: unb64u(box.nonce), additionalData: te.encode(aad) }, key, unb64u(box.ct)));
}

export const newVmkBytes = () => crypto.getRandomValues(new Uint8Array(32));

// Recovery key (see assentd/vcrypto.py): an ECDSA key sealed with the VMK. Replacing the passkey
// needs its signature over the enrollment challenge, the new passkey and its key wrap.
const RECOVERY_KEY_AAD = "assentd/recovery-key/v1";
const REENROLL_PREFIX = "assentd/reenroll/v1\n";
const ECDSA = { name: "ECDSA", namedCurve: "P-256" };
const vmkKey = (vmkBytes) => crypto.subtle.importKey("raw", vmkBytes, "AES-GCM", false, ["encrypt", "decrypt"]);
const sha256 = async (bytes) => new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));

export async function newRecoveryKey(vmkBytes) {
  const kp = await crypto.subtle.generateKey(ECDSA, true, ["sign", "verify"]);
  const pub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey));
  const privBox = await seal(await vmkKey(vmkBytes), pkcs8, RECOVERY_KEY_AAD);
  pkcs8.fill(0);
  return { pub: b64u(pub), priv_box: privBox };
}

export async function reenrollMessage(challenge, credId, vmkWrap) {
  const wrap = new Uint8Array([...unb64u(vmkWrap.nonce), ...unb64u(vmkWrap.ct)]);
  return new Uint8Array([...te.encode(REENROLL_PREFIX), ...challenge, ...await sha256(credId), ...await sha256(wrap)]);
}

export async function signReenroll(vmkBytes, privBox, message) {
  const pkcs8 = await open(await vmkKey(vmkBytes), privBox, RECOVERY_KEY_AAD);
  const priv = await crypto.subtle.importKey("pkcs8", pkcs8, ECDSA, false, ["sign"]);
  pkcs8.fill(0);
  return b64u(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, priv, message));  // r||s
}
export const wrapVmk = (kekKey, vmkBytes) => seal(kekKey, vmkBytes, VMK_AAD);

// Raw bytes are only needed to re-wrap the key for a replacement passkey (recovery).
export const unwrapVmkRaw = (kekKey, box) => open(kekKey, box, VMK_AAD);

export function decodeRecoveryCode(text) {
  const s = text.toUpperCase().replace(/[^A-Z2-7]/g, "");
  let bits = 0, acc = 0;
  const out = [];
  for (const ch of s) {
    acc = (acc << 5) | B32.indexOf(ch); bits += 5;
    if (bits >= 8) { out.push((acc >>> (bits - 8)) & 255); bits -= 8; }
    acc &= (1 << bits) - 1;
  }
  if (out.length !== 32) throw new Error("A recovery code is 52 characters (A–Z, 2–7).");
  return new Uint8Array(out);
}

export async function unwrapVmk(kekKey, box) {
  const raw = await open(kekKey, box, VMK_AAD);
  const key = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
  raw.fill(0);
  return key;
}

export const sealSecret = (vmk, metaJson, value) => seal(vmk, te.encode(value), SECRET_AAD_PREFIX + metaJson);
export const openSecret = async (vmk, metaJson, box) => td.decode(await open(vmk, box, SECRET_AAD_PREFIX + metaJson));

// Deposit inbox (format in assentd/vcrypto.py). The private key only ever exists on the
// phone, sealed with the VMK; the Mac encrypts deposits to the public key.
const INBOX_INFO = "assentd/inbox/v1";
const INBOX_PRIV_AAD = "assentd/inbox-key/v1";
const DEPOSIT_AAD_PREFIX = "assentd/deposit/v1\n";
const P256 = { name: "ECDH", namedCurve: "P-256" };

export async function newInbox(vmk) {
  const kp = await crypto.subtle.generateKey(P256, true, ["deriveBits"]);
  const pub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey));
  const privBox = await seal(vmk, pkcs8, INBOX_PRIV_AAD);
  pkcs8.fill(0);
  return { pub: b64u(pub), priv_box: privBox };
}

export async function openDeposit(vmk, privBox, box, depositId) {
  const pkcs8 = await open(vmk, privBox, INBOX_PRIV_AAD);
  const priv = await crypto.subtle.importKey("pkcs8", pkcs8, P256, false, ["deriveBits"]);
  pkcs8.fill(0);
  const ephRaw = unb64u(box.eph);
  const eph = await crypto.subtle.importKey("raw", ephRaw, P256, false, []);
  const shared = await crypto.subtle.deriveBits({ name: "ECDH", public: eph }, priv, 256);
  const base = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: ephRaw, info: te.encode(INBOX_INFO) },
    base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  return td.decode(await open(key, box, DEPOSIT_AAD_PREFIX + depositId));
}

// Recovery code: 32 random bytes as RFC 4648 base32, in dash-separated groups of 4.
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function newRecoveryCode() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  let bits = 0, acc = 0, out = "";
  for (const b of bytes) {
    acc = (acc << 8) | b; bits += 8;
    while (bits >= 5) { out += B32[(acc >>> (bits - 5)) & 31]; bits -= 5; }
    acc &= (1 << bits) - 1;
  }
  if (bits > 0) out += B32[(acc << (5 - bits)) & 31];
  return { bytes, text: out.match(/.{1,4}/g).join("-") };
}

// Canonical metadata JSON: sorted keys, no whitespace. Stored verbatim and bound into the AAD.
export function canonicalJson(obj) {
  if (Array.isArray(obj)) return "[" + obj.map(canonicalJson).join(",") + "]";
  if (obj && typeof obj === "object") {
    return "{" + Object.keys(obj).sort().map((k) => JSON.stringify(k) + ":" + canonicalJson(obj[k])).join(",") + "}";
  }
  return JSON.stringify(obj);
}
