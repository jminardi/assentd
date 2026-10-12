# assentd's crypto

Standard primitives only (AES-256-GCM, HKDF-SHA256, P-256 ECDH and ECDSA, WebAuthn with the PRF
extension), composed into a small format of our own. The phone side is `web/vcrypto.mjs`
(WebCrypto); the daemon side is `cmd/assentd/vcrypto.go`. `go test ./...` checks that they agree
byte for byte, and that a vault written by the earlier Python daemon still opens.

## Keys

| Key | What it is | Where it lives |
|---|---|---|
| VMK | 32 random bytes, the vault master key; encrypts every secret | Only wrapped, in `store.json`. Unwrapped in the phone page's memory, for one action, after Face ID |
| PRF KEK | `HKDF-SHA256(ikm = WebAuthn PRF output, salt = "", info = "assentd/kek/prf/v1")` | Derived on the phone at each Face ID. The PRF input is `"assentd/prf/v1"` |
| Recovery KEK | `HKDF-SHA256(ikm = recovery code, salt = "", info = "assentd/kek/recovery/v1")` | The recovery code is 32 random bytes, shown once as 52 base32 characters |
| Recovery key | P-256 ECDSA keypair | Public key in the clear; private key (PKCS#8) sealed under the VMK |
| Inbox key | P-256 ECDH keypair, for deposits | Public key in the clear; private key (PKCS#8) sealed under the VMK |
| VAPID key | P-256 ECDSA, signs Web Push requests | Daemon's store, in the clear (it only authenticates pushes) |

The Mac never holds the VMK, the PRF output or the recovery code (except during `sudo
assentd-admin recover-*`, which you run by hand).

## Formats

Every encryption is AES-256-GCM with a random 12-byte nonce, stored as a box:
`{"nonce": b64url(nonce), "ct": b64url(ciphertext || tag)}`. The associated data (AAD) binds each
box to what it is:

| Box | Key | Plaintext | AAD |
|---|---|---|---|
| `vmk_wraps[cred_id]` | PRF KEK of that passkey | VMK | `assentd/vmk/v1` |
| `recovery_wrap` | Recovery KEK | VMK | `assentd/vmk/v1` |
| `secrets[NAME].box` | VMK | the value (UTF-8) | `assentd/secret/v1\n` + `meta_json` |
| `recovery_key.priv_box` | VMK | PKCS#8 private key | `assentd/recovery-key/v1` |
| `inbox.priv_box` | VMK | PKCS#8 private key | `assentd/inbox-key/v1` |
| `deposits[id].box` | see below | the value | `assentd/deposit/v1\n` + deposit id |

`meta_json` is the secret's policy (name, description, modes, hosts, longest approval, HTTP
header and limits) as canonical JSON (sorted keys, no whitespace). Because it is in the AAD,
changing a policy without the VMK makes the secret fail to decrypt, so an edit always re-encrypts
on the phone.

**Deposits** are ECIES to the inbox key: the daemon makes an ephemeral P-256 key, and
`key = HKDF-SHA256(ikm = ECDH(ephemeral, inbox), salt = ephemeral public key, info = "assentd/inbox/v1")`.
The box carries `"eph": b64url(ephemeral public key, uncompressed)`. The daemon forgets the value
and the ephemeral key at once; only the phone, after Face ID, can open it.

## Fill (Chrome extension)

The assentd extension makes a P-256 ECDH key in Chrome (WebCrypto, non-extractable, kept in the
extension's IndexedDB) and sends the public key when it connects. You pair it on the phone, with
Face ID, after comparing its fingerprint: the first 8 bytes of SHA-256(raw public key), as hex in
groups of 4, shown by both the extension's popup and the phone. The daemon stores paired public
keys in `store.json` (`chrome_keys`).

After you approve a fill, the daemon (which received the value from the phone, as for any use)
seals it to the paired key that reported the tab:

```
key  = HKDF-SHA256(ikm = ECDH(ephemeral, extension key), salt = "", info = "assentd/fill/v1")
ct   = AES-256-GCM(key, iv = 12 random bytes, value, aad = request id || "\n" || origin || "\n" || tab id)
sent = {"type": "fill", "id", "tabId", "origin", "eph": b64url(ephemeral public key), "iv", "ct"}
```

The AAD binds the value to the request, the site and the tab it was approved for. The native
messaging host only relays it. `extension/fillcrypto.js` is the extension's side.

Naming a key isn't enough to count as it: right after the extension says which key it has, the
daemon seals 32 random bytes to that key the same way, with `info = "assentd/fill-proof/v1"` and
`aad = "proof\n" || connection id`, and the extension must send them back. Until it does, the
connection gets no pairing request and no fills.

## Passkey replacement

`sudo assentd-admin reenroll` writes a one-hour, single-attempt token. The new phone enters the
recovery code, unwraps the VMK, opens the recovery private key, and signs (ECDSA P-256, SHA-256,
raw r||s):

```
"assentd/reenroll/v1\n" || enrollment challenge || SHA-256(new credential id) || SHA-256(nonce || ct of the new vmk_wrap)
```

The daemon accepts the new passkey only with a valid signature from the stored recovery public
key. So the token alone (root on the Mac, briefly) can't swap in an attacker's passkey: that needs
the recovery code too.

## Web Push

Notifications use RFC 8291 (aes128gcm, ECDH with the browser's subscription key, its auth
secret) and RFC 8292 (VAPID, ES256 JWT), so Apple's push service carries them without reading
them.

## What the crypto doesn't do

It protects the store at rest and keeps the Mac from decrypting it. It doesn't protect against a
compromised daemon, which serves the phone page and could take the VMK on your next Face ID; see
the threat model in the README.
