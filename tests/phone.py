"""The phone's side of the vault formats (a Python mirror of web/vcrypto.mjs), for the tests.

Formats are documented in docs/crypto.md.
"""
import base64
import hashlib
import hmac
import json
import os

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (Encoding, NoEncryption, PrivateFormat, PublicFormat,
                                                          load_der_private_key)

PRF_SALT = b"assentd/prf/v1"
KEK_INFO_PRF = b"assentd/kek/prf/v1"
KEK_INFO_RECOVERY = b"assentd/kek/recovery/v1"
VMK_AAD = b"assentd/vmk/v1"
SECRET_AAD_PREFIX = "assentd/secret/v1\n"
RECOVERY_KEY_AAD = b"assentd/recovery-key/v1"
REENROLL_PREFIX = b"assentd/reenroll/v1\n"
INBOX_INFO = b"assentd/inbox/v1"
INBOX_PRIV_AAD = b"assentd/inbox-key/v1"
DEPOSIT_AAD_PREFIX = "assentd/deposit/v1\n"


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def kek(ikm: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(ikm)


def seal(key: bytes, plaintext: bytes, aad: bytes) -> dict:
    nonce = os.urandom(12)
    return {"nonce": b64u(nonce), "ct": b64u(AESGCM(key).encrypt(nonce, plaintext, aad))}


def open_box(key: bytes, box: dict, aad: bytes) -> bytes:
    return AESGCM(key).decrypt(unb64u(box["nonce"]), unb64u(box["ct"]), aad)


def secret_aad(meta_json: str) -> bytes:
    return (SECRET_AAD_PREFIX + meta_json).encode()


def deposit_aad(deposit_id: str) -> bytes:
    return (DEPOSIT_AAD_PREFIX + deposit_id).encode()


def raw_public(key) -> bytes:
    return key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def keypair_box(vmk: bytes, aad: bytes):
    """A P-256 keypair with its private key sealed under the VMK (recovery key, deposit inbox)."""
    k = ec.generate_private_key(ec.SECP256R1())
    return k, {"pub": b64u(raw_public(k)),
               "priv_box": seal(vmk, k.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption()), aad)}


def reenroll_message(challenge: bytes, cred_id: bytes, vmk_wrap: dict) -> bytes:
    wrap = unb64u(vmk_wrap["nonce"]) + unb64u(vmk_wrap["ct"])
    return REENROLL_PREFIX + challenge + hashlib.sha256(cred_id).digest() + hashlib.sha256(wrap).digest()


def sign_reenroll(priv, message: bytes) -> bytes:
    r, s = decode_dss_signature(priv.sign(message, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def open_from_inbox(priv, box: dict, aad: bytes) -> bytes:
    eph_raw = unb64u(box["eph"])
    shared = priv.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), eph_raw))
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=eph_raw, info=INBOX_INFO).derive(shared)
    return open_box(key, box, aad)


def load_pkcs8(der: bytes):
    return load_der_private_key(der, None)


class SoftPasskey:
    """A P-256 passkey with a deterministic PRF, like iCloud Keychain's (counter stays 0)."""

    def __init__(self, rp_id, origin, key=None, cred_id=None, prf_seed=None):
        self.key = key or ec.generate_private_key(ec.SECP256R1())
        self.cred_id = cred_id or os.urandom(16)
        self.prf_seed = prf_seed or os.urandom(32)
        self.rp_id, self.origin = rp_id, origin

    def _cdj(self, typ, challenge, origin=None):
        return json.dumps({"type": typ, "challenge": b64u(challenge), "origin": origin or self.origin}).encode()

    def create(self, challenge):
        nums = self.key.public_key().public_numbers()
        cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")})
        ad = (hashlib.sha256(self.rp_id.encode()).digest() + bytes([0x45]) + (0).to_bytes(4, "big")
              + bytes(16) + len(self.cred_id).to_bytes(2, "big") + self.cred_id + cose)
        att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": ad})
        return {"attestationObject": b64u(att), "clientDataJSON": b64u(self._cdj("webauthn.create", challenge))}

    def get(self, challenge, origin=None, uv=True):
        ad = hashlib.sha256(self.rp_id.encode()).digest() + bytes([0x05 if uv else 0x01]) + (0).to_bytes(4, "big")
        cdj = self._cdj("webauthn.get", challenge, origin)
        sig = self.key.sign(ad + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256()))
        prf = hmac.new(self.prf_seed, PRF_SALT, hashlib.sha256).digest()
        return {"cred_id": b64u(self.cred_id), "authenticatorData": b64u(ad),
                "clientDataJSON": b64u(cdj), "signature": b64u(sig)}, prf
