package main

// Vault formats, shared with the phone (web/vcrypto.mjs; keep both in lockstep). docs/crypto.md
// describes them. The daemon never encrypts or decrypts secrets: that happens on the phone. This
// code exists to check what the phone sends, to seal deposits to the phone, and for the offline
// recovery commands.
//
//   KEK      = HKDF-SHA256(ikm, salt="", info=<label>) -> AES-256-GCM key
//              ikm is the WebAuthn PRF output, or the 32-byte recovery code
//   vmk_wrap = AES-GCM(KEK, VMK, aad=vmkAAD)
//   secret   = AES-GCM(VMK, utf8(value), aad=secretAADPrefix + meta_json)
//   box      = {"nonce": b64url(12 bytes), "ct": b64url(ciphertext||tag)}

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
)

const (
	prfSalt         = "assentd/prf/v1"
	kekInfoPRF      = "assentd/kek/prf/v1"
	kekInfoRecovery = "assentd/kek/recovery/v1"
	vmkAAD          = "assentd/vmk/v1"
	secretAADPrefix = "assentd/secret/v1\n"
	// Recovery key: a P-256 ECDSA keypair made at enrollment; private key (PKCS#8) sealed with the
	// VMK, public key stored in the clear. Replacing the passkey needs a signature from it, which
	// only someone who opened the VMK (with the recovery code) can make.
	recoveryKeyAAD = "assentd/recovery-key/v1"
	reenrollPrefix = "assentd/reenroll/v1\n"
	// Deposit inbox: ECIES over P-256, so the Mac can encrypt to the vault but never decrypt.
	//   inbox   = P-256 keypair made on the phone; private key (PKCS#8) sealed with the VMK
	//   deposit = AES-GCM(HKDF(ECDH(eph, inbox_pub), salt=eph_pub, info=inboxInfo), value,
	//             aad=depositAADPrefix + deposit_id), box["eph"] = eph_pub (uncompressed)
	inboxInfo        = "assentd/inbox/v1"
	inboxPrivAAD     = "assentd/inbox-key/v1"
	depositAADPrefix = "assentd/deposit/v1\n"
)

// Box is an AES-GCM ciphertext. Eph is set only on deposits (the sender's ephemeral key).
type Box struct {
	Nonce string `json:"nonce"`
	Ct    string `json:"ct"`
	Eph   string `json:"eph,omitempty"`
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// unb64u accepts base64url with or without padding, like the Python side did.
func unb64u(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

func kek(ikm []byte, info string) ([]byte, error) {
	return hkdf.Key(sha256.New, ikm, nil, info, 32)
}

func gcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func seal(key, plaintext []byte, aad string) (Box, error) {
	g, err := gcm(key)
	if err != nil {
		return Box{}, err
	}
	nonce := make([]byte, 12)
	rand.Read(nonce)
	return Box{Nonce: b64u(nonce), Ct: b64u(g.Seal(nil, nonce, plaintext, []byte(aad)))}, nil
}

func openBox(key []byte, box Box, aad string) ([]byte, error) {
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	nonce, err1 := unb64u(box.Nonce)
	ct, err2 := unb64u(box.Ct)
	if err1 != nil || err2 != nil || len(nonce) != 12 {
		return nil, errors.New("bad box")
	}
	return g.Open(nil, nonce, ct, []byte(aad))
}

func secretAAD(metaJSON string) string { return secretAADPrefix + metaJSON }

// decodeRecoveryCode: 52 base32 characters, any grouping or case.
func decodeRecoveryCode(code string) ([]byte, error) {
	var b strings.Builder
	for _, c := range strings.ToUpper(code) {
		if (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			b.WriteRune(c)
		}
	}
	s := b.String()
	if pad := len(s) % 8; pad != 0 {
		s += strings.Repeat("=", 8-pad)
	}
	raw, err := base32.StdEncoding.DecodeString(s)
	if err != nil || len(raw) != 32 {
		return nil, errors.New("recovery code must decode to 32 bytes")
	}
	return raw, nil
}

// reenrollMessage is what the recovery key signs: this enrollment's challenge, the new passkey,
// and its key wrap.
func reenrollMessage(challenge, credID []byte, wrap Box) ([]byte, error) {
	nonce, err1 := unb64u(wrap.Nonce)
	ct, err2 := unb64u(wrap.Ct)
	if err1 != nil || err2 != nil {
		return nil, errors.New("bad wrap")
	}
	c := sha256.Sum256(credID)
	w := sha256.Sum256(append(append([]byte{}, nonce...), ct...))
	msg := append([]byte(reenrollPrefix), challenge...)
	msg = append(msg, c[:]...)
	return append(msg, w[:]...), nil
}

// p256Public parses an uncompressed P-256 point, rejecting anything not on the curve.
func p256Public(raw []byte) (*ecdh.PublicKey, error) {
	if len(raw) != 65 || raw[0] != 4 {
		return nil, errors.New("key must be an uncompressed P-256 point")
	}
	return ecdh.P256().NewPublicKey(raw)
}

func ecdsaPublic(raw []byte) (*ecdsa.PublicKey, error) {
	if _, err := p256Public(raw); err != nil {
		return nil, err
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(raw[1:33]), Y: new(big.Int).SetBytes(raw[33:])}, nil
}

// verifyReenroll checks an r||s (64-byte) signature, as WebCrypto produces it.
func verifyReenroll(pubRaw, sig, msg []byte) bool {
	if len(sig) != 64 {
		return false
	}
	pub, err := ecdsaPublic(pubRaw)
	if err != nil {
		return false
	}
	h := sha256.Sum256(msg)
	return ecdsa.Verify(pub, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
}

func depositAAD(id string) string { return depositAADPrefix + id }

func inboxKey(shared, ephRaw []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, shared, ephRaw, inboxInfo, 32)
}

func sealToInbox(pubRaw, plaintext []byte, aad string) (Box, error) {
	pub, err := p256Public(pubRaw)
	if err != nil {
		return Box{}, err
	}
	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return Box{}, err
	}
	shared, err := eph.ECDH(pub)
	if err != nil {
		return Box{}, err
	}
	ephRaw := eph.PublicKey().Bytes()
	key, err := inboxKey(shared, ephRaw)
	if err != nil {
		return Box{}, err
	}
	box, err := seal(key, plaintext, aad)
	box.Eph = b64u(ephRaw)
	return box, err
}
