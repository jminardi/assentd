package main

// Minimal WebAuthn verification: ES256 passkeys, attestation "none", UV required.
//
// We only need two things from WebAuthn: proof that a specific passkey (behind Face ID) signed a
// challenge we issued, and the credential's public key from registration. Attestation statements
// are ignored on purpose; the passkey's identity is pinned at enrollment instead.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

const (
	flagUP = 0x01
	flagUV = 0x04
	flagAT = 0x40
)

// Cred is a registered passkey, as stored in store.json.
type Cred struct {
	CredID    string  `json:"cred_id"`
	X         string  `json:"x"`
	Y         string  `json:"y"`
	SignCount int64   `json:"sign_count"`
	AAGUID    string  `json:"aaguid"`
	Created   float64 `json:"created,omitempty"`
	Label     string  `json:"label,omitempty"`
}

type webauthnError struct{ msg string }

func (e webauthnError) Error() string { return e.msg }

func waErr(format string, a ...any) error { return webauthnError{fmt.Sprintf(format, a...)} }

func checkClientData(cdj []byte, typ string, challenge []byte, origin string) error {
	var cd map[string]any
	if err := json.Unmarshal(cdj, &cd); err != nil {
		return waErr("clientDataJSON is not JSON")
	}
	if cd["type"] != typ {
		return waErr("clientData type %q != %q", cd["type"], typ)
	}
	if cd["challenge"] != b64u(challenge) {
		return waErr("challenge mismatch")
	}
	if cd["origin"] != origin {
		return waErr("origin %q != %q", cd["origin"], origin)
	}
	if co, _ := cd["crossOrigin"].(bool); co {
		return waErr("cross-origin ceremony rejected")
	}
	return nil
}

func checkAuthData(ad []byte, rpID string) (byte, int64, error) {
	if len(ad) < 37 {
		return 0, 0, waErr("authenticatorData too short")
	}
	h := sha256.Sum256([]byte(rpID))
	if !bytes.Equal(ad[:32], h[:]) {
		return 0, 0, waErr("rpIdHash mismatch")
	}
	flags := ad[32]
	if flags&flagUP == 0 {
		return 0, 0, waErr("user presence flag not set")
	}
	if flags&flagUV == 0 {
		return 0, 0, waErr("user verification (Face ID) flag not set")
	}
	return flags, int64(binary.BigEndian.Uint32(ad[33:37])), nil
}

func credPublic(c Cred) (*ecdsa.PublicKey, error) {
	x, err1 := unb64u(c.X)
	y, err2 := unb64u(c.Y)
	if err1 != nil || err2 != nil || len(x) > 32 || len(y) > 32 {
		return nil, errors.New("bad key")
	}
	raw := make([]byte, 65)
	raw[0] = 4
	copy(raw[33-len(x):33], x)
	copy(raw[65-len(y):], y)
	return ecdsaPublic(raw)
}

func verifyRegistration(attObj, cdj, challenge []byte, rpID, origin string) (Cred, error) {
	if err := checkClientData(cdj, "webauthn.create", challenge, origin); err != nil {
		return Cred{}, err
	}
	var att struct {
		AuthData []byte `cbor:"authData"`
	}
	if err := cbor.Unmarshal(attObj, &att); err != nil || att.AuthData == nil {
		return Cred{}, waErr("bad attestationObject")
	}
	ad := att.AuthData
	flags, count, err := checkAuthData(ad, rpID)
	if err != nil {
		return Cred{}, err
	}
	if flags&flagAT == 0 || len(ad) < 55 {
		return Cred{}, waErr("no attested credential data")
	}
	aaguid := ad[37:53]
	idLen := int(binary.BigEndian.Uint16(ad[53:55]))
	if len(ad) < 55+idLen {
		return Cred{}, waErr("bad credential id")
	}
	credID := ad[55 : 55+idLen]
	var cose map[int]any
	dec := cbor.NewDecoder(bytes.NewReader(ad[55+idLen:]))
	if err := dec.Decode(&cose); err != nil {
		return Cred{}, waErr("bad COSE key")
	}
	// kty=EC2, alg=ES256, crv=P-256
	if !coseInt(cose[1], 2) || !coseInt(cose[3], -7) || !coseInt(cose[-1], 1) {
		return Cred{}, waErr("only ES256 / P-256 passkeys are supported")
	}
	x, ok1 := cose[-2].([]byte)
	y, ok2 := cose[-3].([]byte)
	if !ok1 || !ok2 {
		return Cred{}, waErr("bad COSE key")
	}
	c := Cred{CredID: b64u(credID), X: b64u(x), Y: b64u(y), SignCount: count, AAGUID: hex.EncodeToString(aaguid)}
	if _, err := credPublic(c); err != nil {
		return Cred{}, waErr("invalid public key")
	}
	return c, nil
}

func coseInt(v any, want int64) bool {
	switch n := v.(type) {
	case int64:
		return n == want
	case uint64:
		return want >= 0 && n == uint64(want)
	}
	return false
}

// verifyAssertion returns the new signature counter.
func verifyAssertion(c Cred, ad, cdj, sig, challenge []byte, rpID, origin string) (int64, error) {
	if err := checkClientData(cdj, "webauthn.get", challenge, origin); err != nil {
		return 0, err
	}
	_, count, err := checkAuthData(ad, rpID)
	if err != nil {
		return 0, err
	}
	pub, err := credPublic(c)
	if err != nil {
		return 0, waErr("bad stored key")
	}
	h := sha256.New()
	h.Write(ad)
	cdh := sha256.Sum256(cdj)
	h.Write(cdh[:])
	if !ecdsa.VerifyASN1(pub, h.Sum(nil), sig) {
		return 0, waErr("bad signature")
	}
	// iCloud Keychain passkeys always report 0; only enforce when the authenticator counts.
	if (count != 0 || c.SignCount != 0) && count <= c.SignCount {
		return 0, waErr("signature counter did not increase (cloned authenticator?)")
	}
	return count, nil
}
