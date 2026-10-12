package main

// web/vcrypto.mjs (phone) and this daemon must agree byte for byte. Runs the phone's code under
// Node; skipped when node isn't installed.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"os/exec"
	"testing"
)

func TestPhoneCryptoCompat(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	rnd := func(n int) []byte { b := make([]byte, n); rand.Read(b); return b }
	prf, vmk := rnd(32), rnd(32)
	k, _ := kek(prf, kekInfoPRF)
	vmkWrap, _ := seal(k, vmk, vmkAAD)
	goMeta := `{"name":"GO"}`
	goBox, _ := seal(vmk, []byte("from-go"), secretAAD(goMeta))
	inbox, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(inbox)
	inboxPrivBox, _ := seal(vmk, der, inboxPrivAAD)
	inboxPub, _ := inbox.PublicKey.ECDH()
	depBox, err := sealToInbox(inboxPub.Bytes(), []byte("déposé ✓"), depositAAD("dep1"))
	if err != nil {
		t.Fatal(err)
	}
	challenge, credID := rnd(32), rnd(16)
	in, _ := json.Marshal(map[string]any{"prf": b64u(prf), "value": "pässwörd-✓-" + b64u(rnd(8)), "go_vmk_wrap": vmkWrap,
		"go_meta_json": goMeta, "go_box": goBox, "go_inbox_priv_box": inboxPrivBox, "go_deposit_box": depBox,
		"deposit_id": "dep1", "go_vmk_raw": b64u(vmk), "challenge": b64u(challenge), "cred_id": b64u(credID)})
	var inMap map[string]any
	json.Unmarshal(in, &inMap)
	cmd := exec.Command(node, "../../tests/crypto_compat.mjs", string(in))
	outRaw, err := cmd.Output()
	if err != nil {
		t.Fatalf("node: %v", err)
	}
	var out struct {
		RecoveryKey  KeyPairBox `json:"recoveryKey"`
		ReenrollMsg  string     `json:"reenrollMsg"`
		ReenrollSig  string     `json:"reenrollSig"`
		VMKWrap      Box        `json:"vmkWrap"`
		RecoveryWrap Box        `json:"recoveryWrap"`
		RecoveryText string     `json:"recoveryText"`
		MetaJSON     string     `json:"metaJson"`
		Box          Box        `json:"box"`
		GoOpened     string     `json:"goOpened"`
		GoDeposit    string     `json:"goDeposit"`
		JSInbox      KeyPairBox `json:"jsInbox"`
	}
	if err := json.Unmarshal(outRaw, &out); err != nil {
		t.Fatal(err)
	}
	// JS-sealed secret opens via the PRF key and via the recovery code.
	jsVMK, err := openBox(k, out.VMKWrap, vmkAAD)
	if err != nil {
		t.Fatal("PRF wrap:", err)
	}
	code, err := decodeRecoveryCode(out.RecoveryText)
	if err != nil {
		t.Fatal(err)
	}
	rk, _ := kek(code, kekInfoRecovery)
	jsVMK2, err := openBox(rk, out.RecoveryWrap, vmkAAD)
	if err != nil || !bytes.Equal(jsVMK, jsVMK2) {
		t.Fatal("recovery wrap opens a different key", err)
	}
	if v, err := openBox(jsVMK, out.Box, secretAAD(out.MetaJSON)); err != nil || string(v) != inMap["value"] {
		t.Fatal("secret", err)
	}
	var meta map[string]any
	json.Unmarshal([]byte(out.MetaJSON), &meta)
	if canonicalJSON(meta) != out.MetaJSON {
		t.Fatalf("canonical JSON differs:\n%s\n%s", canonicalJSON(meta), out.MetaJSON)
	}
	if out.GoOpened != "from-go" || out.GoDeposit != "déposé ✓" {
		t.Fatalf("phone could not open what the daemon sealed: %q %q", out.GoOpened, out.GoDeposit)
	}
	// Reenrollment: same message on both sides, and the phone's signature verifies here.
	msg, _ := reenrollMessage(challenge, credID, vmkWrap)
	if b64u(msg) != out.ReenrollMsg {
		t.Fatal("reenrollment message differs between phone and daemon")
	}
	rkPub, _ := unb64u(out.RecoveryKey.Pub)
	sig, _ := unb64u(out.ReenrollSig)
	if !verifyReenroll(rkPub, sig, msg) || verifyReenroll(rkPub, sig, append(msg, 'x')) {
		t.Fatal("phone's reenrollment signature")
	}
	pk8, err := openBox(vmk, out.RecoveryKey.PrivBox, recoveryKeyAAD)
	if err != nil {
		t.Fatal(err)
	}
	if priv, err := x509.ParsePKCS8PrivateKey(pk8); err != nil {
		t.Fatal(err)
	} else if p, _ := priv.(*ecdsa.PrivateKey).PublicKey.ECDH(); !bytes.Equal(p.Bytes(), rkPub) {
		t.Fatal("recovery key pair mismatch")
	}
	// A phone-made inbox works with the daemon's sealing.
	ib8, err := openBox(vmk, out.JSInbox.PrivBox, inboxPrivAAD)
	if err != nil {
		t.Fatal(err)
	}
	ibPriv, err := x509.ParsePKCS8PrivateKey(ib8)
	if err != nil {
		t.Fatal(err)
	}
	ibPub, _ := unb64u(out.JSInbox.Pub)
	if _, err := ecdh.P256().NewPublicKey(ibPub); err != nil {
		t.Fatal(err)
	}
	box, _ := sealToInbox(ibPub, []byte("x"), depositAAD("d"))
	if openDeposit(t, ibPriv.(*ecdsa.PrivateKey), box, "d") != "x" {
		t.Fatal("inbox round trip")
	}
}
