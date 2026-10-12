package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The daemon's sealFill and the extension's openFill (extension/fillcrypto.js) must agree.
func TestFillCryptoCompat(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	priv, _ := ecdh.P256().GenerateKey(rand.Reader)
	pk8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PublicKey().Bytes()
	value := "pässwörd ✓ \"quoted\" " + token(6)
	msg, err := sealFill(pub, value, "req1", "https://login.example.com", 42)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 32)
	rand.Read(nonce)
	proof, err := sealProof(pub, "conn1", nonce)
	if err != nil {
		t.Fatal(err)
	}
	in, _ := json.Marshal(map[string]any{"pkcs8": b64u(pk8), "pub": b64u(pub), "msg": msg, "proof": proof})
	raw, err := exec.Command(node, "../../tests/fill_compat.mjs", string(in)).Output()
	if err != nil {
		t.Fatalf("node: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err, string(raw))
	}
	if out["value"] != value {
		t.Fatalf("extension opened %q, want %q", out["value"], value)
	}
	if out["fingerprint"] != fingerprintOf(pub) {
		t.Fatalf("fingerprints differ: extension %v, daemon %s", out["fingerprint"], fingerprintOf(pub))
	}
	if out["proof"] != b64u(nonce) {
		t.Fatalf("extension opened proof %v, want %s", out["proof"], b64u(nonce))
	}
	for k := range out {
		if strings.HasPrefix(k, "opened_with_other_") {
			t.Fatalf("a box opened with a changed %s", strings.TrimPrefix(k, "opened_with_other_"))
		}
	}
}

func TestFillOrigins(t *testing.T) {
	for raw, want := range map[string]string{
		"https://Login.Example.com/sign-in?x=1": "https://login.example.com",
		"https://login.example.com:443/":        "https://login.example.com",
		"https://login.example.com:8443/a":      "https://login.example.com:8443",
		"http://login.example.com/":             "",
		"https://user@login.example.com/":       "",
		"chrome://settings":                     "",
		"file:///etc/passwd":                    "",
		"":                                      "",
	} {
		got, err := tabOrigin(raw)
		if (err != nil) != (want == "") || got != want {
			t.Errorf("tabOrigin(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	for o, ok := range map[string]bool{"https://login.example.com": true, "https://a.example.com:8443": true,
		"https://login.example.com/": false, "http://login.example.com": false, "https://*.example.com": false,
		"https://127.0.0.1": false, "https://localhost": false, "https://LOGIN.example.com": false} {
		if originOK(o) != ok {
			t.Errorf("originOK(%q) = %v", o, !ok)
		}
	}
	meta := func(extra string) string {
		return `{"created":1,"description":"d","hosts":[],"max_ttl":900,"modes":["fill"],"name":"PW"` + extra + `}`
	}
	if _, err := checkMeta(meta(`,"fill":{"origins":["https://login.example.com"]}`)); err != nil {
		t.Error(err)
	}
	for _, bad := range []string{"", `,"fill":{"origins":[]}`, `,"fill":{"origins":["https://*.example.com"]}`,
		`,"fill":{"origins":["https://x.example.com"],"more":1}`} {
		if _, err := checkMeta(meta(bad)); err == nil {
			t.Errorf("checkMeta accepted %s", bad)
		}
	}
	m := parseMeta(meta(`,"fill":{"origins":["https://login.example.com"]}`))
	if checkFill("PW", &FillTarget{Origin: "https://login.example.com"}, m) != nil ||
		checkFill("PW", &FillTarget{Origin: "https://evil.example.com"}, m) == nil {
		t.Error("checkFill")
	}
}

// The host check reads the kernel's view of a process, which argv[0] can't change: this test
// binary is neither the installed host nor started by Chrome.
func TestChromeHostCheck(t *testing.T) {
	self, _ := os.Executable()
	if p, err := pidPath(os.Getpid()); err != nil || !strings.HasSuffix(self, p[strings.LastIndex(p, "/"):]) {
		t.Fatalf("pidPath(self) = %q, %v; executable %q", p, err, self)
	}
	if ppid, err := parentPID(os.Getpid()); err != nil || ppid != os.Getppid() {
		t.Fatalf("parentPID = %d, %v; want %d", ppid, err, os.Getppid())
	}
	if err := checkChromeHost(os.Getpid()); err == nil {
		t.Fatal("the test binary passed the Chrome host check")
	}
	if f, err := csStatus(1); err != nil || f&0x1 == 0 {
		t.Fatalf("csStatus(launchd) = %#x, %v", f, err)
	}
	if err := chromeStartedMe(); err == nil {
		t.Fatal("go test passed as Google Chrome")
	}
}
