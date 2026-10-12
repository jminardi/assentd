package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---- a vault written by the last Python daemon must keep working

type fixture struct {
	RecoveryCode string            `json:"recovery_code_b64u"`
	Secrets      map[string]string `json:"secrets"`
	Passkey      struct {
		Priv    string `json:"priv_pkcs8_b64u"`
		CredID  string `json:"cred_id"`
		PRFSeed string `json:"prf_seed"`
	} `json:"passkey"`
	InboxPriv string `json:"inbox_priv_pkcs8_b64u"`
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := unb64u(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func loadFixture(t *testing.T) (*Store, fixture) {
	t.Helper()
	dir := filepath.Join("testdata", "python-vault")
	st, err := loadStore(filepath.Join(dir, "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fx fixture
	data, _ := os.ReadFile(filepath.Join(dir, "fixture.json"))
	if err := json.Unmarshal(data, &fx); err != nil {
		t.Fatal(err)
	}
	return st, fx
}

func TestPythonStoreLoads(t *testing.T) {
	st, fx := loadFixture(t)
	if len(st.Creds) != 1 || st.RecoveryWrap == nil || st.RecoveryKey == nil || st.Inbox == nil || st.Vapid == nil ||
		len(st.Deposits) != 1 || len(st.PushSubs) != 1 || len(st.Devices) != 1 {
		t.Fatalf("store fields missing: %+v", st)
	}
	// The recovery code opens the VMK, every secret and the recovery key.
	k, _ := kek(mustB64(t, fx.RecoveryCode), kekInfoRecovery)
	vmk, err := openBox(k, *st.RecoveryWrap, vmkAAD)
	if err != nil {
		t.Fatal("recovery wrap:", err)
	}
	for name, want := range fx.Secrets {
		rec := st.Secrets[name]
		got, err := openBox(vmk, rec.Box, secretAAD(rec.MetaJSON))
		if err != nil || string(got) != want {
			t.Fatalf("%s: %q %v", name, got, err)
		}
	}
	if _, err := openBox(vmk, st.RecoveryKey.PrivBox, recoveryKeyAAD); err != nil {
		t.Fatal("recovery key:", err)
	}
	// The passkey PRF opens its own wrap of the same VMK.
	m := hmac.New(sha256.New, mustB64(t, fx.Passkey.PRFSeed))
	m.Write([]byte(prfSalt))
	pk, _ := kek(m.Sum(nil), kekInfoPRF)
	vmk2, err := openBox(pk, st.VMKWraps[fx.Passkey.CredID], vmkAAD)
	if err != nil || !bytes.Equal(vmk, vmk2) {
		t.Fatal("PRF wrap", err)
	}
	// An assertion from the stored passkey verifies against the stored credential.
	priv, err := x509.ParsePKCS8PrivateKey(mustB64(t, fx.Passkey.Priv))
	if err != nil {
		t.Fatal(err)
	}
	ch := []byte("challenge-challenge-challenge-32")
	ad, cdj, sig := softAssert(t, priv.(*ecdsa.PrivateKey), "vault.test", "https://vault.test", ch)
	if _, err := verifyAssertion(st.Creds[0], ad, cdj, sig, ch, "vault.test", "https://vault.test"); err != nil {
		t.Fatal("assertion:", err)
	}
	// The VAPID key it made still signs.
	key, err := loadVapid(*st.Vapid)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := key.PublicKey.ECDH()
	if b64u(pub.Bytes()) != st.Vapid.Public {
		t.Fatal("vapid public key mismatch")
	}
	// The pending deposit opens with the inbox key the phone made.
	ip, err := x509.ParsePKCS8PrivateKey(mustB64(t, fx.InboxPriv))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range st.Deposits {
		if got := openDeposit(t, ip.(*ecdsa.PrivateKey), d.Box, d.ID); got != "deposited-value-1" {
			t.Fatalf("deposit %q", got)
		}
	}
	// Re-saving keeps every field (and the timestamps as numbers the Python side wrote).
	out, err := st.marshal()
	if err != nil {
		t.Fatal(err)
	}
	var a, b map[string]any
	orig, _ := os.ReadFile(filepath.Join("testdata", "python-vault", "store.json"))
	json.Unmarshal(orig, &a)
	json.Unmarshal(out, &b)
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) {
		t.Fatalf("store changed on a load/save round trip:\n%s\n%s", ja, jb)
	}
	// Audit lines it wrote are read back for the Activity screen.
	tail := readAuditTail(filepath.Join("testdata", "python-vault", "audit.jsonl"))
	if len(tail) == 0 || tail[0]["event"] != "device_allowed" {
		t.Fatalf("audit tail: %v", tail)
	}
	// An old "type" secret still lists; its stored policy is read leniently.
	if m := parseMeta(st.Secrets["OLD_TYPE"].MetaJSON); !contains(m.Modes, "type") || m.Name != "OLD_TYPE" {
		t.Fatalf("OLD_TYPE meta %+v", m)
	}
	if m := parseMeta(st.Secrets["API_KEY"].MetaJSON); m.HTTP == nil || m.HTTP.Header != "X-Api-Key: {}" || m.MaxTTL != 3600 {
		t.Fatalf("API_KEY meta %+v", m)
	}
}

func softAssert(t *testing.T, k *ecdsa.PrivateKey, rpID, origin string, challenge []byte) (ad, cdj, sig []byte) {
	t.Helper()
	h := sha256.Sum256([]byte(rpID))
	ad = append(h[:], 0x05, 0, 0, 0, 0)
	cdj, _ = json.Marshal(map[string]string{"type": "webauthn.get", "challenge": b64u(challenge), "origin": origin})
	d := sha256.New()
	d.Write(ad)
	c := sha256.Sum256(cdj)
	d.Write(c[:])
	sig, err := ecdsa.SignASN1(rand.Reader, k, d.Sum(nil))
	if err != nil {
		t.Fatal(err)
	}
	return
}

func openDeposit(t *testing.T, priv *ecdsa.PrivateKey, box Box, id string) string {
	t.Helper()
	ek, err := priv.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	ephRaw := mustB64(t, box.Eph)
	eph, err := ecdh.P256().NewPublicKey(ephRaw)
	if err != nil {
		t.Fatal(err)
	}
	shared, _ := ek.ECDH(eph)
	key, _ := inboxKey(shared, ephRaw)
	out, err := openBox(key, box, depositAAD(id))
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// ---- scrubbing

func TestScrubber(t *testing.T) {
	secret := "sk_live_51HxAbCdEfGhIjKlMnOp"
	s := newScrubber(map[string]string{"K": secret}, nil, nil)
	for form, text := range map[string]string{
		"raw": secret, "hex": hex.EncodeToString([]byte(secret)), "upper hex": strings.ToUpper(hex.EncodeToString([]byte(secret))),
		"base64": base64.StdEncoding.EncodeToString([]byte(secret)), "cut-off echo": "invalid key '" + secret[:14] + "...'",
		"masked echo": secret[:10] + "****" + secret[len(secret)-4:],
	} {
		out := s.scrubText("error: " + text + " end")
		if strings.Contains(out, secret[:10]) || !strings.Contains(out, "[assentd:K]") {
			t.Errorf("%s not redacted: %s", form, out)
		}
	}
	if got := s.scrubText("hello sk_test_other"); got != "hello sk_test_other" {
		t.Errorf("unrelated text changed: %s", got)
	}
	// JSON and URL forms of a value with characters that get escaped.
	odd := "pä\"ss/wörd+1"
	s2 := newScrubber(map[string]string{"P": odd}, nil, nil)
	for _, form := range []string{pyJSONEscape(odd), pyQuote([]byte(odd))} {
		if out := s2.scrubText("x " + form + " y"); out != "x [assentd:P] y" {
			t.Errorf("form %q: %s", form, out)
		}
	}
	if pyJSONEscape("\u00e9\"\n\U0001F600") != "\\u00e9\\\"\\n\\ud83d\\ude00" || pyQuote([]byte("a b/\u00e9")) != "a%20b%2F%C3%A9" {
		t.Error("escaping differs from the JSON / URL forms a server would echo")
	}
	// A value split across reads is still redacted.
	var out bytes.Buffer
	s.pump(&chunkReader{chunks: []string{"head ", secret[:20], secret[20:] + " tail"}}, &out)
	if strings.Contains(out.String(), secret) || !strings.Contains(out.String(), "[assentd:K]") {
		t.Errorf("split value: %s", out.String())
	}
	// Short values aren't redacted, with a warning.
	warned := false
	newScrubber(map[string]string{"S": "abc"}, nil, func(string) { warned = true })
	if !warned {
		t.Error("no warning for a short value")
	}
}

type chunkReader struct{ chunks []string }

func (c *chunkReader) Read(p []byte) (int, error) {
	if len(c.chunks) == 0 {
		return 0, os.ErrClosed
	}
	n := copy(p, c.chunks[0])
	c.chunks = c.chunks[1:]
	return n, nil
}

// ---- policy checks

func TestHostsAndURLs(t *testing.T) {
	for entry, ok := range map[string]bool{"api.example.com": true, "host:8443": true, "*.example.com": false, "*.com": false,
		"169.254.169.254": false, "2130706433": false, "10.1": false, "localhost:8443": false, "a.localhost": false,
		"API.example.com": false, "http://127.0.0.1:80": false} {
		if hostOK(entry) != ok {
			t.Errorf("hostOK(%q) = %v", entry, !ok)
		}
	}
	u, _ := parseRawURL("https://api.x.com/v1/%2e%2e/me?q=%E2%80%AE#frag")
	if d := u.display(); d["host"] != "api.x.com" || d["port"] != nil || d["path"] != "/v1/%2e%2e/me" || d["query"] != "q=%E2%80%AE" {
		t.Errorf("display %v", d)
	}
	for raw, allowed := range map[string]bool{"https://api.x.com/": true, "https://API.X.COM/a": true, "https://api.x.com:443/": true,
		"https://api.x.com:8443/": false, "http://api.x.com/": false, "https://a.api.x.com/": false, "https://x.com/": false} {
		u, err := checkURL(raw)
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if hostAllowed(u, []string{"api.x.com"}) != allowed {
			t.Errorf("hostAllowed(%s) = %v", raw, !allowed)
		}
	}
	for _, raw := range []string{"https://a@api.x.com/", "https://api.x.com\\@evil.test/", "https://api.x.com/x y",
		"https://api.x.com/café", "https://{{vault:K}}.x.com/", "ftp://api.x.com/", "https://api.x.com:99999/", "https://api.x.com//evil"} {
		if _, err := checkURL(raw); err == nil {
			t.Errorf("checkURL(%q) accepted", raw)
		}
	}
	for ip, ok := range map[string]bool{"127.0.0.1": false, "::ffff:127.0.0.1": false, "0.0.0.0": false, "::1": false,
		"224.0.0.1": false, "10.0.0.5": true, "100.101.102.103": true, "93.184.216.34": true} {
		if (checkIP("h", netip.MustParseAddr(ip)) == nil) != ok {
			t.Errorf("checkIP(%s) allowed=%v", ip, !ok)
		}
	}
	for path, ok := range map[string]bool{"/v1/refunds": true, "/v1/refunds/re_1": true, "/v1/refundsX": false,
		"/v1/refunds/../charges": false, "/v1/refunds/%2e%2e/x": false, "/v1/refunds//x": false, "/v1/charges": false} {
		if pathAllowed(path, []string{"/v1/refunds"}) != ok {
			t.Errorf("pathAllowed(%s) = %v", path, !ok)
		}
	}
}

func TestCheckMeta(t *testing.T) {
	base := `"created":1,"description":"","name":"X"`
	good := []string{
		`{` + base + `,"hosts":[],"max_ttl":900,"modes":["command"]}`,
		`{` + base + `,"hosts":["api.x.com"],"max_ttl":600,"modes":["http"],"http":{"header":"Authorization: Basic u:{}","methods":["GET"],"paths":["/v1"]}}`,
	}
	for _, mj := range good {
		if _, err := checkMeta(mj); err != nil {
			t.Errorf("%s: %v", mj, err)
		}
	}
	bad := map[string]string{
		"http without hosts":     `{` + base + `,"hosts":[],"max_ttl":600,"modes":["http"],"http":{"header":"A: {}"}}`,
		"http without header":    `{` + base + `,"hosts":["a.x.com"],"max_ttl":600,"modes":["http"]}`,
		"header without {}":      `{` + base + `,"hosts":["a.x.com"],"max_ttl":600,"modes":["http"],"http":{"header":"Authorization: x"}}`,
		"forbidden header":       `{` + base + `,"hosts":["a.x.com"],"max_ttl":600,"modes":["http"],"http":{"header":"Host: {}"}}`,
		"path with ..":           `{` + base + `,"hosts":["a.x.com"],"max_ttl":600,"modes":["http"],"http":{"header":"A: {}","paths":["/v1/../admin"]}}`,
		"in_url (dropped)":       `{` + base + `,"hosts":["a.x.com"],"max_ttl":600,"modes":["http"],"http":{"header":"A: {}","in_url":true}}`,
		"type mode (dropped)":    `{` + base + `,"hosts":["a.x.com"],"max_ttl":600,"modes":["type"]}`,
		"wildcard host":          `{` + base + `,"hosts":["*.x.com"],"max_ttl":600,"modes":["http"],"http":{"header":"A: {}"}}`,
		"ttl over an hour":       `{` + base + `,"hosts":[],"max_ttl":7200,"modes":["command"]}`,
		"float ttl":              `{` + base + `,"hosts":[],"max_ttl":900.0,"modes":["command"]}`,
		"extra key":              `{` + base + `,"hosts":[],"max_ttl":900,"modes":["command"],"x":1}`,
		"lowercase name":         `{"created":1,"description":"","name":"x","hosts":[],"max_ttl":900,"modes":["command"]}`,
		"loopback outside tests": `{` + base + `,"hosts":["http://127.0.0.1:8080"],"max_ttl":600,"modes":["http"],"http":{"header":"A: {}"}}`,
	}
	for why, mj := range bad {
		if _, err := checkMeta(mj); err == nil {
			t.Errorf("%s accepted", why)
		}
	}
	mj, err := proposalMeta("NEW", &Proposal{Description: "d <&>", Modes: []string{"http"}, Hosts: []string{"api.x.com"},
		HTTP: &HTTPPolc{Header: "Authorization: Bearer {}"}})
	if err != nil || !strings.Contains(mj, `"description":"d <&>"`) || !strings.Contains(mj, `"max_ttl":900`) {
		t.Errorf("proposal %s %v", mj, err)
	}
}

func TestTargets(t *testing.T) {
	meta := Meta{Name: "K", Modes: []string{"http"}, Hosts: []string{"api.x.com"},
		HTTP: &HTTPPolc{Header: "Authorization: Basic user:{}", Methods: []string{"GET", "POST"}, Paths: []string{"/v1"}}}
	metaOf := func(string) Meta { return meta }
	ok := &TargetIn{Method: "POST", URL: "https://api.x.com/v1/a", Use: []string{"K"}, BodyB64: base64.StdEncoding.EncodeToString([]byte("x=1"))}
	tg, err := checkTarget("http", ok, []string{"K"}, metaOf)
	if err != nil {
		t.Fatal(err)
	}
	pub := tg.Public()
	if inj := pub["inject"].([][]string); inj[0][1] != "Authorization" || inj[0][2] != "Basic user:{{vault:K}}" {
		t.Errorf("inject %v", inj)
	}
	cases := map[string]*TargetIn{
		"placeholder in url":  {URL: "https://api.x.com/v1/?k={{vault:K}}", Use: []string{"K"}},
		"placeholder in body": {URL: "https://api.x.com/v1/", Use: []string{"K"}, BodyB64: base64.StdEncoding.EncodeToString([]byte("{{vault:K}}"))},
		"placeholder in -H":   {URL: "https://api.x.com/v1/", Use: []string{"K"}, Headers: json.RawMessage(`[["X","{{vault:K}}"]]`)},
		"forbidden header":    {URL: "https://api.x.com/v1/", Use: []string{"K"}, Headers: json.RawMessage(`[["Host","evil"]]`)},
		"x-forwarded":         {URL: "https://api.x.com/v1/", Use: []string{"K"}, Headers: json.RawMessage(`[["X-Forwarded-Host","evil"]]`)},
		"header collision":    {URL: "https://api.x.com/v1/", Use: []string{"K"}, Headers: json.RawMessage(`[["authorization","x"]]`)},
		"method":              {Method: "DELETE", URL: "https://api.x.com/v1/", Use: []string{"K"}},
		"path":                {URL: "https://api.x.com/v2/", Use: []string{"K"}},
		"host":                {URL: "https://evil.x.com/v1/", Use: []string{"K"}},
		"secret not named":    {URL: "https://api.x.com/v1/"},
		"two secrets":         {URL: "https://api.x.com/v1/", Use: []string{"K", "L"}},
		"non-ascii":           {URL: "https://api.x.com/v1/é", Use: []string{"K"}},
	}
	for why, in := range cases {
		if _, err := checkTarget("http", in, []string{"K"}, metaOf); err == nil {
			t.Errorf("%s accepted", why)
		}
	}
}

// ---- web push

func TestPushTopicAndEncryption(t *testing.T) {
	if pushTopic("welcome") != "welcome" {
		t.Error("plain topic changed")
	}
	if tp := pushTopic("use:NAS_SUDO"); !topicRE.MatchString(tp) || tp != pushTopic("use:NAS_SUDO") {
		t.Errorf("topic %q", tp)
	}
	ua, _ := ecdh.P256().GenerateKey(rand.Reader)
	auth := make([]byte, 16)
	rand.Read(auth)
	body, err := pushEncrypt([]byte(`{"title":"hi"}`), ua.PublicKey().Bytes(), auth)
	if err != nil {
		t.Fatal(err)
	}
	// Decrypt as the browser does (RFC 8291).
	salt, idlen := body[:16], int(body[20])
	if binary.BigEndian.Uint32(body[16:20]) != recordSize {
		t.Fatal("record size")
	}
	asPub, ct := body[21:21+idlen], body[21+idlen:]
	as, _ := ecdh.P256().NewPublicKey(asPub)
	shared, _ := ua.ECDH(as)
	ikm := hkdfExpand(hkdfExtract(auth, shared), append(append([]byte("WebPush: info\x00"), ua.PublicKey().Bytes()...), asPub...), 32)
	prk := hkdfExtract(salt, ikm)
	g, _ := gcm(hkdfExpand(prk, []byte("Content-Encoding: aes128gcm\x00"), 16))
	pt, err := g.Open(nil, hkdfExpand(prk, []byte("Content-Encoding: nonce\x00"), 12), ct, nil)
	if err != nil || string(pt) != "{\"title\":\"hi\"}\x02" {
		t.Fatalf("push decrypt %q %v", pt, err)
	}
	for ep, ok := range map[string]bool{"https://web.push.apple.com/x": true, "https://evil.example.com/push": false,
		"http://web.push.apple.com/x": false, "https://web.push.apple.com.evil.test/x": false} {
		if pushEndpointOK(ep) != ok {
			t.Errorf("endpoint %s", ep)
		}
	}
}

func TestRecoveryCodeAndReenroll(t *testing.T) {
	raw := make([]byte, 32)
	rand.Read(raw)
	code := strings.TrimRight(base32Std(raw), "=")
	grouped := ""
	for i := 0; i < len(code); i += 4 {
		grouped += code[i:min(i+4, len(code))] + "-"
	}
	got, err := decodeRecoveryCode(strings.ToLower(grouped))
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatal("recovery code", err)
	}
	if _, err := decodeRecoveryCode("ABCD"); err == nil {
		t.Error("short code accepted")
	}
	k, _ := ecdsa.GenerateKey(ecdsaCurve(), rand.Reader)
	pub, _ := k.PublicKey.ECDH()
	msg := []byte("message")
	h := sha256.Sum256(msg)
	r, s, _ := ecdsa.Sign(rand.Reader, k, h[:])
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	if !verifyReenroll(pub.Bytes(), sig, msg) || verifyReenroll(pub.Bytes(), sig, append(msg, 'x')) || verifyReenroll(pub.Bytes(), sig[:63], msg) {
		t.Error("reenroll signature check")
	}
}

func base32Std(b []byte) string { return base32.StdEncoding.EncodeToString(b) }

func ecdsaCurve() elliptic.Curve { return elliptic.P256() }
