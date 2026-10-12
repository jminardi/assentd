package main

// Web Push to the vault's Home Screen app (RFC 8030 delivery, RFC 8291 payload encryption,
// RFC 8292 VAPID). Payloads are end-to-end encrypted to the subscribing browser, so the push
// service (Apple's, for an iPhone) carries them without being able to read them.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Only real push services may be subscription endpoints, so a subscription can't be used to make
// the daemon POST to arbitrary hosts.
var pushHosts = []string{"web.push.apple.com", "fcm.googleapis.com", "updates.push.services.mozilla.com"}

const recordSize = 4096

type Vapid struct {
	PrivatePEM string `json:"private_pem"`
	Public     string `json:"public"`
}

type PushSub struct {
	Endpoint string `json:"endpoint"`
	Keys     struct {
		P256dh string `json:"p256dh"`
		Auth   string `json:"auth"`
	} `json:"keys"`
	Created float64 `json:"created"`
	Device  string  `json:"device"`
}

func newVapid() (Vapid, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Vapid{}, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return Vapid{}, err
	}
	pub, _ := k.PublicKey.ECDH()
	return Vapid{PrivatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), Public: b64u(pub.Bytes())}, nil
}

func loadVapid(v Vapid) (*ecdsa.PrivateKey, error) {
	blk, _ := pem.Decode([]byte(v.PrivatePEM))
	if blk == nil {
		return nil, errors.New("bad VAPID key")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("VAPID key is not ECDSA")
	}
	return ek, nil
}

func pushEndpointOK(endpoint string) bool {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	for _, h := range pushHosts {
		if host == h || strings.HasSuffix(host, "."+h) {
			return true
		}
	}
	return false
}

func hkdfExtract(salt, ikm []byte) []byte {
	m := hmac.New(sha256.New, salt)
	m.Write(ikm)
	return m.Sum(nil)
}

// hkdfExpand for length <= 32: a single HMAC block.
func hkdfExpand(prk, info []byte, n int) []byte {
	m := hmac.New(sha256.New, prk)
	m.Write(info)
	m.Write([]byte{1})
	return m.Sum(nil)[:n]
}

// pushEncrypt: RFC 8291 aes128gcm content coding, single record.
func pushEncrypt(payload, uaPublic, authSecret []byte) ([]byte, error) {
	ua, err := p256Public(uaPublic)
	if err != nil {
		return nil, err
	}
	as, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := as.ECDH(ua)
	if err != nil {
		return nil, err
	}
	asPublic := as.PublicKey().Bytes()
	salt := make([]byte, 16)
	rand.Read(salt)
	ikm := hkdfExpand(hkdfExtract(authSecret, shared), append(append([]byte("WebPush: info\x00"), uaPublic...), asPublic...), 32)
	prk := hkdfExtract(salt, ikm)
	cek := hkdfExpand(prk, []byte("Content-Encoding: aes128gcm\x00"), 16)
	nonce := hkdfExpand(prk, []byte("Content-Encoding: nonce\x00"), 12)
	if len(payload)+1+16 > recordSize {
		return nil, errors.New("push payload too large")
	}
	g, err := gcm(cek)
	if err != nil {
		return nil, err
	}
	ct := g.Seal(nil, nonce, append(append([]byte{}, payload...), 2), nil) // 0x02: last-record delimiter
	var out bytes.Buffer
	out.Write(salt)
	binary.Write(&out, binary.BigEndian, uint32(recordSize))
	out.WriteByte(byte(len(asPublic)))
	out.Write(asPublic)
	out.Write(ct)
	return out.Bytes(), nil
}

func vapidHeader(key *ecdsa.PrivateKey, endpoint, subject string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	header := b64u([]byte(`{"typ":"JWT","alg":"ES256"}`))
	claims, _ := json.Marshal(map[string]any{"aud": u.Scheme + "://" + u.Host, "exp": time.Now().Unix() + 12*3600, "sub": subject})
	input := header + "." + b64u(claims)
	h := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	pub, _ := key.PublicKey.ECDH()
	return fmt.Sprintf("vapid t=%s.%s, k=%s", input, b64u(sig), b64u(pub.Bytes())), nil
}

var topicRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

// pushTopic: RFC 8030 Topic is at most 32 base64url characters, or Apple answers 400. Other tags
// (e.g. "use:NAS_SUDO") are hashed, so the same tag still maps to the same topic and replaces.
func pushTopic(tag string) string {
	if topicRE.MatchString(tag) {
		return tag
	}
	h := sha256.Sum256([]byte(tag))
	return b64u(h[:])[:32]
}

type pushMessage struct {
	Title string `json:"title"`
	Body  string `json:"body"`
	URL   string `json:"url"`
	Tag   string `json:"tag"`
}

var pushClient = func() *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	return &http.Client{Timeout: 15 * time.Second, Transport: t}
}()

// pushSend POSTs one notification and returns the HTTP status (201 on success; 404/410 mean the
// subscription is gone).
func pushSend(sub PushSub, msg pushMessage, key *ecdsa.PrivateKey, subject string) (int, error) {
	p256dh, err1 := unb64u(sub.Keys.P256dh)
	auth, err2 := unb64u(sub.Keys.Auth)
	if err1 != nil || err2 != nil {
		return 0, errors.New("bad subscription keys")
	}
	payload, _ := json.Marshal(msg)
	body, err := pushEncrypt(payload, p256dh, auth)
	if err != nil {
		return 0, err
	}
	authz, err := vapidHeader(key, sub.Endpoint, subject)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequest("POST", sub.Endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	tag := msg.Tag
	if tag == "" {
		tag = "assentd"
	}
	for k, v := range map[string]string{"Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream",
		"TTL": "600", "Urgency": "high", "Topic": pushTopic(tag), "Authorization": authz} {
		req.Header.Set(k, v)
	}
	resp, err := pushClient.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}
