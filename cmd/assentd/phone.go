package main

// The phone page and its API. Served to the tailnet by the tsnet node (front.go), which tells us
// which device and login is calling.

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"assentd/web"
)

const (
	maxBody          = 256 * 1024
	deviceNotAllowed = "device_not_allowed" // the page shows how to allow this device
	deviceKeyChanged = "device_key_changed" // the page asks this device to confirm itself with Face ID
)

var (
	pages       = []string{"/", "/add", "/enroll", "/activity", "/settings"}
	enrollPaths = []string{"/enroll", "/api/enroll/begin", "/api/enroll/finish"}
	pageRE      = regexp.MustCompile(`^/(r|d|edit)/[A-Za-z0-9_-]+$`)
	depositRE   = regexp.MustCompile(`^/api/deposit/([A-Za-z0-9_-]+)$`)
	reqRE       = regexp.MustCompile(`^/api/req/([A-Za-z0-9_-]+)$`)
	decideDepRE = regexp.MustCompile(`^/api/deposit/([A-Za-z0-9_-]+)/(accept|reject)$`)
	decideReqRE = regexp.MustCompile(`^/api/req/([A-Za-z0-9_-]+)/(approve|deny)$`)
	static      = map[string]string{
		"/app.mjs": "text/javascript; charset=utf-8", "/vcrypto.mjs": "text/javascript; charset=utf-8",
		"/style.css": "text/css; charset=utf-8", "/sw.js": "text/javascript; charset=utf-8",
		"/manifest.webmanifest": "application/manifest+json", "/icon-32.png": "image/png", "/icon-180.png": "image/png",
		"/icon-192.png": "image/png", "/icon-512.png": "image/png",
	}
)

const notAllowedPage = `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>assentd</title><body style="font:17px/1.45 -apple-system,system-ui,sans-serif;padding:48px 24px;max-width:28em;margin:auto">
<h1 style="font-size:22px">This device can't open the vault</h1>
<p>Only devices you've allowed can see the vault. To allow this one, open assentd on your phone,
go to Settings, and approve it under <b>Devices</b>.</p></body>`

const csp = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"connect-src 'self'; manifest-src 'self'; worker-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// Set on every response.
var securityHeaders = map[string]string{
	"Strict-Transport-Security":    "max-age=31536000",
	"Cross-Origin-Opener-Policy":   "same-origin",
	"Cross-Origin-Resource-Policy": "same-origin",
	"Permissions-Policy":           "camera=(), microphone=(), geolocation=(), payment=(), usb=(), publickey-credentials-create=(self), publickey-credentials-get=(self)",
	"X-Content-Type-Options":       "nosniff",
	"X-Frame-Options":              "DENY",
	"Referrer-Policy":              "no-referrer",
	"Content-Security-Policy":      csp,
	"Cache-Control":                "no-store",
}

// Caller is who is on the other end: a tailnet device and login. nil only where no identity applies.
type Caller struct {
	Device
	label string
	// rekeyOnly: an allowed device that came back with a new tailnet key (Tailscale reinstalled,
	// or its key rotated). It may only load the page and confirm itself with Face ID.
	rekeyOnly bool
}

type phone struct{ v *Vault }

func writeJSON(w http.ResponseWriter, status int, obj any) {
	data, _ := json.Marshal(obj)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(data)
}

func fail(w http.ResponseWriter, err error) {
	var ae *apiError
	if errors.As(err, &ae) {
		writeJSON(w, ae.status, map[string]any{"error": ae.msg})
		return
	}
	log.Printf("internal error: %v", err)
	writeJSON(w, 500, map[string]any{"error": "internal error"})
}

// serve handles one request from an identified tailnet caller (ident nil: unknown).
func (p *phone) serve(w http.ResponseWriter, r *http.Request, ident *Device) {
	for k, val := range securityHeaders {
		w.Header().Set(k, val)
	}
	urlPath := r.URL.Path
	caller, err := p.authorize(urlPath, ident)
	if err != nil {
		if err.Error() == deviceNotAllowed && r.Method == http.MethodGet && !strings.HasPrefix(urlPath, "/api/") {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(403)
			io.WriteString(w, notAllowedPage)
			return
		}
		fail(w, err)
		return
	}
	if caller.rekeyOnly {
		page := (r.Method == http.MethodGet || r.Method == http.MethodHead) && !strings.HasPrefix(urlPath, "/api/")
		if !page && !(r.Method == http.MethodPost && (urlPath == "/api/rekey/challenge" || urlPath == "/api/rekey")) {
			fail(w, apiErr(403, deviceKeyChanged))
			return
		}
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		p.get(w, urlPath)
	case http.MethodPost:
		if r.Header.Get("Origin") != p.v.cfg.Origin {
			fail(w, apiErr(403, "bad origin"))
			return
		}
		if r.ContentLength > maxBody {
			fail(w, apiErr(413, "body too large"))
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		if err != nil || len(raw) > maxBody {
			fail(w, apiErr(413, "body too large"))
			return
		}
		if len(raw) == 0 {
			raw = []byte("{}")
		}
		var probe map[string]json.RawMessage
		if json.Unmarshal(raw, &probe) != nil || probe == nil {
			fail(w, apiErr(400, "body must be a JSON object"))
			return
		}
		p.v.mu.Lock()
		out, err := p.route(urlPath, raw, caller)
		p.v.mu.Unlock()
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, out)
	default:
		fail(w, apiErr(405, "method not allowed"))
	}
}

// authorize decides whether this device may use the page.
func (p *phone) authorize(urlPath string, ident *Device) (*Caller, error) {
	v := p.v
	if ident == nil || ident.Node == "" || ident.NodeID == "" || ident.NodeKey == "" || ident.Login == "" {
		return nil, apiErr(403, "unknown tailnet device")
	}
	if !contains(v.cfg.AllowedLogins, ident.Login) {
		return nil, apiErr(403, "this tailnet user may not use the vault")
	}
	c := &Caller{Device: *ident, label: ident.Node + " (" + ident.Login + ")"}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.deviceAllowed(*ident) {
		return c, nil
	}
	// Enrolling (first time, or a root-opened reenroll window) works from any of your devices;
	// whichever device finishes becomes the allowed one.
	_, isStatic := static[urlPath]
	if (!v.enrolled() || v.reenrollToken() != "") && (contains(enrollPaths, urlPath) || isStatic) {
		return c, nil
	}
	v.noteBlockedDevice(*ident)
	if v.enrolled() && v.rekeyable(*ident) {
		c.rekeyOnly = true
		return c, nil
	}
	return nil, apiErr(403, deviceNotAllowed)
}

func (p *phone) get(w http.ResponseWriter, urlPath string) {
	if contains(pages, urlPath) || pageRE.MatchString(urlPath) {
		serveFile(w, "index.html", "text/html; charset=utf-8")
		return
	}
	if ctype, ok := static[urlPath]; ok {
		serveFile(w, strings.TrimPrefix(urlPath, "/"), ctype)
		return
	}
	v := p.v
	v.mu.Lock()
	defer v.mu.Unlock()
	if urlPath == "/api/state" {
		writeJSON(w, 200, v.state())
		return
	}
	if m := depositRE.FindStringSubmatch(urlPath); m != nil {
		d := v.store.Deposits[m[1]]
		if d == nil {
			if outcome := v.depositOutcome[m[1]]; outcome != "" {
				fail(w, apiErr(404, "deposit already %s", outcome))
			} else {
				fail(w, apiErr(404, "no such deposit"))
			}
			return
		}
		writeJSON(w, 200, v.publicDeposit(d))
		return
	}
	if m := reqRE.FindStringSubmatch(urlPath); m != nil {
		r := v.requests[m[1]]
		if r == nil {
			fail(w, apiErr(404, "no such request (it may have expired)"))
			return
		}
		writeJSON(w, 200, v.publicRequest(r))
		return
	}
	writeJSON(w, 404, map[string]any{"error": "not found"})
}

func serveFile(w http.ResponseWriter, name, ctype string) {
	data, err := fs.ReadFile(web.Files, name)
	if err != nil {
		writeJSON(w, 404, map[string]any{"error": "not found"})
		return
	}
	if ctype == "" {
		ctype = mime.TypeByExtension(path.Ext(name))
	}
	w.Header().Set("Content-Type", ctype)
	w.Write(data)
}

// ---- POST routes (v.mu held)

type postBody struct {
	Action      string          `json:"action"`
	Kind        string          `json:"kind"`
	Ref         string          `json:"ref"`
	Name        string          `json:"name"`
	NodeID      string          `json:"node_id"`
	ChallengeID string          `json:"challenge_id"`
	Assertion   *Assertion      `json:"assertion"`
	InboxSetup  *KeyPairBox     `json:"inbox_setup"`
	MetaJSON    string          `json:"meta_json"`
	Box         *Box            `json:"box"`
	Overwrite   bool            `json:"overwrite"`
	All         bool            `json:"all"`
	GrantID     string          `json:"grant_id"`
	Endpoint    string          `json:"endpoint"`
	Choice      string          `json:"choice"`
	Values      json.RawMessage `json:"values"`
	Creates     json.RawMessage `json:"creates"`
	Sub         *PushSub        `json:"subscription"`
	ID          string          `json:"id"`
	Fingerprint string          `json:"fingerprint"`
	// enrollment
	Token             string      `json:"token"`
	CreateChallengeID string      `json:"create_challenge_id"`
	GetChallengeID    string      `json:"get_challenge_id"`
	AttestationObject string      `json:"attestationObject"`
	ClientDataJSON    string      `json:"clientDataJSON"`
	Label             string      `json:"label"`
	VMKWrap           *Box        `json:"vmk_wrap"`
	RecoveryWrap      *Box        `json:"recovery_wrap"`
	RecoveryKey       *KeyPairBox `json:"recovery_key"`
	RecoverySig       string      `json:"recovery_sig"`
}

func (p *phone) route(urlPath string, raw []byte, c *Caller) (any, error) {
	v := p.v
	var b postBody
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, apiErr(400, "bad request body")
	}
	ok := map[string]any{"ok": true}
	switch urlPath {
	case "/api/enroll/begin":
		return p.enrollBegin(&b)
	case "/api/enroll/finish":
		return p.enrollFinish(&b, c)
	}
	if !v.enrolled() {
		return nil, apiErr(409, "not enrolled yet")
	}
	switch urlPath {
	case "/api/challenge":
		return p.challenge(&b)
	case "/api/unlock":
		return p.unlock(&b)
	case "/api/add":
		return p.add(&b, c)
	case "/api/delete":
		if _, err := v.takeAction(b.Action, []string{"delete"}, &b.Name); err != nil {
			return nil, err
		}
		if err := v.maybeSetupInbox(b.InboxSetup); err != nil {
			return nil, err
		}
		if _, exists := v.store.Secrets[b.Name]; !exists {
			return nil, apiErr(404, "no such secret")
		}
		delete(v.store.Secrets, b.Name)
		v.save()
		v.revoke(hasName(b.Name), b.Name+" deleted")
		v.audit("secret_deleted", map[string]any{"name": b.Name, "device": c.label})
		return ok, nil
	case "/api/devices/allow":
		if _, err := v.takeAction(b.Action, []string{"device"}, &b.NodeID); err != nil {
			return nil, err
		}
		req := v.deviceRequests[b.NodeID]
		if req == nil {
			return nil, apiErr(404, "that device hasn't asked to open the vault (or asked over a day ago)")
		}
		d := req.Device
		d.Added = 0
		v.allowDevice(d, "allowed from "+c.label)
		return ok, nil
	case "/api/devices/dismiss":
		delete(v.deviceRequests, b.NodeID)
		return ok, nil
	case "/api/devices/remove":
		if b.NodeID == c.NodeID {
			return nil, apiErr(400, "you can't remove the device you're using")
		}
		keep := []Device{}
		for _, d := range v.store.Devices {
			if d.NodeID != b.NodeID {
				keep = append(keep, d)
			}
		}
		if len(keep) != len(v.store.Devices) {
			v.store.Devices = keep
			v.save()
			v.audit("device_removed", map[string]any{"node_id": b.NodeID, "by": c.label})
		}
		return ok, nil
	case "/api/rekey/challenge":
		if !c.rekeyOnly {
			return nil, apiErr(400, "this device is already allowed")
		}
		id, ch := v.newChallenge("rekey", c.NodeID)
		ids := []string{}
		for _, cr := range v.store.Creds {
			ids = append(ids, cr.CredID)
		}
		return map[string]any{"rp_id": v.cfg.RPID, "cred_ids": ids, "challenge_id": id, "challenge": b64u(ch)}, nil
	case "/api/rekey":
		// Face ID on the device itself, with the vault's passkey: no ciphertext is involved.
		if !c.rekeyOnly {
			return nil, apiErr(400, "this device is already allowed")
		}
		ch, err := v.takeChallenge(b.ChallengeID, []string{"rekey"}, &c.NodeID)
		if err != nil {
			return nil, err
		}
		if _, err := v.verify(b.Assertion, ch.Challenge); err != nil {
			return nil, err
		}
		if !v.rekeyable(c.Device) {
			return nil, apiErr(403, deviceNotAllowed)
		}
		v.allowDevice(c.Device, "came back with a new tailnet key; confirmed with Face ID on it")
		return ok, nil
	case "/api/deposits/reject":
		// Rejecting only destroys values Claude handed in; like Deny, it needs no Face ID.
		n := 0
		for id, d := range v.store.Deposits {
			delete(v.store.Deposits, id)
			v.depositOutcome[id] = "rejected"
			v.audit("deposit_rejected", map[string]any{"deposit": id, "name": d.Name, "provenance": d.Provenance, "device": c.label})
			n++
		}
		if n > 0 {
			v.save()
		}
		return map[string]any{"ok": true, "rejected": n}, nil
	case "/api/push/subscribe":
		return p.pushSubscribe(&b, c)
	case "/api/push/unsubscribe":
		// Knowing the endpoint (never exposed by the API) is the authority to remove it.
		keep := []PushSub{}
		for _, s := range v.store.PushSubs {
			if s.Endpoint != b.Endpoint {
				keep = append(keep, s)
			}
		}
		if len(keep) != len(v.store.PushSubs) {
			v.store.PushSubs = keep
			v.save()
			v.audit("push_device_removed", map[string]any{"device": c.label})
		}
		return map[string]any{"ok": true, "devices": len(v.store.PushSubs)}, nil
	case "/api/inbox":
		if _, err := v.takeAction(b.Action, []string{"inbox"}, nil); err != nil {
			return nil, err
		}
		if err := v.maybeSetupInbox(b.InboxSetup); err != nil {
			return nil, err
		}
		return map[string]any{"ok": true, "inbox": v.store.Inbox != nil}, nil
	case "/api/chrome/pair":
		// Pairing lets this extension receive fills (each still needs Face ID), so it needs Face ID too.
		if _, err := v.takeAction(b.Action, []string{"chrome"}, &b.ID); err != nil {
			return nil, err
		}
		if err := v.maybeSetupInbox(b.InboxSetup); err != nil {
			return nil, err
		}
		pr := v.pairings[b.ID]
		if pr == nil {
			return nil, apiErr(404, "that pairing request is gone; open the extension's popup to ask again")
		}
		pub, _ := unb64u(pr.Pub)
		delete(v.pairings, b.ID)
		if v.chromeKeyIndex(pub) < 0 {
			if len(v.store.ChromeKeys) >= maxChromeKeys {
				return nil, apiErr(409, "too many paired Chrome extensions; remove one first")
			}
			v.store.ChromeKeys = append(v.store.ChromeKeys, ChromeKey{Pub: pr.Pub, Fingerprint: pr.Fingerprint,
				Added: float64(now64()), By: c.label})
			v.save()
			v.audit("chrome_paired", map[string]any{"fingerprint": pr.Fingerprint, "device": c.label})
		}
		v.broadcastPairing()
		return ok, nil
	case "/api/chrome/dismiss":
		if pr := v.pairings[b.ID]; pr != nil {
			delete(v.pairings, b.ID)
			v.audit("chrome_pair_dismissed", map[string]any{"fingerprint": pr.Fingerprint, "device": c.label})
			v.broadcastPairing()
		}
		return ok, nil
	case "/api/chrome/remove":
		keep := []ChromeKey{}
		for _, k := range v.store.ChromeKeys {
			if k.Fingerprint != b.Fingerprint {
				keep = append(keep, k)
			}
		}
		if len(keep) != len(v.store.ChromeKeys) {
			v.store.ChromeKeys = keep
			v.save()
			v.audit("chrome_removed", map[string]any{"fingerprint": b.Fingerprint, "device": c.label})
			v.broadcastPairing()
		}
		return ok, nil
	case "/api/revoke":
		var n int
		if b.All {
			n = v.revoke(func(*Grant) bool { return true }, "revoked all from phone")
		} else {
			n = v.revoke(func(g *Grant) bool { return g.ID == b.GrantID }, "revoked from phone")
		}
		return map[string]any{"revoked": n}, nil
	}
	if m := decideDepRE.FindStringSubmatch(urlPath); m != nil {
		d := v.store.Deposits[m[1]]
		if d == nil {
			return nil, apiErr(404, "no such deposit")
		}
		return p.depositDecide(d, &b, m[2], c)
	}
	if m := decideReqRE.FindStringSubmatch(urlPath); m != nil {
		r := v.requests[m[1]]
		if r == nil {
			return nil, apiErr(404, "no such request (it may have expired)")
		}
		if r.Status != "pending" {
			return nil, apiErr(409, "request is already %s", r.Status)
		}
		if m[2] == "deny" {
			r.Status, r.Decided = "denied", now()
			v.audit("denied", map[string]any{"request": r.ID, "names": r.Needs})
			return ok, nil
		}
		return p.approve(r, &b, c)
	}
	return nil, apiErr(404, "not found")
}

// ---- enrollment: first passkey via the install-time token; replacement via a root-issued
// reenroll token.

func (p *phone) enrollMode(b *postBody) (string, error) {
	v := p.v
	if b.Token == "" {
		return "", apiErr(403, "missing enrollment token")
	}
	if !v.enrolled() {
		if v.cfg.EnrollToken != "" && subtle.ConstantTimeCompare([]byte(b.Token), []byte(v.cfg.EnrollToken)) == 1 {
			return "first", nil
		}
	} else {
		if t := v.reenrollToken(); t != "" && subtle.ConstantTimeCompare([]byte(b.Token), []byte(t)) == 1 {
			return "recover", nil
		}
		return "", apiErr(409, "already enrolled (use sudo assentd-admin reenroll to replace the passkey)")
	}
	v.audit("enroll_rejected", map[string]any{"reason": "bad token"})
	return "", apiErr(403, "bad enrollment token")
}

func (p *phone) enrollBegin(b *postBody) (any, error) {
	v := p.v
	mode, err := p.enrollMode(b)
	if err != nil {
		return nil, err
	}
	cid, cch := v.newChallenge("enroll-create", "")
	gid, gch := v.newChallenge("enroll-get", "")
	uid := make([]byte, 16)
	rand.Read(uid)
	out := map[string]any{"mode": mode, "rp_id": v.cfg.RPID, "user_id": b64u(uid),
		"create": map[string]any{"challenge_id": cid, "challenge": b64u(cch)},
		"get":    map[string]any{"challenge_id": gid, "challenge": b64u(gch)}}
	if mode == "recover" {
		out["recovery_wrap"] = v.store.RecoveryWrap
		if v.store.RecoveryKey != nil {
			out["recovery_key_box"] = v.store.RecoveryKey.PrivBox
		}
	}
	return out, nil
}

func (p *phone) enrollFinish(b *postBody, c *Caller) (any, error) {
	mode, err := p.enrollMode(b)
	if err != nil {
		return nil, err
	}
	out, err := p.doEnrollFinish(b, mode, c)
	if err != nil && mode == "recover" {
		// A reenroll link is good for one attempt: a wrong guess burns it.
		os.Remove(filepath.Join(p.v.dataDir, reenrollFile))
	}
	return out, err
}

func (p *phone) doEnrollFinish(b *postBody, mode string, c *Caller) (any, error) {
	v := p.v
	cc, err := v.takeChallenge(b.CreateChallengeID, []string{"enroll-create"}, nil)
	if err != nil {
		return nil, err
	}
	gc, err := v.takeChallenge(b.GetChallengeID, []string{"enroll-get"}, nil)
	if err != nil {
		return nil, err
	}
	reject := func(e error) error {
		v.audit("enroll_rejected", map[string]any{"reason": e.Error()})
		return apiErr(403, "passkey verification failed: %s", e)
	}
	att, err1 := unb64u(b.AttestationObject)
	cdj, err2 := unb64u(b.ClientDataJSON)
	if err1 != nil || err2 != nil {
		return nil, reject(waErr("bad base64url"))
	}
	cred, err := verifyRegistration(att, cdj, cc.Challenge, v.cfg.RPID, v.cfg.Origin)
	if err != nil {
		return nil, reject(err)
	}
	if b.Assertion == nil || b.Assertion.CredID != cred.CredID {
		return nil, reject(waErr("unlock used a different passkey"))
	}
	ad, acdj, sig, err := b.Assertion.decode()
	if err == nil {
		cred.SignCount, err = verifyAssertion(cred, ad, acdj, sig, gc.Challenge, v.cfg.RPID, v.cfg.Origin)
	}
	if err != nil {
		return nil, reject(err)
	}
	cred.Created = float64(now64())
	cred.Label = b.Label
	if cred.Label == "" {
		cred.Label = "phone"
	}
	if r := []rune(cred.Label); len(r) > 60 {
		cred.Label = string(r[:60])
	}
	vmkWrap, err := checkBox(b.VMKWrap)
	if err != nil {
		return nil, err
	}
	if mode == "first" {
		rk := b.RecoveryKey
		if rk == nil {
			return nil, apiErr(400, "bad recovery key")
		}
		pub, err := unb64u(rk.Pub)
		if err == nil {
			_, err = p256Public(pub)
		}
		if err != nil {
			return nil, apiErr(400, "bad recovery key")
		}
		rw, err := checkBox(b.RecoveryWrap)
		if err != nil {
			return nil, err
		}
		rkb, err := checkBox(&rk.PrivBox)
		if err != nil {
			return nil, err
		}
		v.store.RecoveryWrap = &rw
		v.store.RecoveryKey = &KeyPairBox{Pub: b64u(pub), PrivBox: rkb}
	} else {
		// A new passkey must prove it opened the real vault key (with the recovery code): only that
		// key opens the recovery signing key, and the signature covers this enrollment's challenge,
		// the new passkey and its key wrap, so it can't be replayed or moved.
		sig, _ := unb64u(b.RecoverySig)
		credID, _ := unb64u(cred.CredID)
		msg, err := reenrollMessage(gc.Challenge, credID, vmkWrap)
		var pub []byte
		if v.store.RecoveryKey != nil {
			pub, _ = unb64u(v.store.RecoveryKey.Pub)
		}
		if err != nil || pub == nil || !verifyReenroll(pub, sig, msg) {
			v.audit("reenroll_rejected", map[string]any{"reason": "recovery signature invalid", "device": c.label})
			return nil, apiErr(403, "that does not unlock this vault (wrong recovery code?)")
		}
	}
	var old []string
	for _, oc := range v.store.Creds {
		old = append(old, oc.CredID[:min(12, len(oc.CredID))])
	}
	v.store.Creds = []Cred{cred}
	v.store.VMKWraps = map[string]Box{cred.CredID: vmkWrap}
	v.store.Devices = []Device{} // a (re)enrolled vault answers only to the device that enrolled it
	if mode == "recover" {
		// Re-enrolling usually means a lost or replaced phone: it must stop getting notifications,
		// which name secrets and reasons. Turn them on again on the new phone. (Paired Chrome
		// extensions live on the Mac, so they stay.)
		v.store.PushSubs = []PushSub{}
	}
	v.save()
	why := "enrolled the vault"
	if mode == "recover" {
		why = "re-enrolled the passkey"
	}
	v.allowDevice(c.Device, why)
	short := cred.CredID[:min(12, len(cred.CredID))]
	if mode == "recover" {
		os.Remove(filepath.Join(v.dataDir, reenrollFile))
		v.revoke(func(*Grant) bool { return true }, "passkey replaced")
		v.audit("reenrolled", map[string]any{"cred": short, "replaced": old, "aaguid": cred.AAGUID, "device": c.label})
	} else {
		v.audit("enrolled", map[string]any{"cred": short, "aaguid": cred.AAGUID, "device": c.label})
	}
	return map[string]any{"ok": true}, nil
}

// ---- authenticated operations. Every one is two steps: /api/challenge (nothing secret), then
// /api/unlock with the Face ID assertion, which returns the ciphertext the phone needs and a
// single-use action token for the change itself. No ciphertext leaves before Face ID.

var unlockKinds = []string{"add", "edit", "delete", "req", "deposit", "device", "inbox", "push", "chrome"}

func (p *phone) challenge(b *postBody) (any, error) {
	v := p.v
	ref := b.Ref
	switch b.Kind {
	case "add", "inbox", "push":
		ref = ""
	case "delete", "edit":
		if _, ok := v.store.Secrets[ref]; !ok {
			return nil, apiErr(404, "no such secret")
		}
	case "req":
		if r := v.requests[ref]; r == nil || r.Status != "pending" {
			return nil, apiErr(404, "request is not pending")
		}
	case "deposit":
		if _, ok := v.store.Deposits[ref]; !ok {
			return nil, apiErr(404, "no such deposit")
		}
	case "device":
		if _, ok := v.deviceRequests[ref]; !ok {
			return nil, apiErr(404, "that device hasn't asked to open the vault")
		}
	case "chrome":
		if _, ok := v.pairings[ref]; !ok {
			return nil, apiErr(404, "that pairing request is gone")
		}
	default:
		return nil, apiErr(400, "bad challenge kind")
	}
	id, ch := v.newChallenge(b.Kind, ref)
	ids := []string{}
	for _, c := range v.store.Creds {
		ids = append(ids, c.CredID)
	}
	return map[string]any{"rp_id": v.cfg.RPID, "cred_ids": ids, "challenge_id": id, "challenge": b64u(ch),
		"inbox_needed": v.store.Inbox == nil}, nil
}

type secretOut struct {
	Name     string `json:"name"`
	MetaJSON string `json:"meta_json"`
	Box      Box    `json:"box"`
}

func (p *phone) unlock(b *postBody) (any, error) {
	v := p.v
	c, err := v.takeChallenge(b.ChallengeID, unlockKinds, nil)
	if err != nil {
		return nil, err
	}
	cred, err := v.verify(b.Assertion, c.Challenge)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"vmk_wrap": v.store.VMKWraps[cred.CredID]}
	switch c.Kind {
	case "edit":
		rec := v.store.Secrets[c.Ref]
		if rec == nil {
			return nil, apiErr(404, "no such secret")
		}
		out["secret"] = secretOut{c.Ref, rec.MetaJSON, rec.Box}
	case "req":
		r := v.requests[c.Ref]
		if r == nil || r.Status != "pending" {
			return nil, apiErr(404, "request is not pending")
		}
		list := []secretOut{}
		for _, n := range r.Needs {
			if _, isNew := r.Creates[n]; isNew {
				continue
			}
			if rec := v.store.Secrets[n]; rec != nil {
				list = append(list, secretOut{n, rec.MetaJSON, rec.Box})
			}
		}
		out["secrets"] = list
	case "deposit":
		d := v.store.Deposits[c.Ref]
		if d == nil {
			return nil, apiErr(404, "no such deposit")
		}
		out["deposit"] = map[string]any{"id": d.ID, "box": d.Box, "meta_json": d.MetaJSON}
		if v.store.Inbox != nil {
			out["inbox_priv_box"] = v.store.Inbox.PrivBox
		}
	}
	out["action"] = v.newAction(c.Kind, c.Ref, cred)
	return out, nil
}

func (p *phone) add(b *postBody, c *Caller) (any, error) {
	v := p.v
	a, err := v.takeAction(b.Action, []string{"add", "edit"}, nil)
	if err != nil {
		return nil, err
	}
	if err := v.maybeSetupInbox(b.InboxSetup); err != nil {
		return nil, err
	}
	meta, err := checkMeta(b.MetaJSON)
	if err != nil {
		return nil, err
	}
	box, err := checkBox(b.Box)
	if err != nil {
		return nil, err
	}
	name := meta.Name
	if a.Kind == "edit" && a.Ref != name {
		return nil, apiErr(400, "an edit cannot rename a secret")
	}
	old := v.store.Secrets[name]
	if old != nil && !(b.Overwrite || a.Kind == "edit") {
		return nil, apiErr(409, "%s already exists; tick 'replace existing' to overwrite", name)
	}
	ver := 1
	if old != nil {
		ver = old.Version + 1
	}
	v.store.Secrets[name] = &SecretRec{MetaJSON: b.MetaJSON, Box: box, Version: ver, Updated: float64(now64())}
	v.save()
	if old != nil {
		v.revoke(hasName(name), name+" changed")
	}
	event := "secret_added"
	if a.Kind == "edit" {
		event = "secret_edited"
	} else if old != nil {
		event = "secret_replaced"
	}
	v.audit(event, map[string]any{"name": name, "device": c.label})
	return map[string]any{"ok": true, "name": name}, nil
}

type createItem struct {
	MetaJSON string `json:"meta_json"`
	Box      *Box   `json:"box"`
}

func (p *phone) approve(r *Request, b *postBody, c *Caller) (any, error) {
	v := p.v
	a, err := v.takeAction(b.Action, []string{"req"}, &r.ID)
	if err != nil {
		return nil, err
	}
	storeOnly := r.Mode == "store"
	choice := b.Choice
	if !storeOnly {
		if _, ok := choices[choice]; !ok {
			return nil, apiErr(400, "bad choice")
		}
	}
	if r.Mode == "fill" && choice != "once" {
		return nil, apiErr(400, "a fill is approved once at a time")
	}
	// New secrets entered on the phone (ask), under the policy you settled on. Validated before any write.
	var creates map[string]createItem
	if len(b.Creates) > 0 && string(b.Creates) != "null" {
		if json.Unmarshal(b.Creates, &creates) != nil {
			return nil, apiErr(400, "creates must cover exactly the proposed new secrets")
		}
	}
	if len(creates) != len(r.Creates) {
		return nil, apiErr(400, "creates must cover exactly the proposed new secrets")
	}
	type final struct {
		metaJSON string
		box      Box
		meta     Meta
	}
	finals := map[string]final{}
	for n := range r.Creates {
		item, ok := creates[n]
		if !ok {
			return nil, apiErr(400, "creates must cover exactly the proposed new secrets")
		}
		meta, err := checkMeta(item.MetaJSON)
		if err != nil {
			return nil, err
		}
		if meta.Name != n {
			return nil, apiErr(400, "a new secret cannot be renamed here")
		}
		box, err := checkBox(item.Box)
		if err != nil {
			return nil, err
		}
		finals[n] = final{item.MetaJSON, box, meta}
	}
	var values map[string]string
	if !storeOnly {
		if json.Unmarshal(b.Values, &values) != nil || len(values) != len(r.Needs) {
			return nil, apiErr(400, "values must cover exactly the requested secrets")
		}
		for _, n := range r.Needs {
			val, ok := values[n]
			if !ok || len(val) > maxSecretValue {
				return nil, apiErr(400, "values must cover exactly the requested secrets")
			}
			if !contains(v.meta(n).Modes, r.Mode) {
				return nil, apiErr(400, "the policy for %s no longer allows %s", n, r.Mode)
			}
		}
		tin := r.TargetIn
		if tin != nil && r.Target != nil {
			c := *tin
			c.BodyB64 = base64.StdEncoding.EncodeToString(r.Target.Body)
			tin = &c
		}
		t, err := checkTarget(r.Mode, tin, r.Needs, v.meta)
		if err == nil && r.Mode == "fill" {
			err = checkFill(r.Needs[0], r.Fill, v.meta(r.Needs[0]))
		}
		if err != nil {
			return nil, err
		}
		if t != nil {
			r.Target = t
		}
	}
	if err := v.maybeSetupInbox(b.InboxSetup); err != nil {
		return nil, err
	}
	for n, f := range finals {
		old := v.store.Secrets[n]
		ver := 1
		if old != nil {
			ver = old.Version + 1
		}
		v.store.Secrets[n] = &SecretRec{MetaJSON: f.metaJSON, Box: f.box, Version: ver, Updated: float64(now64())}
	}
	if len(finals) > 0 {
		v.save()
		for n := range finals {
			event := "secret_added"
			if v.store.Secrets[n].Version > 1 {
				v.revoke(hasName(n), n+" replaced")
				event = "secret_replaced"
			}
			v.audit(event, map[string]any{"name": n, "source": "asked by Claude", "request": r.ID})
		}
	}
	if storeOnly {
		r.Status, r.Decided = "stored", now()
		names := make([]string, 0, len(finals))
		for n := range finals {
			names = append(names, n)
		}
		v.audit("stored", map[string]any{"request": r.ID, "names": names})
		return map[string]any{"ok": true, "ttl": 0}, nil
	}
	capTTL := float64(maxTTL)
	for _, n := range r.Needs {
		if t := float64(v.meta(n).MaxTTL); t < capTTL {
			capTTL = t
		}
	}
	ttl := min(choices[choice], capTTL)
	r.Status, r.Choice, r.TTL, r.Decided = "approved", choice, ttl, now()
	r.values = values
	if ttl > 0 {
		gid := token(9)
		vals := map[string]string{}
		for k, x := range values {
			vals[k] = x
		}
		v.grants[gid] = &Grant{ID: gid, Names: append([]string{}, r.Needs...), Mode: r.Mode, SessionKey: r.Session.Key,
			SessionLabel: r.Session.Label, Session: r.Session, Created: now(), Expires: now() + ttl, values: vals}
		r.GrantID = gid
	}
	v.audit("approved", map[string]any{"request": r.ID, "names": r.Needs, "mode": r.Mode, "choice": choice, "ttl": ttl,
		"cred": a.CredID[:min(12, len(a.CredID))], "session": r.Session.Label, "device": c.label})
	return map[string]any{"ok": true, "ttl": ttl}, nil
}

// pushSubscribe registers a device for notifications. Face ID required: notifications name the
// secrets and reasons, so a subscription is read access to request details.
func (p *phone) pushSubscribe(b *postBody, c *Caller) (any, error) {
	v := p.v
	if _, err := v.takeAction(b.Action, []string{"push"}, nil); err != nil {
		return nil, err
	}
	if err := v.maybeSetupInbox(b.InboxSetup); err != nil {
		return nil, err
	}
	sub := b.Sub
	if sub == nil {
		return nil, apiErr(400, "not a Web Push subscription from a known push service")
	}
	p256dh, err1 := unb64u(sub.Keys.P256dh)
	auth, err2 := unb64u(sub.Keys.Auth)
	testEP := loopbackHTTPOK && loopbackRE.MatchString(strings.Join(strings.SplitN(sub.Endpoint, "/", 4)[:min(3, len(strings.SplitN(sub.Endpoint, "/", 4)))], "/"))
	if err1 != nil || err2 != nil || !(pushEndpointOK(sub.Endpoint) || testEP) || len(p256dh) != 65 || len(auth) != 16 {
		return nil, apiErr(400, "not a Web Push subscription from a known push service")
	}
	entry := PushSub{Endpoint: sub.Endpoint, Created: float64(now64()), Device: c.label}
	entry.Keys.P256dh, entry.Keys.Auth = sub.Keys.P256dh, sub.Keys.Auth
	keep := []PushSub{}
	for _, s := range v.store.PushSubs {
		if s.Endpoint != sub.Endpoint {
			keep = append(keep, s)
		}
	}
	v.store.PushSubs = append(keep, entry)
	v.save()
	v.audit("push_device_added", map[string]any{"device": c.label})
	v.notify("Notifications are on", "Requests from Claude will show up here.", "/", "welcome")
	return map[string]any{"ok": true, "devices": len(v.store.PushSubs)}, nil
}

func (p *phone) depositDecide(d *Deposit, b *postBody, action string, c *Caller) (any, error) {
	v := p.v
	if action == "accept" {
		// Storing needs Face ID; rejecting (below) only destroys the value, like Deny.
		if _, err := v.takeAction(b.Action, []string{"deposit"}, &d.ID); err != nil {
			return nil, err
		}
		if err := v.maybeSetupInbox(b.InboxSetup); err != nil {
			return nil, err
		}
		meta, err := checkMeta(b.MetaJSON)
		if err != nil {
			return nil, err
		}
		if meta.Name != d.Name {
			return nil, apiErr(400, "a deposit cannot be renamed")
		}
		box, err := checkBox(b.Box)
		if err != nil {
			return nil, err
		}
		old := v.store.Secrets[d.Name]
		ver := 1
		if old != nil {
			ver = old.Version + 1
		}
		v.store.Secrets[d.Name] = &SecretRec{MetaJSON: b.MetaJSON, Box: box, Version: ver, Updated: float64(now64())}
		if old != nil {
			v.revoke(hasName(d.Name), d.Name+" replaced")
		}
	}
	delete(v.store.Deposits, d.ID)
	v.save()
	outcome := "rejected"
	if action == "accept" {
		outcome = "accepted"
	}
	v.depositOutcome[d.ID] = outcome
	v.audit("deposit_"+outcome, map[string]any{"deposit": d.ID, "name": d.Name, "provenance": d.Provenance, "device": c.label})
	return map[string]any{"ok": true}, nil
}
