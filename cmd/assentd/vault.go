package main

// Vault state: the store on disk (ciphertext only), and in memory the challenges, Face ID
// unlocks, pending requests and live grants. Plaintext exists in this process only between a Face
// ID approval and the grant's expiry (or, for a single use, until it has been handed over).

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"log"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	challengeTTL          = 300
	actionTTL             = 120 // a Face ID unlock must be used for its action within this many seconds
	maxPendingPerSession  = 10
	maxPendingTotal       = 20
	maxPendingDeposits    = 10 // waiting on the phone, all sessions
	maxDepositsPerSession = 5
	maxNewPerMinute       = 30   // requests and deposits that reach the phone, per minute
	maxFinishedRequests   = 500  // answered requests kept (shed, for the phone's "already answered" page)
	maxAuditString        = 2000 // characters of any one string in an audit record
	maxAuditFile          = 64 << 20
	finishedRequestKeep   = 3600
	reenrollFile          = "reenroll.json"
	maxSecretValue        = 64 * 1024
	auditTailLen          = 100
	deviceRequestLifetime = 86400
)

func now() float64 { return float64(time.Now().UnixNano()) / 1e9 }
func now64() int64 { return time.Now().Unix() }
func token(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return b64u(b)
}

// ---- store.json

type SecretRec struct {
	MetaJSON string  `json:"meta_json"`
	Box      Box     `json:"box"`
	Version  int     `json:"version"`
	Updated  float64 `json:"updated"`
}

type KeyPairBox struct {
	Pub     string  `json:"pub"`
	PrivBox Box     `json:"priv_box"`
	Created float64 `json:"created,omitempty"`
}

type Deposit struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	MetaJSON      string  `json:"meta_json"`
	Box           Box     `json:"box"`
	Created       float64 `json:"created"`
	Length        int     `json:"length"`
	Provenance    string  `json:"provenance"`
	ClaimedSource *string `json:"claimed_source"`
	Reason        string  `json:"reason"`
	Session       string  `json:"session"`
}

type Device struct {
	Node    string  `json:"node"`
	NodeID  string  `json:"node_id"`
	NodeKey string  `json:"node_key"`
	Login   string  `json:"login"`
	Added   float64 `json:"added"`
}

type Store struct {
	Version      int                   `json:"version"`
	Creds        []Cred                `json:"creds"`
	VMKWraps     map[string]Box        `json:"vmk_wraps"`
	RecoveryWrap *Box                  `json:"recovery_wrap"`
	RecoveryKey  *KeyPairBox           `json:"recovery_key,omitempty"`
	Secrets      map[string]*SecretRec `json:"secrets"`
	Inbox        *KeyPairBox           `json:"inbox"`
	Deposits     map[string]*Deposit   `json:"deposits"`
	PushSubs     []PushSub             `json:"push_subs"`
	Devices      []Device              `json:"devices"` // tailnet devices allowed to open the page
	Vapid        *Vapid                `json:"vapid,omitempty"`
	ChromeKeys   []ChromeKey           `json:"chrome_keys,omitempty"` // paired Chrome extensions (fill)
	extra        map[string]json.RawMessage
}

var storeKeys = []string{"version", "creds", "vmk_wraps", "recovery_wrap", "recovery_key", "secrets", "inbox",
	"deposits", "push_subs", "devices", "vapid", "chrome_keys"}

func loadStore(path string) (*Store, error) {
	s := &Store{Version: 1}
	data, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(data, s); err != nil {
			return nil, err
		}
		// Keep keys this version doesn't know, so a store written by a newer version survives.
		var all map[string]json.RawMessage
		json.Unmarshal(data, &all)
		for _, k := range storeKeys {
			delete(all, k)
		}
		s.extra = all
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if s.VMKWraps == nil {
		s.VMKWraps = map[string]Box{}
	}
	if s.Secrets == nil {
		s.Secrets = map[string]*SecretRec{}
	}
	if s.Deposits == nil {
		s.Deposits = map[string]*Deposit{}
	}
	if s.Creds == nil {
		s.Creds = []Cred{}
	}
	if s.PushSubs == nil {
		s.PushSubs = []PushSub{}
	}
	if s.Devices == nil {
		s.Devices = []Device{}
	}
	return s, nil
}

func (s *Store) marshal() ([]byte, error) {
	data, err := json.Marshal(s)
	if err != nil || len(s.extra) == 0 {
		return data, err
	}
	var all map[string]json.RawMessage
	json.Unmarshal(data, &all)
	for k, v := range s.extra {
		all[k] = v
	}
	return json.Marshal(all)
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	return writeFileAtomicAs(path, data, mode, -1, -1)
}

// writeFileAtomicAs writes data to path through a fresh temp file, owned uid:gid (-1: unchanged).
// The data directory belongs to _assentd, and root (assentd-admin, the installer) writes here
// too, so nothing may follow a link someone planted: the temp is created new (O_EXCL, never
// through a symlink), ownership is set on the open file, and rename replaces a link at path
// rather than writing through it.
func writeFileAtomicAs(path string, data []byte, mode os.FileMode, uid, gid int) error {
	tmp := path + ".tmp"
	if _, err := os.Lstat(tmp); err == nil {
		if err := os.Remove(tmp); err != nil { // removes a link itself, not what it points to
			return err
		}
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if uid >= 0 {
		if err := f.Chown(uid, gid); err != nil {
			return err
		}
	}
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	ok = true
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	// Make the rename itself durable: otherwise a crash could bring back the old file, undoing a
	// change you approved (a deleted secret, a removed device).
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// ---- in memory

type Challenge struct {
	Challenge []byte
	Kind, Ref string
	Expires   float64
}

type Action struct {
	Kind, Ref, CredID string
	Expires           float64
}

type Session struct {
	Key     string   `json:"key"`
	PID     *int     `json:"pid"`
	Kind    string   `json:"kind"`
	TTY     *string  `json:"tty"`
	Started *float64 `json:"started"`
	Label   string   `json:"label"`
}

type Request struct {
	ID       string
	Needs    []string
	Reason   string
	Argv     []string
	Cwd      string
	Mode     string // http | command | fill | store
	Target   *Target
	Fill     *FillTarget // fill: the tab, as Chrome reported it
	TargetIn *TargetIn
	Creates  map[string]string // name -> proposed meta_json (store mode)
	Session  Session
	Created  float64
	Expires  float64
	Status   string // pending | approved | denied | expired | cancelled | stored
	Choice   string
	TTL      float64
	Decided  float64
	GrantID  string
	values   map[string]string
}

// shed drops what a finished request no longer needs (bodies, commands, proposals): finished
// requests are kept for an hour, and anything running as you can make lots of them.
// Called with v.mu held, once the requester is done with it.
func (r *Request) shed() {
	r.Argv, r.Cwd, r.TargetIn, r.Creates, r.values = nil, "", nil, nil, nil
	if r.Target != nil {
		t := *r.Target
		t.Body, t.BodyPreview, t.Headers = nil, "", nil
		r.Target = &t
	}
}

// allowNew rate-limits what reaches the phone (requests, deposits): code running as you could
// otherwise flood it with notifications. Called with v.mu held.
func (v *Vault) allowNew() bool {
	t := now()
	keep := v.recentNew[:0]
	for _, x := range v.recentNew {
		if x > t-60 {
			keep = append(keep, x)
		}
	}
	v.recentNew = keep
	limit := maxNewPerMinute
	if v.cfg.NewPerMinute > 0 {
		limit = v.cfg.NewPerMinute
	}
	if len(keep) >= limit {
		return false
	}
	v.recentNew = append(v.recentNew, t)
	return true
}

// pruneFinished keeps at most maxFinishedRequests answered requests. Called with v.mu held.
func (v *Vault) pruneFinished() {
	var done []*Request
	for _, r := range v.requests {
		if r.Status != "pending" {
			done = append(done, r)
		}
	}
	if len(done) <= maxFinishedRequests {
		return
	}
	sort.Slice(done, func(i, j int) bool { return done[i].Created < done[j].Created })
	for _, r := range done[:len(done)-maxFinishedRequests] {
		delete(v.requests, r.ID)
	}
}

type Grant struct {
	ID           string            `json:"id"`
	Names        []string          `json:"names"`
	Mode         string            `json:"mode"`
	SessionKey   string            `json:"session_key"`
	SessionLabel string            `json:"session_label"`
	Session      Session           `json:"session"`
	Created      float64           `json:"created"`
	Expires      float64           `json:"expires"`
	values       map[string]string `json:"-"`
}

type DeviceRequest struct {
	Device
	Last       float64 `json:"last"`
	KeyChanged bool    `json:"key_changed"`
}

type Config struct {
	RPID                  string   `json:"rp_id"`
	Origin                string   `json:"origin"`
	ClientUID             *int     `json:"client_uid"`
	AllowedLogins         []string `json:"allowed_logins"`
	EnrollToken           string   `json:"enroll_token"`
	RequestTimeout        int      `json:"request_timeout"`
	NewPerMinute          int      `json:"new_per_minute"` // 0: maxNewPerMinute
	HTTPSocket            string   `json:"http_socket"`    // test mode only: the phone page on a Unix socket
	TestMode              bool     `json:"test_mode"`
	TestAllowLoopbackHTTP bool     `json:"test_allow_loopback_http"`
}

type Vault struct {
	mu             sync.Mutex
	cfg            Config
	dataDir        string
	store          *Store
	challenges     map[string]*Challenge
	actions        map[string]*Action
	requests       map[string]*Request
	grants         map[string]*Grant
	depositOutcome map[string]string
	deviceRequests map[string]*DeviceRequest
	hosts          map[string]*hostConn // connected Chrome extensions
	pairings       map[string]*Pairing  // extension keys waiting to be paired on the phone
	recentNew      []float64            // when recent requests and deposits were made (allowNew)
	auditSize      int64                // -1 until known
	auditMu        sync.Mutex
	auditTail      []map[string]any
	version        string
}

func newVault(cfg Config, dataDir string) (*Vault, error) {
	st, err := loadStore(filepath.Join(dataDir, "store.json"))
	if err != nil {
		return nil, err
	}
	v := &Vault{cfg: cfg, dataDir: dataDir, store: st, challenges: map[string]*Challenge{}, actions: map[string]*Action{},
		requests: map[string]*Request{}, grants: map[string]*Grant{}, depositOutcome: map[string]string{},
		deviceRequests: map[string]*DeviceRequest{}, hosts: map[string]*hostConn{}, pairings: map[string]*Pairing{},
		version: version, auditSize: -1}
	v.auditTail = readAuditTail(filepath.Join(dataDir, "audit.jsonl"))
	return v, nil
}

func (v *Vault) save() {
	data, err := v.store.marshal()
	if err == nil {
		err = writeFileAtomic(filepath.Join(v.dataDir, "store.json"), data, 0o600)
	}
	if err != nil {
		// Losing a write would silently undo a change you approved: stop rather than carry on.
		log.Fatalf("cannot save the store: %v", err)
	}
}

func readAuditTail(path string) []map[string]any {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var rec map[string]any
		if json.Unmarshal(sc.Bytes(), &rec) == nil {
			out = append(out, rec)
			if len(out) > auditTailLen {
				out = out[1:]
			}
		}
	}
	return out
}

// auditValue bounds what one audit field can hold: requesters choose argv, reasons and URLs.
func auditValue(x any) any {
	switch t := x.(type) {
	case string:
		return truncMark(t, maxAuditString)
	case []string:
		out, total := []string{}, 0
		for _, s := range t {
			s = truncMark(s, maxAuditString)
			if total += len([]rune(s)); total > 2*maxAuditString {
				return append(out, "…")
			}
			out = append(out, s)
		}
		return out
	case *string:
		if t != nil {
			s := truncMark(*t, maxAuditString)
			return &s
		}
	}
	return x
}

func truncMark(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

func (v *Vault) audit(event string, kw map[string]any) {
	rec := map[string]any{"ts": math.Round(now()*1000) / 1000, "event": event}
	for k, x := range kw {
		rec[k] = auditValue(x)
	}
	line := []byte(canonicalJSON(rec))
	path := filepath.Join(v.dataDir, "audit.jsonl")
	v.auditMu.Lock()
	if v.auditSize < 0 {
		v.auditSize = 0
		if fi, err := os.Stat(path); err == nil {
			v.auditSize = fi.Size()
		}
	}
	// Keep the log bounded: past the limit, the current file becomes audit.jsonl.1 (one kept).
	if v.auditSize+int64(len(line)) > maxAuditFile {
		if err := os.Rename(path, path+".1"); err == nil {
			v.auditSize = 0
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err == nil {
		if n, err := f.Write(append(line, '\n')); err == nil {
			v.auditSize += int64(n)
		}
		f.Close()
	} else {
		log.Printf("audit write failed: %v", err)
	}
	v.auditTail = append(v.auditTail, rec)
	if len(v.auditTail) > auditTailLen {
		v.auditTail = v.auditTail[1:]
	}
	v.auditMu.Unlock()
	s := canonicalJSON(kw)
	if len(s) > 300 {
		s = s[:300]
	}
	log.Printf("audit %s %s", event, s)
}

func (v *Vault) enrolled() bool { return len(v.store.Creds) > 0 }

func (v *Vault) meta(name string) Meta {
	if rec, ok := v.store.Secrets[name]; ok {
		return parseMeta(rec.MetaJSON)
	}
	return Meta{}
}

// reenrollToken: a root-issued token (sudo assentd-admin reenroll) that allows replacing the passkey.
func (v *Vault) reenrollToken() string {
	data, err := os.ReadFile(filepath.Join(v.dataDir, reenrollFile))
	if err != nil {
		return ""
	}
	var d struct {
		Token   string  `json:"token"`
		Expires float64 `json:"expires"`
	}
	if json.Unmarshal(data, &d) != nil || d.Expires <= now() {
		return ""
	}
	return d.Token
}

// ---- challenges and Face ID unlocks

func (v *Vault) newChallenge(kind, ref string) (string, []byte) {
	id := token(12)
	ch := make([]byte, 32)
	rand.Read(ch)
	v.challenges[id] = &Challenge{Challenge: ch, Kind: kind, Ref: ref, Expires: now() + challengeTTL}
	return id, ch
}

func (v *Vault) takeChallenge(id string, kinds []string, ref *string) (*Challenge, error) {
	c := v.challenges[id]
	delete(v.challenges, id)
	if c == nil || !contains(kinds, c.Kind) || (ref != nil && c.Ref != *ref) {
		return nil, apiErr(400, "unknown challenge; reload the page")
	}
	if c.Expires < now() {
		return nil, apiErr(410, "challenge expired; reload the page")
	}
	return c, nil
}

// Assertion is a WebAuthn get() result, as the phone sends it.
type Assertion struct {
	CredID            string `json:"cred_id"`
	AuthenticatorData string `json:"authenticatorData"`
	ClientDataJSON    string `json:"clientDataJSON"`
	Signature         string `json:"signature"`
}

func (a *Assertion) decode() (ad, cdj, sig []byte, err error) {
	var e1, e2, e3 error
	ad, e1 = unb64u(a.AuthenticatorData)
	cdj, e2 = unb64u(a.ClientDataJSON)
	sig, e3 = unb64u(a.Signature)
	if e1 != nil || e2 != nil || e3 != nil {
		return nil, nil, nil, waErr("bad base64url")
	}
	return
}

func (v *Vault) verify(a *Assertion, challenge []byte) (*Cred, error) {
	if a == nil {
		return nil, apiErr(400, "missing assertion")
	}
	var cred *Cred
	for i := range v.store.Creds {
		if v.store.Creds[i].CredID == a.CredID {
			cred = &v.store.Creds[i]
		}
	}
	if cred == nil {
		return nil, apiErr(403, "unknown passkey")
	}
	ad, cdj, sig, err := a.decode()
	var count int64
	if err == nil {
		count, err = verifyAssertion(*cred, ad, cdj, sig, challenge, v.cfg.RPID, v.cfg.Origin)
	}
	if err != nil {
		v.audit("auth_failed", map[string]any{"reason": err.Error()})
		return nil, apiErr(403, "passkey verification failed: %s", err)
	}
	if count != cred.SignCount {
		cred.SignCount = count
		v.save()
	}
	return cred, nil
}

func (v *Vault) newAction(kind, ref string, cred *Cred) string {
	t := token(18)
	v.actions[t] = &Action{Kind: kind, Ref: ref, CredID: cred.CredID, Expires: now() + actionTTL}
	return t
}

// takeAction consumes the Face ID unlock (POST /api/unlock) that authorizes this action. Single use.
func (v *Vault) takeAction(tok string, kinds []string, ref *string) (*Action, error) {
	a := v.actions[tok]
	delete(v.actions, tok)
	if a == nil || !contains(kinds, a.Kind) || (ref != nil && a.Ref != *ref) {
		return nil, apiErr(403, "this needs Face ID; reload the page")
	}
	if a.Expires < now() {
		return nil, apiErr(410, "the Face ID unlock expired; try again")
	}
	return a, nil
}

// ---- devices: identified by the tailnet's stable node ID, the node key the tunnel proved, and
// the login. A name can be reused by another device; these can't.

func (v *Vault) allowDevice(d Device, why string) {
	out := []Device{}
	for _, x := range v.store.Devices {
		if x.NodeID != d.NodeID {
			out = append(out, x)
		}
	}
	d.Added = float64(now64())
	v.store.Devices = append(out, d)
	delete(v.deviceRequests, d.NodeID)
	v.save()
	v.audit("device_allowed", map[string]any{"node": d.Node, "node_id": d.NodeID, "why": why})
}

func (v *Vault) deviceAllowed(d Device) bool {
	for _, x := range v.store.Devices {
		if x.NodeID == d.NodeID && x.NodeKey == d.NodeKey && x.Login == d.Login {
			return true
		}
	}
	return false
}

// rekeyable: an allowed device (same stable node ID and login) whose tailnet node key changed.
// The node ID is assigned by the tailnet and can't be taken by another machine; the new key still
// has to be confirmed with Face ID on the device (/api/rekey).
func (v *Vault) rekeyable(d Device) bool {
	for _, x := range v.store.Devices {
		if x.NodeID == d.NodeID && x.Login == d.Login && x.NodeKey != d.NodeKey {
			return true
		}
	}
	return false
}

func (v *Vault) noteBlockedDevice(d Device) {
	changed := false
	for _, x := range v.store.Devices {
		if x.NodeID == d.NodeID && x.NodeKey != d.NodeKey {
			changed = true
		}
	}
	v.deviceRequests[d.NodeID] = &DeviceRequest{Device: d, Last: now(), KeyChanged: changed}
}

// maybeSetupInbox: the phone creates the deposit inbox on the first Face ID action that offers it.
func (v *Vault) maybeSetupInbox(setup *KeyPairBox) error {
	if setup == nil || v.store.Inbox != nil {
		return nil
	}
	pub, err := unb64u(setup.Pub)
	if err == nil {
		_, err = p256Public(pub)
	}
	if err != nil {
		return apiErr(400, "bad inbox key")
	}
	box, err := checkBox(&setup.PrivBox)
	if err != nil {
		return err
	}
	v.store.Inbox = &KeyPairBox{Pub: b64u(pub), PrivBox: box, Created: float64(now64())}
	v.save()
	v.audit("inbox_enabled", map[string]any{})
	return nil
}

func checkBox(b *Box) (Box, error) {
	if b == nil {
		return Box{}, apiErr(400, "bad ciphertext box")
	}
	nonce, err1 := unb64u(b.Nonce)
	ct, err2 := unb64u(b.Ct)
	if err1 != nil || err2 != nil || len(nonce) != 12 || len(ct) < 16 || len(ct) > 128*1024 {
		return Box{}, apiErr(400, "bad ciphertext box")
	}
	return Box{Nonce: b.Nonce, Ct: b.Ct}, nil
}

// ---- views

func metaMap(metaJSON string) map[string]any {
	var m map[string]any
	json.Unmarshal([]byte(metaJSON), &m)
	if m == nil {
		m = map[string]any{}
	}
	return m
}

func (v *Vault) secretMetas() []map[string]any {
	names := make([]string, 0, len(v.store.Secrets))
	for n := range v.store.Secrets {
		names = append(names, n)
	}
	sort.Strings(names)
	out := []map[string]any{}
	for _, n := range names {
		rec := v.store.Secrets[n]
		m := metaMap(rec.MetaJSON)
		m["version"] = rec.Version
		m["updated"] = rec.Updated
		out = append(out, m)
	}
	return out
}

func (v *Vault) publicRequest(r *Request) map[string]any {
	metaOf := func(n string) map[string]any {
		if mj, ok := r.Creates[n]; ok {
			return metaMap(mj)
		}
		if rec, ok := v.store.Secrets[n]; ok {
			return metaMap(rec.MetaJSON)
		}
		return map[string]any{}
	}
	secrets := []map[string]any{}
	for _, n := range r.Needs {
		m := metaOf(n)
		desc, _ := m["description"].(string)
		ttl, _ := m["max_ttl"].(float64)
		_, isNew := r.Creates[n]
		secrets = append(secrets, map[string]any{"name": n, "description": desc, "max_ttl": ttl, "new": isNew})
	}
	creates := map[string]any{}
	replaces := map[string]any{}
	for n, mj := range r.Creates {
		creates[n] = metaMap(mj)
		if rec, ok := v.store.Secrets[n]; ok {
			replaces[n] = rec.Version
		}
	}
	// Another session asking for the same secret at the same time: possibly a lookalike request
	// racing a real one, so the phone points it out.
	concurrent := []string{}
	seen := map[string]bool{}
	for _, o := range v.requests {
		if o == r || o.Status != "pending" || o.Session.Key == r.Session.Key {
			continue
		}
		for _, n := range o.Needs {
			if contains(r.Needs, n) && !seen[n] {
				seen[n] = true
				concurrent = append(concurrent, n)
			}
		}
	}
	sort.Strings(concurrent)
	out := map[string]any{"id": r.ID, "needs": r.Needs, "reason": r.Reason, "argv": r.Argv, "cwd": r.Cwd,
		"mode": r.Mode, "target": r.Target.Public(), "session": r.Session, "created": r.Created, "expires": r.Expires,
		"status": r.Status, "secrets": secrets, "creates": creates, "replaces": replaces, "concurrent": concurrent,
		"now": now()}
	if r.Fill != nil {
		out["target"] = r.Fill.Public()
	}
	if r.Status != "pending" {
		out["decided"] = r.Decided
	}
	if r.Status == "approved" {
		out["choice"] = r.Choice
		out["ttl"] = r.TTL
		if r.GrantID != "" {
			out["grant_id"] = r.GrantID
		}
	}
	return out
}

func (v *Vault) publicDeposit(d *Deposit) map[string]any {
	var replaces any
	if rec, ok := v.store.Secrets[d.Name]; ok {
		replaces = rec.Version
	}
	return map[string]any{"id": d.ID, "name": d.Name, "created": d.Created, "length": d.Length, "provenance": d.Provenance,
		"claimed_source": d.ClaimedSource, "reason": d.Reason, "session": d.Session, "meta": metaMap(d.MetaJSON),
		"replaces": replaces, "now": now()}
}

func (v *Vault) state() map[string]any {
	creds := []map[string]any{}
	for _, c := range v.store.Creds {
		creds = append(creds, map[string]any{"cred_id": c.CredID, "created": c.Created, "label": c.Label})
	}
	pending := []map[string]any{}
	for _, r := range v.sortedRequests() {
		if r.Status == "pending" {
			pending = append(pending, v.publicRequest(r))
		}
	}
	grants := []*Grant{}
	for _, g := range v.grants {
		grants = append(grants, g)
	}
	sort.Slice(grants, func(i, j int) bool { return grants[i].Created < grants[j].Created })
	devReqs := []*DeviceRequest{}
	for _, r := range v.deviceRequests {
		if r.Last > now()-deviceRequestLifetime {
			devReqs = append(devReqs, r)
		}
	}
	sort.Slice(devReqs, func(i, j int) bool { return devReqs[i].Last > devReqs[j].Last })
	deposits := []map[string]any{}
	dids := make([]string, 0, len(v.store.Deposits))
	for id := range v.store.Deposits {
		dids = append(dids, id)
	}
	sort.Slice(dids, func(i, j int) bool { return v.store.Deposits[dids[i]].Created < v.store.Deposits[dids[j]].Created })
	for _, id := range dids {
		deposits = append(deposits, v.publicDeposit(v.store.Deposits[id]))
	}
	v.auditMu.Lock()
	tail := v.auditTail
	if len(tail) > 40 {
		tail = tail[len(tail)-40:]
	}
	audit := make([]map[string]any, len(tail))
	for i, rec := range tail {
		audit[len(tail)-1-i] = rec
	}
	v.auditMu.Unlock()
	return map[string]any{"enrolled": v.enrolled(), "rp_id": v.cfg.RPID, "creds": creds, "secrets": v.secretMetas(),
		"pending": pending, "grants": grants, "inbox": v.store.Inbox != nil,
		"push":    map[string]any{"vapid_public": v.vapid().Public, "devices": len(v.store.PushSubs)},
		"devices": v.store.Devices, "device_requests": devReqs, "version": v.version, "deposits": deposits,
		"chrome": v.chromeState(), "audit": audit, "now": now()}
}

func (v *Vault) sortedRequests() []*Request {
	out := make([]*Request, 0, len(v.requests))
	for _, r := range v.requests {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created < out[j].Created })
	return out
}

// ---- grants

func (v *Vault) sessionValues(sessionKey string, names []string, mode string) map[string]string {
	out := map[string]string{}
	for _, g := range v.grants {
		if g.SessionKey == sessionKey && g.Expires > now() && covers[g.Mode][mode] {
			for _, n := range names {
				if val, ok := g.values[n]; ok {
					out[n] = val
				}
			}
		}
	}
	return out
}

func (v *Vault) revoke(pred func(*Grant) bool, why string) int {
	n := 0
	for id, g := range v.grants {
		if pred(g) {
			delete(v.grants, id)
			clear(g.values)
			v.audit("revoke", map[string]any{"grant": id, "names": g.Names, "why": why})
			n++
		}
	}
	return n
}

func hasName(name string) func(*Grant) bool {
	return func(g *Grant) bool { return contains(g.Names, name) }
}

func (v *Vault) sweep() {
	v.mu.Lock()
	defer v.mu.Unlock()
	t := now()
	for tok, a := range v.actions {
		if a.Expires <= t {
			delete(v.actions, tok)
		}
	}
	for id, g := range v.grants {
		if g.Expires <= t {
			delete(v.grants, id)
			clear(g.values)
			v.audit("grant_expired", map[string]any{"grant": id, "names": g.Names})
		}
	}
	for _, r := range v.requests {
		if r.Status == "pending" && r.Expires <= t {
			r.Status = "expired"
			v.audit("request_expired", map[string]any{"request": r.ID, "names": r.Needs})
		}
	}
	for id, r := range v.requests {
		if r.Status != "pending" && r.Created+finishedRequestKeep < t {
			delete(v.requests, id)
		}
	}
	for id, c := range v.challenges {
		if c.Expires <= t {
			delete(v.challenges, id)
		}
	}
	for id, p := range v.pairings {
		if p.Last+pairingLifetime <= t {
			delete(v.pairings, id)
		}
	}
}

// chromeState: paired extensions and pairing requests, for the phone.
func (v *Vault) chromeState() map[string]any {
	keys := []map[string]any{}
	for _, k := range v.store.ChromeKeys {
		connected := false
		for _, h := range v.hosts {
			if h.pub != nil && b64u(h.pub) == k.Pub {
				connected = true
			}
		}
		keys = append(keys, map[string]any{"fingerprint": k.Fingerprint, "added": k.Added, "connected": connected})
	}
	pairings := []*Pairing{}
	for _, p := range v.pairings {
		pairings = append(pairings, p)
	}
	sort.Slice(pairings, func(i, j int) bool { return pairings[i].Created < pairings[j].Created })
	return map[string]any{"keys": keys, "pairings": pairings}
}

// ---- notifications

// vapid is the daemon's Web Push signing key (made on first use, kept in the store).
func (v *Vault) vapid() Vapid {
	if v.store.Vapid == nil {
		k, err := newVapid()
		if err != nil {
			log.Fatalf("vapid: %v", err)
		}
		v.store.Vapid = &k
		v.save()
	}
	return *v.store.Vapid
}

// notify sends Web Push to the Home Screen app: end-to-end encrypted, so it may say what is being
// asked. Called with v.mu held; the sending happens in the background.
func (v *Vault) notify(title, body, path, tag string) {
	subs := append([]PushSub{}, v.store.PushSubs...)
	vp := v.vapid()
	origin := v.cfg.Origin
	go func() {
		if len(subs) == 0 {
			return
		}
		key, err := loadVapid(vp)
		if err != nil {
			log.Printf("web push: %v", err)
			return
		}
		var gone []string
		for _, sub := range subs {
			status, err := pushSend(sub, pushMessage{Title: title, Body: body, URL: path, Tag: tag}, key, origin)
			if err != nil {
				log.Printf("web push failed: %v", err)
				continue
			}
			if status == 404 || status == 410 {
				gone = append(gone, sub.Endpoint)
			} else if status < 200 || status >= 300 {
				host := sub.Endpoint
				if i := strings.Index(host, "://"); i >= 0 {
					host = strings.SplitN(host[i+3:], "/", 2)[0]
				}
				log.Printf("web push to %s returned %d", host, status)
			}
		}
		if len(gone) > 0 {
			v.mu.Lock()
			keep := []PushSub{}
			for _, s := range v.store.PushSubs {
				if !contains(gone, s.Endpoint) {
					keep = append(keep, s)
				}
			}
			v.store.PushSubs = keep
			v.save()
			v.audit("push_device_gone", map[string]any{"count": len(gone)})
			v.mu.Unlock()
		}
	}()
}
