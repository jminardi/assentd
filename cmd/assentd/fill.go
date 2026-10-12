package main

// Fill: a password typed into a Chrome tab by the assentd extension, never by the agent.
//
//   agent ─ `assentd fill NAME` ─▶ daemon ◀─ socket ─ assentd-chrome-host ◀─ native messaging ─ extension
//
// The extension has its own P-256 key, paired with the vault on the phone (Face ID). A fill asks
// the extension which tab it would fill (the origin comes from Chrome, not the agent), checks it
// against the secret's policy, and after Face ID seals the value to the paired key. The CLI only
// learns whether it worked.

import (
	"bufio"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	extensionOrigin = "chrome-extension://jcbnicpanjmggphgoonehlalfmjcfmmi/"
	chromeHostBin   = "/usr/local/libexec/assentd/bin/assentd-chrome-host"
	// Google's signature on Chrome itself: the only process allowed to have started the host.
	chromeRequirement = `anchor apple generic and identifier "com.google.Chrome" and certificate leaf[subject.OU] = "EQHXZ8M8AV"`
	fillInfo          = "assentd/fill/v1"
	proofInfo         = "assentd/fill-proof/v1"
	maxHostConns      = 8
	maxHostMsg        = 64 * 1024
	maxPairings       = 5
	maxChromeKeys     = 10
	pairingLifetime   = 86400
	tabQueryTimeout   = 5 * time.Second
	fillDoneTimeout   = 20 * time.Second
)

// hostWriteTimeout: how long a message to the Chrome host may take to be read (a var for tests).
var hostWriteTimeout = 5 * time.Second

// https://host[:port], lowercase, no path: what Chrome's URL.origin gives for an https page.
var originRE = regexp.MustCompile(`^https://([a-z0-9-]+(\.[a-z0-9-]+)*)(:\d{1,5})?$`)

// ChromeKey is a paired extension's public key (raw P-256, base64url).
type ChromeKey struct {
	Pub         string  `json:"pub"`
	Fingerprint string  `json:"fingerprint"`
	Added       float64 `json:"added"`
	By          string  `json:"by"`
}

// Pairing is an extension key waiting for you to pair it on the phone.
type Pairing struct {
	ID          string  `json:"id"`
	Pub         string  `json:"-"`
	Fingerprint string  `json:"fingerprint"`
	Created     float64 `json:"created"`
	Last        float64 `json:"last"`
}

// FillPolc is where a secret may be filled: exact https origins.
type FillPolc struct {
	Origins []string `json:"origins"`
}

// FillTarget is the tab a fill request is for, as the extension (Chrome) reported it.
type FillTarget struct {
	Origin string
	URL    string
	Title  string
	TabID  int
	host   *hostConn
}

func (f *FillTarget) Public() map[string]any {
	return map[string]any{"origin": f.Origin, "url": f.URL, "title": f.Title}
}

func fingerprintOf(pubRaw []byte) string {
	d := sha256.Sum256(pubRaw)
	h := hex.EncodeToString(d[:8])
	return h[0:4] + "-" + h[4:8] + "-" + h[8:12] + "-" + h[12:16]
}

// originOK: a policy origin entry. Same host rules as http mode: a DNS name, no IPs or localhost.
func originOK(o string) bool {
	m := originRE.FindStringSubmatch(o)
	if m == nil {
		return false
	}
	return hostOK(strings.TrimPrefix(o, "https://"))
}

// tabOrigin turns the URL Chrome reported into the origin it will be checked against.
func tabOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return "", errors.New("not an https page")
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	o := "https://" + host
	if port != "" && port != "443" {
		o += ":" + port
	}
	if !originRE.MatchString(o) {
		return "", errors.New("not an https page")
	}
	return o, nil
}

// sealTo seals plaintext to an extension's public key (fillcrypto.js opens it): ECDH with a fresh
// key, HKDF-SHA256 (no salt, info), AES-256-GCM with aad.
func sealTo(pubRaw []byte, info, aad string, plaintext []byte) (eph, iv, ct string, err error) {
	pub, err := p256Public(pubRaw)
	if err != nil {
		return "", "", "", err
	}
	ek, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", "", err
	}
	shared, err := ek.ECDH(pub)
	if err != nil {
		return "", "", "", err
	}
	key, err := hkdf.Key(sha256.New, shared, nil, info, 32)
	if err != nil {
		return "", "", "", err
	}
	g, err := gcm(key)
	if err != nil {
		return "", "", "", err
	}
	n := make([]byte, 12)
	rand.Read(n)
	return b64u(ek.PublicKey().Bytes()), b64u(n), b64u(g.Seal(nil, n, plaintext, []byte(aad))), nil
}

func sealFill(pubRaw []byte, value, id, origin string, tabID int) (map[string]any, error) {
	eph, iv, ct, err := sealTo(pubRaw, fillInfo, id+"\n"+origin+"\n"+strconv.Itoa(tabID), []byte(value))
	if err != nil {
		return nil, err
	}
	return map[string]any{"type": "fill", "id": id, "tabId": tabID, "origin": origin, "eph": eph, "iv": iv, "ct": ct}, nil
}

// sealProof asks an extension to prove it holds the private key for the public key it claimed:
// only that key opens the nonce.
func sealProof(pubRaw []byte, connID string, nonce []byte) (map[string]any, error) {
	eph, iv, ct, err := sealTo(pubRaw, proofInfo, "proof\n"+connID, nonce)
	if err != nil {
		return nil, err
	}
	return map[string]any{"type": "prove", "id": connID, "eph": eph, "iv": iv, "ct": ct}, nil
}

// ---- who is on the other end of a host connection

// pidPath is the kernel's path of a process's executable (proc_pidpath), which argv[0] can't fake.
func pidPath(pid int) (string, error) {
	buf := make([]byte, 4096)
	// __proc_info(PROC_INFO_CALL_PIDINFO, pid, PROC_PIDPATHINFO, 0, buf, len)
	_, _, errno := syscall.Syscall6(336, 2, uintptr(pid), 11, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if errno != 0 {
		return "", errno
	}
	if i := strings.IndexByte(string(buf), 0); i >= 0 {
		buf = buf[:i]
	}
	return string(buf), nil
}

func parentPID(pid int) (int, error) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return 0, err
	}
	return int(kp.Eproc.Ppid), nil
}

// checkChromeHost: the peer must be the installed, root-owned host binary, running with the
// hardened runtime the installer signs it with, so code running as you can neither inject into it
// (DYLD_* variables, task ports) nor put another program at its path. The host itself checks that
// Google Chrome started it (chromeStartedMe): Chrome runs from a per-user copy of its bundle that
// only the login user can read, so _assentd can't verify Chrome's signature from here.
func checkChromeHost(pid int) error {
	path, err := pidPath(pid)
	if err != nil || path != chromeHostBin {
		return fmt.Errorf("not the installed Chrome host (%s)", path)
	}
	flags, err := csStatus(pid)
	if err != nil {
		return fmt.Errorf("can't read the Chrome host's code signature: %v", err)
	}
	const csValid, csRuntime = 0x1, 0x10000
	if flags&csValid == 0 || flags&csRuntime == 0 {
		return errors.New("the Chrome host isn't signed with the hardened runtime; run install.sh again")
	}
	return nil
}

// csStatus is the kernel's code-signing status for a process (csops CS_OPS_STATUS).
func csStatus(pid int) (uint32, error) {
	var flags uint32
	_, _, errno := syscall.Syscall6(169, uintptr(pid), 0, uintptr(unsafe.Pointer(&flags)), 4, 0, 0)
	if errno != 0 {
		return 0, errno
	}
	return flags, nil
}

// chromeStartedMe: the host's parent is Google Chrome, by its code signature (not its path, which
// is a per-user copy). Runs in the host, as the login user, who can read that copy.
func chromeStartedMe() error {
	ppid := os.Getppid()
	if ppid <= 1 {
		return errors.New("the Chrome host has no parent")
	}
	cmd := exec.Command("/usr/bin/codesign", "-v", "-R="+chromeRequirement, strconv.Itoa(ppid))
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			return errors.New("the Chrome host wasn't started by Google Chrome")
		}
	case <-time.After(10 * time.Second):
		cmd.Process.Kill()
		return errors.New("checking Chrome's signature timed out")
	}
	return nil
}

// ---- host connections

type hostConn struct {
	id      string
	sc      *sockConn
	mu      sync.Mutex // guards writes and waiters
	waiters map[string]chan map[string]any
	claimed []byte // the key the extension says it has (hello)
	nonce   []byte // what it must open to prove it (prove/proof)
	pub     []byte // set once proven: only then does this connection count as that key
	hello   float64
	closed  bool
}

// write sends one message with a deadline. Called with h.mu held. A host that stops reading is
// dropped, rather than left holding h.mu (and every fill waiting on it).
func (h *hostConn) write(obj any) error {
	if h.closed {
		return errors.New("the Chrome extension disconnected")
	}
	h.sc.c.SetWriteDeadline(time.Now().Add(hostWriteTimeout))
	if err := h.sc.send(obj); err != nil {
		h.closed = true
		h.sc.c.Close()
		return errors.New("the Chrome extension stopped answering")
	}
	return nil
}

func (h *hostConn) send(obj any) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.write(obj)
}

// ask sends a message and waits for the reply with the same id.
func (h *hostConn) ask(msg map[string]any, timeout time.Duration) (map[string]any, error) {
	id := msg["id"].(string)
	ch := make(chan map[string]any, 1)
	h.mu.Lock()
	if err := h.write(msg); err != nil {
		h.mu.Unlock()
		return nil, err
	}
	h.waiters[id] = ch
	h.mu.Unlock()
	defer func() { h.mu.Lock(); delete(h.waiters, id); h.mu.Unlock() }()
	select {
	case r, ok := <-ch:
		if !ok {
			return nil, errors.New("the Chrome extension disconnected")
		}
		return r, nil
	case <-time.After(timeout):
		return nil, errors.New("the Chrome extension didn't answer")
	}
}

// chromeKeyIndex: the paired key matching pub, or -1. Called with v.mu held.
func (v *Vault) chromeKeyIndex(pub []byte) int {
	s := b64u(pub)
	for i, k := range v.store.ChromeKeys {
		if k.Pub == s {
			return i
		}
	}
	return -1
}

// notePairing records an unpaired extension key for the phone. Called with v.mu held.
func (v *Vault) notePairing(pub []byte) {
	fp := fingerprintOf(pub)
	for _, p := range v.pairings {
		if p.Fingerprint == fp {
			p.Last = now()
			return
		}
	}
	if len(v.pairings) >= maxPairings {
		log.Printf("chrome: ignoring a pairing request from key %s (too many waiting)", fp)
		return
	}
	p := &Pairing{ID: token(9), Pub: b64u(pub), Fingerprint: fp, Created: now(), Last: now()}
	v.pairings[p.ID] = p
	v.audit("chrome_pair_requested", map[string]any{"fingerprint": fp})
	v.notify("Pair Chrome?", "The assentd extension in Chrome wants to fill passwords. Key "+fp, "/settings", "pair:"+fp)
}

// pairedHost: the most recently connected extension whose key is paired. Called with v.mu held.
func (v *Vault) pairedHost() (*hostConn, error) {
	var best *hostConn
	connected := false
	for _, h := range v.hosts {
		if h.pub == nil {
			continue
		}
		connected = true
		if v.chromeKeyIndex(h.pub) >= 0 && (best == nil || h.hello > best.hello) {
			best = h
		}
	}
	if best == nil {
		if connected {
			return nil, apiErr(409, "the assentd Chrome extension isn't paired yet: pair it in Settings on your phone, after "+
				"checking the key matches the extension's popup")
		}
		return nil, apiErr(409, "the assentd Chrome extension isn't connected: is Chrome open, with the extension installed?")
	}
	return best, nil
}

// pairStatus is what an extension is told about its key. Called with v.mu held.
func (v *Vault) pairStatus(pub []byte) map[string]any {
	fp := fingerprintOf(pub)
	pending := false
	for _, p := range v.pairings {
		pending = pending || p.Fingerprint == fp
	}
	return map[string]any{"type": "status", "paired": v.chromeKeyIndex(pub) >= 0, "pending": pending}
}

// broadcastPairing tells every connected extension whether it is paired. Called with v.mu held.
func (v *Vault) broadcastPairing() {
	for _, h := range v.hosts {
		if h.pub != nil {
			go h.send(v.pairStatus(h.pub))
		}
	}
}

// chromeHost serves one connection from assentd-chrome-host, for as long as Chrome keeps it open.
func (s *sockServer) chromeHost(sc *sockConn, r *bufio.Reader, pid, pidver uint32) {
	v := s.v
	if !v.cfg.TestMode {
		if err := checkChromeHost(int(pid)); err != nil {
			log.Printf("chrome: refused host pid %d: %v", pid, err)
			sc.send(map[string]any{"ok": false, "error": err.Error()})
			return
		}
	}
	h := &hostConn{id: token(6), sc: sc, waiters: map[string]chan map[string]any{}}
	v.mu.Lock()
	if len(v.hosts) >= maxHostConns {
		v.mu.Unlock()
		sc.send(map[string]any{"ok": false, "error": "too many Chrome connections"})
		return
	}
	v.hosts[h.id] = h
	v.mu.Unlock()
	defer func() {
		v.mu.Lock()
		delete(v.hosts, h.id)
		v.mu.Unlock()
		h.mu.Lock()
		h.closed = true
		for _, ch := range h.waiters {
			close(ch)
		}
		h.waiters = map[string]chan map[string]any{}
		h.mu.Unlock()
	}()
	if h.send(map[string]any{"ok": true, "test_mode": v.cfg.TestMode}) != nil {
		return
	}
	for {
		line, err := readLine(r, maxHostMsg)
		if err != nil {
			return
		}
		// Every message must come from the process that connected (see handle).
		if _, p2, v2, err := peerIdentity(sc.c); err != nil || p2 != pid || v2 != pidver {
			return
		}
		var m map[string]any
		if json.Unmarshal(line, &m) != nil {
			continue
		}
		switch m["type"] {
		case "hello":
			// The extension names its key; it counts as that key only once it proves it (proof).
			ps, _ := m["pub"].(string)
			pub, err := unb64u(ps)
			if err == nil {
				_, err = p256Public(pub)
			}
			if err != nil || h.claimed != nil {
				h.send(map[string]any{"type": "status", "paired": false, "error": "bad hello"})
				return
			}
			h.claimed, h.nonce = pub, make([]byte, 32)
			rand.Read(h.nonce)
			prove, err := sealProof(pub, h.id, h.nonce)
			if err != nil || h.send(prove) != nil {
				return
			}
		case "proof":
			got, _ := m["nonce"].(string)
			nb, err := unb64u(got)
			if h.nonce == nil || h.pub != nil || err != nil || subtle.ConstantTimeCompare(nb, h.nonce) != 1 {
				log.Printf("chrome: host pid %d failed to prove its key", pid)
				h.send(map[string]any{"type": "status", "paired": false, "error": "the extension could not prove its key"})
				return
			}
			v.mu.Lock()
			h.pub, h.hello, h.nonce = h.claimed, now(), nil
			if v.chromeKeyIndex(h.pub) < 0 {
				v.notePairing(h.pub)
			}
			st := v.pairStatus(h.pub)
			v.mu.Unlock()
			h.send(st)
		case "pair":
			// The popup was opened on an unpaired extension: ask the phone again (deduplicated).
			v.mu.Lock()
			if h.pub == nil {
				v.mu.Unlock()
				continue
			}
			if v.chromeKeyIndex(h.pub) < 0 {
				v.notePairing(h.pub)
			}
			st := v.pairStatus(h.pub)
			v.mu.Unlock()
			h.send(st)
		case "tab", "filled":
			id, _ := m["id"].(string)
			h.mu.Lock()
			if ch := h.waiters[id]; ch != nil {
				ch <- m
				delete(h.waiters, id)
			}
			h.mu.Unlock()
		}
	}
}

// fillTarget asks the paired extension which tab it would fill. Called without v.mu.
func (v *Vault) fillTarget(tabID *int) (*FillTarget, error) {
	v.mu.Lock()
	h, err := v.pairedHost()
	v.mu.Unlock()
	if err != nil {
		return nil, err
	}
	q := map[string]any{"type": "tab", "id": token(9)}
	if tabID != nil {
		q["tabId"] = *tabID
	}
	r, err := h.ask(q, tabQueryTimeout)
	if err != nil {
		return nil, apiErr(503, "%s", err.Error())
	}
	tid, ok := r["tabId"].(float64)
	if !ok || tid != float64(int(tid)) || tid < 0 {
		return nil, apiErr(404, "Chrome has no tab to fill (no focused window, or no such tab)")
	}
	rawURL, _ := r["url"].(string)
	title, _ := r["title"].(string)
	origin, err := tabOrigin(rawURL)
	if err != nil {
		return nil, apiErr(400, "the tab isn't an https page; fill only works on https sites")
	}
	return &FillTarget{Origin: origin, URL: trunc(rawURL, 2000), Title: trunc(title, 200), TabID: int(tid), host: h}, nil
}

// checkFill: the secret's policy allows filling on this origin. Called with v.mu held.
func checkFill(name string, f *FillTarget, meta Meta) error {
	if f == nil {
		return apiErr(400, "a fill needs a tab")
	}
	if meta.Fill == nil || !contains(meta.Fill.Origins, f.Origin) {
		allowed := "none"
		if meta.Fill != nil && len(meta.Fill.Origins) > 0 {
			allowed = strings.Join(meta.Fill.Origins, ", ")
		}
		// Not naming the tab's site: with --tab, that would let the agent read any tab's address.
		return apiErr(403, "%s may not be filled on that tab's site (allowed: %s); change its sites on the phone", name, allowed)
	}
	return nil
}

// deliverFill seals the approved value to the extension that reported the tab and waits for it to
// fill. Called without v.mu.
func (v *Vault) deliverFill(r *Request, value string) (bool, string) {
	f := r.Fill
	v.mu.Lock()
	h := v.hosts[f.host.id]
	paired := h == f.host && h.pub != nil && v.chromeKeyIndex(h.pub) >= 0
	v.mu.Unlock()
	if !paired {
		return false, "the Chrome extension that showed this tab disconnected or was unpaired; nothing was filled"
	}
	msg, err := sealFill(h.pub, value, r.ID, f.Origin, f.TabID)
	if err != nil {
		return false, "could not seal the value: " + err.Error()
	}
	reply, err := h.ask(msg, fillDoneTimeout)
	if err != nil {
		return false, err.Error()
	}
	if ok, _ := reply["ok"].(bool); ok {
		return true, ""
	}
	e, _ := reply["error"].(string)
	if e == "" {
		e = "the extension couldn't fill the field"
	}
	return false, trunc(e, 200)
}
