package main

// The Unix socket for the assentd CLI. Only the configured client uid may connect, and a request
// must be written by the process that connected (that process's Claude session gets any grant).

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	maxSockConnections = 64
	maxSockMsg         = 4 * 1024 * 1024
	localPeerToken     = 0x006 // LOCAL_PEERTOKEN: the peer's audit_token_t
)

type sockServer struct {
	v     *Vault
	slots chan struct{}
}

// peerIdentity returns (uid, pid, pidversion) of the peer. macOS reports the process that last
// wrote to the socket, and pidversion tells a reused pid apart from the original process.
func peerIdentity(c *net.UnixConn) (uid uint32, pid, pidver uint32, err error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, 0, 0, err
	}
	var inner error
	cerr := raw.Control(func(fd uintptr) {
		var cred *unix.Xucred
		cred, inner = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if inner != nil {
			return
		}
		uid = cred.Uid
		var tok [8]uint32
		size := uint32(unsafe.Sizeof(tok))
		_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, unix.SOL_LOCAL, localPeerToken,
			uintptr(unsafe.Pointer(&tok[0])), uintptr(unsafe.Pointer(&size)), 0)
		if errno != 0 {
			inner = errno
			return
		}
		pid, pidver = tok[5], tok[7]
	})
	if cerr != nil {
		return 0, 0, 0, cerr
	}
	return uid, pid, pidver, inner
}

// peerGone: the CLI exited or closed the connection (a request it can no longer receive is withdrawn).
func peerGone(c *net.UnixConn) bool {
	raw, err := c.SyscallConn()
	if err != nil {
		return true
	}
	gone := false
	raw.Control(func(fd uintptr) {
		buf := make([]byte, 1)
		n, _, err := unix.Recvfrom(int(fd), buf, unix.MSG_PEEK|unix.MSG_DONTWAIT)
		if err == nil && n == 0 {
			gone = true
		} else if err != nil && !errors.Is(err, unix.EAGAIN) {
			gone = true
		}
	})
	return gone
}

func (s *sockServer) serve(ln *net.UnixListener) {
	for {
		c, err := ln.AcceptUnix()
		if err != nil {
			log.Printf("socket accept: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go s.handle(c)
	}
}

type sockConn struct {
	c *net.UnixConn
	w *bufio.Writer
}

func (sc *sockConn) send(obj any) error {
	data, _ := json.Marshal(obj)
	if _, err := sc.w.Write(append(data, '\n')); err != nil {
		return err
	}
	return sc.w.Flush()
}

type sockMsg struct {
	Op        string               `json:"op"`
	Needs     []string             `json:"needs"`
	Reason    string               `json:"reason"`
	Argv      []string             `json:"argv"`
	Cwd       string               `json:"cwd"`
	Mode      string               `json:"mode"`
	Target    *TargetIn            `json:"target"`
	Timeout   int                  `json:"timeout"`
	Replace   bool                 `json:"replace"`
	Proposals map[string]*Proposal `json:"proposals"`
	All       bool                 `json:"all"`
	Names     []string             `json:"names"`
	// deposit
	Name     string        `json:"name"`
	Proposal *Proposal     `json:"proposal"`
	Generate *GenerateSpec `json:"generate"`
	Value    *string       `json:"value"`
	Source   string        `json:"source"`
	Wait     bool          `json:"wait"`
	// fill
	Tab *int `json:"tab"`
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

func (s *sockServer) handle(c *net.UnixConn) {
	defer c.Close()
	sc := &sockConn{c, bufio.NewWriter(c)}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		sc.send(map[string]any{"ok": false, "error": "too many connections to the vault; try again shortly"})
		return
	}
	v := s.v
	uid, pid, pidver, err := peerIdentity(c)
	if err != nil {
		return
	}
	if v.cfg.ClientUID == nil || uid != uint32(*v.cfg.ClientUID) {
		log.Printf("rejected socket peer uid=%d pid=%d", uid, pid)
		return
	}
	// A connection that doesn't say what it wants soon gives its slot back.
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReaderSize(c, 65536)
	line, err := readLine(r, maxSockMsg)
	if err != nil {
		return
	}
	c.SetReadDeadline(time.Time{})
	// The request must come from the process that connected: a connection handed to another
	// process (or left behind by one that exited) would be attributed to the wrong session.
	if _, p2, v2, err := peerIdentity(c); err != nil || p2 != pid || v2 != pidver {
		sc.send(map[string]any{"ok": false, "error": "the request must be sent by the process that connected"})
		return
	}
	var msg sockMsg
	if json.Unmarshal(line, &msg) != nil {
		sc.send(map[string]any{"ok": false, "error": "bad request"})
		return
	}
	var ae *apiError
	switch msg.Op {
	case "list":
		v.mu.Lock()
		out := map[string]any{"ok": true, "secrets": v.secretMetas(), "enrolled": v.enrolled(), "url": v.cfg.Origin}
		v.mu.Unlock()
		sc.send(out)
	case "status":
		// Names only: anything running as you can call this, and other sessions' reasons and
		// commands are none of its business.
		v.mu.Lock()
		grants := []map[string]any{}
		for _, g := range v.grants {
			grants = append(grants, map[string]any{"names": g.Names, "mode": g.Mode, "expires": g.Expires})
		}
		pending := []map[string]any{}
		for _, r := range v.sortedRequests() {
			if r.Status == "pending" {
				pending = append(pending, map[string]any{"names": r.Needs, "mode": r.Mode})
			}
		}
		v.mu.Unlock()
		sort.Slice(grants, func(i, j int) bool { return grants[i]["expires"].(float64) < grants[j]["expires"].(float64) })
		sc.send(map[string]any{"ok": true, "grants": grants, "pending": pending})
	case "revoke":
		v.mu.Lock()
		pred := func(g *Grant) bool {
			for _, n := range msg.Names {
				if contains(g.Names, n) {
					return true
				}
			}
			return false
		}
		if msg.All {
			pred = func(*Grant) bool { return true }
		}
		n := v.revoke(pred, "revoked from CLI")
		v.mu.Unlock()
		sc.send(map[string]any{"ok": true, "revoked": n})
	case "request":
		if err := s.request(sc, int(pid), &msg); err != nil {
			if errors.As(err, &ae) {
				sc.send(map[string]any{"ok": false, "error": ae.msg})
			} else {
				sc.send(map[string]any{"ok": false, "error": err.Error()})
			}
		}
	case "chrome-host":
		s.chromeHost(sc, r, pid, pidver)
	case "deposit":
		if err := s.deposit(sc, int(pid), &msg); err != nil {
			if errors.As(err, &ae) {
				sc.send(map[string]any{"ok": false, "error": ae.msg})
			} else {
				sc.send(map[string]any{"ok": false, "error": err.Error()})
			}
		}
	default:
		sc.send(map[string]any{"ok": false, "error": fmt.Sprintf("unknown op %q", msg.Op)})
	}
}

func readLine(r *bufio.Reader, limit int) ([]byte, error) {
	var out []byte
	for {
		chunk, isPrefix, err := r.ReadLine()
		if err != nil {
			return nil, err
		}
		out = append(out, chunk...)
		if len(out) > limit {
			return nil, errors.New("message too large")
		}
		if !isPrefix {
			return out, nil
		}
	}
}

func dedupe(list []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, x := range list {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func (s *sockServer) request(sc *sockConn, pid int, msg *sockMsg) error {
	v := s.v
	if len(msg.Needs) == 0 {
		return apiErr(400, "needs must be a non-empty list of names")
	}
	needs := dedupe(msg.Needs)
	reason := trunc(msg.Reason, 500)
	argv := []string{}
	for i, a := range msg.Argv {
		if i >= 100 {
			break
		}
		argv = append(argv, trunc(a, 500))
	}
	cwd := trunc(msg.Cwd, 500)
	mode := msg.Mode
	if mode == "" {
		mode = "command"
	}
	if mode != "http" && mode != "command" && mode != "fill" && mode != "store" {
		return apiErr(400, "mode must be one of [http command fill store]")
	}
	var fill *FillTarget
	if mode == "fill" {
		if len(needs) != 1 {
			return apiErr(400, "a fill uses exactly one secret")
		}
		// Refuse what the policy can't allow before asking Chrome anything.
		v.mu.Lock()
		_, exists := v.store.Secrets[needs[0]]
		m := v.meta(needs[0])
		v.mu.Unlock()
		if !exists {
			return apiErr(404, "unknown secret %s; have it entered on the phone first: assentd ask %s --modes fill "+
				"--fill-origin https://... --description ... --reason ...", needs[0], needs[0])
		}
		if !contains(m.Modes, "fill") {
			return apiErr(403, "%s does not allow 'fill' delivery (allowed: %s); change it on the phone page", needs[0], strings.Join(m.Modes, ", "))
		}
		var err error
		if fill, err = v.fillTarget(msg.Tab); err != nil {
			return err
		}
	}
	session := identifySession(pid)

	v.mu.Lock()
	if !v.enrolled() {
		v.mu.Unlock()
		return apiErr(409, "vault is not enrolled yet")
	}
	pendingTotal, pendingSession := 0, 0
	for _, r := range v.requests {
		if r.Status == "pending" {
			pendingTotal++
			if r.Session.Key == session.Key {
				pendingSession++
			}
		}
	}
	if pendingTotal >= maxPendingTotal || pendingSession >= maxPendingPerSession {
		v.mu.Unlock()
		return apiErr(429, "too many requests are already waiting on the phone")
	}
	// ask: secrets to be entered on the phone, under a proposed policy (or, to replace one, its own).
	creates := map[string]string{}
	for _, n := range needs {
		_, exists := v.store.Secrets[n]
		if mode == "store" {
			if !nameRE.MatchString(n) {
				v.mu.Unlock()
				return apiErr(400, "bad secret name %q", n)
			}
			if exists && !msg.Replace {
				v.mu.Unlock()
				return apiErr(409, "%s already exists; pass --replace to ask for a new value", n)
			}
			for _, d := range v.store.Deposits {
				if d.Name == n {
					v.mu.Unlock()
					return apiErr(409, "a deposit for %s is already waiting on the phone", n)
				}
			}
			if p := msg.Proposals[n]; p != nil && !exists {
				mj, err := proposalMeta(n, p)
				if err != nil {
					v.mu.Unlock()
					return err
				}
				creates[n] = mj
			} else if exists {
				creates[n] = v.store.Secrets[n].MetaJSON
			} else {
				v.mu.Unlock()
				return apiErr(400, "no proposed policy for %s", n)
			}
		} else if !exists {
			v.mu.Unlock()
			return apiErr(404, "unknown secret %s; have it entered on the phone first: assentd ask %s --description ... --reason ...", n, n)
		}
	}
	if mode != "store" {
		for _, n := range needs {
			m := v.meta(n)
			if !contains(m.Modes, mode) {
				v.mu.Unlock()
				return apiErr(403, "%s does not allow '%s' delivery (allowed: %s); change it on the phone page", n, mode, strings.Join(m.Modes, ", "))
			}
		}
	}
	target, err := checkTarget(mode, msg.Target, needs, v.meta)
	if err == nil && mode == "fill" {
		err = checkFill(needs[0], fill, v.meta(needs[0]))
	}
	if err != nil {
		v.mu.Unlock()
		return err
	}
	have := map[string]string{}
	if mode != "store" {
		have = v.sessionValues(session.Key, needs, mode)
	}
	var missing []string
	for _, n := range needs {
		if _, ok := have[n]; !ok {
			missing = append(missing, n)
		}
	}
	var targetURL any
	if target != nil {
		targetURL = target.URL
	}
	if fill != nil {
		targetURL = fill.Origin
	}
	var req *Request
	if len(missing) == 0 {
		v.audit("reused", map[string]any{"names": needs, "mode": mode, "argv": argv, "cwd": cwd, "url": targetURL, "session": session.Label})
	} else {
		timeout := msg.Timeout
		if timeout == 0 {
			timeout = v.cfg.RequestTimeout
		}
		if timeout == 0 {
			timeout = 300
		}
		timeout = max(30, min(timeout, 900))
		if !v.allowNew() {
			v.mu.Unlock()
			return apiErr(429, "too many requests in the last minute; wait a bit")
		}
		v.pruneFinished()
		// The body is kept once, decoded, in target; approve re-encodes it to re-check the policy.
		var tin *TargetIn
		if msg.Target != nil {
			c := *msg.Target
			c.BodyB64 = ""
			tin = &c
			msg.Target.BodyB64 = ""
		}
		req = &Request{ID: token(9), Needs: missing, Reason: reason, Argv: argv, Cwd: cwd, Mode: mode, Target: target,
			TargetIn: tin, Fill: fill, Creates: creates, Session: session, Created: now(), Status: "pending"}
		req.Expires = req.Created + float64(timeout)
		v.requests[req.ID] = req
		newNames := make([]string, 0, len(creates))
		for n := range creates {
			newNames = append(newNames, n)
		}
		sort.Strings(newNames)
		v.audit("requested", map[string]any{"request": req.ID, "names": missing, "new": newNames, "mode": mode, "reason": reason,
			"argv": argv, "cwd": cwd, "url": targetURL, "session": session.Label})
		label := strings.Join(missing, ", ")
		title, where := "Use "+label, ""
		switch mode {
		case "store":
			title, where = "Enter "+label, "save only"
		case "http":
			where = target.Method + " " + target.Parsed.Host
		case "fill":
			title, where = "Fill "+label, "into "+strings.TrimPrefix(fill.Origin, "https://")
		default:
			where = "run a command"
			if len(argv) > 0 {
				where = "run " + filepath.Base(argv[0])
			}
		}
		r := reason
		if r == "" {
			r = "No reason given"
		}
		sorted := append([]string{}, missing...)
		sort.Strings(sorted)
		// One notification per secret: a burst of requests for it replaces, rather than stacks.
		v.notify(title, r+" · "+where, "/r/"+req.ID, "use:"+strings.Join(sorted, ","))
	}
	v.mu.Unlock()

	var values map[string]string
	var ttl any
	if req != nil {
		defer func() {
			v.mu.Lock()
			req.shed()
			v.mu.Unlock()
		}()
		newList := make([]string, 0, len(creates))
		for n := range creates {
			newList = append(newList, n)
		}
		sort.Strings(newList)
		sc.send(map[string]any{"pending": req.ID, "url": v.cfg.Origin + "/r/" + req.ID, "names": missing, "new": newList})
		for {
			v.mu.Lock()
			status := req.Status
			v.mu.Unlock()
			if status != "pending" {
				break
			}
			if peerGone(sc.c) {
				v.mu.Lock()
				if req.Status == "pending" {
					req.Status, req.Decided = "cancelled", now()
					v.audit("cancelled", map[string]any{"request": req.ID, "names": missing})
				}
				v.mu.Unlock()
				return nil
			}
			time.Sleep(200 * time.Millisecond)
		}
		v.mu.Lock()
		status := req.Status
		values = req.values
		req.values = nil
		if status == "approved" {
			// `have` came from grants that were live when this request was made; any of them
			// revoked since must not ride along on this approval.
			still := v.sessionValues(session.Key, keys(have), mode)
			if len(still) != len(have) {
				v.mu.Unlock()
				sc.send(map[string]any{"ok": false, "status": "denied", "error": "an approval this request relied on was revoked; ask again"})
				return nil
			}
			for k, x := range still {
				values[k] = x
			}
			if mode == "http" {
				// Place the secret by the policy as saved at approval (re-checked in approve).
				target = req.Target
			}
		}
		ttl = req.TTL
		v.mu.Unlock()
		switch status {
		case "stored":
			sc.send(map[string]any{"ok": true, "stored": keys(creates)})
			return nil
		case "approved":
		default:
			sc.send(map[string]any{"ok": false, "status": status, "error": "request " + status})
			return nil
		}
	} else {
		values = have
	}
	if mode == "fill" {
		ok, ferr := v.deliverFill(req, values[needs[0]])
		clear(values)
		v.mu.Lock()
		kw := map[string]any{"request": req.ID, "name": needs[0], "origin": fill.Origin, "ok": ok}
		if !ok {
			kw["error"] = ferr
		}
		v.audit("filled", kw)
		v.mu.Unlock()
		if !ok {
			sc.send(map[string]any{"ok": false, "error": "not filled: " + ferr})
			return nil
		}
		sc.send(map[string]any{"ok": true, "filled": needs[0], "origin": fill.Origin})
		return nil
	}
	if mode == "http" {
		res := performHTTP(target, values[target.Secret])
		v.mu.Lock()
		kw := map[string]any{"names": needs, "method": target.Method, "url": target.URL, "status": nil, "error": nil}
		if res.OK {
			kw["status"] = res.Status
		} else {
			kw["error"] = res.Error
		}
		v.audit("http_sent", kw)
		v.mu.Unlock()
		clear(values)
		out := map[string]any{"ttl": ttl}
		data, _ := json.Marshal(res)
		json.Unmarshal(data, &out)
		out["ok"] = res.OK
		sc.send(out)
		return nil
	}
	sc.send(map[string]any{"ok": true, "values": values, "ttl": ttl})
	clear(values)
	return nil
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// deposit seals a value (given, or generated here) to the phone's inbox. Nothing on the Mac can
// read it back.
func (s *sockServer) deposit(sc *sockConn, pid int, msg *sockMsg) error {
	v := s.v
	name := msg.Name
	if !nameRE.MatchString(name) {
		return apiErr(400, "name must look like an env var: A-Z, 0-9, _")
	}
	session := identifySession(pid)
	v.mu.Lock()
	if v.store.Inbox == nil {
		v.mu.Unlock()
		return apiErr(409, "deposits are not enabled yet: open the vault page on the phone and tap 'Turn on' "+
			"next to Deposits in Settings (or approve any request)")
	}
	_, exists := v.store.Secrets[name]
	if exists && !msg.Replace {
		v.mu.Unlock()
		return apiErr(409, "%s already exists; pass --replace to deposit a new value", name)
	}
	mine := 0
	for _, d := range v.store.Deposits {
		if d.Name == name {
			v.mu.Unlock()
			return apiErr(409, "a deposit for %s is already waiting on the phone", name)
		}
		if d.Session == session.Label {
			mine++
		}
	}
	// Each deposit sits in the store until you decide, so their number is capped.
	if len(v.store.Deposits) >= maxPendingDeposits || mine >= maxDepositsPerSession {
		v.mu.Unlock()
		return apiErr(429, "too many deposits are already waiting on the phone")
	}
	for _, r := range v.requests {
		if _, asking := r.Creates[name]; asking && r.Status == "pending" {
			v.mu.Unlock()
			return apiErr(409, "the phone is already asking for %s", name)
		}
	}
	var metaJSON string
	var err error
	if exists {
		// A new value for an existing secret keeps its policy: a replacement mustn't quietly
		// widen where the secret may go. Change the policy on the phone if you want to.
		metaJSON = v.store.Secrets[name].MetaJSON
	} else if metaJSON, err = proposalMeta(name, msg.Proposal); err != nil {
		v.mu.Unlock()
		return err
	}
	if !v.allowNew() {
		v.mu.Unlock()
		return apiErr(429, "too many requests in the last minute; wait a bit")
	}
	var value, provenance string
	var claimed *string
	if msg.Generate != nil {
		value, err = generateValue(msg.Generate)
		if err != nil {
			v.mu.Unlock()
			return err
		}
		cs := msg.Generate.Charset
		if cs == "" {
			cs = "alnum"
		}
		provenance = fmt.Sprintf("generated by the vault daemon (%d chars, %s)", len(value), cs)
	} else {
		if msg.Value != nil {
			value = *msg.Value
		}
		provenance = "handed in by a process on the Mac (not verified)"
		if src := trunc(msg.Source, 300); src != "" {
			claimed = &src
		}
	}
	if value == "" || len(value) > maxSecretValue {
		v.mu.Unlock()
		return apiErr(400, "value must be a non-empty string up to 64 KiB")
	}
	did := token(9)
	pub, _ := unb64u(v.store.Inbox.Pub)
	box, err := sealToInbox(pub, []byte(value), depositAAD(did))
	length := len([]rune(value))
	value = ""
	msg.Value = nil
	if err != nil {
		v.mu.Unlock()
		return err
	}
	v.store.Deposits[did] = &Deposit{ID: did, Name: name, MetaJSON: metaJSON, Box: box, Created: now(), Length: length,
		Provenance: provenance, ClaimedSource: claimed, Reason: trunc(msg.Reason, 500), Session: session.Label}
	v.save()
	v.audit("deposited", map[string]any{"deposit": did, "name": name, "provenance": provenance, "claimed_source": claimed,
		"replace": exists, "session": session.Label})
	reason := trunc(msg.Reason, 500)
	if reason == "" {
		reason = "New secret from Claude"
	}
	v.notify("Store "+name+"?", reason, "/d/"+did, did)
	v.mu.Unlock()

	url := v.cfg.Origin + "/d/" + did
	sc.send(map[string]any{"pending_deposit": did, "url": url, "length": length})
	if !msg.Wait {
		sc.send(map[string]any{"ok": true, "status": "pending", "id": did, "url": url})
		return nil
	}
	timeout := msg.Timeout
	if timeout == 0 {
		timeout = 300
	}
	deadline := time.Now().Add(time.Duration(max(30, min(timeout, 3600))) * time.Second)
	for {
		v.mu.Lock()
		outcome := v.depositOutcome[did]
		v.mu.Unlock()
		if outcome == "accepted" {
			sc.send(map[string]any{"ok": true, "status": "accepted", "name": name})
			return nil
		}
		if outcome != "" {
			sc.send(map[string]any{"ok": false, "status": "denied", "error": "the deposit for " + name + " was rejected; the value is gone"})
			return nil
		}
		if peerGone(sc.c) {
			return nil
		}
		if time.Now().After(deadline) {
			sc.send(map[string]any{"ok": false, "status": "timeout", "error": "still waiting on the phone; the deposit is kept: " + url})
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
}
