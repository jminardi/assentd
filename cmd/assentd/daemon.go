package main

// assentd daemon. Runs as the dedicated _assentd user, from root-owned code. Two listeners:
//   - a Unix socket for the assentd CLI and the Chrome extension's native messaging host (only the
//     configured client uid may connect)
//   - the phone page, on the vault's own Tailscale node (tsnet): HTTPS with that node's
//     certificate, and every caller's tailnet device and login from Tailscale itself. Only
//     _assentd controls this node, so nothing running as your login user can repoint what is
//     served at its name (unlike `tailscale serve` on the Mac's own node).
//
// The daemon holds only ciphertext at rest. Plaintext exists in its memory only between a Face ID
// approval and the grant's expiry.
//
// Delivery modes:
//   command  plaintext to one command on the Mac, as an environment variable
//   http     plaintext never reaches the Mac: the daemon makes the HTTPS request to an allowed host
//            itself, placing the secret in the header its policy names
//   fill     plaintext never reaches the Mac's processes: sealed to the paired assentd Chrome
//            extension, which types it into the password field of an allowed https site (fill.go)
//   store    (no use) a request whose only purpose is for you to enter a new secret on the phone
// New secrets can also arrive as deposits: the daemon encrypts a value (generated here, or handed
// over by the CLI) to the inbox public key and forgets it. Only the phone can open the inbox.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"tailscale.com/tsnet"
)

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

var (
	dataDir  = envOr("ASSENTD_DATA", "/var/db/assentd")
	sockPath = envOr("ASSENTD_SOCK", "/var/db/assentd-sock/assentd.sock")
)

func loadConfig() (Config, error) {
	var cfg Config
	data, err := os.ReadFile(filepath.Join(dataDir, "config.json"))
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("config.json: %w", err)
	}
	return cfg, nil
}

func checkConfig(cfg Config) error {
	if cfg.RPID == "" || cfg.Origin == "" || cfg.ClientUID == nil {
		return errors.New("config.json needs rp_id, origin and client_uid")
	}
	if len(cfg.AllowedLogins) == 0 {
		return errors.New("config.json needs allowed_logins: the tailnet logins that may use the vault")
	}
	if cfg.TestMode && cfg.HTTPSocket == "" {
		return errors.New("test mode serves the phone page on http_socket; set it")
	}
	return nil
}

func runDaemon(args []string) {
	log.SetFlags(log.Ldate | log.Ltime)
	if len(args) > 0 {
		log.Fatalf("usage: assentd daemon")
	}
	var front *tsnetFront
	var cfg Config
	// Production: join the tailnet first, so the installer can learn the vault's name (and the
	// login link) before there is a config.
	probe, perr := loadConfig()
	if perr == nil && probe.TestMode {
		cfg = probe
	} else {
		var err error
		front, err = startFront(envOr("ASSENTD_HOSTNAME", "assentd"), envOr("ASSENTD_TS_DIR", "/var/db/assentd-ts"))
		if err != nil {
			log.Fatalf("tailnet: %v", err)
		}
		cfg = waitForConfig(front.domain)
	}
	if err := checkConfig(cfg); err != nil {
		log.Fatal(err)
	}
	loopbackHTTPOK = cfg.TestMode && cfg.TestAllowLoopbackHTTP
	v, err := newVault(cfg, dataDir)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	v.mu.Lock()
	v.vapid()
	v.mu.Unlock()

	os.Remove(sockPath)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sockPath, Net: "unix"})
	if err != nil {
		log.Fatalf("socket: %v", err)
	}
	os.Chmod(sockPath, 0o666) // access control is the peer-uid check, not file mode
	go (&sockServer{v: v, slots: make(chan struct{}, maxSockConnections)}).serve(ln)
	go func() {
		for {
			time.Sleep(2 * time.Second)
			v.sweep()
		}
	}()
	p := &phone{v: v}
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second,
		IdleTimeout: 120 * time.Second, ErrorLog: log.New(os.Stderr, "http: ", log.LstdFlags)}
	log.Printf("assentd %s up: socket %s, origin %s, enrolled=%v, secrets=%d", version, sockPath, cfg.Origin,
		v.enrolled(), len(v.store.Secrets))
	if cfg.TestMode {
		// Test suite only: the phone page on a Unix socket, trusting identity headers from the
		// test harness in place of Tailscale's.
		os.Remove(cfg.HTTPSocket)
		hl, err := net.Listen("unix", cfg.HTTPSocket)
		if err != nil {
			log.Fatalf("http socket: %v", err)
		}
		os.Chmod(cfg.HTTPSocket, 0o600)
		srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := r.Header
			ident := &Device{Node: h.Get("X-Assentd-Node"), NodeID: h.Get("X-Assentd-Node-ID"), NodeKey: h.Get("X-Assentd-Node-Key"),
				Login: h.Get("X-Assentd-Login")}
			p.serve(w, r, ident)
		})
		log.Printf("TEST MODE: phone page on %s", cfg.HTTPSocket)
		log.Fatal(srv.Serve(hl))
	}
	front.serve(srv, p)
}

// waitForConfig waits until config.json exists and is for this tailnet name. The installer
// writes it once it has read the name from this log.
func waitForConfig(domain string) Config {
	said := ""
	for {
		cfg, err := loadConfig()
		var msg string
		switch {
		case errors.Is(err, os.ErrNotExist):
			msg = "waiting for config.json (run the installer)"
		case err != nil:
			msg = err.Error()
		case cfg.TestMode:
			msg = "config.json is in test mode but the tailnet is up; refusing"
		case cfg.RPID != domain:
			msg = fmt.Sprintf("config.json is for %s, not %s; waiting (the installer retires the old vault)", cfg.RPID, domain)
		default:
			return cfg
		}
		if msg != said {
			log.Print(msg)
			said = msg
		}
		time.Sleep(2 * time.Second)
	}
}

type tsnetFront struct {
	srv    *tsnet.Server
	domain string
}

func startFront(hostname, stateDir string) (*tsnetFront, error) {
	srv := &tsnet.Server{
		Hostname: hostname,
		Dir:      stateDir,
		Logf:     func(string, ...any) {}, // tsnet's backend logs are very chatty
		UserLogf: log.Printf,              // includes the one-time login URL
	}
	if _, err := srv.Up(context.Background()); err != nil {
		return nil, err
	}
	domains := srv.CertDomains()
	if len(domains) == 0 {
		return nil, errors.New("no cert domain: enable HTTPS certificates for the tailnet")
	}
	log.Printf("assentd: tailnet name https://%s", domains[0])
	return &tsnetFront{srv: srv, domain: domains[0]}, nil
}

func (f *tsnetFront) serve(srv *http.Server, p *phone) {
	lc, err := f.srv.LocalClient()
	if err != nil {
		log.Fatalf("local client: %v", err)
	}
	// Get the certificate now, not on the phone's first visit: issuing one can take a while, and
	// until then Safari just shows a blank page.
	for attempt := 1; ; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		_, _, err := lc.CertPair(ctx, f.domain)
		cancel()
		if err == nil {
			break
		}
		log.Printf("getting the certificate for %s (attempt %d): %v", f.domain, attempt, err)
		time.Sleep(time.Duration(min(attempt, 6)) * 5 * time.Second)
	}
	ln, err := f.srv.ListenTLS("tcp", ":443")
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who, err := lc.WhoIs(r.Context(), r.RemoteAddr)
		if err != nil || who.Node == nil || who.UserProfile == nil {
			for k, val := range securityHeaders {
				w.Header().Set(k, val)
			}
			http.Error(w, "unknown tailnet peer", http.StatusForbidden)
			return
		}
		// Tagged devices have no person behind them, and shared-in devices belong to someone
		// else's tailnet: neither may use the vault.
		if who.Node.IsTagged() || who.Node.Sharer != 0 {
			for k, val := range securityHeaders {
				w.Header().Set(k, val)
			}
			http.Error(w, "tagged or shared devices can't use the vault", http.StatusForbidden)
			return
		}
		// The stable ID never changes or gets reused; the node key is what the tunnel proved.
		p.serve(w, r, &Device{Node: strings.TrimSuffix(who.Node.Name, "."), NodeID: string(who.Node.StableID),
			NodeKey: who.Node.Key.String(), Login: who.UserProfile.LoginName})
	})
	log.Printf("assentd: serving https://%s (certificate ready)", f.domain)
	log.Fatal(srv.Serve(ln))
}
