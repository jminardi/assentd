package main

// Root-only setup helpers: sudo assentd-admin <cmd> (or sudo assentd admin <cmd>).
//
// Enrollment links carry a token that lets a passkey be (re)registered, so they are only ever
// shown here, in a root terminal.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	qrcode "github.com/skip2/go-qrcode"
	"golang.org/x/term"
)

const adminUsage = `assentd-admin: root-only setup helpers (run with sudo)

  init-config --rp-id HOST --client-uid UID --allowed-login LOGIN
                    write config.json if it does not exist
  enroll-link       show the one-time enrollment link, as a QR code, in this terminal
  reenroll          allow replacing the passkey (lost/new phone) for 1 hour; shows the link here.
                    The phone must enter the recovery code and prove, with the recovery key it
                    opens, that it unlocked the real vault key. One attempt per link.
  recover-check     prompt for the recovery code; verify it opens every secret and the recovery key
  recover-export NAME
                    prompt for the recovery code; print one secret (break glass)
`

func adminDie(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}

func runAdmin(args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Print(adminUsage)
		return 2
	}
	if os.Geteuid() != 0 && os.Getenv("ASSENTD_DATA") == "" {
		adminDie("assentd-admin must run as root (sudo)")
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "init-config":
		p, err := parseArgs(rest, map[string]optSpec{"rp-id": {true, false}, "client-uid": {true, false},
			"allowed-login": {true, false}}, nil)
		if err != nil || p.get("rp-id") == "" || p.get("client-uid") == "" || p.get("allowed-login") == "" {
			adminDie("usage: assentd-admin init-config --rp-id HOST --client-uid UID --allowed-login LOGIN")
		}
		return initConfig(p.get("rp-id"), p.int("client-uid", -1), p.get("allowed-login"))
	case "enroll-link":
		if adminEnrolled() {
			adminDie("already enrolled; to replace the passkey use: sudo assentd-admin reenroll")
		}
		cfg, err := loadConfig()
		if err != nil {
			adminDie("%v", err)
		}
		showLink(cfg.Origin+"/enroll#token="+cfg.EnrollToken, "Enroll this vault")
	case "reenroll":
		if !adminEnrolled() {
			adminDie("not enrolled yet; use enroll-link")
		}
		tok := token(24)
		data, _ := json.Marshal(map[string]any{"token": tok, "expires": now() + 3600})
		writeOwned(filepath.Join(dataDir, reenrollFile), data)
		cfg, err := loadConfig()
		if err != nil {
			adminDie("%v", err)
		}
		showLink(cfg.Origin+"/enroll#token="+tok, "Replace the vault passkey (valid 1 hour; needs the recovery code)")
	case "recover-check":
		st, vmk := openWithRecoveryCode()
		names := keys(st.Secrets)
		for _, n := range names {
			rec := st.Secrets[n]
			if _, err := openBox(vmk, rec.Box, secretAAD(rec.MetaJSON)); err != nil {
				adminDie("FAILED %s: %v", n, err)
			}
			fmt.Printf("ok  %s\n", n)
		}
		if st.RecoveryKey == nil {
			adminDie("this vault has no recovery key, so reenroll can't work; set it up again")
		}
		if _, err := openBox(vmk, st.RecoveryKey.PrivBox, recoveryKeyAAD); err != nil {
			adminDie("the recovery key doesn't open: %v", err)
		}
		fmt.Printf("recovery code opens all %d secret(s) and the recovery key (so reenroll will work)\n", len(names))
	case "recover-export":
		if len(rest) != 1 {
			adminDie("usage: assentd-admin recover-export NAME")
		}
		st, vmk := openWithRecoveryCode()
		rec := st.Secrets[rest[0]]
		if rec == nil {
			adminDie("no secret named %s", rest[0])
		}
		val, err := openBox(vmk, rec.Box, secretAAD(rec.MetaJSON))
		if err != nil {
			adminDie("cannot open %s: %v", rest[0], err)
		}
		fmt.Println(string(val))
	default:
		fmt.Print(adminUsage)
		return 2
	}
	return 0
}

// writeOwned writes a file in the data directory, owned like the directory (by _assentd), 0600.
// Ownership is set on the open temp file before it is renamed into place: chown on the path
// would follow a link _assentd planted there and hand it a root-owned file.
func writeOwned(path string, data []byte) {
	uid, gid := -1, -1
	if fi, err := os.Stat(dataDir); err == nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			uid, gid = int(st.Uid), int(st.Gid)
		}
	}
	if err := writeFileAtomicAs(path, data, 0o600, uid, gid); err != nil {
		adminDie("cannot write %s: %v", path, err)
	}
}

func initConfig(rpID string, uid int, login string) int {
	path := filepath.Join(dataDir, "config.json")
	if _, err := os.Stat(path); err == nil {
		fmt.Printf("%s exists; leaving it alone\n", path)
		return 0
	}
	if uid < 0 {
		adminDie("bad --client-uid")
	}
	cfg := map[string]any{"rp_id": rpID, "origin": "https://" + rpID, "client_uid": uid, "allowed_logins": []string{login},
		"enroll_token": token(24), "request_timeout": 300}
	data, _ := json.MarshalIndent(cfg, "", " ")
	writeOwned(path, append(data, '\n'))
	fmt.Printf("wrote %s\n", path)
	return 0
}

func adminEnrolled() bool {
	st, err := loadStore(filepath.Join(dataDir, "store.json"))
	return err == nil && len(st.Creds) > 0
}

func showLink(link, what string) {
	fmt.Printf("\n%s: scan with the iPhone camera (or open the URL on the phone).\n\n", what)
	q, err := qrcode.New(link, qrcode.Medium)
	if err == nil {
		fmt.Print(q.ToSmallString(false))
	}
	fmt.Printf("\n%s\n\nDo not paste this link anywhere else; it lets a passkey be registered.\n\n", link)
}

func openWithRecoveryCode() (*Store, []byte) {
	st, err := loadStore(filepath.Join(dataDir, "store.json"))
	if err != nil || st.RecoveryWrap == nil {
		adminDie("cannot read an enrolled store in %s", dataDir)
	}
	fmt.Fprint(os.Stderr, "recovery code: ")
	var input []byte
	if term.IsTerminal(int(os.Stdin.Fd())) {
		input, err = term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
	} else {
		var line string
		_, err = fmt.Fscanln(os.Stdin, &line)
		input = []byte(line)
	}
	if err != nil {
		adminDie("no recovery code given")
	}
	code, err := decodeRecoveryCode(string(input))
	if err != nil {
		adminDie("%v", err)
	}
	k, _ := kek(code, kekInfoRecovery)
	vmk, err := openBox(k, *st.RecoveryWrap, vmkAAD)
	if err != nil {
		adminDie("that recovery code does not open this vault")
	}
	return st, vmk
}
