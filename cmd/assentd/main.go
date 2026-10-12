// assentd: use secrets that you approve with Face ID on your phone. One binary:
//
//	assentd daemon            the vault daemon (runs as _assentd, started by launchd)
//	assentd admin ...         root-only setup (also installed as assentd-admin)
//	assentd <command> ...     the CLI an agent uses (list, status, revoke, run, http, fill, ask, generate, deposit)
//	assentd-chrome-host       the native messaging host Chrome starts for the assentd extension
package main

import (
	"os"
	"path/filepath"
	"strings"
)

// version is set at build time (-ldflags "-X main.version=..."); shown in the phone's Settings.
var version = "dev"

func main() {
	args := os.Args[1:]
	if filepath.Base(os.Args[0]) == "assentd-admin" {
		os.Exit(runAdmin(args))
	}
	if filepath.Base(os.Args[0]) == "assentd-chrome-host" || len(args) > 0 && strings.HasPrefix(args[0], "chrome-extension://") {
		os.Exit(runChromeHost(args))
	}
	if len(args) > 0 {
		switch args[0] {
		case "daemon":
			runDaemon(args[1:])
			return
		case "admin":
			os.Exit(runAdmin(args[1:]))
		}
	}
	os.Exit(runCLI(args))
}
