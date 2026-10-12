package main

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type psInfo struct {
	ppid   int
	tty    string
	lstart string
	comm   string
}

func psOf(pid int) *psInfo {
	out, err := exec.Command("/bin/ps", "-o", "ppid=", "-o", "tty=", "-o", "lstart=", "-o", "comm=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return nil
	}
	parts := strings.Fields(string(out))
	if len(parts) < 8 {
		return nil
	}
	ppid, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil
	}
	return &psInfo{ppid: ppid, tty: parts[1], lstart: strings.Join(parts[2:7], " "), comm: strings.Join(parts[7:], " ")}
}

// identifySession: the nearest `claude` ancestor of the requesting process identifies the session.
func identifySession(pid int) Session {
	p := pid
	for i := 0; i < 40; i++ {
		info := psOf(p)
		if info == nil {
			break
		}
		if filepath.Base(info.comm) == "claude" {
			remote := info.tty == "??" || info.tty == "-"
			where := info.tty
			kind := "terminal"
			var tty *string
			if remote {
				where, kind = "headless / Remote Control", "remote"
			} else {
				t := info.tty
				tty = &t
			}
			var started *float64
			if t, err := time.ParseInLocation("Mon Jan 2 15:04:05 2006", info.lstart, time.Local); err == nil {
				s := float64(t.Unix())
				started = &s
			}
			pp := p
			return Session{Key: fmt.Sprintf("%d@%s", p, info.lstart), PID: &pp, Kind: kind, TTY: tty, Started: started,
				Label: fmt.Sprintf("claude pid %d (%s), started %s", p, where, info.lstart)}
		}
		if info.ppid <= 1 {
			break
		}
		p = info.ppid
	}
	// Not under Claude (e.g. you in a terminal): a key unique to this call, so grants never carry over.
	return Session{Key: fmt.Sprintf("nosession-%d-%s", pid, token(4)), Kind: "none",
		Label: fmt.Sprintf("no Claude session (requesting pid %d)", pid)}
}
