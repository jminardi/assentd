package main

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Root writes into _assentd's directory: a link planted at the temp file or the target must
// never be written through.
func TestWriteFileAtomicDoesNotFollowLinks(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	os.WriteFile(victim, []byte("untouched"), 0o644)
	path := filepath.Join(dir, "reenroll.json")
	if err := os.Symlink(victim, path+".tmp"); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomicAs(path, []byte("new"), 0o600, -1, -1); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "untouched" {
		t.Fatalf("wrote through a planted temp link: %q", b)
	}
	os.Remove(path)
	if err := os.Symlink(victim, path); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomicAs(path, []byte("new"), 0o600, -1, -1); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Lstat(path)
	if b, _ := os.ReadFile(victim); string(b) != "untouched" || fi.Mode()&os.ModeSymlink != 0 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("a link at the target was followed (victim %q, mode %v)", b, fi.Mode())
	}
	if _, err := os.Lstat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temp file left behind")
	}
}

func TestAuditValuesAreBounded(t *testing.T) {
	long := strings.Repeat("y", 10000)
	if s := auditValue(long).(string); len([]rune(s)) != maxAuditString+1 {
		t.Fatalf("string kept %d chars", len([]rune(s)))
	}
	argv := make([]string, 100)
	for i := range argv {
		argv[i] = strings.Repeat("a", 500)
	}
	total := 0
	for _, a := range auditValue(argv).([]string) {
		total += len(a)
	}
	if total > 2*maxAuditString+600 {
		t.Fatalf("argv kept %d chars", total)
	}
	if auditValue(42) != 42 {
		t.Fatal("non-strings must pass through")
	}
}

// A Chrome host that stops reading must not hold h.mu (and every fill) forever.
func TestHostWriteDeadline(t *testing.T) {
	old := hostWriteTimeout
	hostWriteTimeout = 300 * time.Millisecond
	defer func() { hostWriteTimeout = old }()
	dir, _ := os.MkdirTemp("/tmp", "hw")
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "s")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	peer, err := net.Dial("unix", sock) // never reads
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	c, err := ln.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	h := &hostConn{id: "t", sc: &sockConn{c, bufio.NewWriter(c)}, waiters: map[string]chan map[string]any{}}
	big := strings.Repeat("z", 256*1024)
	done := make(chan error, 1)
	go func() {
		var err error
		for i := 0; i < 100 && err == nil; i++ {
			err = h.send(map[string]any{"type": "x", "pad": big})
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("writes to a host that never reads kept succeeding")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a stuck host blocked the writer")
	}
	if _, err := h.ask(map[string]any{"type": "tab", "id": "q"}, time.Second); err == nil {
		t.Fatal("a dropped host still accepted a question")
	}
}
