package main

// assentd-chrome-host: the native messaging host Chrome starts for the assentd extension. It only
// relays: native messaging frames (4-byte native-endian length + JSON) on stdin/stdout to and
// from JSON lines on the daemon's socket.

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"sync"
)

const maxFromDaemon = 1024 * 1024 // Chrome's limit for a message to an extension

func writeFrame(w io.Writer, mu *sync.Mutex, data []byte) error {
	mu.Lock()
	defer mu.Unlock()
	var n [4]byte
	binary.NativeEndian.PutUint32(n[:], uint32(len(data)))
	if _, err := w.Write(n[:]); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

func readFrame(r io.Reader) ([]byte, error) {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, err
	}
	size := binary.NativeEndian.Uint32(n[:])
	if size > maxHostMsg {
		return nil, io.ErrShortBuffer
	}
	buf := make([]byte, size)
	_, err := io.ReadFull(r, buf)
	return buf, err
}

func runChromeHost(args []string) int {
	// Chrome passes the calling extension's origin first; only ours may use this host (the host
	// manifest says so too).
	if len(args) == 0 || args[0] != extensionOrigin {
		os.Stderr.WriteString("assentd-chrome-host: started by Chrome for the assentd extension only\n")
		return 1
	}
	var outMu sync.Mutex
	out := bufio.NewWriter(os.Stdout)
	flushOut := func(data []byte) error {
		if err := writeFrame(out, &outMu, data); err != nil {
			return err
		}
		outMu.Lock()
		defer outMu.Unlock()
		return out.Flush()
	}
	refuse := func(msg string) int {
		data, _ := json.Marshal(map[string]any{"type": "status", "paired": false, "error": msg})
		flushOut(data)
		return 1
	}
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sockPath, Net: "unix"})
	if err != nil {
		return refuse("the vault daemon isn't running")
	}
	defer c.Close()
	c.Write([]byte(`{"op":"chrome-host"}` + "\n"))
	r := bufio.NewReaderSize(c, 65536)
	line, err := readLine(r, maxFromDaemon)
	var hs map[string]any
	if err != nil || json.Unmarshal(line, &hs) != nil {
		return refuse("the vault daemon closed the connection")
	}
	if ok, _ := hs["ok"].(bool); !ok {
		e, _ := hs["error"].(string)
		return refuse(e)
	}
	// daemon -> Chrome
	go func() {
		for {
			line, err := readLine(r, maxFromDaemon)
			if err != nil || flushOut(line) != nil {
				os.Exit(0)
			}
		}
	}()
	// Chrome -> daemon. Compacted, so a message is always exactly one line.
	in := bufio.NewReader(os.Stdin)
	for {
		frame, err := readFrame(in)
		if err != nil {
			return 0
		}
		var buf bytes.Buffer
		if !json.Valid(frame) || json.Compact(&buf, frame) != nil {
			continue
		}
		buf.WriteByte('\n')
		if _, err := c.Write(buf.Bytes()); err != nil {
			return 0
		}
	}
}
