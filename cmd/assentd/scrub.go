package main

// Redaction of secret values from output: an http reply on its way back to the requester, and a
// command's output in the CLI. This catches accidents, not determined code: anything that can
// transform the value (reverse it, encrypt it, split it across requests) gets past it.

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf16"
)

const (
	minScrubLen = 6
	// Any run of this many characters of a longer secret is redacted too, so a cut-off or masked
	// echo ("invalid key sk_live_51H***") doesn't give away most of the value.
	runLen = 8
)

type scrubPat struct{ pat, tag []byte }

type Scrubber struct {
	pats []scrubPat // longest first
	runs []scrubPat // (raw value, tag) for run matching
	keep int        // tail held back while streaming, so no secret straddles two writes
}

// newScrubber: extra holds more exact strings per name that also reveal it (e.g. a Basic auth header).
func newScrubber(values map[string]string, extra map[string][]string, warn func(string)) *Scrubber {
	s := &Scrubber{}
	pats := map[string][]byte{}
	names := make([]string, 0, len(values))
	for n := range values {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		raw := []byte(values[name])
		if len(raw) < minScrubLen {
			if warn != nil {
				warn(fmt.Sprintf("warning: %s is shorter than %d bytes and will not be redacted from output", name, minScrubLen))
			}
			continue
		}
		tag := []byte("[assentd:" + name + "]")
		b64 := base64.StdEncoding.EncodeToString(raw)
		variants := []string{string(raw), b64, strings.TrimRight(b64, "="), base64.RawURLEncoding.EncodeToString(raw),
			pyQuote(raw), pyJSONEscape(values[name]), hex.EncodeToString(raw), strings.ToUpper(hex.EncodeToString(raw))}
		variants = append(variants, extra[name]...)
		for _, v := range variants {
			if len(v) >= minScrubLen {
				pats[v] = tag
			}
		}
		if len(raw) > runLen {
			s.runs = append(s.runs, scrubPat{raw, tag})
		}
	}
	s.keep = runLen
	for p, tag := range pats {
		s.pats = append(s.pats, scrubPat{[]byte(p), tag})
		if len(p) > s.keep {
			s.keep = len(p)
		}
	}
	s.keep--
	sort.Slice(s.pats, func(i, j int) bool {
		if len(s.pats[i].pat) != len(s.pats[j].pat) {
			return len(s.pats[i].pat) > len(s.pats[j].pat)
		}
		return bytes.Compare(s.pats[i].pat, s.pats[j].pat) < 0
	})
	return s
}

// pyQuote: percent-encoding of every byte but A-Z a-z 0-9 _ . - ~ (Python's quote(v, safe="")).
func pyQuote(raw []byte) string {
	var b strings.Builder
	for _, c := range raw {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || strings.IndexByte("_.-~", c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// pyJSONEscape: the value as it appears inside a JSON string with ASCII-only escaping.
func pyJSONEscape(v string) string {
	var b strings.Builder
	for _, r := range v {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if r >= 0x20 && r <= 0x7e {
				b.WriteRune(r)
			} else if r > 0xffff {
				r1, r2 := utf16.EncodeRune(r)
				fmt.Fprintf(&b, `\u%04x\u%04x`, r1, r2)
			} else {
				fmt.Fprintf(&b, `\u%04x`, r)
			}
		}
	}
	return b.String()
}

func (s *Scrubber) scrubRuns(data []byte) []byte {
	type span struct {
		start, end int
		tag        []byte
	}
	var spans []span
	for _, r := range s.runs {
		for i := 0; i+runLen <= len(r.pat); i++ {
			gram := r.pat[i : i+runLen]
			for off := 0; ; {
				j := bytes.Index(data[off:], gram)
				if j < 0 {
					break
				}
				spans = append(spans, span{off + j, off + j + runLen, r.tag})
				off += j + 1
			}
		}
	}
	if len(spans) == 0 {
		return data
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start != spans[j].start {
			return spans[i].start < spans[j].start
		}
		return spans[i].end < spans[j].end
	})
	merged := []span{spans[0]}
	for _, sp := range spans[1:] {
		last := &merged[len(merged)-1]
		if sp.start <= last.end {
			if sp.end > last.end {
				last.end = sp.end
			}
		} else {
			merged = append(merged, sp)
		}
	}
	var out bytes.Buffer
	last := 0
	for _, m := range merged {
		out.Write(data[last:m.start])
		out.Write(m.tag)
		last = m.end
	}
	out.Write(data[last:])
	return out.Bytes()
}

func (s *Scrubber) scrub(data []byte) []byte {
	for _, p := range s.pats {
		data = bytes.ReplaceAll(data, p.pat, p.tag)
	}
	if len(s.runs) > 0 {
		data = s.scrubRuns(data)
	}
	return data
}

func (s *Scrubber) scrubText(t string) string {
	return strings.ToValidUTF8(string(s.scrub([]byte(t))), "�")
}

// pump copies r to w, holding back just enough tail that no secret can straddle two writes.
func (s *Scrubber) pump(r io.Reader, w io.Writer) error {
	var buf []byte
	chunk := make([]byte, 65536)
	for {
		n, err := r.Read(chunk)
		if n > 0 {
			buf = s.scrub(append(buf, chunk[:n]...))
			if len(buf) > s.keep {
				cut := len(buf) - s.keep
				if _, werr := w.Write(buf[:cut]); werr != nil {
					return werr
				}
				buf = append([]byte{}, buf[cut:]...)
			}
		}
		if err != nil {
			break
		}
	}
	if len(buf) > 0 {
		_, err := w.Write(s.scrub(buf))
		return err
	}
	return nil
}
