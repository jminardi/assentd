package main

// http mode: the daemon makes the HTTPS request itself, so the secret never reaches the Mac.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const maxHTTPRespBody = 2 * 1024 * 1024

// checkIP refuses addresses no policy host may resolve to.
func checkIP(host string, ip netip.Addr) error {
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
		return fmt.Errorf("%s resolves to %s, which is never allowed", host, ip)
	}
	return nil
}

// pinnedDial resolves the host once, checks every address, and connects to a checked one (no
// rebinding between the check and the connection). TLS still verifies the certificate against
// the host name.
func pinnedDial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%s did not resolve", host)
	}
	for _, ip := range ips {
		if loopbackHTTPOK && ip.Unmap().IsLoopback() {
			continue // test mode only: the loopback stand-in API
		}
		if err := checkIP(host, ip); err != nil {
			return nil, err
		}
	}
	d := net.Dialer{Timeout: 20 * time.Second}
	return d.DialContext(ctx, network, net.JoinHostPort(ips[0].Unmap().String(), port))
}

var outClient = &http.Client{
	Timeout: 60 * time.Second,
	// A redirect could carry the secret to another host; hand the 3xx back instead.
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	Transport: &http.Transport{
		Proxy:               nil,
		DialContext:         pinnedDial,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:   true,
		DisableCompression:  true, // we ask for identity ourselves; nothing may be decoded behind the scrubber
		TLSHandshakeTimeout: 20 * time.Second,
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
	},
}

// HTTPResult is what goes back to the requester (and the audit log).
type HTTPResult struct {
	OK        bool       `json:"ok"`
	Status    int        `json:"status,omitempty"`
	Reason    string     `json:"reason,omitempty"`
	Headers   [][]string `json:"headers,omitempty"`
	BodyB64   string     `json:"body_b64,omitempty"`
	Truncated bool       `json:"truncated,omitempty"`
	Error     string     `json:"error,omitempty"`
}

func performHTTP(t *Target, value string) HTTPResult {
	filled := strings.Replace(t.Inject.Tpl, "{}", value, 1)
	if strings.ContainsAny(filled, "\r\n") {
		return HTTPResult{Error: t.Secret + " contains a line break, so it can't go in a header"}
	}
	extra := map[string][]string{}
	if t.Inject.Basic {
		enc := base64.StdEncoding.EncodeToString([]byte(filled))
		extra[t.Secret] = []string{enc}
		filled = "Basic " + enc
	}
	scrub := newScrubber(map[string]string{t.Secret: value}, extra, nil)
	fail := func(err error) HTTPResult {
		return HTTPResult{Error: scrub.scrubText("request failed: " + err.Error())}
	}

	u := t.Parsed
	hostport := u.Host
	if strings.Contains(hostport, ":") {
		hostport = "[" + hostport + "]"
	}
	if u.Port != 0 {
		hostport += ":" + strconv.Itoa(u.Port)
	}
	var body io.Reader
	if len(t.Body) > 0 {
		body = bytes.NewReader(t.Body)
	}
	req, err := http.NewRequest(t.Method, u.Scheme+"://"+hostport+"/", body)
	if err != nil {
		return fail(err)
	}
	// Send the path and query exactly as approved: Opaque is used verbatim on the request line.
	path := u.Path
	if path == "" {
		path = "/"
	}
	req.URL = &url.URL{Scheme: u.Scheme, Host: hostport, Opaque: path, RawQuery: u.Query}
	if u.Query == "" && strings.HasSuffix(t.URL, "?") {
		req.URL.ForceQuery = true
	}
	req.Header = http.Header{}
	req.Header.Set("User-Agent", "assentd/1")
	req.Header.Set("Accept-Encoding", "identity")
	for _, h := range t.Headers {
		req.Header.Set(h[0], h[1])
	}
	req.Header.Set(t.Inject.Name, filled)
	resp, err := outClient.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // its text would repeat the URL; the reply already knows it
		}
		return fail(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPRespBody+1))
	if err != nil {
		return fail(err)
	}
	if enc := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding"))); enc != "" && enc != "identity" {
		return HTTPResult{Error: fmt.Sprintf("the reply was %s-encoded, which the vault can't check for the secret, so it was withheld",
			scrub.scrubText(enc))}
	}
	truncated := len(data) > maxHTTPRespBody
	if truncated {
		data = data[:maxHTTPRespBody]
	}
	out := scrub.scrub(data)
	if truncated {
		// The cut may have split a secret, leaving a piece too short to recognise: drop the tail.
		out = out[:max(0, len(out)-scrub.keep)]
	}
	reason := strings.TrimSpace(strings.TrimPrefix(resp.Status, strconv.Itoa(resp.StatusCode)))
	keys := make([]string, 0, len(resp.Header))
	for k := range resp.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var hdrs [][]string
	for _, k := range keys {
		if strings.EqualFold(k, "Set-Cookie") {
			continue // cookies the site sets are credentials too, and the scrubber doesn't know them
		}
		for _, v := range resp.Header[k] {
			hdrs = append(hdrs, []string{k, scrub.scrubText(v)})
		}
	}
	return HTTPResult{OK: true, Status: resp.StatusCode, Reason: scrub.scrubText(reason), Headers: hdrs,
		BodyB64: base64.StdEncoding.EncodeToString(out), Truncated: truncated}
}
