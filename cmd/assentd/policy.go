package main

// Secret policies (metadata), and the checks a request's target has to pass before anyone is asked.

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type apiError struct {
	status int
	msg    string
}

func (e *apiError) Error() string { return e.msg }

func apiErr(status int, format string, a ...any) *apiError {
	return &apiError{status, fmt.Sprintf(format, a...)}
}

var (
	nameRE = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	// api.example.com | host:8443 (always https). IP addresses and localhost are refused (hostOK).
	hostRE = regexp.MustCompile(`^[a-z0-9-]+(\.[a-z0-9-]+)*(:\d{1,5})?$`)
	// Plain-http loopback targets exist only for the test suite: anything listening on loopback is
	// controlled by your login user, so allowing it would hand the plaintext to whatever owns that port.
	loopbackRE   = regexp.MustCompile(`^http://(localhost|127\.0\.0\.1):\d{1,5}$`)
	headerNameRE = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,100}$")
	headerValRE  = regexp.MustCompile(`^[\x20-\x7e\t]*$`)
	printableRE  = regexp.MustCompile(`^[\x20-\x7e]+$`)
	// The URL must be plain printable ASCII: no spaces, controls or anything a parser might normalise.
	urlCharsRE = regexp.MustCompile(`^[\x21-\x7e]+$`)
	// With a path limit set, the path may only use these characters (no percent-encoding at all).
	limitedPathRE = regexp.MustCompile(`^/[A-Za-z0-9._~!$&'()*+,;=:@/-]*$`)
	pathPrefixRE  = regexp.MustCompile(`^/[A-Za-z0-9._~!$&'()*+,;=:@/-]{0,199}$`)
)

// loopbackHTTPOK is set from config "test_allow_loopback_http" in test mode; never in production.
var loopbackHTTPOK = false

const (
	maxTTL         = 3600
	maxHTTPReqBody = 2 * 1024 * 1024
	placeholderTag = "{{vault:"
)

var (
	modes       = []string{"http", "command", "fill"}
	httpMethods = map[string]bool{"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true, "HEAD": true}
	// "max": as long as every secret in the request allows, for a policy shorter than 15 min or between the presets.
	choices     = map[string]float64{"once": 0, "15m": 900, "1h": 3600, "max": maxTTL}
	charsets    = map[string]string{
		"alnum":     "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
		"hex":       "0123456789abcdef",
		"base64url": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
		"strong":    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!@#%^*+=",
	}
	// Headers a requester may not set: they would redirect the request to another virtual host,
	// change its method or path behind the policy's back, break framing, or make the reply
	// compressed (which the scrubber can't see into). The daemon sets Host and Accept-Encoding itself.
	forbiddenHeaders = map[string]bool{"host": true, "content-length": true, "transfer-encoding": true, "te": true,
		"trailer": true, "connection": true, "upgrade": true, "keep-alive": true, "expect": true, "accept-encoding": true,
		"range": true, "if-range": true, "forwarded": true, "x-real-ip": true, "x-http-method": true,
		"x-http-method-override": true, "x-method-override": true, "x-original-url": true, "x-rewrite-url": true,
		"x-original-method": true}
	forbiddenHeaderPrefixes = []string{"proxy-", "x-forwarded-"}
	// A grant made for one mode can be reused for these modes. A command already handed out
	// plaintext, so its grant covers http too; an http grant stays narrow.
	covers = map[string]map[string]bool{"command": {"command": true, "http": true}, "http": {"http": true}}
)

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// hostOK: a policy host entry is a DNS name, never an IP address or localhost.
func hostOK(entry string) bool {
	if loopbackHTTPOK && loopbackRE.MatchString(entry) {
		return true
	}
	if !hostRE.MatchString(entry) {
		return false
	}
	name, _, _ := strings.Cut(entry, ":")
	if name == "localhost" || strings.HasSuffix(name, ".localhost") {
		return false
	}
	if net.ParseIP(name) != nil {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if strings.Trim(label, "0123456789") != "" {
			return true
		}
	}
	return false // all numeric: 10.1, 2130706433 and the like
}

// ParsedURL is a URL split the way it will be sent: nothing decoded or normalised.
type ParsedURL struct {
	Scheme, Netloc, Host string
	Port                 int // 0: none given
	Path, Query          string
}

func parseRawURL(raw string) (*ParsedURL, error) {
	scheme, rest, ok := strings.Cut(raw, "://")
	if !ok {
		return nil, fmt.Errorf("no scheme")
	}
	u := &ParsedURL{Scheme: strings.ToLower(scheme)}
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	u.Netloc, rest = rest[:end], rest[end:]
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest = rest[:i]
	}
	u.Path, u.Query, _ = strings.Cut(rest, "?")
	hostport := u.Netloc
	if strings.HasPrefix(hostport, "[") {
		i := strings.IndexByte(hostport, ']')
		if i < 0 {
			return nil, fmt.Errorf("bad host")
		}
		u.Host, hostport = hostport[1:i], hostport[i+1:]
		if hostport != "" && !strings.HasPrefix(hostport, ":") {
			return nil, fmt.Errorf("bad host")
		}
		hostport = strings.TrimPrefix(hostport, ":")
	} else {
		u.Host, hostport, _ = strings.Cut(hostport, ":")
	}
	u.Host = strings.ToLower(u.Host)
	if hostport != "" {
		if strings.Trim(hostport, "0123456789") != "" || len(hostport) > 5 {
			return nil, fmt.Errorf("bad port")
		}
		p, _ := strconv.Atoi(hostport)
		if p > 65535 {
			return nil, fmt.Errorf("bad port")
		}
		u.Port = p
	}
	return u, nil
}

func (u *ParsedURL) display() map[string]any {
	var port any
	if u.Port != 0 {
		port = u.Port
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	return map[string]any{"host": u.Host, "port": port, "path": path, "query": u.Query}
}

func defaultPort(scheme string) int {
	if scheme == "http" {
		return 80
	}
	return 443
}

// hostAllowed: whether this URL's host is on the allowlist (exact match only).
func hostAllowed(u *ParsedURL, hosts []string) bool {
	if u.Host == "" {
		return false
	}
	port := u.Port
	if port == 0 {
		port = defaultPort(u.Scheme)
	}
	for _, h := range hosts {
		if strings.HasPrefix(h, "http://") {
			if !loopbackHTTPOK || u.Scheme != "http" {
				continue
			}
			hu, err := parseRawURL(h)
			if err == nil && u.Host == hu.Host && u.Port != 0 && u.Port == hu.Port {
				return true
			}
			continue
		}
		if u.Scheme != "https" {
			continue
		}
		name, p, _ := strings.Cut(h, ":")
		want := 443
		if p != "" {
			want, _ = strconv.Atoi(p)
		}
		if port == want && u.Host == name {
			return true
		}
	}
	return false
}

func checkURL(raw string) (*ParsedURL, error) {
	if raw == "" || len(raw) > 4096 {
		return nil, apiErr(400, "bad target url")
	}
	if !urlCharsRE.MatchString(raw) {
		return nil, apiErr(400, "the url may only contain printable ASCII: no spaces, control or non-ASCII characters (percent-encode them)")
	}
	u, err := parseRawURL(raw)
	if err == nil && strings.ContainsAny(u.Netloc, "@\\%{}") {
		return nil, apiErr(400, "the host part of the url may not contain @, \\, %% or placeholders")
	}
	if err != nil {
		if _, rest, ok := strings.Cut(raw, "://"); ok && strings.ContainsAny(strings.SplitN(rest, "/", 2)[0], "@\\%{}") {
			return nil, apiErr(400, "the host part of the url may not contain @, \\, %% or placeholders")
		}
		return nil, apiErr(400, "bad target url")
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, apiErr(400, "the url must be https://host/...")
	}
	if strings.HasPrefix(u.Path, "//") {
		return nil, apiErr(400, "the url path may not start with //")
	}
	return u, nil
}

func headerForbidden(name string) bool {
	n := strings.ToLower(name)
	if forbiddenHeaders[n] {
		return true
	}
	for _, p := range forbiddenHeaderPrefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// HeaderTemplate: "Authorization: Bearer {}" -> {Authorization, "Bearer {}", basic=false}.
// "Authorization: Basic user:{}" -> {Authorization, "user:{}", basic=true}: the part after
// "Basic " is base64-encoded once the value is filled in.
type HeaderTemplate struct {
	Name, Tpl string
	Basic     bool
}

func parseHeaderTemplate(tpl string) (HeaderTemplate, error) {
	if len(tpl) > 1000 || !printableRE.MatchString(tpl) {
		return HeaderTemplate{}, apiErr(400, "the header must be printable ASCII, like 'Authorization: Bearer {}'")
	}
	name, value, ok := strings.Cut(tpl, ":")
	name, value = strings.TrimSpace(name), strings.TrimSpace(value)
	if !ok || !headerNameRE.MatchString(name) || headerForbidden(name) {
		shown := name
		if shown == "" {
			shown = tpl
		}
		return HeaderTemplate{}, apiErr(400, "%q can't be used as the secret's header", shown)
	}
	if strings.Count(value, "{}") != 1 {
		return HeaderTemplate{}, apiErr(400, "the header value needs exactly one {} where the secret goes")
	}
	if strings.ToLower(name) == "authorization" && strings.HasPrefix(strings.ToLower(value), "basic ") {
		return HeaderTemplate{name, strings.TrimSpace(value[6:]), true}, nil
	}
	return HeaderTemplate{name, value, false}, nil
}

// Meta is a secret's policy, as stored (meta_json) and bound into its ciphertext.
type Meta struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	MaxTTL      int64     `json:"max_ttl"`
	Modes       []string  `json:"modes"`
	Hosts       []string  `json:"hosts"`
	Created     int64     `json:"created"`
	HTTP        *HTTPPolc `json:"http,omitempty"`
	Fill        *FillPolc `json:"fill,omitempty"`
}

// HTTPPolc says how an HTTPS use places the secret. The requester only names the secret; where it
// goes is policy: header is the one header it is sent in, {} marking the value. methods / paths
// limit the requests it may be used for.
type HTTPPolc struct {
	Header  string   `json:"header,omitempty"`
	Methods []string `json:"methods,omitempty"`
	Paths   []string `json:"paths,omitempty"`
}

// parseMeta reads stored metadata leniently (it was validated when written).
func parseMeta(metaJSON string) Meta {
	var m Meta
	var raw map[string]json.RawMessage
	json.Unmarshal([]byte(metaJSON), &raw)
	json.Unmarshal(raw["name"], &m.Name)
	json.Unmarshal(raw["description"], &m.Description)
	var ttl float64
	json.Unmarshal(raw["max_ttl"], &ttl)
	m.MaxTTL = int64(ttl)
	json.Unmarshal(raw["modes"], &m.Modes)
	json.Unmarshal(raw["hosts"], &m.Hosts)
	var created float64
	json.Unmarshal(raw["created"], &created)
	m.Created = int64(created)
	if h, ok := raw["http"]; ok {
		var hp map[string]json.RawMessage
		if json.Unmarshal(h, &hp) == nil {
			m.HTTP = &HTTPPolc{}
			json.Unmarshal(hp["header"], &m.HTTP.Header)
			json.Unmarshal(hp["methods"], &m.HTTP.Methods)
			json.Unmarshal(hp["paths"], &m.HTTP.Paths)
		}
	}
	if f, ok := raw["fill"]; ok {
		var fp map[string]json.RawMessage
		if json.Unmarshal(f, &fp) == nil {
			m.Fill = &FillPolc{}
			json.Unmarshal(fp["origins"], &m.Fill.Origins)
		}
	}
	return m
}

var metaKeys = []string{"created", "description", "hosts", "max_ttl", "modes", "name"}

func jsonInt(raw json.RawMessage) (int64, bool) {
	s := strings.TrimSpace(string(raw))
	if s == "" || strings.ContainsAny(s, ".eE\"") {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil
}

func jsonStrings(raw json.RawMessage) ([]string, bool) {
	var list []any
	if json.Unmarshal(raw, &list) != nil || list == nil && string(raw) != "[]" {
		return nil, false
	}
	out := make([]string, 0, len(list))
	for _, x := range list {
		s, ok := x.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// checkMeta validates metadata the phone or a proposal wants to store.
func checkMeta(metaJSON string) (Meta, error) {
	if metaJSON == "" || len(metaJSON) > 8192 {
		return Meta{}, apiErr(400, "bad metadata")
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(metaJSON), &raw); err != nil || raw == nil {
		return Meta{}, apiErr(400, "metadata is not a JSON object")
	}
	for _, k := range metaKeys {
		if _, ok := raw[k]; !ok {
			return Meta{}, apiErr(400, "metadata keys must be %v, plus optional 'http' and 'fill'", metaKeys)
		}
	}
	for k := range raw {
		if !contains(metaKeys, k) && k != "http" && k != "fill" {
			return Meta{}, apiErr(400, "metadata keys must be %v, plus optional 'http' and 'fill'", metaKeys)
		}
	}
	var m Meta
	if json.Unmarshal(raw["name"], &m.Name) != nil || !nameRE.MatchString(m.Name) {
		return Meta{}, apiErr(400, "name must look like an env var: A-Z, 0-9, _ (starting with a letter)")
	}
	if json.Unmarshal(raw["description"], &m.Description) != nil || len([]rune(m.Description)) > 500 {
		return Meta{}, apiErr(400, "description must be a string up to 500 chars")
	}
	ttl, ok := jsonInt(raw["max_ttl"])
	if !ok || ttl < 60 || ttl > maxTTL {
		return Meta{}, apiErr(400, "max_ttl must be 60..%d seconds", maxTTL)
	}
	m.MaxTTL = ttl
	ms, ok := jsonStrings(raw["modes"])
	if !ok || len(ms) == 0 {
		return Meta{}, apiErr(400, "modes must be a non-empty subset of %v", modes)
	}
	for _, x := range ms {
		if !contains(modes, x) {
			return Meta{}, apiErr(400, "modes must be a non-empty subset of %v", modes)
		}
	}
	m.Modes = ms
	hs, ok := jsonStrings(raw["hosts"])
	if ok && len(hs) <= 20 {
		for _, h := range hs {
			if !hostOK(h) {
				ok = false
			}
		}
	}
	if !ok || len(hs) > 20 {
		return Meta{}, apiErr(400, "hosts must be up to 20 lowercase hostnames (api.example.com or host:port); "+
			"no wildcards, IP addresses or localhost")
	}
	m.Hosts = hs
	if contains(m.Modes, "http") && len(m.Hosts) == 0 {
		return Meta{}, apiErr(400, "http delivery needs at least one allowed host")
	}
	created, ok := jsonInt(raw["created"])
	if !ok {
		return Meta{}, apiErr(400, "created must be an integer timestamp")
	}
	m.Created = created
	if h, present := raw["http"]; present {
		var hp map[string]json.RawMessage
		if json.Unmarshal(h, &hp) != nil || hp == nil {
			return Meta{}, apiErr(400, "http policy keys must be a subset of [header methods paths]")
		}
		m.HTTP = &HTTPPolc{}
		for k, v := range hp {
			switch k {
			case "header":
				if json.Unmarshal(v, &m.HTTP.Header) != nil {
					return Meta{}, apiErr(400, "the header must be a string")
				}
				if _, err := parseHeaderTemplate(m.HTTP.Header); err != nil {
					return Meta{}, err
				}
			case "methods":
				list, ok := jsonStrings(v)
				for _, x := range list {
					ok = ok && httpMethods[x]
				}
				if !ok {
					return Meta{}, apiErr(400, "methods must be from [DELETE GET HEAD PATCH POST PUT]")
				}
				m.HTTP.Methods = list
			case "paths":
				list, ok := jsonStrings(v)
				for _, x := range list {
					ok = ok && pathPrefixRE.MatchString(x) && !strings.Contains(x, "..")
				}
				if !ok || len(list) > 20 {
					return Meta{}, apiErr(400, "paths must be up to 20 prefixes like /v1/refunds")
				}
				m.HTTP.Paths = list
			default:
				return Meta{}, apiErr(400, "http policy keys must be a subset of [header methods paths]")
			}
		}
	}
	if contains(m.Modes, "http") && (m.HTTP == nil || m.HTTP.Header == "") {
		return Meta{}, apiErr(400, "HTTPS use needs to say which header the secret goes in, like 'Authorization: Bearer {}'")
	}
	if f, present := raw["fill"]; present {
		var fp map[string]json.RawMessage
		if json.Unmarshal(f, &fp) != nil || fp == nil {
			return Meta{}, apiErr(400, "fill policy keys must be [origins]")
		}
		for k := range fp {
			if k != "origins" {
				return Meta{}, apiErr(400, "fill policy keys must be [origins]")
			}
		}
		list, ok := jsonStrings(fp["origins"])
		for _, o := range list {
			ok = ok && originOK(o)
		}
		if !ok || len(list) > 20 {
			return Meta{}, apiErr(400, "fill sites must be up to 20 https origins, like https://login.example.com; "+
				"no paths, wildcards, IP addresses or localhost")
		}
		m.Fill = &FillPolc{Origins: list}
	}
	if contains(m.Modes, "fill") && (m.Fill == nil || len(m.Fill.Origins) == 0) {
		return Meta{}, apiErr(400, "filling in Chrome needs at least one site, like https://login.example.com")
	}
	return m, nil
}

func pathAllowed(path string, prefixes []string) bool {
	if len(prefixes) == 0 {
		return true
	}
	// Refuse anything a server might normalise or decode into a different path than the one approved.
	if strings.Contains(path, "..") || strings.Contains(path, "//") || !limitedPathRE.MatchString(path) {
		return false
	}
	for _, p := range prefixes {
		if path == p || strings.HasPrefix(path, strings.TrimRight(p, "/")+"/") {
			return true
		}
	}
	return false
}

// Target is what a request's secret will be used for. Public() is what the phone shows.
type Target struct {
	Method      string
	URL         string
	Parsed      *ParsedURL
	Headers     [][2]string
	Body        []byte
	Secret      string
	Inject      HeaderTemplate
	BodyPreview string
	BodyLen     int // kept after Body is dropped (see Request.shed)
}

func (t *Target) Public() map[string]any {
	if t == nil {
		return map[string]any{}
	}
	hdrs := make([][]string, 0, len(t.Headers))
	for _, h := range t.Headers {
		hdrs = append(hdrs, []string{h[0], h[1]})
	}
	shown := strings.Replace(t.Inject.Tpl, "{}", placeholderTag+t.Secret+"}}", 1)
	if t.Inject.Basic {
		shown = "Basic " + shown
	}
	return map[string]any{"method": t.Method, "url": t.URL, "display": t.Parsed.display(), "headers": hdrs,
		"inject": [][]string{{t.Secret, t.Inject.Name, shown}}, "body_preview": t.BodyPreview, "body_bytes": t.BodyLen}
}

// TargetIn is a target as the CLI sends it.
type TargetIn struct {
	Method  string          `json:"method"`
	URL     string          `json:"url"`
	Headers json.RawMessage `json:"headers"`
	Use     []string        `json:"use"`
	BodyB64 string          `json:"body_b64"`
}

// checkTarget validates what a secret will be used for, against its policy (metaOf).
func checkTarget(mode string, in *TargetIn, needs []string, metaOf func(string) Meta) (*Target, error) {
	if mode != "http" {
		return nil, nil
	}
	if in == nil {
		return nil, apiErr(400, "http delivery needs a target")
	}
	u, err := checkURL(in.URL)
	if err != nil {
		return nil, err
	}
	if len(needs) != 1 || len(in.Use) != 1 || in.Use[0] != needs[0] {
		return nil, apiErr(400, "an http request uses exactly one secret, named with --secret NAME")
	}
	name := needs[0]
	meta := metaOf(name)
	if !hostAllowed(u, meta.Hosts) {
		allowed := strings.Join(meta.Hosts, ", ")
		if allowed == "" {
			allowed = "none"
		}
		return nil, apiErr(403, "%s is not an allowed host for %s (allowed: %s)", u.Netloc, name, allowed)
	}
	method := strings.ToUpper(in.Method)
	if method == "" {
		method = "GET"
	}
	if !httpMethods[method] {
		return nil, apiErr(400, "method must be one of [DELETE GET HEAD PATCH POST PUT]")
	}
	var headers [][2]string
	if len(in.Headers) > 0 && string(in.Headers) != "null" {
		var raw [][]string
		if json.Unmarshal(in.Headers, &raw) != nil || len(raw) > 50 {
			return nil, apiErr(400, "bad headers")
		}
		for _, h := range raw {
			if len(h) != 2 || !headerNameRE.MatchString(h[0]) || !headerValRE.MatchString(h[1]) || len(h[1]) > 8192 {
				return nil, apiErr(400, "bad header")
			}
			if headerForbidden(h[0]) {
				return nil, apiErr(400, "the %s header can't be set; the vault controls it", h[0])
			}
			if strings.Contains(h[1], placeholderTag) {
				return nil, apiErr(400, "secrets don't go in -H headers: each secret's policy names the header it is "+
					"sent in. Name the secret with --secret NAME instead")
			}
			headers = append(headers, [2]string{h[0], h[1]})
		}
	}
	body, err := base64.StdEncoding.DecodeString(in.BodyB64)
	if err != nil {
		return nil, apiErr(400, "bad body encoding")
	}
	if len(body) > maxHTTPReqBody {
		return nil, apiErr(413, "request body too large")
	}
	if strings.Contains(in.URL, placeholderTag) || bytes.Contains(body, []byte(placeholderTag)) {
		return nil, apiErr(400, "secrets only go in the header their policy names, never in the URL or body; "+
			"name the secret with --secret NAME")
	}
	hp := meta.HTTP
	if hp == nil || hp.Header == "" {
		return nil, apiErr(403, "%s's policy doesn't name a header to send it in; set one on the phone (edit %s)", name, name)
	}
	tpl, err := parseHeaderTemplate(hp.Header)
	if err != nil {
		return nil, err
	}
	for _, h := range headers {
		if strings.EqualFold(h[0], tpl.Name) {
			return nil, apiErr(400, "two values for the %s header (from %s and another header)", tpl.Name, name)
		}
	}
	if len(hp.Methods) > 0 && !contains(hp.Methods, method) {
		return nil, apiErr(403, "%s allows only %s requests", name, strings.Join(hp.Methods, ", "))
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	if !pathAllowed(path, hp.Paths) {
		return nil, apiErr(403, "%s allows only paths under %s, written without percent-encoding, '..' or '//'",
			name, strings.Join(hp.Paths, ", "))
	}
	preview := body
	more := ""
	if len([]rune(string(body))) > 2000 {
		preview = []byte(string([]rune(string(body))[:2000]))
		more = "…"
	}
	return &Target{Method: method, URL: in.URL, Parsed: u, Headers: headers, Body: body, BodyLen: len(body), Secret: name, Inject: tpl,
		BodyPreview: strings.ToValidUTF8(string(preview), "�") + more}, nil
}

// Proposal is the policy a requester suggests for a new secret; you can change it on the phone.
type Proposal struct {
	Description string    `json:"description"`
	Modes       []string  `json:"modes"`
	Hosts       []string  `json:"hosts"`
	MaxTTL      int64     `json:"max_ttl"`
	HTTP        *HTTPPolc `json:"http"`
	Fill        *FillPolc `json:"fill"`
}

func canonicalJSON(v any) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
	return strings.TrimRight(b.String(), "\n")
}

// proposalMeta turns a proposed policy into canonical, validated meta_json.
func proposalMeta(name string, p *Proposal) (string, error) {
	if p == nil {
		return "", apiErr(400, "bad proposed policy for %s", name)
	}
	desc := []rune(p.Description)
	if len(desc) > 500 {
		desc = desc[:500]
	}
	meta := map[string]any{"name": name, "description": string(desc), "modes": p.Modes, "hosts": p.Hosts,
		"max_ttl": p.MaxTTL, "created": now64()}
	if len(p.Modes) == 0 {
		meta["modes"] = []string{"command"}
	}
	if p.Hosts == nil {
		meta["hosts"] = []string{}
	}
	if p.MaxTTL == 0 {
		meta["max_ttl"] = 900
	}
	if p.HTTP != nil && (p.HTTP.Header != "" || len(p.HTTP.Methods) > 0 || len(p.HTTP.Paths) > 0) {
		meta["http"] = p.HTTP
	}
	if p.Fill != nil && len(p.Fill.Origins) > 0 {
		meta["fill"] = p.Fill
	}
	mj := canonicalJSON(meta)
	if _, err := checkMeta(mj); err != nil {
		return "", err
	}
	return mj, nil
}

type GenerateSpec struct {
	Length  int    `json:"length"`
	Charset string `json:"charset"`
}

func generateValue(spec *GenerateSpec) (string, error) {
	cs := spec.Charset
	if cs == "" {
		cs = "alnum"
	}
	charset, ok := charsets[cs]
	if !ok {
		keys := make([]string, 0, len(charsets))
		for k := range charsets {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return "", apiErr(400, "charset must be one of %v", keys)
	}
	n := spec.Length
	if n == 0 {
		n = 32
	}
	if n < 8 || n > 256 {
		return "", apiErr(400, "length must be 8..256")
	}
	out := make([]byte, n)
	for i := range out {
		j, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		out[i] = charset[j.Int64()]
	}
	return string(out), nil
}
