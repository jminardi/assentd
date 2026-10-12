"""End-to-end test: the real assentd binary (daemon + CLI), with a software passkey standing in for
the phone. The daemon runs in test mode: the phone page on a Unix socket, with the caller's tailnet
identity given as headers (in production it comes from Tailscale itself).

  .venv/bin/python tests/test_e2e.py          (builds the binary with Go first; GO=path/to/go to choose)
"""
import base64
import gzip
import http.client
import json
import os
import queue
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
import phone as vc  # noqa: E402
from phone import SoftPasskey, b64u, unb64u  # noqa: E402

RP_ID = "vault.test"
ORIGIN = f"https://{RP_ID}"
BEARER = {"header": "Authorization: Bearer {}"}
PHONE = {"node": "iphone.example.ts.net", "node_id": "nPHONE1CNTRL", "node_key": "nodekey:aa11", "login": "me@example.com"}
NAS = {"node": "nas.example.ts.net", "node_id": "nNAS1CNTRL", "node_key": "nodekey:bb22", "login": "me@example.com"}
TMP = Path(tempfile.mkdtemp(prefix="av-test-", dir="/tmp"))
BIN = str(TMP / "assentd")


def build():
    go = os.environ.get("GO") or next((g for g in ("/usr/local/libexec/assentd-build/go1.24.13/go/bin/go",
                                                   shutil.which("go")) if g and os.path.exists(g)), None)
    if not go:
        sys.exit("needs Go to build the binary (set GO=/path/to/go)")
    subprocess.run([go, "build", "-o", BIN, "./cmd/assentd"], cwd=ROOT, check=True,
                   env=dict(os.environ, GOTOOLCHAIN="local", CGO_ENABLED="0"))


def passkey():
    return SoftPasskey(RP_ID, ORIGIN)


def in_claude_session() -> bool:
    """Whether this process runs under a `claude` process, as the daemon would see it."""
    pid = os.getpid()
    for _ in range(40):
        out = subprocess.run(["/bin/ps", "-o", "ppid=", "-o", "comm=", "-p", str(pid)], capture_output=True, text=True).stdout.split()
        if len(out) < 2:
            return False
        if os.path.basename(" ".join(out[1:])) == "claude":
            return True
        pid = int(out[0])
        if pid <= 1:
            return False
    return False


class UnixConn(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("assentd", timeout=30)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.connect(self.path)


class Env:
    def __init__(self, name="main", data_from=None, cfg_extra=None, start=True):
        self.tmp = TMP / name
        self.tmp.mkdir()
        if data_from:
            for f in ("store.json", "audit.jsonl"):
                shutil.copy(Path(data_from) / f, self.tmp / f)
        self.sock = str(self.tmp / "s.sock")
        self.http_sock = str(self.tmp / "h.sock")
        self.cfg = {"rp_id": RP_ID, "origin": ORIGIN, "test_mode": True, "client_uid": os.getuid(),
                    "http_socket": self.http_sock, "allowed_logins": ["me@example.com"], "enroll_token": "tok",
                    "request_timeout": 300, "test_allow_loopback_http": True, "new_per_minute": 100000, **(cfg_extra or {})}
        (self.tmp / "config.json").write_text(json.dumps(self.cfg))
        self.env = dict(os.environ, ASSENTD_DATA=str(self.tmp), ASSENTD_SOCK=self.sock)
        self.seen = set()
        self.proc = None
        if start:
            self.start()

    def start(self):
        self.log = open(self.tmp / "daemon.log", "w")
        self.proc = subprocess.Popen([BIN, "daemon"], env=self.env, stdout=self.log, stderr=subprocess.STDOUT)
        for _ in range(200):
            if os.path.exists(self.sock) and os.path.exists(self.http_sock):
                try:
                    self.call("GET", "/enroll")
                    return
                except OSError:
                    pass
            time.sleep(0.05)
        raise RuntimeError("daemon did not start: " + (self.tmp / "daemon.log").read_text())

    def close(self):
        if self.proc:
            self.proc.terminate()
            self.proc.wait()

    def call(self, method, path, body=None, dev=PHONE, origin=ORIGIN, raw=False):
        c = UnixConn(self.http_sock)
        hdr = {}
        if dev:
            hdr = {"X-Assentd-Login": dev["login"], "X-Assentd-Node": dev["node"], "X-Assentd-Node-ID": dev["node_id"],
                   "X-Assentd-Node-Key": dev["node_key"]}
        if method == "POST":
            hdr.update({"Origin": origin, "Content-Type": "application/json"})
        c.request(method, path, body=json.dumps(body) if body is not None else None, headers=hdr)
        r = c.getresponse()
        data = r.read()
        if raw:
            return r, data
        try:
            return r.status, json.loads(data)
        except ValueError:
            return r.status, data.decode()

    def get(self, path, dev=PHONE):
        st, body = self.call("GET", path, dev=dev)
        if st != 200:
            raise OSError(st, body)
        return body

    def post(self, path, body, origin=ORIGIN, dev=PHONE):
        return self.call("POST", path, body, dev=dev, origin=origin)

    def cli(self, *args, **kw):
        return subprocess.Popen([BIN, *args], env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, **kw)

    def run(self, *args, stdin=None, timeout=30):
        return subprocess.run([BIN, *args], env=self.env, capture_output=True, text=True, input=stdin, timeout=timeout)

    def next_pending(self, kind="pending", timeout=10):
        """The id of the next request (or deposit) to show up on the phone."""
        end = time.time() + timeout
        while time.time() < end:
            for r in self.get("/api/state")[kind]:
                if r["id"] not in self.seen:
                    self.seen.add(r["id"])
                    return r["id"]
            time.sleep(0.05)
        raise TimeoutError(f"no new {kind}")

    def nothing_new(self):
        st = self.get("/api/state")
        return not [r for r in st["pending"] + st["deposits"] if r["id"] not in self.seen]


# ------------------------------------------------------------------ phone-side helpers (mirror app.mjs)

def enroll_body(b, pk, vmk, code, token="tok"):
    reg = pk.create(unb64u(b["create"]["challenge"]))
    assertion, prf = pk.get(unb64u(b["get"]["challenge"]))
    _, rk = vc.keypair_box(vmk, vc.RECOVERY_KEY_AAD)
    return {"token": token, "create_challenge_id": b["create"]["challenge_id"], "get_challenge_id": b["get"]["challenge_id"],
            **reg, "assertion": assertion,
            "vmk_wrap": vc.seal(vc.kek(prf, vc.KEK_INFO_PRF), vmk, vc.VMK_AAD),
            "recovery_wrap": vc.seal(vc.kek(code, vc.KEK_INFO_RECOVERY), vmk, vc.VMK_AAD),
            "recovery_key": rk}


def enroll(e: Env, pk: SoftPasskey) -> bytes:
    st, b = e.post("/api/enroll/begin", {"token": "tok"})
    assert st == 200, b
    code = os.urandom(32)
    st, r = e.post("/api/enroll/finish", enroll_body(b, pk, os.urandom(32), code))
    assert st == 200, r
    return code


def unlock(e: Env, pk: SoftPasskey, ch: dict, **kw):
    """Face ID, then /api/unlock: returns (action token, vmk, what the phone was given)."""
    assertion, prf = pk.get(unb64u(ch["challenge"]), **kw)
    st, data = e.post("/api/unlock", {"challenge_id": ch["challenge_id"], "assertion": assertion})
    if st != 200:
        raise PermissionError(st, data)
    vmk = vc.open_box(vc.kek(prf, vc.KEK_INFO_PRF), data["vmk_wrap"], vc.VMK_AAD)
    return data["action"], vmk, data


def add_secret(e: Env, pk: SoftPasskey, name: str, value: str, max_ttl=3600, overwrite=False,
               modes=("command",), hosts=(), http=None):
    st, ch = e.post("/api/challenge", {"kind": "add"})
    assert st == 200, ch
    action, vmk, _ = unlock(e, pk, ch)
    meta = {"created": int(time.time()), "description": f"test {name}", "hosts": list(hosts),
            "max_ttl": max_ttl, "modes": list(modes), "name": name}
    if http is None and "http" in modes:
        http = BEARER
    if http is not None:
        meta["http"] = http
    meta_json = json.dumps(meta, sort_keys=True, separators=(",", ":"))
    box = vc.seal(vmk, value.encode(), vc.secret_aad(meta_json))
    return e.post("/api/add", {"action": action, "meta_json": meta_json, "box": box, "overwrite": overwrite})


def decide(e: Env, pk: SoftPasskey, rid, choice="once", deny=False, **unlock_kw):
    if deny:
        return e.post(f"/api/req/{rid}/deny", {})
    st, ch = e.post("/api/challenge", {"kind": "req", "ref": rid})
    assert st == 200, ch
    try:
        action, vmk, data = unlock(e, pk, ch, **unlock_kw)
    except PermissionError as err:
        return err.args
    values = {s["name"]: vc.open_box(vmk, s["box"], vc.secret_aad(s["meta_json"])).decode() for s in data["secrets"]}
    return e.post(f"/api/req/{rid}/approve", {"action": action, "choice": choice, "values": values})


def phone_decide(e: Env, pk: SoftPasskey, **kw):
    return decide(e, pk, e.next_pending(), **kw)


def run_with_phone(e, pk, cli_args, **phone_kw):
    p = e.cli(*cli_args)
    result = {}
    t = threading.Thread(target=lambda: result.update(phone=phone_decide(e, pk, **phone_kw)))
    t.start()
    out, err = p.communicate(timeout=30)
    t.join()
    return p.returncode, out, err, result.get("phone")


class EchoServer(HTTPServer):
    """Plain-http stand-in for an API: records what it received and echoes the auth header back,
    in plain text, gzipped, in the status line, or in a cookie."""

    def __init__(self):
        self.seen = []
        outer = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def handle_one(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                auth = self.headers.get("Authorization") or ""
                outer.seen.append({"path": self.path, "auth": auth, "x": self.headers.get("X-Key"), "body": body,
                                   "method": self.command, "accept_encoding": self.headers.get("Accept-Encoding"),
                                   "host": self.headers.get("Host")})
                if self.path.startswith("/redirect"):
                    self.send_response(302)
                    self.send_header("Location", "http://evil.test/steal")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if self.path.startswith("/reason"):
                    self.send_response(401, f"bad key {auth}")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                out = json.dumps({"you_sent": auth, "x": self.headers.get("X-Key"), "body": body.decode()}).encode()
                if self.path.startswith("/big"):
                    out = b"a" * (3 * 1024 * 1024 - 5) + auth.encode()[-12:]
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", f"session={auth[-12:]}")
                self.send_header("X-Echo", auth)
                if self.path.startswith("/gzip"):
                    out = gzip.compress(out)
                    self.send_header("Content-Encoding", "gzip")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            do_GET = do_POST = do_PUT = do_DELETE = handle_one

            def log_message(self, *a):
                pass

        super().__init__(("127.0.0.1", 0), H)
        threading.Thread(target=self.serve_forever, daemon=True).start()

    def handle_error(self, request, client_address):
        pass  # the daemon hangs up on oversized replies; that's the point of the test


def sock_request(e: Env, msg: dict, op="request") -> dict:
    """Talk to the daemon like the CLI does; returns the final reply."""
    with socket.socket(socket.AF_UNIX) as s:
        s.connect(e.sock)
        s.sendall((json.dumps({"op": op, "cwd": "/", **msg}) + "\n").encode())
        last = {}
        for line in s.makefile():
            last = json.loads(line)
            if "pending" not in last and "pending_deposit" not in last:
                return last
        return last


def bg_sock_request(e: Env, msg: dict):
    """A request that waits on the phone; returns (thread, result dict, request id)."""
    result = {}
    t = threading.Thread(target=lambda: result.update(r=sock_request(e, msg)))
    t.start()
    return t, result, e.next_pending()


# ------------------------------------------------------------------ http mode

def http_checks(e: Env, pk: SoftPasskey, check):
    api = EchoServer()
    port = api.server_address[1]
    base = f"http://127.0.0.1:{port}"
    host = base
    token = "tok_" + os.urandom(10).hex()
    add_secret(e, pk, "API_TOKEN", token, modes=("http",), hosts=(host,))
    add_secret(e, pk, "LIMITED", "limited-" + os.urandom(6).hex(), modes=("http",), hosts=(host,),
               http={"header": "X-Key: {}", "methods": ["GET"], "paths": ["/v1/refunds"]})
    for method, path, why in [("POST", "/v1/refunds", "method"), ("GET", "/v1/charges", "path"),
                              ("GET", "/v1/refunds/../charges", "dot-dot path"),
                              ("GET", "/v1/refunds/%2e%2e/charges", "encoded dot-dot"),
                              ("GET", "/v1/refunds/%252e%252e/charges", "double-encoded dot-dot"),
                              ("GET", "/v1/refunds/re_1;x=..%2f", "encoded slash"),
                              ("GET", "/v1/refundsX", "prefix lookalike")]:
        r = sock_request(e, {"needs": ["LIMITED"], "mode": "http", "reason": "x",
                             "target": {"method": method, "url": f"{base}{path}", "use": ["LIMITED"]}})
        check(f"path/method limits: {why} refused", not r.get("ok") and "allows only" in r.get("error", ""), r)

    # The daemon sends the secret to the allowed host, in the policy's header; the caller sees it redacted.
    rc, out, err, ph = run_with_phone(e, pk, ["http", "--secret", "API_TOKEN", "--reason", "api test", "-i", f"{base}/v1/thing?k=1"])
    seen = api.seen[-1] if api.seen else {}
    check("http: API received the secret in the policy header", rc == 0 and seen.get("auth") == f"Bearer {token}"
          and seen.get("path") == "/v1/thing?k=1", (rc, err, seen))
    check("http: response body and headers redacted, cookies dropped", token not in out and "[assentd:API_TOKEN]" in out
          and "set-cookie" not in out.lower() and "X-Echo: Bearer [assentd:API_TOKEN]" in out, out)
    check("http: the vault asks for an uncompressed reply", seen.get("accept_encoding") == "identity", seen)
    check("http: Host is the URL's host", seen.get("host") == f"127.0.0.1:{port}", seen)

    rc, out, err, _ = run_with_phone(e, pk, ["http", "--secret", "LIMITED", "--reason", "limited ok", f"{base}/v1/refunds/re_1"])
    check("request within method/path limits works", rc == 0 and api.seen[-1]["path"] == "/v1/refunds/re_1"
          and (api.seen[-1]["x"] or "").startswith("limited-"), (rc, err))

    # Basic auth from the policy. The username shifts where the value lands in the base64; the
    # exact header the daemon built is scrubbed whatever the alignment.
    pw = "pw_" + os.urandom(9).hex()
    for user in ("a", "ab", "abc"):
        name = f"BASIC_{len(user)}"
        add_secret(e, pk, name, pw, modes=("http",), hosts=(host,), http={"header": f"Authorization: Basic {user}:{{}}"})
        rc, out, err, _ = run_with_phone(e, pk, ["http", "--secret", name, "--reason", "basic", "-i", f"{base}/basic"])
        enc = base64.b64encode(f"{user}:{pw}".encode()).decode()
        check(f"basic auth ({len(user)}-char user): sent, and the echo redacted",
              rc == 0 and api.seen[-1]["auth"] == f"Basic {enc}" and enc not in out and pw not in out, (rc, err, out))

    # body sent as given
    rc, out, err, _ = run_with_phone(e, pk, ["http", "--secret", "API_TOKEN", "--reason", "body", "--json", '{"t":1}', f"{base}/b"])
    seen = api.seen[-1]
    check("http: JSON body sent as a POST", rc == 0 and json.loads(seen["body"]) == {"t": 1} and seen["method"] == "POST", (rc, err, seen))

    # replies the scrubber can't read are withheld, not decoded
    rc, out, err, _ = run_with_phone(e, pk, ["http", "--secret", "API_TOKEN", "--reason", "gz", f"{base}/gzip"])
    check("http: a compressed reply is withheld", rc == 1 and "withheld" in err and token not in out + err, (rc, out, err))
    rc, out, err, _ = run_with_phone(e, pk, ["http", "--secret", "API_TOKEN", "--reason", "status", "-i", f"{base}/reason"])
    check("http: the status line is redacted", rc == 0 and token not in out + err and "[assentd:API_TOKEN]" in err, (out, err))
    rc, out, err, _ = run_with_phone(e, pk, ["http", "--secret", "API_TOKEN", "--reason", "big", f"{base}/big"])
    check("http: replies over 2 MB are cut, without a split secret at the end",
          rc == 0 and "truncated" in err and len(out) <= 2 * 1024 * 1024 and token[-12:] not in out, (rc, err, len(out)))

    # headers the requester may not set, and secrets in -H, the URL or the body
    for hdr in ("Host: evil.test", "X-HTTP-Method-Override: DELETE", "Transfer-Encoding: chunked",
                "Accept-Encoding: gzip", "X-Forwarded-Host: evil.test"):
        r = e.run("http", "--secret", "API_TOKEN", "--reason", "x", "-H", hdr, f"{base}/")
        check(f"http: requester can't set {hdr.split(':')[0]}", r.returncode == 1 and "can't be set" in r.stderr
              and e.nothing_new(), r.stderr)
    r = e.run("http", "--secret", "API_TOKEN", "--reason", "x", "-H", "X-Key: {{vault:API_TOKEN}}", f"{base}/")
    check("http: secrets in -H headers refused", r.returncode == 2 and "--secret" in r.stderr, r.stderr)
    for where, extra, url in [("URL", [], f"{base}/x?k={{{{vault:API_TOKEN}}}}"),
                              ("body", ["--data", "t={{vault:API_TOKEN}}"], f"{base}/x")]:
        r = e.run("http", "--secret", "API_TOKEN", "--reason", "x", *extra, url)
        check(f"http: placeholder in the {where} refused by the CLI", r.returncode == 2 and "only go in the header" in r.stderr, r.stderr)
        body = base64.b64encode(extra[1].encode()).decode() if extra else ""
        r = sock_request(e, {"needs": ["API_TOKEN"], "mode": "http", "reason": "x",
                             "target": {"url": url, "use": ["API_TOKEN"], "body_b64": body}})
        check(f"http: placeholder in the {where} refused by the daemon", not r.get("ok") and "only go in the header" in r.get("error", ""), r)
    r = sock_request(e, {"needs": ["API_TOKEN"], "mode": "http", "reason": "x",
                         "target": {"url": f"{base}/", "headers": [["X-Key", "{{vault:API_TOKEN}}"]], "use": ["API_TOKEN"]}})
    check("http: the daemon also refuses secrets in requester headers", not r.get("ok") and "--secret" in r.get("error", ""), r)
    r = sock_request(e, {"needs": ["API_TOKEN"], "mode": "http", "reason": "x",
                         "target": {"url": f"{base}/", "use": ["API_TOKEN"], "headers": [["authorization", "x"]]}})
    check("http: a requester header can't collide with the secret's", not r.get("ok") and "two values" in r.get("error", ""), r)
    r = e.run("http", "--secret", "API_TOKEN,LIMITED", "--reason", "x", f"{base}/")
    check("http: one secret per request", r.returncode == 2 and "exactly one secret" in r.stderr, r.stderr)
    r = sock_request(e, {"needs": ["API_TOKEN", "LIMITED"], "mode": "http", "reason": "x",
                         "target": {"url": f"{base}/", "use": ["API_TOKEN", "LIMITED"]}})
    check("http: the daemon also takes one secret per request", not r.get("ok") and "exactly one secret" in r.get("error", ""), r)
    r = sock_request(e, {"needs": ["API_TOKEN"], "mode": "http", "reason": "x", "target": {"url": f"{base}/"}})
    check("http: needs must match the secret used", not r.get("ok") and "exactly one secret" in r.get("error", ""), r)

    # URLs a parser might read differently
    for url, why in [(f"{base}/x y", "a space"), (f"http://a@127.0.0.1:{port}/", "userinfo"),
                     (f"http://127.0.0.1:{port}\\@evil.test/", "a backslash"), (f"{base}/café", "non-ASCII"),
                     (f"http://{{{{vault:API_TOKEN}}}}.test/", "a placeholder in the host")]:
        r = sock_request(e, {"needs": ["API_TOKEN"], "mode": "http", "reason": "x", "target": {"url": url, "use": ["API_TOKEN"]}})
        check(f"http: url with {why} refused", not r.get("ok") and ("ASCII" in r.get("error", "") or "host part" in r.get("error", "")), r)

    # the phone is shown the host and path exactly as they will be sent, never decoded
    t, res, rid = bg_sock_request(e, {"needs": ["API_TOKEN"], "mode": "http", "reason": "x",
                                      "target": {"url": f"{base}/v1/%2e%2e/me?q=%E2%80%AE", "use": ["API_TOKEN"]}})
    tgt = e.get(f"/api/req/{rid}")["target"]
    check("http: display is the raw parse", tgt["display"] == {"host": "127.0.0.1", "port": port, "path": "/v1/%2e%2e/me",
                                                               "query": "q=%E2%80%AE"}, tgt["display"])
    check("http: display shows the injected header with a placeholder",
          tgt["inject"] == [["API_TOKEN", "Authorization", "Bearer {{vault:API_TOKEN}}"]], tgt)
    st, ch = e.post("/api/challenge", {"kind": "req", "ref": rid})
    action, vmk, data = unlock(e, pk, ch)
    vals = {s["name"]: vc.open_box(vmk, s["box"], vc.secret_aad(s["meta_json"])).decode() for s in data["secrets"]}
    e.post(f"/api/req/{rid}/approve", {"action": action, "choice": "once", "values": vals})
    t.join(10)
    check("http: the path is sent exactly as shown", res["r"].get("ok") and api.seen[-1]["path"] == "/v1/%2e%2e/me?q=%E2%80%AE",
          (res, api.seen[-1]))

    # host not on the allowlist: refused before any push
    r = e.run("http", "--secret", "API_TOKEN", "--reason", "x", "https://example.com/")
    check("http: disallowed host refused without asking", r.returncode == 1 and "not an allowed host" in r.stderr
          and e.nothing_new(), r.stderr)
    r = sock_request(e, {"needs": ["API_TOKEN"], "mode": "http", "reason": "x",
                         "target": {"url": f"http://localhost:{port}/", "use": ["API_TOKEN"]}})
    check("http: another name for an allowed address is refused", not r.get("ok") and "not an allowed host" in r.get("error", ""), r)

    # http-only secret cannot be pulled into an environment
    r = e.run("run", "--need", "API_TOKEN", "--reason", "x", "--", "true")
    check("http-only secret refused for command delivery", r.returncode == 1 and "does not allow 'command'" in r.stderr, r.stderr)

    # redirects are returned, never followed
    rc, out, err, _ = run_with_phone(e, pk, ["http", "--secret", "API_TOKEN", "--reason", "redir", f"{base}/redirect"])
    check("http: redirect not followed", rc == 0 and "HTTP 302" in err and not [x for x in api.seen if "steal" in x["path"]], err)

    # a command grant covers http (the value was already handed out); an http grant doesn't cover a command
    add_secret(e, pk, "BOTH", "both-value-" + os.urandom(4).hex(), modes=("command", "http"), hosts=(host,))
    if in_claude_session():
        rc, out, err, _ = run_with_phone(e, pk, ["http", "--secret", "BOTH", "--reason", "x", f"{base}/"], choice="1h")
        p = e.cli("run", "--need", "BOTH", "--reason", "x", "--timeout", "30", "--", "true")
        check("an http grant does not cover command delivery", e.next_pending() is not None)
        p.terminate()
        p.wait()
        e.run("revoke", "--all")

    # edit: change policy without re-entering the value; ciphertext is re-bound to the new metadata
    st, ch = e.post("/api/challenge", {"kind": "edit", "ref": "API_TOKEN"})
    check("challenge carries no ciphertext", "secret" not in ch and "vmk_wraps" not in ch and "vmk_wrap" not in ch, ch)
    action, vmk, data = unlock(e, pk, ch)
    old_value = vc.open_box(vmk, data["secret"]["box"], vc.secret_aad(data["secret"]["meta_json"])).decode()
    meta = json.loads(data["secret"]["meta_json"])
    meta["modes"] = ["http", "command"]
    meta_json = json.dumps(meta, sort_keys=True, separators=(",", ":"))
    st, r = e.post("/api/add", {"action": action, "meta_json": meta_json,
                                "box": vc.seal(vmk, old_value.encode(), vc.secret_aad(meta_json))})
    rec = json.loads((e.tmp / "store.json").read_text())["secrets"]["API_TOKEN"]
    check("edit: policy changed, version bumped, value kept", st == 200 and rec["version"] == 2
          and json.loads(rec["meta_json"])["modes"] == ["http", "command"] and old_value == token, (st, r))
    st, ch = e.post("/api/challenge", {"kind": "edit", "ref": "API_TOKEN"})
    action, vmk, _ = unlock(e, pk, ch)
    meta["name"] = "RENAMED"
    mj = json.dumps(meta, sort_keys=True, separators=(",", ":"))
    st, r = e.post("/api/add", {"action": action, "meta_json": mj, "box": vc.seal(vmk, b"x" * 8, vc.secret_aad(mj))})
    check("edit cannot rename", st == 400, r)

    # policy validation
    for why, meta, needle in [
            ("http mode without hosts", {"modes": ["http"], "hosts": [], "http": BEARER}, "host"),
            ("http mode without a header", {"modes": ["http"], "hosts": ["a.example.com"]}, "which header"),
            ("a header template without {}", {"modes": ["http"], "hosts": ["a.example.com"], "http": {"header": "Authorization: x"}}, "{}"),
            ("a forbidden header", {"modes": ["http"], "hosts": ["a.example.com"], "http": {"header": "Host: {}"}}, "can't be used"),
            ("a path policy with ..", {"modes": ["http"], "hosts": ["a.example.com"], "http": {**BEARER, "paths": ["/v1/../admin"]}}, "paths"),
            ("the URL placement (removed)", {"modes": ["http"], "hosts": ["a.example.com"], "http": {**BEARER, "in_url": True}}, "http policy keys"),
            ("max_ttl over an hour", {"modes": ["command"], "hosts": [], "max_ttl": 7200}, "max_ttl"),
            ("type mode (removed)", {"modes": ["type"], "hosts": ["a.example.com"]}, "modes"),
            ("a wildcard host", {"modes": ["http"], "hosts": ["*.example.com"], "http": BEARER}, "hostnames"),
            ("an IP address host", {"modes": ["http"], "hosts": ["169.254.169.254"], "http": BEARER}, "hostnames"),
            ("a numeric host", {"modes": ["http"], "hosts": ["2130706433"], "http": BEARER}, "hostnames"),
            ("localhost", {"modes": ["http"], "hosts": ["localhost:8443"], "http": BEARER}, "hostnames")]:
        st, ch = e.post("/api/challenge", {"kind": "add"})
        action, vmk, _ = unlock(e, pk, ch)
        mj = json.dumps({"created": 1, "description": "", "max_ttl": 600, "name": "BADPOL", **meta},
                        sort_keys=True, separators=(",", ":"))
        st, r = e.post("/api/add", {"action": action, "meta_json": mj, "box": vc.seal(vmk, b"value123", vc.secret_aad(mj))})
        check(f"policy: {why} refused", st == 400 and needle in r["error"], r)
    api.shutdown()


# ------------------------------------------------------------------ fill (Chrome extension)

EXT_ORIGIN = "chrome-extension://jcbnicpanjmggphgoonehlalfmjcfmmi/"
FILL_ORIGIN = "https://login.example.com"


class FakeExtension:
    """The assentd Chrome extension, talking native messaging to the real host binary (which Chrome
    would start). Answers tab queries with self.tab and opens fills like extension/background.js."""

    def __init__(self, e: Env, key=None, tab=None, claim=None, prove=True):
        self.key = key or ec.generate_private_key(ec.SECP256R1())
        self.pub = claim or vc.raw_public(self.key)  # claim: say it has another key (it can't prove that)
        self.prove = prove  # False: never answer the daemon's proof challenge
        self.tab = tab or {"tabId": 7, "url": FILL_ORIGIN + "/signin?next=%2F", "title": "Sign in"}
        self.filled, self.status, self.asked = [], [], []
        self.fill_reply = None  # set to a dict to answer fills with it (e.g. an error) instead of filling
        self.p = subprocess.Popen([BIN, EXT_ORIGIN], env=e.env, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        threading.Thread(target=self._read, daemon=True).start()
        self.send({"type": "hello", "version": "test", "pub": b64u(self.pub)})

    def send(self, m):
        data = json.dumps(m).encode()
        self.p.stdin.write(struct.pack("=I", len(data)) + data)
        self.p.stdin.flush()

    def _read(self):
        while True:
            n = self.p.stdout.read(4)
            if len(n) < 4:
                return
            m = json.loads(self.p.stdout.read(struct.unpack("=I", n)[0]))
            if m.get("type") == "status":
                self.status.append(m)
            elif m.get("type") == "prove" and self.prove:
                try:
                    nonce = b64u(self._open(m, b"assentd/fill-proof/v1", f"proof\n{m['id']}".encode()))
                except Exception:
                    nonce = b64u(os.urandom(32))  # not our key: the best an impostor can do is guess
                self.send({"type": "proof", "nonce": nonce})
            elif m.get("type") == "tab":
                self.asked.append(m)
                self.send({"type": "tab", "id": m["id"], **self.tab})
            elif m.get("type") == "fill":
                self.send({"type": "filled", "id": m["id"], **self._fill(m)})

    def _fill(self, m):
        if self.fill_reply:
            return self.fill_reply
        cur = re.match(r"https://[^/]+", self.tab["url"])
        if m["tabId"] != self.tab["tabId"] or not cur or cur.group(0) != m["origin"]:
            return {"ok": False, "error": "the tab is no longer on " + m["origin"]}
        aad = f"{m['id']}\n{m['origin']}\n{m['tabId']}".encode()
        self.filled.append({"value": self._open(m, b"assentd/fill/v1", aad).decode(), "msg": m})
        return {"ok": True}

    def _open(self, m, info, aad):
        eph = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), unb64u(m["eph"]))
        k = vc.kek(self.key.exchange(ec.ECDH(), eph), info)
        return AESGCM(k).decrypt(unb64u(m["iv"]), unb64u(m["ct"]), aad)

    def fingerprint(self):
        h = __import__("hashlib").sha256(self.pub).hexdigest()[:16]
        return "-".join(h[i:i + 4] for i in range(0, 16, 4))

    def wait_status(self, n=1, timeout=5):
        end = time.time() + timeout
        while len(self.status) < n and time.time() < end:
            time.sleep(0.02)
        return self.status[n - 1] if len(self.status) >= n else None

    def close(self):
        self.p.stdin.close()
        self.p.wait(timeout=5)


def fill_checks(check):
    e = Env("fill")
    try:
        pk = passkey()
        enroll(e, pk)
        password = "Hunter2-" + os.urandom(8).hex()
        st, r = add_secret(e, pk, "SITE_PW", password, modes=("fill",))
        check("fill: a fill secret needs at least one site", st == 400 and "site" in r.get("error", ""), r)
        meta_fill = {"origins": [FILL_ORIGIN]}

        def put(name, value, origins, modes=("fill",)):
            st, ch = e.post("/api/challenge", {"kind": "add"})
            action, vmk, _ = unlock(e, pk, ch)
            meta = {"created": int(time.time()), "description": f"test {name}", "hosts": [], "max_ttl": 900,
                    "modes": list(modes), "name": name, "fill": {"origins": origins}}
            mj = json.dumps(meta, sort_keys=True, separators=(",", ":"))
            return e.post("/api/add", {"action": action, "meta_json": mj, "box": vc.seal(vmk, value.encode(), vc.secret_aad(mj)),
                                       "overwrite": True})

        st, r = put("SITE_PW", password, meta_fill["origins"])
        check("fill: secret with a fill site saved", st == 200, r)
        for bad in (["https://*.example.com"], ["https://login.example.com/path"], ["http://login.example.com"], ["https://127.0.0.1"]):
            st, r = put("BAD_PW", "x" * 12, bad)
            check(f"fill: site {bad[0]} refused", st == 400, r)
        add_secret(e, pk, "CMD_ONLY", "cmd-only-value-123")

        r = e.run("fill", "SITE_PW", "--reason", "log in")
        check("fill: no extension connected -> clear error", r.returncode == 1 and "isn't connected" in r.stderr, r.stderr)
        r = subprocess.run([BIN, "chrome-extension://someoneelse/"], env=e.env, capture_output=True, timeout=5)
        check("fill: the host refuses other extensions", r.returncode == 1)

        ext = FakeExtension(e)
        st0 = ext.wait_status()
        check("fill: an unknown extension key is told it isn't paired", st0 and st0.get("paired") is False, ext.status)
        chrome = e.get("/api/state")["chrome"]
        check("fill: its pairing request shows on the phone with the popup's fingerprint",
              [x["fingerprint"] for x in chrome["pairings"]] == [ext.fingerprint()] and chrome["keys"] == [], chrome)
        check("fill: the pairing request doesn't expose the key itself", "pub" not in json.dumps(chrome["pairings"]))
        r = e.run("fill", "SITE_PW", "--reason", "log in")
        check("fill: unpaired extension -> clear error, no request", r.returncode == 1 and "isn't paired" in r.stderr
              and e.nothing_new(), r.stderr)
        ext2 = FakeExtension(e, key=ext.key)
        ext2.wait_status()
        check("fill: a reconnect with the same key doesn't add a second pairing request",
              len(e.get("/api/state")["chrome"]["pairings"]) == 1)
        ext2.close()

        pid = e.get("/api/state")["chrome"]["pairings"][0]["id"]
        st, r = e.post("/api/chrome/pair", {"id": pid, "action": "made-up"})
        check("fill: pairing needs Face ID", st == 403, r)
        st, ch = e.post("/api/challenge", {"kind": "chrome", "ref": pid})
        action, _, _ = unlock(e, pk, ch)
        st, r = e.post("/api/chrome/pair", {"id": pid, "action": action})
        chrome = e.get("/api/state")["chrome"]
        check("fill: paired with Face ID", st == 200 and [k["fingerprint"] for k in chrome["keys"]] == [ext.fingerprint()]
              and chrome["keys"][0]["connected"] and chrome["pairings"] == [], (r, chrome))
        s2 = ext.wait_status(2)
        check("fill: the extension is told it is paired", s2 and s2.get("paired") is True, ext.status)
        check("fill: the paired key is stored", ext.fingerprint() in (e.tmp / "store.json").read_text())

        # a key must be proven, not just named
        fake = FakeExtension(e, claim=ext.pub)
        sf = fake.wait_status()
        check("fill: an extension claiming the paired key without holding it is refused",
              sf and sf.get("error") and "prove" in sf["error"] and fake.p.wait(timeout=5) is not None, fake.status)
        mute = FakeExtension(e, prove=False)
        time.sleep(0.5)
        check("fill: an unproven key gets no pairing request", e.get("/api/state")["chrome"]["pairings"] == [] and not mute.status,
              e.get("/api/state")["chrome"])
        p = e.cli("fill", "SITE_PW", "--reason", "log in", "--timeout", "30", "--tab", "999")
        e.next_pending()
        check("fill: an unproven connection isn't a fill target (the proven one is asked)",
              ext.asked and ext.asked[-1].get("tabId") == 999 and not mute.asked, ext.asked[-1:])
        p.terminate()
        p.wait()
        mute.close()

        # success
        p = e.cli("fill", "SITE_PW", "--reason", "log in to example")
        rid = e.next_pending()
        pub = e.get(f"/api/req/{rid}")
        check("fill: the phone shows the origin and page as Chrome reported them",
              pub["mode"] == "fill" and pub["target"] == {"origin": FILL_ORIGIN, "url": ext.tab["url"], "title": "Sign in"}, pub)
        ph = decide(e, pk, rid, choice="15m")
        check("fill: only Once can be chosen", ph[0] == 400, ph)
        ph = decide(e, pk, rid)
        out, err = p.communicate(timeout=30)
        check("fill: approved -> filled into the tab that was shown", p.returncode == 0 and ph[0] == 200 and ph[1]["ttl"] == 0
              and [f["value"] for f in ext.filled] == [password] and ext.filled[0]["msg"]["tabId"] == 7, (out, err, ph, ext.filled))
        check("fill: the value never reaches the CLI", password not in out + err and "filled SITE_PW" in err, (out, err))
        check("fill: no grant is left behind", e.get("/api/state")["grants"] == [])
        check("fill: audited", any(a["event"] == "filled" and a.get("ok") and a.get("origin") == FILL_ORIGIN
                                   for a in e.get("/api/state")["audit"]))
        check("fill: the value is not in the daemon's log", password not in (e.tmp / "daemon.log").read_text())

        # a specific tab
        p = e.cli("fill", "SITE_PW", "--reason", "r", "--tab", "7", "--timeout", "30")
        e.next_pending()
        check("fill: --tab asks Chrome about that tab", ext.asked and ext.asked[-1].get("tabId") == 7, ext.asked[-1:])
        p.terminate()
        p.wait()

        # refused before asking
        ext.tab = {"tabId": 8, "url": "https://evil.example.com/login", "title": "Sign in to example"}
        r = e.run("fill", "SITE_PW", "--reason", "log in")
        check("fill: a site not in the policy is refused without asking", r.returncode == 1 and "may not be filled on that tab's site"
              in r.stderr and e.nothing_new(), r.stderr)
        check("fill: the refusal doesn't tell the agent the tab's address", "evil.example.com" not in r.stderr, r.stderr)
        ext.tab = {"tabId": 8, "url": "http://login.example.com/", "title": "x"}
        r = e.run("fill", "SITE_PW", "--reason", "log in")
        check("fill: a plain-http page is refused", r.returncode == 1 and "https" in r.stderr and e.nothing_new(), r.stderr)
        ext.tab = {"tabId": None, "url": "", "title": ""}
        r = e.run("fill", "SITE_PW", "--reason", "log in")
        check("fill: no tab -> refused", r.returncode == 1 and "no tab" in r.stderr, r.stderr)
        r = e.run("fill", "CMD_ONLY", "--reason", "log in")
        check("fill: a secret without fill in its policy is refused", r.returncode == 1 and "does not allow 'fill'" in r.stderr, r.stderr)
        r = e.run("run", "--need", "SITE_PW", "--reason", "r", "--", "true")
        check("fill: a fill-only secret can't be given to a command", r.returncode == 1 and "does not allow 'command'" in r.stderr, r.stderr)

        # the tab navigated away between the phone and the fill
        ext.tab = {"tabId": 7, "url": FILL_ORIGIN + "/signin", "title": "Sign in"}
        p = e.cli("fill", "SITE_PW", "--reason", "r")
        rid = e.next_pending()
        ext.tab = {"tabId": 7, "url": "https://evil.example.com/", "title": "x"}
        decide(e, pk, rid)
        out, err = p.communicate(timeout=30)
        check("fill: a tab that navigated away isn't filled", p.returncode == 1 and "no longer on" in err and len(ext.filled) == 1, err)

        # the extension that showed the tab went away (another connection, even with the same key, isn't it)
        ext.tab = {"tabId": 7, "url": FILL_ORIGIN + "/signin", "title": "Sign in"}
        p = e.cli("fill", "SITE_PW", "--reason", "r")
        rid = e.next_pending()
        ext.close()
        ext = FakeExtension(e, key=ext.key)
        ext.wait_status()
        decide(e, pk, rid)
        out, err = p.communicate(timeout=30)
        check("fill: not sent to a different connection than the one that showed the tab",
              p.returncode == 1 and "disconnected or was unpaired" in err and not ext.filled, err)

        # the policy changed while the request waited: re-checked at approval
        p = e.cli("fill", "SITE_PW", "--reason", "r")
        rid = e.next_pending()
        put("SITE_PW", password, ["https://other.example.com"])
        ph = decide(e, pk, rid)
        check("fill: policy re-checked at approval", ph[0] == 403 and "may not be filled" in ph[1].get("error", ""), ph)
        e.post(f"/api/req/{rid}/deny", {})
        p.communicate(timeout=30)
        put("SITE_PW", password, [FILL_ORIGIN])

        # unpaired while waiting
        p = e.cli("fill", "SITE_PW", "--reason", "r")
        rid = e.next_pending()
        st, r = e.post("/api/chrome/remove", {"fingerprint": ext.fingerprint()})
        decide(e, pk, rid)
        out, err = p.communicate(timeout=30)
        check("fill: removing the key on the phone stops a fill in flight", st == 200 and p.returncode == 1
              and "unpaired" in err and not ext.filled, (r, err))
        check("fill: the extension is told it was unpaired", ext.wait_status(2) and ext.status[-1].get("paired") is False, ext.status)
        check("fill: removing the key doesn't by itself ask the phone again",
              e.get("/api/state")["chrome"]["pairings"] == [] and ext.status[-1].get("pending") is False, ext.status)
        n = len(ext.status)
        ext.send({"type": "pair"})  # the popup was opened
        got = ext.wait_status(n + 1)
        check("fill: opening the popup after removal asks the phone to pair again",
              got and got.get("pending") is True
              and [x["fingerprint"] for x in e.get("/api/state")["chrome"]["pairings"]] == [ext.fingerprint()], ext.status)
        n = len(ext.status)
        ext.send({"type": "pair"})
        check("fill: asking again while one is waiting doesn't add another",
              ext.wait_status(n + 1) and len(e.get("/api/state")["chrome"]["pairings"]) == 1, ext.status)
        pid = e.get("/api/state")["chrome"]["pairings"][0]["id"]
        n = len(ext.status)
        e.post("/api/chrome/dismiss", {"id": pid})
        check("fill: dismissing tells the extension it's no longer waiting",
              ext.wait_status(n + 1) and ext.status[-1].get("pending") is False, ext.status)
        st, r = e.post("/api/chrome/dismiss", {"id": "nope"})
        check("fill: dismissing an unknown pairing is harmless", st == 200, r)

        # ask can propose a fill site
        p = e.cli("ask", "NEW_PW", "--modes", "fill", "--fill-origin", "https://Signup.Example.com/", "--description", "d", "--reason", "r")
        rid = e.next_pending()
        meta = e.get(f"/api/req/{rid}")["creates"]["NEW_PW"]
        check("fill: ask proposes the fill site", meta["modes"] == ["fill"] and meta["fill"] == {"origins": ["https://signup.example.com"]}, meta)
        e.post(f"/api/req/{rid}/deny", {})
        p.communicate(timeout=30)
        ext.close()
    finally:
        e.close()


# ------------------------------------------------------------------ new secrets

def decide_deposit(e: Env, pk: SoftPasskey, accept=True, edit_meta=None):
    did = e.next_pending("deposits")
    st, ch = e.post("/api/challenge", {"kind": "deposit", "ref": did})
    assert st == 200, ch
    action, vmk, data = unlock(e, pk, ch)
    if not accept:
        return e.post(f"/api/deposit/{did}/reject", {"action": action}), None
    k = vc.load_pkcs8(vc.open_box(vmk, data["inbox_priv_box"], vc.INBOX_PRIV_AAD))
    value = vc.open_from_inbox(k, data["deposit"]["box"], vc.deposit_aad(data["deposit"]["id"])).decode()
    meta = json.loads(data["deposit"]["meta_json"])
    if edit_meta:
        meta.update(edit_meta)
    mj = json.dumps(meta, sort_keys=True, separators=(",", ":"))
    return e.post(f"/api/deposit/{did}/accept", {"action": action, "meta_json": mj,
                                                 "box": vc.seal(vmk, value.encode(), vc.secret_aad(mj))}), value


def stored_value(e: Env, pk: SoftPasskey, name: str) -> str:
    st, ch = e.post("/api/challenge", {"kind": "edit", "ref": name})
    _, vmk, data = unlock(e, pk, ch)
    return vc.open_box(vmk, data["secret"]["box"], vc.secret_aad(data["secret"]["meta_json"])).decode()


def answer_ask(e: Env, pk: SoftPasskey, typed: dict, edit_meta=None):
    """Fill in the new-secret form(s) on a request page."""
    rid = e.next_pending()
    pub = e.get(f"/api/req/{rid}")
    st, ch = e.post("/api/challenge", {"kind": "req", "ref": rid})
    action, vmk, data = unlock(e, pk, ch)
    creates = {}
    for n, meta in pub["creates"].items():
        meta = {**meta, **(edit_meta or {})}
        mj = json.dumps(meta, sort_keys=True, separators=(",", ":"))
        creates[n] = {"meta_json": mj, "box": vc.seal(vmk, typed[n].encode(), vc.secret_aad(mj))}
    return pub, e.post(f"/api/req/{rid}/approve", {"action": action, "choice": "save_only", "creates": creates})


def new_secrets(e: Env, pk: SoftPasskey, check):
    def bg(*args, stdin=None):
        src = subprocess.DEVNULL
        if stdin is not None:
            src = tempfile.TemporaryFile("w+")
            src.write(stdin)
            src.seek(0)
        return subprocess.Popen([BIN, *args], env=e.env, stdin=src, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # deposits need the inbox, which the phone creates on a Face ID approval
    r = e.run("generate", "GEN_PW", "--description", "d", "--reason", "r")
    check("deposit before inbox exists is refused", r.returncode == 1 and "not enabled" in r.stderr, r.stderr)
    st, ch = e.post("/api/challenge", {"kind": "inbox"})
    check("challenge says inbox is needed", ch.get("inbox_needed") is True, ch)
    action, vmk, _ = unlock(e, pk, ch)
    _, inbox = vc.keypair_box(vmk, vc.INBOX_PRIV_AAD)
    st, r = e.post("/api/inbox", {"action": action, "inbox_setup": inbox})
    check("inbox enabled", st == 200 and e.get("/api/state")["inbox"], r)
    store = json.loads((e.tmp / "store.json").read_text())
    check("inbox private key stored only sealed", set(store["inbox"]) == {"pub", "priv_box", "created"})

    # generate: the vault makes the value; Claude only learns its length
    p = bg("generate", "GEN_PW", "--length", "24", "--charset", "hex", "--description", "db password",
           "--modes", "command", "--reason", "new database")
    (st, r), value = decide_deposit(e, pk)
    out, err = p.communicate(timeout=20)
    check("generate: accepted on the phone, CLI returns", p.returncode == 0 and st == 200 and "accepted" in err, (err, r))
    check("generate: value never reached the CLI's output", value not in out + err and len(value) == 24
          and all(c in "0123456789abcdef" for c in value), (out, err))
    check("generate: stored value is what the phone opened", stored_value(e, pk, "GEN_PW") == value)
    check("generate: no plaintext on disk", value not in (e.tmp / "store.json").read_text())

    # deposit from a pipe, extracting a JSON field; no echo of the input
    key = "AKIA" + os.urandom(8).hex()
    blob = json.dumps({"AccessKey": {"AccessKeyId": "AKID", "SecretAccessKey": key}})
    p = bg("deposit", "AWS_SECRET", "--json-field", "AccessKey.SecretAccessKey", "--description", "aws",
           "--hosts", "s3.amazonaws.com", "--reason", "new IAM key", stdin=blob)
    (st, r), value = decide_deposit(e, pk, edit_meta={"max_ttl": 600})
    out, err = p.communicate(timeout=20)
    check("deposit: JSON field extracted and accepted", p.returncode == 0 and value == key, (err, r))
    check("deposit: CLI never printed it", key not in out + err)
    meta = next(m for m in e.get("/api/state")["secrets"] if m["name"] == "AWS_SECRET")
    check("deposit: the phone's policy edit stuck, proposal used otherwise",
          meta["max_ttl"] == 600 and meta["modes"] == ["http"] and meta["hosts"] == ["s3.amazonaws.com"]
          and meta["http"] == BEARER, meta)
    r = sock_request(e, {"name": "SPOOFED", "value": "spoofed-value-1", "wait": False, "reason": "r",
                         "source": "generated on the Mac (32 chars, alnum)", "proposal": {"description": "x", "modes": ["command"]}},
                     op="deposit")
    d = next(x for x in e.get("/api/state")["deposits"] if x["name"] == "SPOOFED")
    check("deposit provenance written by the daemon, requester text kept as a claim",
          d["provenance"].startswith("handed in by a process") and d["claimed_source"].startswith("generated on"), d)
    decide_deposit(e, pk, accept=False)
    r = e.run("deposit", "NOPE_X", "--json-field", "missing.path", "--description", "d", "--reason", "r", stdin=blob)
    check("deposit: bad field fails without echoing input", r.returncode == 1 and key not in r.stderr, r.stderr)
    r = e.run("deposit", "AWS_SECRET", "--description", "d", "--reason", "r", stdin="x" * 20)
    check("deposit: existing name needs --replace", r.returncode == 1 and "--replace" in r.stderr, r.stderr)
    r = e.run("deposit", "WILD", "--description", "d", "--hosts", "*.amazonaws.com", "--reason", "r", stdin="x" * 20)
    check("deposit: a wildcard host proposal is refused", r.returncode == 1 and "hostnames" in r.stderr, r.stderr)
    r = e.run("deposit", "REGEXED", "--regex", r"key=(\S+)", "--description", "d", "--reason", "r", "--no-wait",
              stdin="id=1 key=s3cr3t-val more")
    did = e.next_pending("deposits")
    check("deposit: --regex takes group 1", r.returncode == 0 and e.get(f"/api/deposit/{did}")["length"] == len("s3cr3t-val"), r.stderr)
    check("deposit: accepting needs Face ID", e.post(f"/api/deposit/{did}/accept", {"action": "made-up"})[0] == 403)
    st, r = e.post(f"/api/deposit/{did}/reject", {})
    check("deposit: rejecting needs no Face ID (like Deny)", st == 200 and not e.get("/api/state")["deposits"], r)

    # reject destroys it; --no-wait returns immediately
    r = e.run("generate", "THROWAWAY", "--description", "d", "--reason", "r", "--no-wait")
    check("--no-wait returns with deposit pending", r.returncode == 0 and "waiting on the phone" in r.stderr, r.stderr)
    (st, r), _ = decide_deposit(e, pk, accept=False)
    st2 = e.get("/api/state")
    check("reject removes the deposit", st == 200 and not st2["deposits"]
          and "THROWAWAY" not in [m["name"] for m in st2["secrets"]], (st, r, st2["deposits"]))
    p = bg("generate", "THROWAWAY2", "--description", "d", "--reason", "r")
    decide_deposit(e, pk, accept=False)
    p.communicate(timeout=20)
    check("waiting CLI sees the rejection (exit 77)", p.returncode == 77, p.returncode)

    # deposit --replace keeps the secret's policy, whatever Claude proposes
    before = next(m for m in e.get("/api/state")["secrets"] if m["name"] == "AWS_SECRET")
    p = bg("deposit", "AWS_SECRET", "--replace", "--modes", "command,http", "--hosts", "evil.example.com",
           "--description", "widened", "--reason", "rotate", stdin="AKIA-new-" + os.urandom(6).hex())
    did = e.next_pending("deposits")
    shown = e.get(f"/api/deposit/{did}")["meta"]
    check("deposit --replace: the phone is offered the current policy, not Claude's",
          shown["modes"] == before["modes"] and shown["hosts"] == before["hosts"] and shown["description"] == before["description"], shown)
    e.post(f"/api/deposit/{did}/reject", {})
    p.communicate(timeout=20)
    r = e.run("generate", "AWS_SECRET", "--replace", "--reason", "r", "--no-wait")
    did = e.next_pending("deposits")
    check("generate --replace: no description needed", r.returncode == 0, r.stderr)
    e.post(f"/api/deposit/{did}/reject", {})

    # deposits are capped (each waits in the store until you decide), and can all be rejected at once
    made = [e.run("generate", f"SPAM_{i}", "--description", "d", "--reason", "r", "--no-wait") for i in range(6)]
    check("deposit: at most 5 waiting per session", [x.returncode for x in made] == [0] * 5 + [1]
          and "too many deposits" in made[-1].stderr, [x.stderr for x in made])
    st, r = e.post("/api/deposits/reject", {})
    check("deposit: reject all, without Face ID", st == 200 and r["rejected"] == 5 and not e.get("/api/state")["deposits"], r)
    r = sock_request(e, {"name": "OVER_A", "value": "v" * 12, "wait": False, "reason": "r",
                         "proposal": {"description": "x", "modes": ["command"]}}, op="deposit")
    check("deposit: allowed again once the pile is gone", r.get("status") == "pending" or r.get("ok"), r)
    e.post("/api/deposits/reject", {})

    # ask: a new secret is entered on the phone, with Claude's proposed policy
    p = bg("ask", "LINEAR_KEY", "--description", "Linear API", "--hosts", "api.linear.app", "--reason", "sync issues")
    typed = "lin_api_" + os.urandom(8).hex()
    pub, (st, r) = answer_ask(e, pk, {"LINEAR_KEY": typed})
    out, err = p.communicate(timeout=20)
    check("ask: page shows proposed policy", pub["creates"]["LINEAR_KEY"]["hosts"] == ["api.linear.app"]
          and pub["creates"]["LINEAR_KEY"]["modes"] == ["http"] and pub["creates"]["LINEAR_KEY"]["http"] == BEARER
          and pub["mode"] == "store", pub)
    check("ask: saved, CLI returns 0 without the value", p.returncode == 0 and st == 200 and typed not in out + err, (err, r))
    check("ask: stored correctly", stored_value(e, pk, "LINEAR_KEY") == typed)
    check("new secrets default to a 15 min longest approval", pub["creates"]["LINEAR_KEY"]["max_ttl"] == 900, pub["creates"])
    r = e.run("ask", "LINEAR_KEY", "--description", "x", "--reason", "r")
    check("ask: existing name needs --replace", r.returncode == 1 and "--replace" in r.stderr, r.stderr)
    p = bg("ask", "HDR_KEY", "--description", "x", "--hosts", "api.x.com", "--auth-header", "X-Api-Key: {}", "--reason", "r")
    pub, (st, r) = answer_ask(e, pk, {"HDR_KEY": "hdr-key-value"}, edit_meta={"max_ttl": 600})
    p.communicate(timeout=20)
    check("ask: --auth-header proposed, the phone's edits saved", pub["creates"]["HDR_KEY"]["http"] == {"header": "X-Api-Key: {}"}
          and next(m for m in e.get("/api/state")["secrets"] if m["name"] == "HDR_KEY")["max_ttl"] == 600, pub["creates"])
    p = bg("ask", "LINEAR_KEY", "--description", "x", "--reason", "rotate", "--replace")
    pub, (st, r) = answer_ask(e, pk, {"LINEAR_KEY": "lin_api_new"})
    p.communicate(timeout=20)
    check("ask --replace: keeps the policy, new value, version bumped", pub["replaces"] == {"LINEAR_KEY": 1}
          and stored_value(e, pk, "LINEAR_KEY") == "lin_api_new", pub)
    r = e.run("http", "--reason", "x", "--secret", "NEW_TWO", "https://api.x.com/")
    check("unknown secret explains how to ask", r.returncode == 1 and "assentd ask NEW_TWO" in r.stderr and e.nothing_new(), r.stderr)
    r = e.run("run", "--need", "NEW_TWO", "--reason", "x", "--create-missing", "--", "true")
    check("--create-missing is gone", r.returncode == 2, r.stderr)


# ------------------------------------------------------------------ push

class FakePushService(HTTPServer):
    """Stands in for Apple's push service: records each POST and answers with self.status."""

    def __init__(self):
        self.got = queue.Queue()
        self.status = 201
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                outer.got.put({"path": self.path, "headers": dict(self.headers), "body": body})
                self.send_response(outer.status)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass

        super().__init__(("127.0.0.1", 0), H)
        threading.Thread(target=self.serve_forever, daemon=True).start()


def hkdf_extract(salt, ikm):
    import hashlib
    import hmac
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk, info, n):
    import hashlib
    import hmac
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()[:n]


def push_decrypt(body: bytes, ua_key, auth: bytes) -> dict:
    """RFC 8291 decryption, as the phone's browser does it."""
    salt, (rs, idlen) = body[:16], struct.unpack(">IB", body[16:21])
    as_pub, ct = body[21:21 + idlen], body[21 + idlen:]
    ecdh = ua_key.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), as_pub))
    ikm = hkdf_expand(hkdf_extract(auth, ecdh), b"WebPush: info\x00" + vc.raw_public(ua_key) + as_pub, 32)
    prk = hkdf_extract(salt, ikm)
    pt = AESGCM(hkdf_expand(prk, b"Content-Encoding: aes128gcm\x00", 16)).decrypt(
        hkdf_expand(prk, b"Content-Encoding: nonce\x00", 12), ct, None)
    return json.loads(pt.rstrip(b"\x00")[:-1])


def push_checks(e: Env, pk: SoftPasskey, check):
    svc = FakePushService()
    ua = ec.generate_private_key(ec.SECP256R1())
    auth = os.urandom(16)
    sub = {"endpoint": f"http://127.0.0.1:{svc.server_address[1]}/push/abc",
           "keys": {"p256dh": b64u(vc.raw_public(ua)), "auth": b64u(auth)}}
    check("push: daemon publishes a VAPID key", len(unb64u(e.get("/api/state")["push"]["vapid_public"])) == 65)
    st, r = e.post("/api/push/subscribe", {"action": "made-up", "subscription": sub})
    check("push: adding a device needs Face ID", st == 403, r)
    st, ch = e.post("/api/challenge", {"kind": "push"})
    action, _, _ = unlock(e, pk, ch)
    st, r = e.post("/api/push/subscribe", {"action": action, "subscription": {**sub, "endpoint": "https://evil.example.com/push"}})
    check("push: unknown push services refused", st == 400, r)
    st, ch = e.post("/api/challenge", {"kind": "push"})
    action, _, _ = unlock(e, pk, ch)
    st, r = e.post("/api/push/subscribe", {"action": action, "subscription": sub})
    check("push: device added", st == 200 and r["devices"] == 1, r)
    welcome = svc.got.get(timeout=10)
    check("push: welcome notification decrypts", push_decrypt(welcome["body"], ua, auth)["title"] == "Notifications are on")
    hdr = welcome["headers"]
    check("push: aes128gcm + VAPID headers", hdr.get("Content-Encoding") == "aes128gcm" and hdr.get("Authorization", "").startswith("vapid t="), hdr)

    p = e.cli("run", "--need", "TEST_KEY", "--reason", "Count orders", "--timeout", "30", "--", "sh", "-c", "true")
    got = svc.got.get(timeout=10)
    msg = push_decrypt(got["body"], ua, auth)
    check("push: Topic header is base64url, at most 32 chars (Apple 400s otherwise)",
          re.fullmatch(r"[A-Za-z0-9_-]{1,32}", got["headers"].get("Topic", "")), got["headers"])
    check("push: request notification names the secret and reason", msg["title"] == "Use TEST_KEY"
          and msg["body"].startswith("Count orders") and msg["url"].startswith("/r/") and msg["tag"] == "use:TEST_KEY", msg)
    e.seen.add(msg["url"].rsplit("/", 1)[1])
    p.terminate()
    p.wait()

    # the device is gone (410): it is dropped
    svc.status = 410
    p = e.cli("run", "--need", "TEST_KEY", "--reason", "Count orders again", "--timeout", "30", "--", "sh", "-c", "true")
    svc.got.get(timeout=10)
    e.next_pending()
    time.sleep(0.5)
    check("push: a gone device is dropped", e.get("/api/state")["push"]["devices"] == 0)
    p.terminate()
    p.wait()
    svc.shutdown()


# ------------------------------------------------------------------ devices, config, compat

def allowlist_checks(check):
    """Only allowed tailnet devices may use the page; the enrolling device is pinned."""
    e = Env("allowlist")
    try:
        check("allowlist: before enrollment only the setup page is open",
              e.call("GET", "/enroll", dev=NAS)[0] == 200 and e.call("GET", "/api/state", dev=NAS)[0] == 403)
        pk = passkey()
        st, b = e.post("/api/enroll/begin", {"token": "tok"})
        st, r = e.post("/api/enroll/finish", enroll_body(b, pk, os.urandom(32), os.urandom(32)))
        devs = e.get("/api/state")["devices"]
        check("allowlist: enrollment pins the enrolling device by stable ID and key", st == 200
              and [(d["node_id"], d["node_key"]) for d in devs] == [(PHONE["node_id"], PHONE["node_key"])], r)
        st, body = e.call("GET", "/api/state", dev=NAS)
        check("allowlist: another device is refused", st == 403 and body.get("error") == "device_not_allowed", body)
        st, page = e.call("GET", "/", dev=NAS)
        check("allowlist: a refused device gets the explanation page, not the app", st == 403 and "can't open the vault" in page, page[:80])
        check("allowlist: a device that took the allowed device's name is refused",
              e.call("GET", "/api/state", dev={**NAS, "node": PHONE["node"]})[0] == 403)
        state = e.get("/api/state")
        check("allowlist: the refused device shows up for approval", [r["node_id"] for r in state["device_requests"]] == [NAS["node_id"]],
              state["device_requests"])
        st, r = e.post("/api/devices/allow", {"action": "made-up", "node_id": NAS["node_id"]})
        check("allowlist: allowing a device needs Face ID", st == 403, r)
        st, ch = e.post("/api/challenge", {"kind": "device", "ref": NAS["node_id"]})
        action, _, _ = unlock(e, pk, ch)
        st, r = e.post("/api/devices/allow", {"action": action, "node_id": NAS["node_id"]})
        check("allowlist: allowing a device with Face ID works (several devices)", st == 200
              and e.call("GET", "/api/state", dev=NAS)[0] == 200 and len(e.get("/api/state")["devices"]) == 2, r)
        NAS2 = {**NAS, "node_key": "nodekey:cc33"}
        st, body = e.call("GET", "/api/state", dev=NAS2)
        req = next((r for r in e.get("/api/state")["device_requests"] if r["node_id"] == NAS["node_id"]), {})
        check("allowlist: an allowed device with a new node key is held back", st == 403
              and body.get("error") == "device_key_changed" and req.get("key_changed") is True, (body, req))
        check("rekey: that device still loads the app (to confirm itself)", e.call("GET", "/", dev=NAS2)[0] == 200)
        st, r = e.post("/api/challenge", {"kind": "add"}, dev=NAS2)
        check("rekey: nothing else is open to it", st == 403 and r.get("error") == "device_key_changed", r)
        st, r = e.post("/api/rekey/challenge", {}, dev={**NAS2, "node_id": "nOTHER9CNTRL"})
        check("rekey: a different node with the same login can't", st == 403 and r.get("error") == "device_not_allowed", r)
        st, r = e.post("/api/rekey/challenge", {})
        check("rekey: an allowed device has nothing to confirm", st == 400, r)
        st, ch = e.post("/api/rekey/challenge", {}, dev=NAS2)
        st, r = e.post("/api/unlock", {"challenge_id": ch["challenge_id"], "assertion": pk.get(unb64u(ch["challenge"]))[0]})
        check("rekey: its challenge can't unlock the vault key", st == 400 and "vmk_wrap" not in r, r)
        st, ch = e.post("/api/rekey/challenge", {}, dev=NAS2)
        st, r = e.post("/api/rekey", {"challenge_id": ch["challenge_id"], "assertion": passkey().get(unb64u(ch["challenge"]))[0]}, dev=NAS2)
        check("rekey: needs the vault's passkey", st == 403 and e.call("GET", "/api/state", dev=NAS2)[0] == 403, r)
        st, ch = e.post("/api/rekey/challenge", {}, dev=NAS2)
        st, r = e.post("/api/rekey", {"challenge_id": ch["challenge_id"], "assertion": pk.get(unb64u(ch["challenge"]))[0]}, dev=NAS2)
        devs = {d["node_id"]: d["node_key"] for d in e.get("/api/state")["devices"]}
        check("rekey: Face ID on the device lets it back in under its new key", st == 200
              and e.call("GET", "/api/state", dev=NAS2)[0] == 200 and devs.get(NAS["node_id"]) == NAS2["node_key"], (r, devs))
        check("rekey: the old key no longer works", e.call("GET", "/api/state", dev=NAS)[0] == 403)
        check("rekey: audited", any(a["event"] == "device_allowed" and "new tailnet key" in a.get("why", "")
                                    for a in e.get("/api/state")["audit"]))
        check("allowlist: another login on an allowed device is refused",
              e.call("GET", "/api/state", dev={**NAS, "login": "eve@example.com"})[0] == 403)
        st, r = e.post("/api/devices/remove", {"node_id": PHONE["node_id"]})
        check("allowlist: can't remove the device you're using", st == 400, r)
        st, r = e.post("/api/devices/remove", {"node_id": NAS["node_id"]})
        check("allowlist: removing a device locks it out again", st == 200 and e.call("GET", "/api/state", dev=NAS2)[0] == 403, r)
        (e.tmp / "reenroll.json").write_text(json.dumps({"token": "re", "expires": time.time() + 600}))
        check("allowlist: a reenroll window opens only the setup page to other devices",
              e.call("GET", "/enroll", dev=NAS)[0] == 200 and e.call("GET", "/api/state", dev=NAS)[0] == 403)
        st, body = e.call("GET", "/api/state", dev={**PHONE, "login": "eve@example.com"})
        check("allowlist: other tailnet login refused", st == 403 and "user may not" in body.get("error", ""), body)
        st, body = e.call("GET", "/api/state", dev=None)
        check("allowlist: no identity refused", st == 403 and "unknown tailnet device" in body.get("error", ""), body)
        check("the phone page's socket is 0600", oct(os.stat(e.http_sock).st_mode & 0o777) == "0o600")
    finally:
        e.close()


def limits_checks(check):
    """What code running as you can pile onto the phone, the daemon's memory and the audit log."""
    e = Env("limits", cfg_extra={"new_per_minute": 4})
    try:
        pk = passkey()
        enroll(e, pk)
        add_secret(e, pk, "K", "limit-value-123")
        big = ["x" * 500] * 100
        t, res, rid = bg_sock_request(e, {"needs": ["K"], "mode": "command", "argv": big, "reason": "r", "timeout": 60})
        e.post(f"/api/req/{rid}/deny", {})
        t.join(timeout=10)
        line = next(x for x in (e.tmp / "audit.jsonl").read_text().splitlines() if '"requested"' in x and rid in x)
        check("limits: a huge command is cut down in the audit log", len(line) < 6000, len(line))
        time.sleep(0.3)
        pub = e.get(f"/api/req/{rid}")
        check("limits: an answered request drops its command and body", pub["status"] == "denied" and not pub["argv"], pub)
        procs = [e.cli("run", "--need", "K", "--reason", "r", "--timeout", "30", "--", "true") for _ in range(3)]
        for _ in range(3):
            e.next_pending()
        r = e.run("run", "--need", "K", "--reason", "r", "--", "true")
        check("limits: only so many new requests a minute reach the phone", r.returncode == 1
              and "too many requests in the last minute" in r.stderr and e.nothing_new(), r.stderr)
        for p in procs:
            p.terminate()
            p.wait()
    finally:
        e.close()


def config_checks(check):
    for name, extra, why in [("nologins", {"allowed_logins": []}, "allowed_logins is required"),
                             ("nosock", {"http_socket": ""}, "test mode needs its socket")]:
        e = Env(name, cfg_extra=extra, start=False)
        r = subprocess.run([BIN, "daemon"], env=e.env, capture_output=True, text=True, timeout=10)
        check(f"config: {why}", r.returncode != 0, r.stderr[-200:])


def python_store_checks(check):
    """A vault made by the last Python daemon (cmd/assentd/testdata/python-vault) keeps working."""
    fx_dir = ROOT / "cmd" / "assentd" / "testdata" / "python-vault"
    fx = json.loads((fx_dir / "fixture.json").read_text())
    e = Env("python-vault", data_from=fx_dir)
    try:
        pk = SoftPasskey(RP_ID, ORIGIN, key=vc.load_pkcs8(unb64u(fx["passkey"]["priv_pkcs8_b64u"])),
                         cred_id=unb64u(fx["passkey"]["cred_id"]), prf_seed=unb64u(fx["passkey"]["prf_seed"]))
        out = e.run("list").stdout
        check("python vault: list shows its secrets", all(n in out for n in ("NAS_SUDO", "API_KEY", "OLD_TYPE")), out)
        st = e.get("/api/state")
        check("python vault: enrolled, device, inbox, deposit and push device carried over", st["enrolled"] and st["inbox"]
              and [d["node_id"] for d in st["devices"]] == [PHONE["node_id"]] and len(st["deposits"]) == 1
              and st["push"]["devices"] == 1, st)
        rc, out, err, ph = run_with_phone(e, pk, ["run", "--need", "NAS_SUDO", "--reason", "nas", "--", "sh", "-c", 'printf %s "$NAS_SUDO" | wc -c'])
        check("python vault: its passkey approves, the command gets the value",
              rc == 0 and out.strip() == str(len(fx["secrets"]["NAS_SUDO"].encode())), (rc, out, err, ph))
        did = st["deposits"][0]["id"]
        e.seen.add(did)
        stc, ch = e.post("/api/challenge", {"kind": "deposit", "ref": did})
        action, vmk, data = unlock(e, pk, ch)
        k = vc.load_pkcs8(vc.open_box(vmk, data["inbox_priv_box"], vc.INBOX_PRIV_AAD))
        check("python vault: its pending deposit opens on the phone",
              vc.open_from_inbox(k, data["deposit"]["box"], vc.deposit_aad(did)) == b"deposited-value-1")
        p = e.cli("run", "--need", "OLD_TYPE", "--reason", "x", "--timeout", "30", "--", "true")
        rid = e.next_pending()
        check("python vault: a secret with an old 'type' mode still works for its other modes", rid is not None)
        p.terminate()
        p.wait()
        audit = e.get("/api/state")["audit"]
        check("python vault: its audit log is kept and appended to", audit[-1]["event"] == "device_allowed"
              and any(a["event"] == "approved" for a in audit), [a["event"] for a in audit][:5])
    finally:
        e.close()


def handoff_check(e: Env, check):
    """A connection made by one process and used by another is refused (the session would be wrong)."""
    with socket.socket(socket.AF_UNIX) as s:
        s.connect(e.sock)
        child = ("import json,socket,sys; s=socket.socket(fileno=int(sys.argv[1])); "
                 "s.sendall(b'{\"op\":\"list\"}\\n'); print(s.makefile().readline())")
        r = subprocess.run([sys.executable, "-c", child, str(s.fileno())], pass_fds=[s.fileno()],
                           capture_output=True, text=True, timeout=10)
    check("socket: a connection handed to another process is refused", "process that connected" in r.stdout, r.stdout + r.stderr)


def orphaned(e: Env, *args):
    """Run the CLI reparented to launchd, so the daemon sees no Claude session behind it."""
    subprocess.run(["/bin/sh", "-c", '("$@" >/dev/null 2>&1 &)', "sh", BIN, *args], env=e.env, check=True)


# ------------------------------------------------------------------ main

def main():
    build()
    e = Env()
    failures = 0

    def check(name, cond, detail=""):
        nonlocal failures
        print(("ok   " if cond else "FAIL ") + name + ("" if cond else f"  -- {detail}"))
        failures += 0 if cond else 1

    try:
        pk = passkey()
        check("bad enroll token rejected", e.post("/api/enroll/begin", {"token": "nope"})[0] == 403)
        check("bad origin rejected", e.post("/api/enroll/begin", {"token": "tok"}, origin="https://evil.test")[0] == 403)
        code = enroll(e, pk)
        check("enrolled", e.get("/api/state")["enrolled"])
        check("second enrollment refused", e.post("/api/enroll/begin", {"token": "tok"})[0] == 409)

        secret = "sk_live_" + os.urandom(12).hex()
        st, r = add_secret(e, pk, "TEST_KEY", secret)
        check("add secret", st == 200, r)
        st, r = add_secret(e, pk, "TEST_KEY", "x" * 20)
        check("duplicate add refused without overwrite", st == 409, r)
        add_secret(e, pk, "SHORT_TTL", "short-ttl-value-123", max_ttl=600)
        store = (e.tmp / "store.json").read_text()
        check("store holds no plaintext", secret not in store)

        # recovery code opens the vault without the passkey
        s = json.loads(store)
        vmk = vc.open_box(vc.kek(code, vc.KEK_INFO_RECOVERY), s["recovery_wrap"], vc.VMK_AAD)
        rec = s["secrets"]["TEST_KEY"]
        check("recovery code decrypts", vc.open_box(vmk, rec["box"], vc.secret_aad(rec["meta_json"])).decode() == secret)
        tampered = rec["meta_json"].replace('"max_ttl":3600', '"max_ttl":600')
        try:
            vc.open_box(vmk, rec["box"], vc.secret_aad(tampered))
            check("tampered metadata fails to decrypt", False)
        except Exception:
            check("tampered metadata fails to decrypt", True)
        b32 = base64.b32encode(code).decode().rstrip("=")
        r = subprocess.run([BIN, "admin", "recover-check"], env=e.env, input="-".join(b32[i:i + 4] for i in range(0, 52, 4)) + "\n",
                           capture_output=True, text=True, timeout=10)
        check("admin recover-check opens every secret and the recovery key", r.returncode == 0 and "opens all 2 secret(s)" in r.stdout,
              r.stdout + r.stderr)
        r = subprocess.run([BIN, "admin", "recover-check"], env=e.env, input="A" * 52 + "\n", capture_output=True, text=True, timeout=10)
        check("admin recover-check refuses a wrong code", r.returncode != 0 and "does not open" in r.stderr, r.stderr)

        out = e.run("list").stdout
        check("list shows names, not values", "TEST_KEY" in out and secret not in out, out)
        handoff_check(e, check)

        # approve once: env injected, output scrubbed
        rc, out, err, ph = run_with_phone(e, pk, ["run", "--need", "TEST_KEY", "--reason", "unit test", "--",
                                                  "sh", "-c", 'echo "v=$TEST_KEY"; printf %s "$TEST_KEY" | base64; echo "$TEST_KEY" >&2; exit 3'])
        check("approve once succeeds, exit status passed through", rc == 3 and ph[0] == 200, (rc, err, ph))
        check("child saw the secret, output scrubbed",
              "v=[assentd:TEST_KEY]" in out and secret not in out and secret not in err, (out, err))
        check("base64 form scrubbed", out.count("[assentd:TEST_KEY]") == 2, out)
        check("once leaves no grant", e.get("/api/state")["grants"] == [])

        # deny
        rc, out, err, _ = run_with_phone(e, pk, ["run", "--need", "TEST_KEY", "--reason", "r", "--", "true"], deny=True)
        check("deny -> exit 77", rc == 77, (rc, err))

        # Face ID first: forged assertions get no ciphertext and no action token
        p = e.cli("run", "--need", "TEST_KEY", "--reason", "r", "--timeout", "30", "--", "true")
        rid = e.next_pending()
        for why, make in [
                ("bad signature", lambda ch: {**pk.get(unb64u(ch["challenge"]))[0], "signature": b64u(b"\x30\x06\x02\x01\x01\x02\x01\x01")}),
                ("unenrolled passkey", lambda ch: passkey().get(unb64u(ch["challenge"]))[0]),
                ("assertion from another origin", lambda ch: pk.get(unb64u(ch["challenge"]), origin="https://evil.test")[0]),
                ("assertion without Face ID (UV)", lambda ch: pk.get(unb64u(ch["challenge"]), uv=False)[0])]:
            st, ch = e.post("/api/challenge", {"kind": "req", "ref": rid})
            st, r = e.post("/api/unlock", {"challenge_id": ch["challenge_id"], "assertion": make(ch)})
            check(f"unlock: {why} rejected, nothing handed out", st == 403 and "vmk_wrap" not in r and "secrets" not in r, r)
        st, r = e.post(f"/api/req/{rid}/approve", {"action": "made-up", "choice": "once", "values": {"TEST_KEY": "x"}})
        check("approve without a Face ID unlock refused", st == 403, r)
        st, ch = e.post("/api/challenge", {"kind": "add"})
        action, _, _ = unlock(e, pk, ch)
        st, r = e.post(f"/api/req/{rid}/approve", {"action": action, "choice": "once", "values": {"TEST_KEY": "x"}})
        check("an unlock for one action can't approve another", st == 403, r)
        e.post(f"/api/req/{rid}/deny", {})
        _, err = p.communicate(timeout=10)
        check("request stayed pending after forgeries, then denied -> 77", p.returncode == 77, (p.returncode, err))

        # timed grants, capped by the secret's max_ttl
        rc, out, err, ph = run_with_phone(e, pk, ["run", "--need", "TEST_KEY,SHORT_TTL", "--reason", "r", "--",
                                                  "sh", "-c", "test -n \"$TEST_KEY\" && test -n \"$SHORT_TTL\""], choice="1h")
        check("1h choice capped to SHORT_TTL max (600s)", rc == 0 and ph[1]["ttl"] == 600, (rc, err, ph))
        st = e.get("/api/state")
        check("grant listed", len(st["grants"]) == 1 and set(st["grants"][0]["names"]) == {"TEST_KEY", "SHORT_TTL"}, st["grants"])
        out = e.run("status").stdout
        check("status shows names only", "TEST_KEY" in out and "claude pid" not in out and "/r/" not in out, out)
        add_secret(e, pk, "OTHER_KEY", "other-value-123456")
        if in_claude_session():
            # Running inside a Claude session: the same session reuses its grant without asking.
            r = e.run("run", "--need", "TEST_KEY", "--reason", "r", "--", "sh", "-c", 'test -n "$TEST_KEY"')
            check("same Claude session reuses grant without asking", r.returncode == 0 and e.nothing_new(), r.stderr)
            # A request that relies on a grant revoked while it waits must not get that grant's value.
            p = e.cli("run", "--need", "TEST_KEY,OTHER_KEY", "--reason", "r", "--timeout", "30", "--", "true")
            rid = e.next_pending()
            e.run("revoke", "--all")
            decide(e, pk, rid)
            _, err = p.communicate(timeout=10)
            check("revoke reaches a request already waiting on its grant", p.returncode == 77 and "revoked" in err, err)
        p = e.cli("run", "--need", "OTHER_KEY", "--reason", "r", "--timeout", "30", "--", "true")
        check("uncovered request asks the phone", e.next_pending() is not None)
        p.terminate()
        p.wait()
        time.sleep(1)
        check("killed CLI cancels its request",
              any(a["event"] == "cancelled" for a in e.get("/api/state")["audit"]), e.get("/api/state")["audit"][:3])
        rc, out, err, ph = run_with_phone(e, pk, ["run", "--need", "SHORT_TTL", "--reason", "r", "--", "true"], choice="max")
        check("'max' choice grants the policy's own limit (600s)", rc == 0 and ph[1]["ttl"] == 600, (rc, err, ph))
        out = e.run("revoke", "--all").stdout
        check("revoke --all", "revoked 1" in out and e.get("/api/state")["grants"] == [], out)

        # two sessions asking for the same secret at once are flagged on the phone
        orphaned(e, "run", "--need", "OTHER_KEY", "--reason", "one", "--timeout", "30", "--", "true")
        orphaned(e, "run", "--need", "OTHER_KEY", "--reason", "two", "--timeout", "30", "--", "true")
        a, b = e.next_pending(), e.next_pending()
        check("concurrent request from another session flagged", e.get(f"/api/req/{a}")["concurrent"] == ["OTHER_KEY"])
        e.post(f"/api/req/{b}/deny", {})
        check("finished requests no longer flagged", e.get(f"/api/req/{a}")["concurrent"] == [])
        e.post(f"/api/req/{a}/deny", {})

        # unknown secret
        r = e.run("run", "--need", "NOPE", "--reason", "r", "--", "true")
        check("unknown secret errors", r.returncode == 1 and "unknown secret" in r.stderr, r.stderr)

        # delete requires a Face ID unlock for that secret
        st, r = e.post("/api/delete", {"action": "made-up", "name": "SHORT_TTL"})
        check("delete without Face ID refused", st == 403, r)
        st, ch = e.post("/api/challenge", {"kind": "delete", "ref": "SHORT_TTL"})
        action, _, _ = unlock(e, pk, ch)
        st, r = e.post("/api/delete", {"action": action, "name": "TEST_KEY"})
        check("an unlock to delete one secret can't delete another", st == 403, r)
        st, ch = e.post("/api/challenge", {"kind": "delete", "ref": "SHORT_TTL"})
        action, _, _ = unlock(e, pk, ch)
        st, r = e.post("/api/delete", {"action": action, "name": "SHORT_TTL"})
        check("delete with Face ID", st == 200 and "SHORT_TTL" not in json.loads((e.tmp / "store.json").read_text())["secrets"], r)
        st, r = e.post("/api/delete", {"action": action, "name": "SHORT_TTL"})
        check("an unlock is single use", st == 403, r)

        http_checks(e, pk, check)
        new_secrets(e, pk, check)

        # the phone that gets lost has notifications on
        lost_svc = FakePushService()
        lost_ua = ec.generate_private_key(ec.SECP256R1())
        st, ch = e.post("/api/challenge", {"kind": "push"})
        action, _, _ = unlock(e, pk, ch)
        st, r = e.post("/api/push/subscribe", {"action": action, "subscription": {
            "endpoint": f"http://127.0.0.1:{lost_svc.server_address[1]}/push/lost",
            "keys": {"p256dh": b64u(vc.raw_public(lost_ua)), "auth": b64u(os.urandom(16))}}})
        lost_svc.got.get(timeout=10)  # the welcome
        before_push = e.get("/api/state")["push"]["devices"]
        # lost phone: root issues a reenroll token; the new passkey gets the VMK via the recovery code
        (e.tmp / "reenroll.json").write_text(json.dumps({"token": "re-tok", "expires": time.time() + 600}))
        check("reenroll needs the root-issued token", e.post("/api/enroll/begin", {"token": "tok"})[0] == 409)
        st, b = e.post("/api/enroll/begin", {"token": "re-tok"})
        check("reenroll begin returns the recovery wrap and recovery key box", st == 200 and b["mode"] == "recover"
              and b["recovery_wrap"] and b["recovery_key_box"], b)
        pk2 = passkey()

        def reenroll_body(b, vmk_for_wrap, signer):
            reg = pk2.create(unb64u(b["create"]["challenge"]))
            assertion, prf2 = pk2.get(unb64u(b["get"]["challenge"]))
            wrap = vc.seal(vc.kek(prf2, vc.KEK_INFO_PRF), vmk_for_wrap, vc.VMK_AAD)
            msg = vc.reenroll_message(unb64u(b["get"]["challenge"]), pk2.cred_id, wrap)
            return {"token": "re-tok", "create_challenge_id": b["create"]["challenge_id"],
                    "get_challenge_id": b["get"]["challenge_id"], **reg, "assertion": assertion,
                    "vmk_wrap": wrap, "recovery_sig": b64u(vc.sign_reenroll(signer, msg))}

        # An attacker holding the token but not the recovery code cannot swap in its own passkey.
        st, r = e.post("/api/enroll/finish", reenroll_body(b, os.urandom(32), ec.generate_private_key(ec.SECP256R1())))
        check("reenroll without the recovery key's signature refused", st == 403, r)
        check("a failed reenroll burns the token", not (e.tmp / "reenroll.json").exists()
              and e.post("/api/enroll/begin", {"token": "re-tok"})[0] == 409)
        st, ch = e.post("/api/challenge", {"kind": "edit", "ref": "TEST_KEY"})
        check("old passkey still works after the refused swap", st == 200 and unlock(e, pk, ch)[1] is not None)
        (e.tmp / "reenroll.json").write_text(json.dumps({"token": "re-tok", "expires": time.time() + 600}))
        st, b = e.post("/api/enroll/begin", {"token": "re-tok"})
        vmk = vc.open_box(vc.kek(code, vc.KEK_INFO_RECOVERY), b["recovery_wrap"], vc.VMK_AAD)
        signer = vc.load_pkcs8(vc.open_box(vmk, b["recovery_key_box"], vc.RECOVERY_KEY_AAD))
        good = reenroll_body(b, vmk, signer)
        replay = dict(good)
        st, r = e.post("/api/enroll/finish", good)
        check("reenroll finish with the recovery key's signature", st == 200, r)
        check("reenroll token is single use", not (e.tmp / "reenroll.json").exists())
        check("reenroll: the old phone's notifications are turned off", before_push == 1
              and e.get("/api/state")["push"]["devices"] == 0, before_push)
        lost_svc.shutdown()
        st, ch = e.post("/api/challenge", {"kind": "edit", "ref": "TEST_KEY"})
        try:
            unlock(e, pk, ch)
            old_ok = True
        except PermissionError:
            old_ok = False
        check("old passkey no longer works", not old_ok)
        st, ch = e.post("/api/challenge", {"kind": "edit", "ref": "TEST_KEY"})
        _, vmk2, data = unlock(e, pk2, ch)
        check("new passkey opens existing secrets",
              vc.open_box(vmk2, data["secret"]["box"], vc.secret_aad(data["secret"]["meta_json"])).decode() == secret)
        (e.tmp / "reenroll.json").write_text(json.dumps({"token": "re-tok", "expires": time.time() + 600}))
        e.post("/api/enroll/begin", {"token": "re-tok"})
        st, r = e.post("/api/enroll/finish", replay)
        check("a reenroll signature can't be replayed", st != 200, r)

        push_checks(e, pk2, check)  # the re-enrollment test above replaced the passkey

        # static page + security headers
        resp, _ = e.call("GET", "/r/abc", raw=True)
        csp = resp.getheader("Content-Security-Policy") or ""
        check("page served with strict CSP and security headers", "script-src 'self'" in csp and "connect-src 'self'" in csp
              and resp.getheader("X-Frame-Options") == "DENY" and "max-age" in (resp.getheader("Strict-Transport-Security") or ""), csp)
    finally:
        e.close()
    fill_checks(check)
    allowlist_checks(check)
    limits_checks(check)
    config_checks(check)
    python_store_checks(check)
    shutil.rmtree(TMP, ignore_errors=True)
    print(f"\n{'all passed' if not failures else f'{failures} FAILED'}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
