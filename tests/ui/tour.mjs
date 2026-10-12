// UI tour: throwaway vault on localhost + headless Chrome with a virtual passkey (PRF, via the
// DevTools WebAuthn domain). Drives every phone-page flow for real (enroll, add, approve, deny,
// deposits, edit, reveal, delete) at iPhone size, light and dark, and saves screenshots.
//   cd tests/ui && npm ci && npx playwright install chromium-headless-shell && node tour.mjs ./shots
//   (CHROME_PATH overrides the browser; GO the Go used to build the binary)
// The daemon runs in test mode, serving the page on a Unix socket; a small proxy here puts it on
// localhost and adds the tailnet identity headers Tailscale would. No pushes are sent and nothing
// touches the real vault.
import { chromium } from "playwright";
import { spawn, execFileSync } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { b64u, openFill, openProof } from "../../extension/fillcrypto.js";

const REPO = new URL("../..", import.meta.url).pathname.replace(/\/$/, "");
const OUT = process.argv[2] || "./out";
const PORT = 18000 + Math.floor(Math.random() * 1000);
const ORIGIN = `http://localhost:${PORT}`;
const tmp = fs.mkdtempSync("/tmp/av-ui-");
const SOCK = path.join(tmp, "s.sock");
const HTTP_SOCK = path.join(tmp, "h.sock");
const BIN = path.join(tmp, "assentd");
const GO = process.env.GO || (fs.existsSync("/usr/local/libexec/assentd-build/go1.24.13/go/bin/go") ? "/usr/local/libexec/assentd-build/go1.24.13/go/bin/go" : "go");
execFileSync(GO, ["build", "-o", BIN, "./cmd/assentd"], { cwd: REPO, stdio: "inherit", env: { ...process.env, GOTOOLCHAIN: "local", CGO_ENABLED: "0" } });
fs.mkdirSync(OUT, { recursive: true });
fs.writeFileSync(path.join(tmp, "config.json"), JSON.stringify({
  rp_id: "localhost", origin: ORIGIN, test_mode: true, http_socket: HTTP_SOCK, client_uid: os.userInfo().uid,
  allowed_logins: ["me@example.com"], enroll_token: "tok", request_timeout: 900, new_per_minute: 1000,
}));
const env = { ...process.env, ASSENTD_DATA: tmp, ASSENTD_SOCK: SOCK };
const daemon = spawn(BIN, ["daemon"], { env, stdio: ["ignore", "ignore", "inherit"] });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
for (let i = 0; i < 200 && !fs.existsSync(HTTP_SOCK); i++) await sleep(50);
const IDENTITY = { "x-assentd-node": "iphone.example.ts.net", "x-assentd-node-id": "nPHONE1CNTRL", "x-assentd-node-key": "nodekey:aa11", "x-assentd-login": "me@example.com" };
const proxy = http.createServer((req, res) => {
  const up = http.request({ socketPath: HTTP_SOCK, path: req.url, method: req.method, headers: { ...req.headers, ...IDENTITY } }, (r) => {
    res.writeHead(r.statusCode, r.headers);
    r.pipe(res);
  });
  up.on("error", (e) => { res.writeHead(502); res.end(String(e)); });
  req.pipe(up);
});
await new Promise((r) => proxy.listen(PORT, "127.0.0.1", r));

const bg = [];
// Any failed step: report it and stop, rather than hang on the requester processes still waiting.
const bail = (e) => { console.error("TOUR FAILED:", e?.message || e); for (const p of bg) try { p.kill(); } catch {} daemon.kill(); proxy.close(); process.exit(1); };
process.on("unhandledRejection", bail);
process.on("uncaughtException", bail);
function cli(...args) {  // a requester, as Claude would run it; resolves when it exits
  const p = spawn(BIN, args, { env, stdio: ["pipe", "pipe", "pipe"] });
  let err = "";
  p.stderr.on("data", (d) => { err += d; });
  const done = new Promise((r) => p.on("exit", (code) => r({ code, err })));
  bg.push(p);
  return { p, done, err: () => err };
}
async function stateJson() { return (await fetch(`${ORIGIN}/api/state`)).json(); }
async function waitPending(n) {
  for (let i = 0; i < 100; i++) { const s = await stateJson(); if (s.pending.length + s.deposits.length >= n) return s; await sleep(100); }
  for (const p of bg) try { p.kill(); } catch {}; daemon.kill(); proxy.close(); throw new Error("requests did not appear");
}

const browser = await chromium.launch(process.env.CHROME_PATH ? { executablePath: process.env.CHROME_PATH } : {});
async function mkPage(scheme = "light") {
  const ctx = await browser.newContext({ viewport: { width: 393, height: 852 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true, colorScheme: scheme });
  const page = await ctx.newPage();
  page.on("pageerror", (e) => console.log("PAGE ERROR", e.message));
  page.on("console", (m) => { if (m.type() === "error") console.log("CONSOLE", m.text()); });
  const cdp = await ctx.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
    protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true,
    isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  return { page, cdp };
}
let n = 0;
async function shot(page, name, full = true) {
  await sleep(250);
  const f = path.join(OUT, `${String(++n).padStart(2, "0")}-${name}.png`);
  await page.screenshot({ path: f, fullPage: full });
  console.log("shot", f);
}
const btn = (page, name) => page.getByRole("button", { name, exact: false }).first();

const { page, cdp } = await mkPage();

// ---- enrollment
await page.goto(`${ORIGIN}/enroll#token=tok`);
await btn(page, "Create passkey").waitFor();
await shot(page, "enroll-step1");
await btn(page, "Create passkey").click();
await btn(page, "Unlock with Face ID").waitFor();
await shot(page, "enroll-step2");
await btn(page, "Unlock with Face ID").click();
await page.getByText("Type it into your password manager").waitFor();
await shot(page, "enroll-recovery-code");

await page.goto(`${ORIGIN}/`);
await sleep(500);
await shot(page, "home-empty");

// ---- add secrets through the real form
const TITLES = { http: "HTTPS request", command: "Give to a command", fill: "Fill in Chrome" };
const TTL = { 900: "15 min", 3600: "1 hr" };
async function addSecret({ name, description, value, modes, hosts, ttl, origins }) {
  await page.goto(`${ORIGIN}/add`);
  await btn(page, "Save with Face ID").waitFor();
  await page.waitForFunction(() => !document.querySelector(".decide button.primary").disabled);
  await page.getByPlaceholder("STRIPE_API_KEY").fill(name);
  await page.getByPlaceholder("Paste the secret").fill(value);
  await page.getByPlaceholder("What it is and what it's for").fill(description);
  for (const [m, t] of Object.entries(TITLES)) await page.locator("label.mode", { hasText: t }).locator("input").setChecked(modes.includes(m));
  if (hosts) await page.getByPlaceholder("api.example.com").fill(hosts);
  if (origins) await page.getByPlaceholder("https://login.example.com").fill(origins);
  if (ttl) await page.locator(".seg label", { hasText: TTL[ttl] }).click();
}
async function saveSecret(name) {
  await btn(page, "Save with Face ID").click();
  await page.getByRole("heading", { name: `Added ${name}` }).waitFor();
}
await addSecret({ name: "STRIPE_SECRET_KEY", description: "Stripe live key, for refunds", value: "sk_live_51Hx9EXAMPLEEXAMPLE0000", modes: ["http"], hosts: "api.stripe.com", ttl: 900 });
await shot(page, "add-form-filled");
await saveSecret("STRIPE_SECRET_KEY");
await shot(page, "add-saved");
for (const s of [
  { name: "GITHUB_TOKEN", description: "Fine-grained PAT for the deploy repos", value: "github_pat_11AEXAMPLE000000000", modes: ["http"], hosts: "api.github.com" },
  { name: "DB_PASSWORD", description: "Production Postgres (read-only role)", value: "pg-readonly-EXAMPLE-0001", modes: ["command"] },
  { name: "KUBECONFIG_PROD", description: "prod cluster kubeconfig", value: "apiVersion: v1\nkind: Config\nEXAMPLE", modes: ["command"] },
  { name: "SENTRY_TOKEN", description: "Sentry auth token for release uploads", value: "sntrys_EXAMPLE_0000000000", modes: ["command"] },
]) { await addSecret(s); await saveSecret(s.name); }
await addSecret({ name: "GITHUB_PASSWORD", description: "GitHub account password", value: "correct-horse-EXAMPLE", modes: ["fill"], origins: "https://github.com" });
await shot(page, "add-form-fill");
await saveSecret("GITHUB_PASSWORD");

// The assentd Chrome extension, as Chrome would run it: native messaging to the real host binary.
const ext = { filled: [], tab: { tabId: 12, url: "https://github.com/login", title: "Sign in to GitHub · GitHub" } };
{
  const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  const host = spawn(BIN, ["chrome-extension://jcbnicpanjmggphgoonehlalfmjcfmmi/"], { env, stdio: ["pipe", "pipe", "inherit"] });
  bg.push(host);
  const send = (m) => { const b = Buffer.from(JSON.stringify(m)); const n = Buffer.alloc(4); n.writeUInt32LE(b.length); host.stdin.write(Buffer.concat([n, b])); };
  let buf = Buffer.alloc(0);
  host.stdout.on("data", async (d) => {
    buf = Buffer.concat([buf, d]);
    while (buf.length >= 4 && buf.length >= 4 + buf.readUInt32LE(0)) {
      const m = JSON.parse(buf.subarray(4, 4 + buf.readUInt32LE(0)));
      buf = buf.subarray(4 + buf.readUInt32LE(0));
      if (m.type === "prove") send({ type: "proof", nonce: await openProof(pair.privateKey, m) });
      if (m.type === "tab") send({ type: "tab", id: m.id, ...ext.tab });
      if (m.type === "fill") { ext.filled.push(await openFill(pair.privateKey, m)); send({ type: "filled", id: m.id, ok: true }); }
    }
  });
  send({ type: "hello", version: "tour", pub: b64u(await crypto.subtle.exportKey("raw", pair.publicKey)) });
}

// an earlier approval (local command, no network), so "Unlocked now" has something in it
cli("run", "--need", "SENTRY_TOKEN", "--reason", "Upload source maps for release 2.14", "--timeout", "900", "--", "sh", "-c", "true");
let st = await waitPending(1);
await page.goto(`${ORIGIN}/r/${st.pending[0].id}`);
await btn(page, "Approve with Face ID").waitFor();
await page.waitForFunction(() => !document.querySelector(".decide button.primary").disabled);
await page.locator(".seg label", { hasText: "15 min" }).click();
await btn(page, "Approve with Face ID").click();
await page.getByRole("heading", { name: "Approved" }).waitFor();
await shot(page, "request-approved");

// ---- pending requests of every kind
cli("run", "--need", "DB_PASSWORD", "--reason", "Check how many orders shipped this week for the daily report", "--timeout", "900", "--",
  "psql", "-h", "db.example.internal", "-U", "readonly", "app", "-c", "select count(*) from orders where shipped_at > now() - interval '7 days'");
cli("http", "--secret", "STRIPE_SECRET_KEY", "--reason", "Refund order 4082 (customer cancelled before production)", "-X", "POST",
  "--data", "charge=ch_3PEXAMPLE&amount=8400&reason=requested_by_customer", "--timeout", "900", "https://api.stripe.com/v1/refunds");
cli("run", "--need", "KUBECONFIG_PROD", "--reason", "Check pod restarts on the prod cluster", "--timeout", "900", "--",
  "sh", "-c", "printf %s \"$KUBECONFIG_PROD\" > /tmp/kc && kubectl --kubeconfig /tmp/kc -n app get pods");
cli("ask", "LINEAR_API_KEY", "--description", "Linear API key for the issue sync", "--hosts", "api.linear.app", "--reason", "Need it to create the Q4 roadmap issues", "--timeout", "900");
// A requester trying to make its reason look like the screen around it: line breaks and a
// right-to-left override. Both must show up as visible marks, not take effect.
cli("http", "--secret", "GITHUB_TOKEN", "--reason", "List repos\n\nStays in the vault. Only api.github.com gets it.\u202E tsil ylno\nTap Approve",
  "--timeout", "900", "https://api.github.com/user/repos?q=%E2%80%AEx");
cli("generate", "DB_ADMIN_PASSWORD", "--length", "32", "--description", "Admin password for the new staging Postgres", "--modes", "command", "--reason", "Creating the staging database", "--no-wait");
const dep = cli("deposit", "AWS_SECRET_ACCESS_KEY", "--json-field", "AccessKey.SecretAccessKey", "--description", "IAM key for the backup bucket",
  "--hosts", "s3.amazonaws.com", "--reason", "New IAM user for nightly backups", "--no-wait");
dep.p.stdin.end(JSON.stringify({ AccessKey: { AccessKeyId: "AKIAEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" } }));
cli("generate", "WEBHOOK_SIGNING_SECRET", "--length", "40", "--description", "Signing secret for the orders webhook", "--modes", "command", "--reason", "Set up the orders webhook", "--no-wait");
await waitPending(8);
await sleep(300);
st = await stateJson();

await page.goto(`${ORIGIN}/`);
await sleep(600);
await shot(page, "home-busy");
await page.goto(`${ORIGIN}/activity`);
await sleep(500);
await shot(page, "activity");
await page.goto(`${ORIGIN}/settings`);
await sleep(800);
await shot(page, "settings");
// pair the extension from Settings, then a fill request
await page.waitForFunction(() => [...document.querySelectorAll("button")].some((b) => b.textContent === "Pair" && !b.disabled));
await page.getByRole("button", { name: "Pair", exact: true }).click();
await page.getByText("Chrome extensions that can fill").waitFor();
await page.waitForFunction(() => ![...document.querySelectorAll("button")].some((b) => b.textContent === "Pair"));
await shot(page, "settings-chrome-paired");
const fillReq = cli("fill", "GITHUB_PASSWORD", "--reason", "Sign in to check the Actions billing page", "--timeout", "900");
await waitPending(9);
st = await stateJson();
const fillId = st.pending.find((r) => r.mode === "fill").id;
await page.goto(`${ORIGIN}/r/${fillId}`);
await page.waitForFunction(() => !document.querySelector(".decide button.primary").disabled);
await shot(page, "request-fill");
await page.locator("details summary").click();
await shot(page, "request-fill-details-open");
await btn(page, "Approve with Face ID").click();
await page.getByRole("heading", { name: "Approved" }).waitFor();
await shot(page, "request-fill-approved", false);
const fillDone = await fillReq.done;
if (fillDone.code !== 0 || ext.filled[0] !== "correct-horse-EXAMPLE" || fillDone.err.includes("correct-horse")) {
  throw new Error("fill did not reach the extension (or leaked to the CLI): " + JSON.stringify(fillDone));
}
st = await stateJson();

const byNeed = (name) => st.pending.find((r) => r.needs.includes(name));
for (const [name, r] of [
  ["request-env", byNeed("DB_PASSWORD")],
  ["request-http-stripe", byNeed("STRIPE_SECRET_KEY")],
  ["request-command-kube", byNeed("KUBECONFIG_PROD")],
  ["request-ask", byNeed("LINEAR_API_KEY")],
  ["request-spoofy-reason", byNeed("GITHUB_TOKEN")],
]) {
  await page.goto(`${ORIGIN}/r/${r.id}`);
  await page.waitForFunction(() => !document.querySelector(".decide button.primary").disabled);
  await shot(page, name);
  if (name === "request-env") await shot(page, "request-env-viewport", false);
}
await page.goto(`${ORIGIN}/r/${byNeed("STRIPE_SECRET_KEY").id}`);
await page.locator("details summary").click();
await shot(page, "request-http-details-open");
await page.goto(`${ORIGIN}/r/${byNeed("GITHUB_TOKEN").id}`);
const text = await page.locator("main").innerText();
if (/\u202E/.test(text) || !text.includes("⟨U+202E⟩")) throw new Error("a bidi override reached the screen unescaped");
await page.goto(`${ORIGIN}/r/${byNeed("LINEAR_API_KEY").id}`);
await btn(page, "Change").click();
await shot(page, "request-ask-policy-open");

await page.goto(`${ORIGIN}/r/${byNeed("KUBECONFIG_PROD").id}`);
await page.waitForFunction(() => !document.querySelector(".decide button.primary").disabled);
await btn(page, "Deny").click();
await sleep(500);
await shot(page, "request-denied", false);

const depGen = st.deposits.find((d) => d.name === "DB_ADMIN_PASSWORD");
const depAws = st.deposits.find((d) => d.name === "AWS_SECRET_ACCESS_KEY");
await page.goto(`${ORIGIN}/d/${depGen.id}`);
await page.waitForFunction(() => !document.querySelector(".decide button.primary").disabled);
await shot(page, "deposit-generated");
await page.goto(`${ORIGIN}/d/${depAws.id}`);
await page.waitForFunction(() => !document.querySelector(".decide button.primary").disabled);
await shot(page, "deposit-piped");
await btn(page, "Reject").click();
await sleep(300);
await shot(page, "deposit-reject-confirm", false);
await page.goto(`${ORIGIN}/d/${depGen.id}`);
await page.waitForFunction(() => !document.querySelector(".decide button.primary").disabled);
await btn(page, "Store with Face ID").click();
await page.getByRole("heading", { name: "Stored DB_ADMIN_PASSWORD" }).waitFor();
await btn(page, "Show value").click();
await shot(page, "deposit-accepted-shown", false);

await page.goto(`${ORIGIN}/edit/STRIPE_SECRET_KEY`);
await page.waitForFunction(() => !document.querySelector(".decide button.primary").disabled);
await shot(page, "edit");
await page.mouse.wheel(0, 3000); await sleep(400);
await shot(page, "edit-scrolled-bottom", false);
await btn(page, "Reveal").click();
await sleep(600);
await btn(page, "Delete secret").click();
await sleep(400);
await shot(page, "edit-revealed-delete-confirm");

await page.goto(`${ORIGIN}/r/doesnotexist`);
await sleep(400);
await shot(page, "request-not-found", false);

// This phone comes back with a new tailnet key (Tailscale reinstalled): it must confirm itself.
IDENTITY["x-assentd-node-key"] = "nodekey:aa22";
await page.goto(`${ORIGIN}/`);
await page.getByRole("heading", { name: "Confirm this device" }).waitFor();
await page.waitForFunction(() => !document.querySelector(".decide button.primary").disabled);
await shot(page, "rekey", false);
await btn(page, "Confirm with Face ID").click();
await page.locator("p.status").waitFor();
await shot(page, "rekey-done", false);

fs.writeFileSync(path.join(tmp, "reenroll.json"), JSON.stringify({ token: "re-tok", expires: Date.now() / 1000 + 600 }));
await page.goto(`${ORIGIN}/enroll#token=re-tok`);
await sleep(600);
await shot(page, "reenroll", false);

const dark = (await mkPage("dark")).page;
await dark.goto(`${ORIGIN}/`);
await sleep(600);
await shot(dark, "dark-home");
const now = await stateJson();
await dark.goto(`${ORIGIN}/r/${now.pending.find((r) => r.needs.includes("STRIPE_SECRET_KEY")).id}`);
await dark.waitForFunction(() => !document.querySelector(".decide button.primary").disabled);
await shot(dark, "dark-request-http", false);
await dark.goto(`${ORIGIN}/r/${now.pending.find((r) => r.needs.includes("LINEAR_API_KEY")).id}`);
await dark.waitForFunction(() => !document.querySelector(".decide button.primary").disabled);
await shot(dark, "dark-request-ask");

await browser.close();
for (const p of bg) try { p.kill(); } catch {}
daemon.kill();
proxy.close();
fs.rmSync(tmp, { recursive: true, force: true });
console.log("done");
