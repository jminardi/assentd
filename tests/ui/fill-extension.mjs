// The real extension in a real Chromium: loads extension/ unpacked, registers the native messaging
// host in the test profile, and fills a password into an https login page after a Face ID approval
// on the phone page (virtual passkey). The daemon runs in test mode, which skips the "started by
// Google Chrome" check (this is Chromium, and the host isn't at its installed path).
//   cd tests/ui && node fill-extension.mjs
// Needs a full Chromium (Chrome for Testing): branded Chrome no longer loads extensions from the
// command line, and the headless shell can't run them. CHROME_PATH chooses one; by default the
// newest Playwright-installed Chromium is used (npx playwright install chromium).
import { chromium } from "playwright";
import { spawn, execFileSync } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";

const REPO = new URL("../..", import.meta.url).pathname.replace(/\/$/, "");
const EXT = path.join(REPO, "extension");
const EXT_ID = "jcbnicpanjmggphgoonehlalfmjcfmmi";
const PORT = 19000 + Math.floor(Math.random() * 1000);
const ORIGIN = `http://localhost:${PORT}`;
const LOGIN = "https://login.example.com";
const PASSWORD = "correct-horse-" + Math.random().toString(36).slice(2);
const tmp = fs.mkdtempSync("/tmp/av-ext-");
const SOCK = path.join(tmp, "s.sock");
const HTTP_SOCK = path.join(tmp, "h.sock");
const BIN = path.join(tmp, "assentd");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function findChromium() {
  if (process.env.CHROME_PATH) return process.env.CHROME_PATH;
  const cache = path.join(os.homedir(), "Library/Caches/ms-playwright");
  const dirs = fs.existsSync(cache) ? fs.readdirSync(cache).filter((d) => /^chromium-\d+$/.test(d)).sort((a, b) => b.split("-")[1] - a.split("-")[1]) : [];
  for (const d of dirs) {
    const p = path.join(cache, d, "chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing");
    if (fs.existsSync(p)) return p;
  }
  return null;
}
const CHROME = findChromium();
if (!CHROME) {
  console.log("SKIP: no full Chromium found (npx playwright install chromium, or set CHROME_PATH)");
  process.exit(0);
}

const GO = process.env.GO || (fs.existsSync("/usr/local/libexec/assentd-build/go1.24.13/go/bin/go") ? "/usr/local/libexec/assentd-build/go1.24.13/go/bin/go" : "go");
execFileSync(GO, ["build", "-o", BIN, "./cmd/assentd"], { cwd: REPO, stdio: "inherit", env: { ...process.env, GOTOOLCHAIN: "local", CGO_ENABLED: "0" } });
fs.writeFileSync(path.join(tmp, "config.json"), JSON.stringify({
  rp_id: "localhost", origin: ORIGIN, test_mode: true, http_socket: HTTP_SOCK, client_uid: os.userInfo().uid,
  allowed_logins: ["me@example.com"], enroll_token: "tok", request_timeout: 300,
}));
const env = { ...process.env, ASSENTD_DATA: tmp, ASSENTD_SOCK: SOCK };
const daemon = spawn(BIN, ["daemon"], { env, stdio: ["ignore", "ignore", "ignore"] });
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

// Chromium reads per-profile native messaging hosts from <user data dir>/NativeMessagingHosts.
const profile = path.join(tmp, "profile");
fs.mkdirSync(path.join(profile, "NativeMessagingHosts"), { recursive: true });
fs.writeFileSync(path.join(profile, "NativeMessagingHosts", "org.assentd.fill.json"), JSON.stringify({
  name: "org.assentd.fill", description: "test", path: BIN, type: "stdio", allowed_origins: [`chrome-extension://${EXT_ID}/`] }));

let ctx;
const cleanup = async () => { try { await ctx?.close(); } catch {} daemon.kill(); proxy.close(); fs.rmSync(tmp, { recursive: true, force: true }); };
const fail = async (msg) => { console.error("FAIL:", msg); await cleanup(); process.exit(1); };
process.on("unhandledRejection", (e) => fail(e?.message || e));
process.on("uncaughtException", (e) => fail(e?.message || e));

ctx = await chromium.launchPersistentContext(profile, {
  executablePath: CHROME, headless: false, env,
  args: ["--headless=new", `--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`],
});
const sw = ctx.serviceWorkers().find((w) => w.url().startsWith(`chrome-extension://${EXT_ID}/`))
  || await ctx.waitForEvent("serviceworker", { predicate: (w) => w.url().startsWith(`chrome-extension://${EXT_ID}/`), timeout: 15000 });
console.log("ok   extension loaded with the fixed ID", EXT_ID);

// The phone: enroll, add a fill secret, pair the extension.
const phone = ctx.pages()[0] || await ctx.newPage();
const cdp = await ctx.newCDPSession(phone);
await cdp.send("WebAuthn.enable");
await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", transport: "internal", hasResidentKey: true,
  hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
const btn = (name) => phone.getByRole("button", { name, exact: false }).first();
await phone.goto(`${ORIGIN}/enroll#token=tok`);
await btn("Create passkey").click();
await btn("Unlock with Face ID").click();
await phone.getByText("Type it into your password manager").waitFor();
await phone.goto(`${ORIGIN}/add`);
await phone.waitForFunction(() => !document.querySelector(".decide button.primary").disabled);
await phone.getByPlaceholder("STRIPE_API_KEY").fill("SITE_PW");
await phone.getByPlaceholder("Paste the secret").fill(PASSWORD);
await phone.locator("label.mode", { hasText: "HTTPS request" }).locator("input").setChecked(false);
await phone.locator("label.mode", { hasText: "Fill in Chrome" }).locator("input").setChecked(true);
await phone.getByPlaceholder("https://login.example.com").fill(LOGIN);
await btn("Save with Face ID").click();
await phone.getByRole("heading", { name: "Added SITE_PW" }).waitFor();

const popupFp = await sw.evaluate(async () => {
  const fingerprint = async (raw) => [...new Uint8Array(await crypto.subtle.digest("SHA-256", raw)).slice(0, 8)]
    .map((b) => b.toString(16).padStart(2, "0")).join("").match(/..../g).join("-");  // as fillcrypto.js
  const db = await new Promise((r) => { const q = indexedDB.open("assentd", 1); q.onsuccess = () => r(q.result); });
  const k = await new Promise((r) => { const q = db.transaction("keys").objectStore("keys").get("ecdh"); q.onsuccess = () => r(q.result); });
  return { fp: await fingerprint(k.pub), extractable: k.priv.extractable };
});
if (popupFp.extractable) await fail("the extension's private key is extractable");
console.log("ok   the extension's private key is non-extractable");
let st;
for (let i = 0; i < 100; i++) { st = await (await fetch(`${ORIGIN}/api/state`)).json(); if (st.chrome.pairings.length) break; await sleep(100); }
if (st.chrome.pairings[0]?.fingerprint !== popupFp.fp) await fail(`pairing fingerprint ${st.chrome.pairings[0]?.fingerprint} != extension's ${popupFp.fp}`);
console.log("ok   the extension asked to pair, and the phone shows the same key as the popup");
await phone.goto(`${ORIGIN}/settings`);
await phone.waitForFunction(() => [...document.querySelectorAll("button")].some((b) => b.textContent === "Pair" && !b.disabled));
await phone.getByRole("button", { name: "Pair", exact: true }).click();
await phone.waitForFunction(() => ![...document.querySelectorAll("button")].some((b) => b.textContent === "Pair"));
console.log("ok   paired from the phone with Face ID");
const popup = await ctx.newPage();
await popup.goto(`chrome-extension://${EXT_ID}/popup.html`);
await popup.waitForFunction(() => document.getElementById("status").textContent === "paired", null, { timeout: 5000 }).catch(() => {});
const popupText = await popup.locator("body").innerText();
if (!popupText.includes("paired") || !popupText.includes(popupFp.fp)) await fail("popup shows: " + popupText);
await popup.close();
console.log("ok   the popup shows it is paired, with the key the phone showed");

// The login page, served by Playwright as if it were https://login.example.com.
await ctx.route(`${LOGIN}/**`, (r) => r.fulfill({ contentType: "text/html", body:
  `<!doctype html><title>Sign in</title><form><input name=u value=me><input type=password id=pw><button>Sign in</button></form>` }));
const login = await ctx.newPage();
await login.goto(`${LOGIN}/signin`);
await login.locator("#pw").click();
const tabId = await sw.evaluate(async (u) => (await chrome.tabs.query({ url: u + "/*" }))[0]?.id, LOGIN);

async function fill(tab) {
  const p = spawn(BIN, ["fill", "SITE_PW", "--reason", "log in", "--tab", String(tab)], { env });
  let out = "";
  p.stdout.on("data", (d) => { out += d; });
  p.stderr.on("data", (d) => { out += d; });
  const done = new Promise((r) => p.on("exit", (code) => r(code)));
  for (let i = 0; i < 100; i++) { st = await (await fetch(`${ORIGIN}/api/state`)).json(); if (st.pending.length) break; await sleep(100); }
  if (!st.pending.length) return { code: await done, out };
  const req = st.pending[0];
  await phone.goto(`${ORIGIN}/r/${req.id}`);
  await phone.waitForFunction(() => !document.querySelector(".decide button.primary").disabled);
  await btn("Approve with Face ID").click();
  await phone.getByRole("heading", { name: "Approved" }).waitFor();
  return { code: await done, out, req };
}

let r = await fill(tabId);
const value = await login.locator("#pw").inputValue();
if (r.code !== 0 || value !== PASSWORD) await fail(`not filled: code ${r.code}, field ${JSON.stringify(value)}, cli ${r.out}`);
if (r.req.target.origin !== LOGIN || r.req.target.url !== `${LOGIN}/signin`) await fail("phone target " + JSON.stringify(r.req.target));
if (r.out.includes(PASSWORD)) await fail("the CLI saw the password");
console.log("ok   approved fill typed the password into the login page; the CLI never saw it");

// The tab navigates to another site between the phone and the fill: nothing is filled there.
await login.locator("#pw").fill("");
await ctx.route("https://evil.example.com/**", (q) => q.fulfill({ contentType: "text/html", body: `<input type=password id=pw>` }));
const p = spawn(BIN, ["fill", "SITE_PW", "--reason", "log in", "--tab", String(tabId)], { env });
let out2 = "";
p.stderr.on("data", (d) => { out2 += d; });
const done2 = new Promise((q) => p.on("exit", (code) => q(code)));
for (let i = 0; i < 100; i++) { st = await (await fetch(`${ORIGIN}/api/state`)).json(); if (st.pending.length) break; await sleep(100); }
await login.goto("https://evil.example.com/login");
await phone.goto(`${ORIGIN}/r/${st.pending[0].id}`);
await phone.waitForFunction(() => !document.querySelector(".decide button.primary").disabled);
await btn("Approve with Face ID").click();
const code2 = await done2;
const v2 = await login.locator("#pw").inputValue();
if (code2 === 0 || v2 !== "" || !out2.includes("no longer on")) await fail(`navigated tab: code ${code2}, field ${JSON.stringify(v2)}, cli ${out2}`);
console.log("ok   a tab that navigated to another site isn't filled");

await cleanup();
console.log("all passed");
