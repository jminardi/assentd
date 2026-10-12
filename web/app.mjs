// assentd phone page. Everything that came from a requester (reason, argv, cwd, deposit
// claims) is untrusted: it is only ever inserted as text nodes, never as HTML. An XSS here
// could steal the vault key, which is why there is no innerHTML anywhere.

import * as vc from "/vcrypto.mjs";

const app = document.getElementById("app");
const topleft = document.getElementById("topleft");
const topright = document.getElementById("topright");

// ------------------------------------------------------------------ DOM helpers

// Characters that reorder or hide text. A requester could use them to make a request read as
// something else, so every text node shows them as visible escapes like ⟨U+202E⟩.
const INVISIBLE = /[\u00AD\u061C\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF\u2028\u2029]/g;
const visible = (s) => s.replace(INVISIBLE, (c) => `⟨U+${c.codePointAt(0).toString(16).toUpperCase().padStart(4, "0")}⟩`);
// Headings show long SECRET_NAMES; let them wrap after underscores instead of mid-word.
const wrapName = (s) => h("span", { class: "nm" }, s.split("_").flatMap((part, i) => (i ? ["_", h("wbr"), part] : [part])));
const clean = (nodes) => nodes.flat(Infinity).filter((n) => n != null && n !== false);
const oneLine = (s) => s.replace(/\s*[\r\n]+\s*/g, " ⏎ ");

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "class") el.className = v;
    else if (v === true) el.setAttribute(k, "");
    else if (v !== false && v != null) el.setAttribute(k, v);
  }
  for (const kid of clean(kids)) el.append(kid instanceof Node ? kid : document.createTextNode(visible(String(kid))));
  return el;
}
const fill = (el, ...nodes) => { el.replaceChildren(...clean(nodes)); return el; };
const render = (...nodes) => { fill(app, ...nodes); sizeTextareas(); };
let uid = 0;
const nextId = (p) => `${p}-${++uid}`;

// Header: brand or back on the left (the usual place), screen icons on the right.
function setNav(left, right) { fill(topleft, left); fill(topright, right); }
const brandLink = () => h("a", { href: "/", class: "brand" }, "assentd");
const backLink = () => h("a", { href: "/", class: "back" }, "‹ Home");

const ICONS = {
  clock: ["M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18", "M12 7.5V12l3 2"],
  gear: ["M4 7h10", "M18 7h2", "M16 5v4", "M4 17h4", "M12 17h8", "M10 15v4"],
};
function icon(name) {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  for (const [k, v] of Object.entries({ viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", "stroke-width": "1.9", "stroke-linecap": "round", "aria-hidden": "true" })) svg.setAttribute(k, v);
  for (const d of ICONS[name]) { const p = document.createElementNS(ns, "path"); p.setAttribute("d", d); svg.append(p); }
  return svg;
}
const iconLink = (href, name, label) => h("a", { href, class: "iconbtn", "aria-label": label, title: label }, icon(name));

async function api(method, path, body) {
  const r = await fetch(path, {
    method, cache: "no-store",
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await r.json().catch(() => ({}));
  // An allowed device whose tailnet key changed may only confirm itself; the daemon refuses the rest.
  if (data.error === "device_key_changed") { rekeyView(); return new Promise(() => {}); }
  if (!r.ok) throw Object.assign(new Error(data.error || `HTTP ${r.status}`), { status: r.status });
  return data;
}

// ------------------------------------------------------------------ formatting

function fmtTtl(s) {
  s = Math.max(0, Math.round(s));
  if (s >= 3600) return `${Math.floor(s / 3600)} hr${s % 3600 >= 60 ? ` ${Math.floor((s % 3600) / 60)} min` : ""}`;
  if (s >= 60) return `${Math.floor(s / 60)} min`;
  return `${s} s`;
}
function fmtClock(s) {
  s = Math.max(0, Math.round(s));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}
function relTime(ts, now = Date.now() / 1000) {
  const d = now - ts;
  if (d < 45) return "now";
  if (d < 3600) return `${Math.round(d / 60)}m`;
  if (d < 86400) return `${Math.round(d / 3600)}h`;
  return new Date(ts * 1000).toLocaleDateString([], { month: "short", day: "numeric" });
}
const clock = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });

function sessionText(s) {
  if (!s) return "";
  const when = s.started ? ` since ${new Date(s.started * 1000).toLocaleString([], { weekday: "short", hour: "numeric", minute: "2-digit" })}` : "";
  if (s.kind === "remote") return `Remote Control session${when}`;
  if (s.kind === "terminal") return `Terminal session (${s.tty})${when}`;
  if (s.kind === "none") return "Not from a Claude session";
  return s.label || "";
}
function shortPath(p) {
  if (!p) return "";
  p = p.replace(/^\/Users\/[^/]+/, "~");
  const parts = p.split("/");
  return p.length > 42 && parts.length > 3 ? `…/${parts.slice(-2).join("/")}` : p;
}
function errorText(e) {
  if (e && e.name === "NotAllowedError") return "Face ID was cancelled or timed out.";
  return (e && e.message) || String(e);
}
function shellQuote(a) {
  return /^[A-Za-z0-9_@%+=:,./-]+$/.test(a) ? a : `'${a.replace(/'/g, `'\\''`)}'`;
}
// Show {{vault:NAME}} placeholders as chips instead of template syntax.
function withPlaceholders(text) {
  const out = [];
  let last = 0;
  for (const m of text.matchAll(/\{\{vault:([A-Z][A-Z0-9_]*)\}\}/g)) {
    out.push(text.slice(last, m.index), h("span", { class: "ph" }, m[1]));
    last = m.index + m[0].length;
  }
  out.push(text.slice(last));
  return out;
}

const MODES = {
  http: { title: "HTTPS request", chip: "http", tone: "safe", desc: "The vault sends the request itself. The value never leaves it." },
  command: { title: "Give to a command", chip: "command", tone: "warn", desc: "As an environment variable. The command, and anything it runs, can read it." },
  fill: { title: "Fill in Chrome", chip: "fill", tone: "warn", desc: "Typed into a password field by the assentd extension, only on the sites below. The site can read it." },
};
const MODE_ORDER = ["http", "command", "fill"];
const TTLS = [[900, "15 min"], [3600, "1 hr"]];

const chip = (text, tone = "") => h("span", { class: `chip ${tone}` }, text);
const modeChip = (m) => chip(MODES[m]?.chip || m, MODES[m]?.tone);
const msgEl = () => h("p", { class: "msg", role: "status", "aria-live": "polite" });
const setMsg = (el, text, kind = "error") => { el.className = `msg ${kind}`; el.textContent = text; };

function segmented(name, options, value) {
  // options: [[value, label, disabled]]
  const el = h("div", { class: "seg", role: "radiogroup" },
    options.map(([v, label, disabled]) => h("label", {},
      h("input", { type: "radio", name, value: String(v), checked: String(v) === String(value), disabled: !!disabled, "data-off": disabled ? "1" : "0" }), label)));
  el.value = () => el.querySelector("input:checked")?.value;
  return el;
}

function markIcon(ok) {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  for (const [k, v] of Object.entries({ fill: "none", stroke: "currentColor", "stroke-width": "2.6", "stroke-linecap": "round", "stroke-linejoin": "round" })) svg.setAttribute(k, v);
  const path = document.createElementNS(ns, "path");
  path.setAttribute("d", ok ? "M5 12.5l4.5 4.5L19 7.5" : "M7 7l10 10M17 7L7 17");
  svg.append(path);
  return h("div", { class: `mark ${ok ? "" : "no"}` }, svg);
}

function doneScreen({ ok = true, title, text, extra }) {
  setNav(brandLink(), null);
  render(h("section", { class: "done" }, markIcon(ok), h("h1", {}, title), text ? h("p", { class: "muted" }, text) : null,
    extra, h("a", { href: "/", class: "button primary wide" }, "Done")));
}

// ------------------------------------------------------------------ WebAuthn

function serializeAssertion(cred) {
  return {
    cred_id: vc.b64u(cred.rawId),
    authenticatorData: vc.b64u(cred.response.authenticatorData),
    clientDataJSON: vc.b64u(cred.response.clientDataJSON),
    signature: vc.b64u(cred.response.signature),
  };
}

// Must be called synchronously from a tap handler: Safari only allows WebAuthn
// with a fresh user gesture, so the challenge is always fetched beforehand.
// The daemon sends the encrypted vault key (and whatever ciphertext this action needs) only after
// it has checked the Face ID assertion, and returns a single-use action token for the change.
function faceIdUnlock(ch) {
  return navigator.credentials.get({
    publicKey: {
      challenge: vc.unb64u(ch.challenge),
      rpId: ch.rp_id,
      allowCredentials: ch.cred_ids.map((id) => ({ type: "public-key", id: vc.unb64u(id) })),
      userVerification: "required",
      timeout: 120000,
      extensions: { prf: { eval: { first: vc.PRF_SALT } } },
    },
  }).then(async (cred) => {
    const prf = cred.getClientExtensionResults().prf?.results?.first;
    if (!prf) throw new Error("This passkey did not return a PRF secret; this browser or passkey provider lacks WebAuthn PRF support.");
    const data = await api("POST", "/api/unlock", { challenge_id: ch.challenge_id, assertion: serializeAssertion(cred) });
    let vmk;
    try {
      vmk = await vc.unwrapVmk(await vc.kekFromPrf(prf), data.vmk_wrap);
    } catch {
      // Apple passkeys can return a different PRF secret on different devices for the same passkey
      // (a known Apple issue), so this device's unlock doesn't open the key your phone set up.
      throw new Error("Your passkey worked, but on this device it produces a different unlock key than the one the vault was set up with (a known Apple passkey issue). Nothing was opened. Use your iPhone for this.");
    }
    // First Face ID after an upgrade also creates the deposit inbox (no extra tap).
    const inbox_setup = ch.inbox_needed ? await vc.newInbox(vmk) : undefined;
    return { action: data.action, vmk, data, inbox_setup };
  });
}

// A plain Face ID assertion (no vault key): proves the passkey's owner is at this device.
function faceIdAssert(ch) {
  return navigator.credentials.get({
    publicKey: {
      challenge: vc.unb64u(ch.challenge),
      rpId: ch.rp_id,
      allowCredentials: ch.cred_ids.map((id) => ({ type: "public-key", id: vc.unb64u(id) })),
      userVerification: "required",
      timeout: 120000,
    },
  }).then(serializeAssertion);
}

// This device was allowed, but Tailscale now reports a new key for it (reinstalled, or the key
// rotated). It keeps access only after Face ID here.
let rekeyShown = false;
function rekeyView() {
  if (rekeyShown) return;
  rekeyShown = true;
  setNav(brandLink(), null);
  const msg = msgEl();
  const go = h("button", { class: "primary wide", disabled: true }, "Confirm with Face ID");
  render(h("header", {}, h("h1", {}, "Confirm this device")),
    h("p", { class: "muted" }, "Tailscale reports a new key for this device, which happens when Tailscale is reinstalled or its key expires. Confirm it's still yours to keep using the vault here."),
    msg, h("div", { class: "decide" }, go));
  let ch;
  api("POST", "/api/rekey/challenge", {}).then((c) => { ch = c; go.disabled = false; }).catch((e) => setMsg(msg, errorText(e)));
  go.addEventListener("click", () => {
    go.disabled = true;
    faceIdAssert(ch)
      .then((assertion) => api("POST", "/api/rekey", { challenge_id: ch.challenge_id, assertion }))
      .then(() => { location.href = "/"; })
      .catch((e) => {
        setMsg(msg, errorText(e));
        api("POST", "/api/rekey/challenge", {}).then((c) => { ch = c; go.disabled = false; }).catch(() => {});
      });
  });
}

// Size grow-to-fit textareas once they're on screen (they also resize as you type).
function sizeTextareas() {
  requestAnimationFrame(() => { for (const t of document.querySelectorAll("textarea.grow")) { t.style.height = "auto"; t.style.height = `${t.scrollHeight + 2}px`; } });
}

// Disable every control in a bar while Face ID is up, so a second tap can't race the first.
function busy(container, on) {
  for (const b of container.querySelectorAll("button, input")) b.disabled = on ? true : b.dataset.off === "1";
}

// ------------------------------------------------------------------ policy editor

// Edits a secret's policy. read() returns the final meta or throws a user-facing Error.
function policyEditor(meta) {
  const ids = { desc: nextId("desc"), hosts: nextId("hosts") };
  const modes = Object.fromEntries(MODE_ORDER.map((m) => [m, h("input", { type: "checkbox", checked: meta.modes.includes(m) })]));
  const description = h("textarea", { id: ids.desc, class: "grow", rows: "2", placeholder: "What it is and what it's for" }, meta.description || "");
  const hosts = h("input", { type: "text", id: ids.hosts, class: "mono", autocapitalize: "off", autocomplete: "off", spellcheck: "false",
    value: meta.hosts.join(", "), placeholder: "api.example.com" });
  const ttlOpts = TTLS.some(([v]) => v === meta.max_ttl) ? TTLS : [...TTLS, [meta.max_ttl, fmtTtl(meta.max_ttl)]];
  const ttl = segmented(nextId("ttl"), ttlOpts, meta.max_ttl);
  const hostField = h("div", { class: "field" },
    h("label", { for: ids.hosts }, "Allowed hosts"), hosts,
    h("div", { class: "hint" }, "Exact hosts, like api.example.com."));
  const oId = nextId("origins");
  const origins = h("input", { type: "text", id: oId, class: "mono", autocapitalize: "off", autocomplete: "off", spellcheck: "false",
    value: (meta.fill?.origins || []).join(", "), placeholder: "https://login.example.com" });
  const originField = h("div", { class: "field" },
    h("label", { for: oId }, "Fill on these sites"), origins,
    h("div", { class: "hint" }, "Exact addresses, like https://login.example.com."));
  // HTTPS limits. Default: headers only, any method, any path.
  const hp = meta.http || {};
  const hdrId = nextId("header");
  const header = h("input", { type: "text", id: hdrId, class: "mono", autocapitalize: "off", autocomplete: "off", spellcheck: "false",
    value: hp.header ?? "Authorization: Bearer {}", placeholder: "Authorization: Bearer {}" });
  const mId = nextId("methods"), pId = nextId("paths");
  const methods = h("input", { type: "text", id: mId, class: "mono", autocapitalize: "characters", autocomplete: "off", spellcheck: "false",
    value: (hp.methods || []).join(", "), placeholder: "Any method" });
  const paths = h("input", { type: "text", id: pId, class: "mono", autocapitalize: "off", autocomplete: "off", spellcheck: "false",
    value: (hp.paths || []).join(", "), placeholder: "Any path, e.g. /v1/refunds" });
  const anyLimit = hp.methods?.length || hp.paths?.length;
  const headerField = h("div", { class: "field" },
    h("label", { for: hdrId }, "Sent in header"), header,
    h("div", { class: "hint" }, "{} is where the secret goes."));
  const httpField = h("details", { class: "more limits", open: !!anyLimit },
    h("summary", {}, "HTTPS limits"),
    h("label", { for: mId }, "Only these methods"), methods,
    h("label", { for: pId }, "Only these paths"), paths);
  // A fill is always approved once, so the longest approval only matters for the other ways.
  const ttlField = h("div", { class: "field" }, h("div", { class: "field-label" }, "Longest approval"), ttl);
  const node = h("div", { class: "card" },
    h("div", { class: "field" }, h("label", { for: ids.desc }, "Description"), description),
    h("div", { class: "field" }, h("div", { class: "field-label" }, "How it can be used"),
      h("div", { class: "modes" }, MODE_ORDER.map((m) => h("label", { class: "mode" }, modes[m],
        h("b", {}, MODES[m].title, m === "http" ? chip("safest", "safe") : null), h("span", {}, MODES[m].desc))))),
    hostField,
    headerField,
    httpField,
    originField,
    ttlField);
  const syncHosts = () => {
    hostField.classList.toggle("hidden", !modes.http.checked && !hosts.value);
    httpField.classList.toggle("hidden", !modes.http.checked);
    headerField.classList.toggle("hidden", !modes.http.checked);
    originField.classList.toggle("hidden", !modes.fill.checked);
    ttlField.classList.toggle("hidden", !modes.http.checked && !modes.command.checked);
  };
  for (const box of Object.values(modes)) box.addEventListener("change", syncHosts);
  syncHosts();
  function read() {
    const chosen = MODE_ORDER.filter((m) => modes[m].checked);
    const hostList = hosts.value.split(",").map((x) => x.trim().toLowerCase()).filter(Boolean);
    if (!chosen.length) throw new Error(`Choose at least one way ${meta.name || "it"} can be used.`);
    if (chosen.includes("http") && !hostList.length) throw new Error(`Add the site ${meta.name || "it"} may be sent to.`);
    const wild = hostList.find((x) => x.includes("*"));
    if (wild) throw new Error(`List each host exactly (${wild} is a wildcard).`);
    const out = { name: meta.name, created: meta.created, description: description.value.trim(), hosts: hostList, max_ttl: Number(ttl.value()), modes: chosen };
    const list = (el) => el.value.split(",").map((x) => x.trim()).filter(Boolean);
    const http = {};
    if (chosen.includes("http")) {
      const ms = list(methods).map((x) => x.toUpperCase());
      const bad = ms.find((x) => !["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"].includes(x));
      if (bad) throw new Error(`${bad} isn't an HTTP method. Use GET, POST, PUT, PATCH, DELETE or HEAD.`);
      const ps = list(paths);
      const badPath = ps.find((x) => !x.startsWith("/") || x.includes(".."));
      if (badPath) throw new Error(`Paths start with / and can't contain .. (got ${badPath}).`);
      const hv = header.value.trim();
      if (!hv) throw new Error(`Say which header ${meta.name || "it"} is sent in, like Authorization: Bearer {}.`);
      if (!/^[A-Za-z0-9-]+:.*\{\}/.test(hv)) throw new Error("The header looks like Name: value, with {} where the secret goes.");
      http.header = hv;
      if (ms.length) http.methods = ms;
      if (ps.length) http.paths = ps;
    }
    if (Object.keys(http).length) out.http = http;
    if (chosen.includes("fill")) {
      const fillSites = origins.value.split(",").map((x) => x.trim().toLowerCase().replace(/\/+$/, "")).filter(Boolean);
      if (!fillSites.length) throw new Error(`Add the site ${meta.name || "it"} may be filled on, like https://login.example.com.`);
      const badO = fillSites.find((x) => !/^https:\/\/[a-z0-9-]+(\.[a-z0-9-]+)*(:\d{1,5})?$/.test(x));
      if (badO) throw new Error(`${badO} isn't a site address. Use https://host, with no path or wildcard.`);
      out.fill = { origins: fillSites };
    }
    return out;
  }
  function onChange(fn) { node.addEventListener("input", fn); node.addEventListener("change", fn); }
  return { node, read, onChange };
}

// A one-line summary of a policy with a Change button that reveals the full editor.
function policySummary(editor) {
  const line = h("div", { class: "policy-line" });
  const toggle = h("button", { class: "small", type: "button" }, "Change");
  const wrap = h("div", { class: "hidden" }, editor.node);
  function update() {
    let m;
    try { m = editor.read(); } catch (e) { fill(line, h("span", { class: "msg error" }, e.message), toggle); return; }
    const hp = m.http || {};
    const extras = [hp.header && hp.header !== "Authorization: Bearer {}" && hp.header.split(":")[0], hp.methods && `${hp.methods.join("/")} only`,
      hp.paths && `paths ${hp.paths.join(", ")}`].filter(Boolean);
    const sites = [...m.hosts, ...(m.fill?.origins || []).map(hostOf)];
    const timed = m.modes.some((x) => x !== "fill");
    fill(line, h("span", {}, "Usable via ", h("b", {}, m.modes.map((x) => (x === "http" ? "HTTPS" : MODES[x].chip)).join(", ")),
      sites.length ? [" on ", sites.map((x, i) => [i ? ", " : "", h("b", {}, x)])] : null, timed ? ` · up to ${fmtTtl(m.max_ttl)}` : null,
      extras.length ? [" · ", h("b", {}, extras.join(" · "))] : null), toggle);
  }
  toggle.addEventListener("click", () => { wrap.classList.toggle("hidden"); toggle.textContent = wrap.classList.contains("hidden") ? "Change" : "Done"; update(); sizeTextareas(); });
  editor.onChange(update);
  update();
  return h("div", { class: "field" }, line, wrap);
}

// ------------------------------------------------------------------ home

const names = (a) => (a.names || []).join(", ");
const hostOf = (u) => { try { return new URL(u).host; } catch { return u; } };
const EVENT_TEXT = {
  requested: (a) => `Claude asked for ${names(a)}`,
  approved: (a) => `You approved ${names(a)}${a.ttl ? ` for ${fmtTtl(a.ttl)}` : " once"}`,
  denied: (a) => `You denied ${names(a)}`,
  reused: (a) => `${names(a)} reused within an approval`,
  http_sent: (a) => `Sent ${names(a)} to ${hostOf(a.url)} · ${a.status ?? a.error}`,
  secret_added: (a) => `Added ${a.name}`,
  secret_replaced: (a) => `Replaced ${a.name}`,
  secret_edited: (a) => `Changed ${a.name}`,
  secret_deleted: (a) => `Deleted ${a.name}`,
  deposited: (a) => `Claude deposited ${a.name}`,
  deposit_accepted: (a) => `You stored ${a.name}`,
  deposit_rejected: (a) => `You rejected ${a.name}`,
  stored: (a) => `You saved ${names(a)}`,
  revoke: (a) => `Locked ${names(a)} again`,
  grant_expired: (a) => `Access to ${names(a)} ended`,
  cancelled: (a) => `Claude withdrew its request for ${names(a)}`,
  request_expired: (a) => `Request for ${names(a)} timed out`,
  enrolled: () => "Vault set up on this phone",
  reenrolled: () => "Passkey replaced",
  inbox_enabled: () => "Deposits turned on",
  auth_failed: (a) => `Rejected a Face ID check: ${a.reason}`,
  enroll_rejected: (a) => `Rejected a setup attempt: ${a.reason}`,
  reenroll_rejected: () => "Rejected a passkey replacement",
  device_allowed: (a) => `Allowed ${(a.node || "a device").split(".")[0]} to open the vault`,
  device_removed: () => "Removed a device",
  filled: (a) => (a.ok ? `Filled ${a.name} on ${hostOf(a.origin)}` : `Didn't fill ${a.name}: ${a.error}`),
  chrome_pair_requested: (a) => `Chrome extension asked to pair (${a.fingerprint})`,
  chrome_paired: (a) => `Paired Chrome extension ${a.fingerprint}`,
  chrome_pair_dismissed: (a) => `Ignored Chrome extension ${a.fingerprint}`,
  chrome_removed: (a) => `Removed Chrome extension ${a.fingerprint}`,
};
const ALERT_EVENTS = new Set(["auth_failed", "enroll_rejected", "reenroll_rejected"]);

const siteList = (s) => [...s.hosts, ...(s.fill?.origins || []).map(hostOf)].join(", ");
const reqKind = (r) => (Object.keys(r.creates).length ? chip("new", "accent") : modeChip(r.mode));

async function homeView() {
  setNav(brandLink(), [iconLink("/activity", "clock", "Activity"), iconLink("/settings", "gear", "Settings")]);
  let st;
  try { st = await api("GET", "/api/state"); } catch (e) { return render(h("p", { class: "msg error" }, errorText(e))); }
  if (!st.enrolled) {
    setNav(brandLink(), null);
    return render(h("div", { class: "empty" }, h("h1", {}, "Not set up yet"),
      h("p", { class: "muted" }, "Run the installer on the Mac and scan the setup code it shows.")));
  }
  const waiting = [
    ...st.pending.map((r) => ({ href: `/r/${r.id}`, kind: reqKind(r), name: r.needs.join(", "), sub: r.reason ? oneLine(r.reason) : "No reason given", ts: r.created })),
    ...st.deposits.map((d) => ({ href: `/d/${d.id}`, kind: chip("new", "accent"), name: d.name, sub: d.reason ? oneLine(d.reason) : "New secret to store", ts: d.created })),
    ...st.chrome.pairings.map((p) => ({ href: "/settings", kind: chip("pair", "accent"), name: "Chrome extension", sub: `Key ${p.fingerprint}`, ts: p.created })),
  ].sort((a, b) => b.ts - a.ts);

  const out = [];
  out.push(h("p", { class: `status ${waiting.length ? "wait" : st.grants.length ? "on" : ""}` },
    waiting.length ? `${waiting.length} waiting for you` : st.grants.length ? `${st.grants.length} unlocked right now` : "All locked"));
  const nudge = await setupNudge(st);
  if (nudge) out.push(nudge);
  if (waiting.length) {
    out.push(h("div", { class: "list" }, waiting.map((w) => h("a", { href: w.href, class: "row" }, w.kind,
      h("div", { class: "main" }, h("div", { class: "name" }, w.name), h("div", { class: "sub" }, w.sub)),
      h("div", { class: "meta" }, relTime(w.ts, st.now))))));
  }
  // A pile of deposits is more likely spam than work: let them all go in two taps.
  if (st.deposits.length >= 3) {
    const n = st.deposits.length;
    const btn = h("button", { class: "text small danger" }, `Reject all ${n} new secrets`);
    btn.addEventListener("click", () => {
      if (btn.dataset.armed) return api("POST", "/api/deposits/reject", {}).then(homeView);
      btn.dataset.armed = "1";
      btn.textContent = `Tap again to destroy all ${n} values`;
    });
    out.push(h("div", { class: "list-foot" }, btn));
  }
  if (st.grants.length) {
    out.push(h("section", { class: "field" }, h("h2", {}, "Unlocked"),
      h("div", { class: "list" }, st.grants.map((g) => h("div", { class: "row" }, modeChip(g.mode),
        h("div", { class: "main" }, h("div", { class: "name" }, g.names.join(", ")),
          h("div", { class: "sub" }, `${fmtTtl(g.expires - st.now)} left · ${sessionText(g.session) || g.session_label}`)),
        h("button", { class: "small danger", onclick: async () => { await api("POST", "/api/revoke", { grant_id: g.id }); homeView(); } }, "Lock"))))));
  }
  out.push(h("section", { class: "field" },
    h("div", { class: "section-head" }, h("h2", {}, "Secrets"), st.secrets.length ? h("a", { href: "/add" }, "+ Add") : null),
    st.secrets.length
      ? h("div", { class: "list" }, st.secrets.map((s) => h("a", { href: `/edit/${s.name}`, class: "row plain" },
          h("div", { class: "main" }, h("div", { class: "name" }, s.name),
            h("div", { class: "chips" }, s.modes.map(modeChip), siteList(s) ? h("span", { class: "sub" }, siteList(s)) : null)),
          h("div", { class: "meta" }))))
      : h("div", { class: "card empty" }, h("p", { class: "muted" }, "No secrets yet. Add one, or Claude will ask when it needs one."),
          h("a", { href: "/add", class: "button primary" }, "Add a secret"))));
  render(out);
}

// One quiet line on home, only while notifications aren't set up on this device.
async function setupNudge(st) {
  if (!standalone()) {
    if (dismissed("av-a2hs")) return null;
    return h("a", { href: "/settings", class: "nudge" }, "Add assentd to your Home Screen to get requests as notifications");
  }
  if ((await pushState(st)).on) return null;
  return h("a", { href: "/settings", class: "nudge" }, "Turn on notifications");
}

// ------------------------------------------------------------------ activity

async function activityView() {
  setNav(backLink(), null);
  let st;
  try { st = await api("GET", "/api/state"); } catch (e) { return render(h("p", { class: "msg error" }, errorText(e))); }
  const days = new Map();
  for (const a of st.audit) {
    const day = new Date(a.ts * 1000).toLocaleDateString([], { weekday: "long", month: "short", day: "numeric" });
    if (!days.has(day)) days.set(day, []);
    days.get(day).push(a);
  }
  render(h("header", {}, h("h1", {}, "Activity")),
    st.audit.length ? [...days].map(([day, items]) => h("section", { class: "field" }, h("h2", {}, day),
      h("div", { class: "list activity" }, items.map((a) => h("div", { class: `row ${ALERT_EVENTS.has(a.event) ? "alert" : ""}` },
        h("div", { class: "main" }, (EVENT_TEXT[a.event] || ((x) => x.event.replace(/_/g, " ")))(a)),
        h("div", { class: "meta" }, clock(a.ts)))))))
      : h("p", { class: "muted" }, "Nothing yet."));
}

// ------------------------------------------------------------------ settings

const standalone = () => matchMedia("(display-mode: standalone)").matches || navigator.standalone === true;
const pushSupported = () => "serviceWorker" in navigator && "PushManager" in window && "Notification" in window;
const dismissed = (k) => { try { return localStorage.getItem(k) === "1"; } catch { return false; } };
const dismiss = (k) => { try { localStorage.setItem(k, "1"); } catch { /* private mode */ } };

async function pushState(st) {
  if (!standalone() || !pushSupported()) return { on: false, reg: null, sub: null };
  const reg = await Promise.race([navigator.serviceWorker.ready, new Promise((r) => setTimeout(r, 4000))]);
  const sub = reg ? await reg.pushManager.getSubscription() : null;
  return { on: !!(sub && Notification.permission === "granted" && st.push.devices > 0), reg, sub };
}

// A settings row: label (and optional note) on the left, value or control on the right.
const setRow = (label, note, right) => h("div", { class: "row plain" },
  h("div", { class: "main" }, h("div", {}, label), note ? h("div", { class: "sub wrap" }, note) : null), right);

async function settingsView() {
  setNav(backLink(), null);
  let st;
  try { st = await api("GET", "/api/state"); } catch (e) { return render(h("p", { class: "msg error" }, errorText(e))); }
  const msg = msgEl();
  const refresh = () => settingsView();
  const short = (node) => node.split(".")[0];

  // Notifications (this device)
  const ps = await pushState(st);
  let notif;
  if (!standalone()) {
    notif = setRow("Notifications", "Open this page in Safari, tap Share, then Add to Home Screen. Open assentd from there to turn them on.", null);
  } else if (!pushSupported() || !ps.reg) {
    notif = setRow("Notifications", "Not available right now. Reopen the app to try again.", null);
  } else if (ps.on) {
    notif = setRow("Notifications", "On for this device", h("button", { class: "small", onclick: async () => {
      await api("POST", "/api/push/unsubscribe", { endpoint: ps.sub.endpoint }).catch(() => {});
      await ps.sub.unsubscribe().catch(() => {});
      refresh();
    } }, "Turn off"));
  } else {
    const turnOn = h("button", { class: "small primary" }, "Turn on");
    let ch;
    api("POST", "/api/challenge", { kind: "push" }).then((c) => { ch = c; }).catch((e) => setMsg(msg, errorText(e)));
    turnOn.addEventListener("click", async () => {
      let sub;
      try {
        if (await Notification.requestPermission() !== "granted") throw new Error("Notifications are blocked. Allow them for assentd in iOS Settings > Notifications.");
        sub = ps.sub || await ps.reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: vc.unb64u(st.push.vapid_public) });
      } catch (e) { return setMsg(msg, errorText(e)); }
      // Registering a device needs Face ID, which needs a fresh tap.
      fill(turnOn.parentElement, h("div", { class: "main" }, h("div", {}, "Notifications"), h("div", { class: "sub" }, "Confirm this device may see request details")),
        h("button", { class: "small primary", onclick: () => faceIdUnlock(ch)
          .then(({ action, inbox_setup }) => api("POST", "/api/push/subscribe", { action, inbox_setup, subscription: sub.toJSON() }))
          .then(refresh).catch((e) => setMsg(msg, errorText(e))) }, "Face ID"));
    });
    notif = setRow("Notifications", "Off for this device", turnOn);
  }

  // Devices allowed to open the vault (R8)
  const devRows = st.devices.map((d) => setRow(short(d.node), `${d.login} · since ${new Date(d.added * 1000).toLocaleDateString([], { month: "short", day: "numeric" })}`,
    st.devices.length > 1 ? h("button", { class: "small danger", onclick: () => api("POST", "/api/devices/remove", { node_id: d.node_id }).then(refresh, (e) => setMsg(msg, errorText(e))) }, "Remove") : null));
  const reqRows = st.device_requests.map((r) => {
    const allow = h("button", { class: "small primary", disabled: true }, "Allow");
    let ch;
    api("POST", "/api/challenge", { kind: "device", ref: r.node_id }).then((c) => { ch = c; allow.disabled = false; }).catch(() => {});
    allow.addEventListener("click", () => faceIdUnlock(ch)
      .then(({ action, inbox_setup }) => api("POST", "/api/devices/allow", { action, node_id: r.node_id, inbox_setup }))
      .then(refresh).catch((e) => setMsg(msg, errorText(e))));
    // A known device whose tailnet key changed was reinstalled or replaced: say so, it needs a fresh yes.
    return setRow(`${short(r.node)} ${r.key_changed ? "came back with a new key" : "wants access"}`, `${r.login} · ${relTime(r.last, st.now)} ago`,
      h("div", { class: "chips" }, h("button", { class: "small text", onclick: () => api("POST", "/api/devices/dismiss", { node_id: r.node_id }).then(refresh) }, "Ignore"), allow));
  });
  const devices = reqRows.length || devRows.length ? h("div", { class: "list" }, reqRows, devRows) : null;

  // Chrome extensions that may receive fills. Pairing needs Face ID; removing doesn't.
  const pairRows = st.chrome.pairings.map((p) => {
    const pair = h("button", { class: "small primary", disabled: true }, "Pair");
    let ch;
    api("POST", "/api/challenge", { kind: "chrome", ref: p.id }).then((c) => { ch = c; pair.disabled = false; }).catch(() => {});
    pair.addEventListener("click", () => faceIdUnlock(ch)
      .then(({ action, inbox_setup }) => api("POST", "/api/chrome/pair", { action, id: p.id, inbox_setup }))
      .then(refresh).catch((e) => setMsg(msg, errorText(e))));
    return setRow("Chrome extension wants to pair", [h("span", { class: "mono" }, p.fingerprint), " · pair only if the extension's popup shows this key"],
      h("div", { class: "chips" }, h("button", { class: "small text", onclick: () => api("POST", "/api/chrome/dismiss", { id: p.id }).then(refresh) }, "Ignore"), pair));
  });
  const keyRows = st.chrome.keys.map((k) => setRow(h("span", { class: "mono" }, k.fingerprint),
    `Paired ${new Date(k.added * 1000).toLocaleDateString([], { month: "short", day: "numeric" })}${k.connected ? " · connected" : ""}`,
    h("button", { class: "small danger", onclick: () => api("POST", "/api/chrome/remove", { fingerprint: k.fingerprint }).then(refresh, (e) => setMsg(msg, errorText(e))) }, "Remove")));
  const chrome = pairRows.length || keyRows.length ? h("div", { class: "list" }, pairRows, keyRows) : null;

  // Vault
  let depositsRight = h("span", { class: "sub" }, "On");
  if (!st.inbox) {
    depositsRight = h("button", { class: "small", disabled: true }, "Turn on");
    let ch;
    api("POST", "/api/challenge", { kind: "inbox" }).then((c) => { ch = c; depositsRight.disabled = false; }).catch(() => {});
    depositsRight.addEventListener("click", () => faceIdUnlock(ch)
      .then(({ action, inbox_setup }) => api("POST", "/api/inbox", { action, inbox_setup }))
      .then(refresh).catch((e) => setMsg(msg, errorText(e))));
  }
  const cred = st.creds[0];
  const vault = h("div", { class: "list" },
    setRow("Passkey", cred ? `Set up ${new Date(cred.created * 1000).toLocaleDateString([], { month: "short", day: "numeric", year: "numeric" })}` : "None", null),
    setRow("Deposits", "Lets Claude hand you secrets it generates without seeing them", depositsRight),
    st.grants.length ? setRow("Lock everything now", `${st.grants.length} unlocked`, h("button", { class: "small danger", onclick: () => api("POST", "/api/revoke", { all: true }).then(refresh) }, "Lock all")) : null);

  render(h("header", {}, h("h1", {}, "Settings")), msg,
    h("section", { class: "field" }, h("h2", {}, "This phone"), h("div", { class: "list" }, notif)),
    devices ? h("section", { class: "field" }, h("h2", {}, "Devices that can open the vault"), devices) : null,
    chrome ? h("section", { class: "field" }, h("h2", {}, "Chrome extensions that can fill"), chrome) : null,
    h("section", { class: "field" }, h("h2", {}, "Vault"), vault),
    h("p", { class: "hint center" }, `assentd ${st.version}`));
}

// ------------------------------------------------------------------ request

// One line saying where the value goes. Tone: safe (stays in the vault), warn (released), danger.
const safety = (tone, lead, text) => h("p", { class: `safety ${tone}` }, h("b", {}, lead), " ", text);

// The requester's own words (R5): labelled as Claude's, never presented as fact, and set below
// and quieter than the vault's own lines. Line breaks show as ⏎ so a reason can't lay itself out
// like the screen around it.
const claudeSays = (reason) => [h("div", { class: "said" }, "Claude says"),
  h("p", { class: "reason" }, reason ? `“${oneLine(reason)}”` : "No reason given.")];

// Host and path exactly as the daemon parsed them and will send them: never re-parsed or decoded here.
const hostText = (d) => d.port ? `${d.host}:${d.port}` : d.host;
const pathText = (d) => d.path + (d.query ? `?${d.query}` : "");

// What else goes with the request: shown on the main screen, so a header or body Claude added
// isn't only behind Details.
function extrasText(t) {
  const n = (t.headers || []).length;
  const parts = [];
  if (n) parts.push(`${n} more header${n > 1 ? "s" : ""}`);
  if (t.body_bytes) parts.push(`a ${t.body_bytes >= 1024 ? `${(t.body_bytes / 1024).toFixed(1)} KB` : `${t.body_bytes} B`} body`);
  return parts.length ? `With ${parts.join(" and ")} · see Details` : "";
}

function whatHappens(req) {
  const t = req.target || {};
  if (req.mode === "http") {
    const d = t.display;
    return [
      h("div", { class: "target" }, h("div", { class: "chips" }, chip(t.method), h("span", { class: "host" }, hostText(d))),
        h("div", { class: "path" }, pathText(d)), extrasText(t) ? h("div", { class: "caption" }, extrasText(t)) : null),
      safety("safe", "Stays in the vault.", `Only ${hostText(d)} gets it, and the reply comes back with it blanked out.`),
    ];
  }
  if (req.mode === "store") return safety("safe", "Only saved.", "Each use will ask you again.");
  if (req.mode === "fill") {
    return [
      h("div", { class: "target" }, h("div", { class: "chips" }, chip("Chrome"), h("span", { class: "host" }, hostOf(t.origin)))),
      safety("warn", `Fills ${req.needs[0]}`, `into the password field on ${t.origin}, as Chrome reports the tab. That site can read it.`),
    ];
  }
  const cmd = h("pre", { class: "cmd" }, req.argv.map(shellQuote).join(" "));
  const more = h("button", { class: "text small cmd-more", type: "button", onclick: () => {
    cmd.classList.toggle("open"); more.textContent = cmd.classList.contains("open") ? "Less" : "Full command"; } }, "Full command");
  requestAnimationFrame(() => { if (cmd.scrollHeight <= cmd.clientHeight + 2) more.remove(); });
  return [
    cmd, h("div", { class: "caption" }, "Command as reported by Claude", more),
    safety("warn", "Given to this command.", "It, and anything it runs, can read the value."),
  ];
}

// If the target can't be shown, show it raw rather than no screen (and no Deny button) at all.
function whatHappensSafe(req) {
  try { return whatHappens(req); } catch { return h("pre", { class: "cmd open" }, JSON.stringify(req.target || {}, null, 1)); }
}

// Collapsed by default. Grouped by who vouches for each item (R5).
function detailsLink(groups) {
  const rows = [];
  for (const [title, items] of groups) {
    if (!items.length) continue;
    rows.push(h("div", { class: "kv-group" }, title), items.map(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]));
  }
  return h("details", { class: "more" }, h("summary", {}, "Details"), h("dl", { class: "kv" }, rows));
}

function requestDetails(req) {
  const t = req.target || {};
  const exact = [];
  if (req.mode === "http") {
    const lines = [...(t.inject || []).map(([, k, v]) => [k, v]), ...(t.headers || [])];
    if (lines.length) exact.push(["Headers", h("pre", {}, lines.map(([k, v]) => [`${k}: `, ...withPlaceholders(v), "\n"]))]);
    if (t.body_bytes) exact.push([`Body · ${t.body_bytes} B`, h("pre", {}, withPlaceholders(t.body_preview))]);
  }
  const checked = [["Asked", clock(req.created)]];
  const chrome = [];
  const page = [];
  if (req.mode === "fill") {
    chrome.push(["Site", h("span", { class: "mono" }, t.origin)], ["Page", h("span", { class: "mono" }, t.url)]);
    if (t.title) page.push(["Tab title", oneLine(t.title)]);
  }
  for (const s of req.secrets) if (s.description && !s.new) checked.push([s.name, s.description]);
  const claimed = [["Session", sessionText(req.session)], ["Folder", h("span", { class: "mono" }, shortPath(req.cwd))]];
  return detailsLink([
    ["Sent exactly as shown", exact],
    ["Reported by Chrome", chrome],
    ["Checked by the vault", checked],
    ["As the page reports it", page],
    ["As Claude reports it", claimed],
  ]);
}

async function requestView(id) {
  setNav(backLink(), null);
  let req;
  try { req = await api("GET", `/api/req/${id}`); }
  catch (e) { return doneScreen({ ok: false, title: "Request not found", text: "It was answered, withdrawn, or timed out." }); }
  if (req.status !== "pending") {
    const words = { approved: "Already approved", denied: "Denied", expired: "Timed out", cancelled: "Withdrawn by Claude", stored: "Saved" };
    return doneScreen({ ok: ["approved", "stored"].includes(req.status), title: words[req.status] || req.status, text: req.needs.join(", ") });
  }

  const storeOnly = req.mode === "store";
  const newNames = Object.keys(req.creates);
  const label = req.needs.join(", ");
  const head = h("header", {},
    h("div", { class: "eyebrow" }, storeOnly ? "New secret" : MODES[req.mode].title),
    h("h1", {}, wrapName(storeOnly ? `Enter ${label}` : req.mode === "fill" ? `Fill ${label}` : `Use ${label}`)));

  // The heading already names a lone new secret, so its form doesn't repeat the name.
  const soloNew = newNames.length === 1 && req.needs.length === 1;
  const forms = newNames.map((n) => {
    const vid = nextId("val");
    const value = h("textarea", { id: vid, autocomplete: "off", autocapitalize: "off", autocorrect: "off", spellcheck: "false",
      placeholder: soloNew ? "Paste the value here" : `Paste ${n} here`, "aria-label": `Value for ${n}` });
    const editor = policyEditor(req.creates[n]);
    return { name: n, value, editor, card: h("section", { class: "card" },
      soloNew ? null : h("label", { for: vid, class: "name" }, n),
      req.replaces[n] ? safety("danger", "Replaces the current value.", `Version ${req.replaces[n]} will be overwritten.`) : null,
      value, policySummary(editor)) };
  });
  const msg = msgEl();
  const note = h("span", { class: "note" });
  const capOf = () => Math.min(...req.secrets.map((s) => {
    const f = forms.find((x) => x.name === s.name);
    if (!f) return s.max_ttl;
    try { return f.editor.read().max_ttl; } catch { return s.max_ttl; }
  }));
  const seg = storeOnly || req.mode === "fill" ? null : segmented(nextId("dur"), [["once", "Once"], ["15m", "15 min"], ["1h", "1 hr"], ["max", ""]], "once");
  // Offer only the durations every secret's policy allows; a greyed-out option is just clutter. A
  // limit that isn't one of the presets (say 5 min) is offered as itself.
  const fitSeg = () => {
    if (!seg) return;
    const cap = capOf();
    for (const input of seg.querySelectorAll("input")) {
      const hide = input.value === "max" ? cap === 900 || cap === 3600 : { once: 0, "15m": 900, "1h": 3600 }[input.value] > cap;
      if (input.value === "max") input.parentElement.lastChild.textContent = hide ? "" : fmtTtl(cap);
      input.parentElement.classList.toggle("hidden", hide);
      if (hide && input.checked) seg.querySelector("input[value=once]").checked = true;
    }
  };
  fitSeg();
  const primary = h("button", { class: "primary wide", disabled: true }, storeOnly ? "Save with Face ID" : "Approve with Face ID");
  const deny = h("button", { class: "text danger", disabled: true }, storeOnly ? "Decline" : "Deny");
  const bar = h("div", { class: "decide" }, msg,
    seg ? [h("div", { class: "seg-label" }, "Let this session reuse it for"), seg] : null,
    primary, h("div", { class: "under" }, deny, note));

  const concurrent = req.concurrent?.length
    ? safety("danger", "Another session wants this too.", `A different Claude session is also asking for ${req.concurrent.join(", ")}. Make sure this is the one you meant.`)
    : null;
  let details;
  try { details = requestDetails(req); } catch { details = null; }
  render(head, h("section", { class: "card" }, whatHappensSafe(req), concurrent, claudeSays(req.reason)), forms.map((f) => f.card), details, bar);

  const expiresAt = Date.now() + (req.expires - req.now) * 1000;
  const tick = setInterval(() => {
    const left = (expiresAt - Date.now()) / 1000;
    if (left <= 0) { clearInterval(tick); doneScreen({ ok: false, title: "Timed out", text: "Claude will have to ask again." }); }
    else note.textContent = left < 60 ? `Expires in ${fmtClock(left)}` : "";
  }, 1000);

  let ch;
  async function prepare() {
    try { ch = await api("POST", "/api/challenge", { kind: "req", ref: id }); }
    catch (e) { clearInterval(tick); return setMsg(msg, errorText(e)); }
    for (const b of [primary, deny]) { b.disabled = false; b.dataset.off = "0"; }
  }

  function approve(choice) {
    const creating = [];
    try {
      for (const f of forms) {
        if (!f.value.value) throw new Error(`Paste a value for ${f.name}.`);
        const meta = f.editor.read();
        creating.push({ name: f.name, value: f.value.value, metaJson: vc.canonicalJson(meta) });
      }
    } catch (e) { return setMsg(msg, errorText(e)); }
    setMsg(msg, "", "ok");
    busy(bar, true);
    faceIdUnlock(ch).then(async ({ action, vmk, data, inbox_setup }) => {
      const creates = {};
      for (const c of creating) creates[c.name] = { meta_json: c.metaJson, box: await vc.sealSecret(vmk, c.metaJson, c.value) };
      let values;
      if (choice !== "save_only") {
        values = {};
        for (const s of data.secrets) values[s.name] = await vc.openSecret(vmk, s.meta_json, s.box);
      }
      const r = await api("POST", `/api/req/${id}/approve`, { action, choice, values, creates, inbox_setup });
      for (const f of forms) f.value.value = "";
      clearInterval(tick);
      if (choice === "save_only") {
        doneScreen({ title: "Saved", text: `${label} is in the vault. Claude can now ask to use it.` });
      } else {
        doneScreen({ title: "Approved", text: r.ttl ? `This Claude session can use ${label} for ${fmtTtl(r.ttl)} without asking again.`
          : req.mode === "fill" ? `The extension fills ${label} on ${hostOf(req.target.origin)} now.` : "Released once. Claude asks again next time." });
      }
    }).catch((e) => { setMsg(msg, errorText(e)); busy(bar, false); prepare(); });  // challenges are single-use
  }

  primary.addEventListener("click", () => approve(storeOnly ? "save_only" : seg ? seg.value() : "once"));
  deny.addEventListener("click", async () => {
    try { await api("POST", `/api/req/${id}/deny`, {}); } catch (e) { return setMsg(msg, errorText(e)); }
    clearInterval(tick);
    doneScreen({ ok: false, title: storeOnly ? "Declined" : "Denied", text: `Claude did not get ${label}.` });
  });
  for (const f of forms) f.editor.onChange(fitSeg);
  prepare();
}

// ------------------------------------------------------------------ deposit

async function depositView(id) {
  setNav(backLink(), null);
  let d;
  try { d = await api("GET", `/api/deposit/${id}`); }
  catch (e) { return doneScreen({ ok: false, title: "Nothing to store", text: errorText(e) }); }
  const generated = d.provenance.startsWith("generated");
  const editor = policyEditor(d.meta);
  const msg = msgEl();
  const accept = h("button", { class: "primary wide", disabled: true }, "Store with Face ID");
  const reject = h("button", { class: "text danger" }, "Reject"); // no Face ID needed, so never waits on one
  const bar = h("div", { class: "decide" }, msg, accept, h("div", { class: "under" }, reject));

  render(
    h("header", {}, h("div", { class: "eyebrow" }, "New secret from Claude"), h("h1", {}, wrapName(`Store ${d.name}?`))),
    h("section", { class: "card" },
      generated
        ? safety("safe", "Made by the vault.", "Generated inside the vault and sealed for this phone. Claude never saw it.")
        : safety("warn", "Handed in from the Mac.", d.claimed_source
            ? `Claude says it was ${d.claimed_source.replace(/^./, (c) => c.toLowerCase())}; the vault can't check that.`
            : "The vault can't check where it came from."),
      d.replaces ? safety("danger", `Replaces ${d.name}.`, `Version ${d.replaces} will be overwritten.`) : null,
      claudeSays(d.reason), policySummary(editor)),
    detailsLink([["Checked by the vault", [["Source", d.provenance], ["Session", d.session], ["Sent", clock(d.created)]]]]),
    bar);

  let ch;
  async function prepare() {
    try { ch = await api("POST", "/api/challenge", { kind: "deposit", ref: id }); }
    catch (e) { return setMsg(msg, errorText(e)); }
    accept.disabled = reject.disabled = false;
    accept.dataset.off = reject.dataset.off = "0";
  }
  const fail = (e) => { setMsg(msg, errorText(e)); busy(bar, false); prepare(); };

  accept.addEventListener("click", () => {
    let metaJson;
    try { metaJson = vc.canonicalJson(editor.read()); } catch (e) { return setMsg(msg, errorText(e)); }
    busy(bar, true);
    faceIdUnlock(ch).then(async ({ action, vmk, data, inbox_setup }) => {
      const value = await vc.openDeposit(vmk, data.inbox_priv_box, data.deposit.box, id);
      const box = await vc.sealSecret(vmk, metaJson, value);
      await api("POST", `/api/deposit/${id}/accept`, { action, meta_json: metaJson, box, inbox_setup });
      doneScreen({ title: `Stored ${d.name}`, text: "Claude can now ask to use it.", extra: revealer(value) });
    }).catch(fail);
  });

  reject.addEventListener("click", () => {
    const confirmMsg = h("p", { class: "msg error" }, "Destroy this value? Anything Claude already set up with it will need a new one.");
    fill(bar, confirmMsg,
      h("button", { class: "danger solid wide", onclick: () => {
        busy(bar, true);
        api("POST", `/api/deposit/${id}/reject`, {})
          .then(() => doneScreen({ ok: false, title: "Rejected", text: `The value for ${d.name} was destroyed.` }))
          .catch((e) => { busy(bar, false); setMsg(confirmMsg, errorText(e)); });
      } }, "Destroy it"),
      h("button", { class: "text", onclick: () => depositView(id) }, "Keep it"));
  });
  prepare();
}

// Show/copy a value that is already decrypted on this phone.
function revealer(value) {
  const pre = h("pre", { class: "cmd open hidden sensitive" }, value);
  const show = h("button", { class: "small", onclick: () => {
    pre.classList.toggle("hidden"); show.textContent = pre.classList.contains("hidden") ? "Show value" : "Hide value"; } }, "Show value");
  const copy = h("button", { class: "small", onclick: () => navigator.clipboard.writeText(value).then(
    () => { copy.textContent = "Copied"; },
    () => { pre.classList.remove("hidden"); window.getSelection().selectAllChildren(pre); }) }, "Copy");
  return h("div", { class: "field wide" }, h("div", { class: "chips" }, show, copy), pre);
}

// ------------------------------------------------------------------ add / edit

async function secretFormView(editName) {
  setNav(backLink(), null);
  const msg = msgEl();
  const ids = { name: nextId("name"), value: nextId("value") };
  const name = h("input", { type: "text", id: ids.name, class: "mono", autocapitalize: "characters", autocomplete: "off", spellcheck: "false", placeholder: "STRIPE_API_KEY" });
  const value = h("textarea", { id: ids.value, autocomplete: "off", autocapitalize: "off", autocorrect: "off", spellcheck: "false",
    placeholder: editName ? "Leave empty to keep the current value" : "Paste the secret" });
  const save = h("button", { class: "primary wide", disabled: true }, "Save with Face ID");
  const bar = h("div", { class: "decide" }, msg, save);
  let ch, overwrite = false;

  async function prepare() {
    try { ch = await api("POST", "/api/challenge", editName ? { kind: "edit", ref: editName } : { kind: "add" }); }
    catch (e) { setMsg(msg, errorText(e)); return false; }
    save.disabled = false;
    save.dataset.off = "0";
    return true;
  }
  if (!(await prepare()) && editName) return doneScreen({ ok: false, title: "Not found", text: `There is no secret called ${editName}.` });
  let meta = { name: "", description: "", modes: ["http"], hosts: [], max_ttl: 900, created: Math.floor(Date.now() / 1000) };
  if (editName) {
    const st = await api("GET", "/api/state").catch(() => null);
    const found = st?.secrets.find((x) => x.name === editName);
    if (!found) return doneScreen({ ok: false, title: "Not found", text: `There is no secret called ${editName}.` });
    meta = Object.fromEntries(Object.entries(found).filter(([k]) => !["version", "updated"].includes(k)));
  }
  const editor = policyEditor(meta);

  let valueCard;
  if (editName) {
    const shown = h("pre", { class: "cmd open hidden sensitive" });
    const dots = h("span", { class: "dots" }, "••••••••");
    const reveal = h("button", { class: "small", onclick: () => {
      if (!shown.classList.contains("hidden")) { shown.classList.add("hidden"); dots.classList.remove("hidden"); shown.textContent = ""; reveal.textContent = "Reveal"; return; }
      // Decrypts on the phone only. The unlock used up this challenge, so get a fresh one for Save.
      faceIdUnlock(ch).then(async ({ vmk, data }) => {
        shown.textContent = await vc.openSecret(vmk, data.secret.meta_json, data.secret.box);
        shown.classList.remove("hidden");
        dots.classList.add("hidden");
        reveal.textContent = "Hide";
      }).catch((e) => setMsg(msg, errorText(e))).finally(prepare);
    } }, "Reveal");
    const replaceBox = h("div", { class: "field hidden" }, h("label", { for: ids.value }, "New value"), value);
    const replace = h("button", { class: "small", onclick: () => { replaceBox.classList.remove("hidden"); replace.remove(); value.focus(); } }, "Replace");
    valueCard = h("section", { class: "card" },
      h("div", { class: "policy-line" }, h("span", {}, h("b", {}, "Value "), dots),
        h("span", { class: "chips" }, reveal, replace)), shown, replaceBox);
  } else {
    valueCard = h("section", { class: "card" },
      h("div", { class: "field" }, h("label", { for: ids.name }, "Name"), name, h("div", { class: "hint" }, "Letters, digits and _. Claude refers to it by this name.")),
      h("div", { class: "field" }, h("label", { for: ids.value }, "Value"), value,
        h("div", { class: "hint" }, "Encrypted on this phone before it is sent. The Mac and Claude only see the name and policy.")));
  }

  render(h("header", {}, h("div", { class: "eyebrow" }, editName ? "Secret" : "New secret"), h("h1", {}, editName ? wrapName(editName) : "Add a secret")),
    valueCard, editor.node, editName ? deleteSection(editName, msg) : null, bar);

  save.addEventListener("click", () => {
    const n = editName || name.value.trim().toUpperCase();
    const newValue = value.value;
    let m;
    try {
      if (!/^[A-Z][A-Z0-9_]{0,63}$/.test(n)) throw new Error("Name must be letters, digits and _, starting with a letter.");
      if (!editName && !newValue) throw new Error("Paste the value first.");
      m = { ...editor.read(), name: n };
    } catch (e) { return setMsg(msg, errorText(e)); }
    const metaJson = vc.canonicalJson(m);
    busy(bar, true);
    faceIdUnlock(ch).then(async ({ action, vmk, data, inbox_setup }) => {
      // The policy is bound into the ciphertext, so an edit always re-encrypts.
      const v = newValue || await vc.openSecret(vmk, data.secret.meta_json, data.secret.box);
      const box = await vc.sealSecret(vmk, metaJson, v);
      await api("POST", "/api/add", { action, meta_json: metaJson, box, overwrite, inbox_setup });
      value.value = "";
      doneScreen({ title: editName ? "Saved" : `Added ${n}`, text: "Claude can ask to use it within this policy." });
    }).catch((e) => {
      busy(bar, false);
      if (e.status === 409 && !editName) {
        overwrite = true;
        setMsg(msg, `${n} already exists. Tap again to replace it.`);
        save.textContent = `Replace ${n} with Face ID`;
      } else setMsg(msg, errorText(e));
      prepare();
    });
  });
}

function deleteSection(name, msg) {
  const box = h("section", { class: "field" });
  const start = h("button", { class: "danger wide" }, "Delete secret");
  fill(box, start);
  start.addEventListener("click", async () => {
    let ch;
    try { ch = await api("POST", "/api/challenge", { kind: "delete", ref: name }); } catch (e) { return setMsg(msg, errorText(e)); }
    const saveBar = document.querySelector(".decide");
    saveBar?.classList.add("hidden");
    fill(box, h("div", { class: "notice" }, h("div", {}, h("strong", {}, `Delete ${name}?`), " This can't be undone, and anything that uses it stops working."),
      h("button", { class: "danger solid wide", onclick: () => {
        faceIdUnlock(ch)
          .then(({ action, inbox_setup }) => api("POST", "/api/delete", { action, name, inbox_setup }))
          .then(() => doneScreen({ ok: false, title: "Deleted", text: `${name} is gone from the vault.` }))
          .catch((e) => setMsg(msg, errorText(e)));
      } }, "Delete with Face ID"),
      h("button", { class: "text", onclick: () => { saveBar?.classList.remove("hidden"); fill(box, start); } }, "Keep it")));
  });
  return box;
}

// ------------------------------------------------------------------ enrollment

async function enrollView() {
  const token = new URLSearchParams(location.hash.slice(1)).get("token");
  history.replaceState(null, "", "/enroll");  // keep the token out of history and screenshots
  setNav(brandLink(), null);
  const msg = msgEl();
  const steps = h("ol", { class: "steps" });
  const action = h("div", { class: "field" });
  const title = h("h1", {}, "Set up the vault");
  const intro = h("p", { class: "muted" }, "Your passkey becomes the key to the vault. Whenever Claude needs a secret, you approve it here with Face ID.");
  render(h("header", {}, title), intro, steps, msg, action);
  if (!token) return setMsg(msg, "This link is missing its setup code. Scan the QR code the installer shows on the Mac.");

  let begin, created, recoveryBytes;
  try { begin = await api("POST", "/api/enroll/begin", { token }); }
  catch (e) { return setMsg(msg, errorText(e)); }
  const recover = begin.mode === "recover";
  const labels = recover ? ["Enter recovery code", "Create new passkey", "Unlock with Face ID"] : ["Create passkey", "Unlock with Face ID", "Save recovery code"];
  const showStep = (i) => fill(steps, labels.map((l, j) => h("li", { "data-n": j + 1, class: j < i ? "did" : j === i ? "now" : "" }, l)));

  if (recover) {
    title.textContent = "Replace the passkey";
    intro.textContent = "Use your recovery code. The old passkey stops working once the new one is set up.";
    showStep(0);
    const code = h("input", { type: "text", id: "recovery", class: "mono", autocomplete: "off", autocapitalize: "characters", spellcheck: "false", placeholder: "XXXX-XXXX-XXXX-…" });
    fill(action, h("label", { for: "recovery", class: "field-label" }, "Recovery code"), code,
      h("button", { class: "primary wide", onclick: () => {
        try { recoveryBytes = vc.decodeRecoveryCode(code.value); } catch (e) { return setMsg(msg, errorText(e)); }
        vc.kekFromRecovery(recoveryBytes).then((k) => vc.unwrapVmkRaw(k, begin.recovery_wrap)).then((raw) => {
          raw.fill(0);
          setMsg(msg, "", "ok");
          showStep(1);
          fill(action, h("button", { class: "primary wide", onclick: createPasskey }, "Create new passkey"));
        }).catch(() => setMsg(msg, "That recovery code does not open this vault."));
      } }, "Continue"));
  } else {
    showStep(0);
    fill(action, h("button", { class: "primary wide", onclick: createPasskey }, "Create passkey"));
  }

  function createPasskey() {
    setMsg(msg, "", "ok");
    const short = begin.rp_id.split(".")[0];
    navigator.credentials.create({
      publicKey: {
        rp: { id: begin.rp_id, name: "assentd" },
        user: { id: vc.unb64u(begin.user_id), name: `assentd@${short}`, displayName: `assentd (${short})` },
        challenge: vc.unb64u(begin.create.challenge),
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "required" },
        attestation: "none",
        timeout: 120000,
        extensions: { prf: {} },
      },
    }).then((cred) => {
      const prf = cred.getClientExtensionResults().prf;
      if (!prf || prf.enabled === false) throw new Error("This passkey provider does not support WebAuthn PRF. Use iCloud Keychain on iOS 18+.");
      created = cred;
      showStep(recover ? 2 : 1);
      fill(action, h("button", { class: "primary wide", onclick: unlock }, "Unlock with Face ID"));
    }).catch((e) => setMsg(msg, errorText(e)));
  }

  function unlock() {
    setMsg(msg, "", "ok");
    navigator.credentials.get({
      publicKey: {
        challenge: vc.unb64u(begin.get.challenge), rpId: begin.rp_id,
        allowCredentials: [{ type: "public-key", id: created.rawId }],
        userVerification: "required", timeout: 120000,
        extensions: { prf: { eval: { first: vc.PRF_SALT } } },
      },
    }).then(async (cred) => {
      const prf = cred.getClientExtensionResults().prf?.results?.first;
      if (!prf) throw new Error("The passkey did not return a PRF secret. Use iCloud Keychain on iOS 18+.");
      const body = {
        token, create_challenge_id: begin.create.challenge_id, get_challenge_id: begin.get.challenge_id,
        attestationObject: vc.b64u(created.response.attestationObject),
        clientDataJSON: vc.b64u(created.response.clientDataJSON),
        assertion: serializeAssertion(cred), label: "iPhone",
      };
      let recovery = null;
      let vmk;
      if (recover) {
        vmk = await vc.unwrapVmkRaw(await vc.kekFromRecovery(recoveryBytes), begin.recovery_wrap);
        recoveryBytes.fill(0);
      } else {
        vmk = vc.newVmkBytes();
        recovery = vc.newRecoveryCode();
        body.recovery_wrap = await vc.wrapVmk(await vc.kekFromRecovery(recovery.bytes), vmk);
        body.recovery_key = await vc.newRecoveryKey(vmk);
        recovery.bytes.fill(0);
      }
      body.vmk_wrap = await vc.wrapVmk(await vc.kekFromPrf(prf), vmk);
      if (recover) {
        // Proves to the daemon that this new passkey's key wrap came from someone who opened the vault key.
        const message = await vc.reenrollMessage(vc.unb64u(begin.get.challenge), new Uint8Array(cred.rawId), body.vmk_wrap);
        body.recovery_sig = await vc.signReenroll(vmk, begin.recovery_key_box, message);
      }
      vmk.fill(0);
      await api("POST", "/api/enroll/finish", body);
      if (recovery) { showStep(2); showRecovery(recovery.text); }
      else doneScreen({ title: "Passkey replaced", text: "The vault now answers only to this passkey. Your recovery code is unchanged." });
    }).catch((e) => setMsg(msg, errorText(e)));
  }

  function showRecovery(code) {
    title.textContent = "Save your recovery code";
    intro.textContent = "If you lose this passkey, this code is the only way back into the vault. It is shown once.";
    // No Copy button: the clipboard syncs to your other devices, where other software can read it.
    fill(action,
      h("div", { class: "notice" },
        h("div", {}, h("strong", {}, "Type it into your password manager now. "), "With the vault's data file it opens every secret. Keep a copy outside your Apple account too."),
        h("div", { class: "code-grid sensitive", id: "code" }, code.split("-").map((g) => h("span", {}, g)))),
      h("a", { href: "/", class: "button primary wide" }, "I've saved it"));
  }
}

// ------------------------------------------------------------------ routing

const path = location.pathname;
let m;
if (path === "/enroll") enrollView();
else if (path === "/activity") activityView();
else if (path === "/settings") settingsView();
else if (path === "/add") secretFormView(null);
else if ((m = path.match(/^\/edit\/([A-Z][A-Z0-9_]*)$/))) secretFormView(m[1]);
else if ((m = path.match(/^\/r\/([A-Za-z0-9_-]+)$/))) requestView(m[1]);
else if ((m = path.match(/^\/d\/([A-Za-z0-9_-]+)$/))) depositView(m[1]);
else {
  homeView();
  // Refresh for new requests, unless the person is typing, scrolled down, or mid-way through a flow.
  setInterval(() => {
    if (document.visibilityState === "visible" && !document.activeElement?.matches("input, textarea")
        && window.scrollY < 40 && !document.querySelector("[data-busy]")) homeView();
  }, 10000);
}

// Blur revealed values and the recovery code while the app is in the background, so they aren't
// in the iOS app switcher's snapshot.
document.addEventListener("visibilitychange", () => {
  document.body.classList.toggle("backgrounded", document.visibilityState === "hidden");
});

document.addEventListener("input", (e) => {
  if (e.target.matches?.("textarea.grow")) { e.target.style.height = "auto"; e.target.style.height = `${e.target.scrollHeight + 2}px`; }
});

// Lets notifications open the right page; it never caches anything (see sw.js).
if ("serviceWorker" in navigator) navigator.serviceWorker.register("/sw.js").catch(() => {});
