// assentd fill: the Chrome side of `assentd fill NAME`.
//
// Chrome starts the root-owned native host (assentd-chrome-host), which relays between this
// worker and the daemon. Messages (JSON, one per native-messaging frame):
//   ← {type:"status", paired, pending?, error?}
//                                             after hello, and whenever pairing changes
//   → {type:"pair"}                           ask the phone to pair this key again (popup opened)
//   → {type:"hello", version, pub}            on connect; pub = this extension's P-256 key (raw, base64url)
//   ← {type:"prove", id, eph, iv, ct}         a nonce sealed to pub: only the holder of the key opens it
//   → {type:"proof", nonce}                   the opened nonce; until then the daemon ignores this key
//   ← {type:"tab", id, tabId?}                which tab would be filled? (tabId: that one, else the active tab)
//   → {type:"tab", id, tabId, url, title}     as Chrome reports them
//   ← {type:"fill", id, tabId, origin, eph, iv, ct}
//                                             the value, sealed to pub (fillcrypto.js)
//   → {type:"filled", id, ok, error?}
// The daemon only sends a fill after Face ID, and only to a key you paired on the phone. The value
// never goes through the CLI or the agent; this worker checks the tab's origin again before filling.

import { b64u, fingerprint, openFill, openProof } from "./fillcrypto.js";

const HOST = "org.assentd.fill";
const VERSION = chrome.runtime.getManifest().version;

function idb() {
  return new Promise((resolve, reject) => {
    const r = indexedDB.open("assentd", 1);
    r.onupgradeneeded = () => r.result.createObjectStore("keys");
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

async function idbGet(k) {
  const db = await idb();
  return new Promise((resolve, reject) => {
    const r = db.transaction("keys").objectStore("keys").get(k);
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

async function idbAdd(k, v) {
  const db = await idb();
  return new Promise((resolve, reject) => {
    const t = db.transaction("keys", "readwrite");
    t.objectStore("keys").add(v, k); // add, not put: never replace a key that already exists
    t.oncomplete = () => resolve();
    t.onerror = () => reject(t.error);
  });
}

// The private key is non-extractable: page scripts and other extensions can't read it, and this
// worker can only use it to open values sealed to it.
let keyPromise = null;
function key() {
  keyPromise ??= (async () => {
    let k = await idbGet("ecdh");
    if (!k) {
      const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
      try {
        await idbAdd("ecdh", { priv: pair.privateKey, pub: await crypto.subtle.exportKey("raw", pair.publicKey) });
      } catch { /* another wake-up stored one first */ }
      k = await idbGet("ecdh");
    }
    return k;
  })();
  return keyPromise;
}

// Runs in the page's isolated world, in one go: nothing can navigate the page in the middle. It
// checks the page's own origin, because the tab can navigate between the worker's check and this
// script running, and the value must never land on another site.
function fillField(value, origin) {
  if (window.top !== window || location.origin !== origin) return { ok: false, error: "the tab is no longer on " + origin };
  const visible = (el) => el.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true }) && !el.disabled && !el.readOnly;
  let el = document.activeElement;
  if (!(el instanceof HTMLInputElement && el.type === "password" && visible(el))) {
    const all = [...document.querySelectorAll('input[type="password"]')].filter(visible);
    if (all.length !== 1) return { ok: false, error: all.length ? "more than one password field; click the right one first" : "no password field on the page" };
    el = all[0];
  }
  el.focus();
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set.call(el, value);
  el.dispatchEvent(new Event("input", { bubbles: true }));
  el.dispatchEvent(new Event("change", { bubbles: true }));
  return { ok: true };
}

async function findTab(tabId) {
  if (Number.isInteger(tabId)) return chrome.tabs.get(tabId).catch(() => null);
  const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true, windowType: "normal" });
  return tab ?? null;
}

async function onFill(m) {
  const { priv } = await key();
  const tab = await chrome.tabs.get(m.tabId).catch(() => null);
  // The tab may have navigated since it was shown on the phone.
  if (!tab?.url || new URL(tab.url).origin !== m.origin) return { ok: false, error: "the tab is no longer on " + m.origin };
  let value = await openFill(priv, m);
  try {
    const [res] = await chrome.scripting.executeScript({ target: { tabId: m.tabId, frameIds: [0] }, func: fillField, args: [value, m.origin] });
    return res?.result ?? { ok: false, error: "the page didn't answer" };
  } finally {
    value = null;
  }
}

let port = null;
let status = "connecting";

async function handle(m) {
  if (m.type === "tab") {
    const tab = await findTab(m.tabId);
    port?.postMessage({ type: "tab", id: m.id, tabId: tab?.id ?? null, url: tab?.url ?? "", title: tab?.title ?? "" });
  } else if (m.type === "fill") {
    let res;
    try { res = await onFill(m); } catch (e) { res = { ok: false, error: String(e?.message || e).slice(0, 200) }; }
    port?.postMessage({ type: "filled", id: m.id, ...res });
  } else if (m.type === "prove") {
    const { priv } = await key();
    port?.postMessage({ type: "proof", nonce: await openProof(priv, m) });
  } else if (m.type === "status") {
    status = m.error ? `assentd refused: ${m.error}` : m.paired ? "paired"
      : m.pending ? "waiting for you to pair it on your phone" : "not paired";
  }
}

async function connect() {
  if (port) return;
  try {
    port = chrome.runtime.connectNative(HOST);
  } catch {
    status = "assentd isn't installed";
    return;
  }
  status = "connected";
  port.onMessage.addListener((m) => { handle(m).catch(() => {}); });
  port.onDisconnect.addListener(() => {
    const err = chrome.runtime.lastError?.message || "";
    if (!status.startsWith("assentd refused")) status = /not found/i.test(err) ? "assentd isn't installed" : "disconnected";
    port = null;
  });
  const { pub } = await key();
  port?.postMessage({ type: "hello", version: VERSION, pub: b64u(pub) });
}

// An open native port keeps the worker alive; the alarm reconnects after the daemon restarts.
chrome.runtime.onStartup.addListener(connect);
chrome.runtime.onInstalled.addListener(connect);
chrome.alarms.create("reconnect", { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener(connect);
connect();

chrome.runtime.onMessage.addListener((m, sender, reply) => {
  if (sender.id !== chrome.runtime.id || m?.type !== "popup") return;
  (async () => {
    const { pub } = await key();
    if (!port) connect();
    // Opening the popup is how you ask to pair again, e.g. after removing the key on the phone.
    else if (status === "not paired") {
      port.postMessage({ type: "pair" });
      status = "waiting for you to pair it on your phone";
    }
    reply({ status, fingerprint: await fingerprint(pub) });
  })();
  return true;
});
