# assentd

Approve each use of a secret by your AI coding agent with Face ID on your iPhone.

assentd is a small secret broker for macOS. An agent (Claude Code, in practice) asks for an API
key by name, with a reason. Your phone shows exactly what will happen, and nothing happens until
you approve it with Face ID (or your passcode). For API keys, the daemon makes the HTTPS request
itself, so the key never reaches the agent or any other process on the Mac.

> **Status: a personal project, not audited.** I'm not a security engineer. The code was written
> largely with Claude, and reviewed by AI agents, not by a human security professional. Read the
> [threat model](#threat-model) before trusting it with anything that matters, and please report
> problems (see [SECURITY.md](SECURITY.md)).

Requirements: an Apple Silicon Mac, an iPhone on iOS 18+ with the passkey in iCloud Keychain, and
a [Tailscale](https://tailscale.com) tailnet with HTTPS certificates turned on. It is one Go
binary; the installer builds it with a checksum-pinned Go.

## How it works

```
 agent ──CLI──▶ daemon (_assentd user) ──Web Push──▶ iPhone ── Face ID ──┐
                  │  ▲                                                     │
                  │  └──────── tailnet (own tsnet node, HTTPS) ◀───────────┘
                  ▼
          api.example.com   (http mode: the daemon sends the request; the agent gets the reply, key blanked out)
```

- The daemon runs as its own macOS user, `_assentd`, from a root-owned binary. Other code running
  as your login user can't read its store, change its code or approve anything.
- Every secret is encrypted with a vault master key (VMK). The VMK exists only wrapped: by a key
  derived from your passkey's [WebAuthn PRF](https://w3c.github.io/webauthn/#prf-extension)
  output, and by a 256-bit recovery code. It is unwrapped only in the phone page, after Face ID.
  [docs/crypto.md](docs/crypto.md) has the formats.
- The daemon serves the phone page from its own Tailscale node (tsnet), which only `_assentd`
  controls. The passkey is bound to that hostname, so nothing else on the Mac can serve a page
  that asks for it.
- Approving sends the decrypted value from the phone to the daemon, which uses it once (or keeps
  it in memory for a 15-minute or 1-hour grant) and drops it.

## Install

```
git clone https://github.com/jminardi/assentd.git && cd assentd
env -i /bin/bash --noprofile --norc       # a clean shell; see "Installing" under Threat model
/usr/bin/sudo ./install.sh
```

The installer creates the `_assentd` user, builds and installs the binary root-owned, and starts
one launchd service. The first run also:
- prints a Tailscale login link for the new `assentd` machine (approve it, then turn off its key
  expiry in the admin console)
- asks for your tailnet login, the only one allowed to use the vault
- waits until the page has its HTTPS certificate, then shows a one-time enrollment QR code. Scan
  it with the iPhone, create the passkey, and type the recovery code into your password manager.

Then open the page in Safari, Share → Add to Home Screen, open it from there and turn on
notifications. Running the installer again upgrades in place and keeps the vault.
`sudo ./uninstall.sh` removes everything (the vault only if you confirm).

## Using it

Every command waits for your approval (5 minutes by default). Exit codes: 69 daemon unreachable,
75 timed out or cancelled, 77 denied. [AGENTS.md](AGENTS.md) is a snippet to give your agent.

| Mode | Example | Does the value reach the Mac? |
|---|---|---|
| `http` | `assentd http --secret STRIPE_KEY --reason R -X POST --data … https://api.stripe.com/v1/refunds` | **No.** The daemon sends the request and returns the reply with the value blanked out. |
| `command` | `assentd run --need DB_PW --reason R -- sh -c 'psql … "$DB_PW"'` | Yes, to that command, as `$DB_PW`. |
| `fill` | `assentd fill GITHUB_PW --reason R` | Into Chrome only: the assentd extension types it into the login page. Not to the agent. |

```
assentd list                 # names, policies and allowed hosts; never values
assentd status               # live grants and pending requests (names only)
assentd revoke --all         # end every grant now
```

**Policies.** Each secret has a policy you set on the phone: the modes it allows, the exact hosts
it may go to (`api.example.com`, `host:8443`), and the longest approval.

**`http` mode:**
- One secret per request. The requester only names it (`--secret NAME`); the policy says which
  header it goes in: `Authorization: Bearer {}`, `X-Api-Key: {}`, or `Authorization: Basic user:{}`.
  It never goes in the URL or the body.
- Policies can limit methods and path prefixes. With a path limit, `..`, `//` and any
  percent-encoding in the path are refused.
- The requester can't set `Host`, method-override, forwarding, framing or `Accept-Encoding`
  headers. Redirects are returned, not followed. The host must resolve to something other than
  loopback.
- Replies are scrubbed: the value raw, base64, URL- and JSON-encoded, hex, and any run of 8+ of its
  characters are replaced with `[assentd:NAME]`, in the body, the status line and the headers.
  `Set-Cookie` is dropped, compressed replies are withheld, and replies over 2 MB are cut. This
  catches a server echoing the key back. It can't stop misuse of the key's own authority during an
  approval: any allowed method and path on the allowed host.

**`command` mode.** Reference the secret inside the child shell (`sh -c '…$NAME…'`), not the
calling one. Output is scrubbed the same way, which catches accidents, not determined code.

**`fill` mode** puts a password into a login page in Chrome without it passing through the agent,
for agents that drive Chrome (Claude in Chrome, for example).
- Setup: the installer puts the extension in `/usr/local/libexec/assentd/extension` and registers
  its native messaging host. In Chrome open `chrome://extensions`, turn on Developer mode, choose
  Load unpacked and pick that folder. Open the extension's popup: it shows a key, and your phone
  asks to pair it (Home or Settings). Pair it, with Face ID, only if the phone shows the same key.
  After removing or ignoring a pairing, open the popup again to ask the phone again.
- Use: the agent opens the login page and clicks the password field, then runs `assentd fill NAME
  --reason R` (or `--tab ID` for a tab other than the active one). The extension tells the vault
  which site the tab is on, as Chrome reports it; the vault refuses unless it is one of the
  secret's sites (exact `https://` origins). Your phone shows the site; after Face ID the value is
  encrypted to the paired extension's key, the extension and then the page itself check the tab is
  still on that site, and it fills the focused (or only) password field. The agent gets "filled" or an error, never the value.
- A fill is always approved Once, and only the top frame of a page is filled.

**Approvals.** Once (the default), 15 min or 1 hr, capped by the secret's policy (fills are always
Once). A timed
approval is a grant for the requesting Claude session (its nearest `claude` ancestor process) and
that mode; anything the session runs can use it until it ends.

**New secrets.**
- `assentd ask NAME --description D --reason R` asks you to type the value on the phone, under
  a proposed policy you can change there. Using a secret that doesn't exist yet tells the agent to
  ask first.
- Deposits put a value into the vault that the agent never sees. The daemon seals it to the
  phone at once, and you accept or reject it there:
  - `assentd generate NAME` makes a random value (a password for a new account; with
    `--modes fill --fill-origin https://site`, `assentd fill` can then type it into the sign-up form).
  - `… | assentd deposit NAME --json-field a.b` takes one from a pipe (a newly created API key,
    straight from the API's reply).
  - With `--replace`, a new value for an existing secret keeps that secret's policy.
  - At most 10 deposits wait at once (5 per session). Rejecting needs no Face ID, and Home offers
    "Reject all" when several are waiting.

## The phone app

- **Request screen:** one line saying where the value goes (green: it stays in the vault; amber:
  it is released to a command or filled into a page; red: something is replaced, or another session is asking for the
  same secret), then the agent's reason, always shown as the agent's words, with line breaks and
  invisible characters made visible. **Details** shows the exact request and separates what the
  vault checked from what the agent merely reports.
- **Home** shows what's waiting, what's unlocked and the secrets. **Activity** is the audit log.
  **Settings** covers notifications, the devices allowed to open the vault, and paired Chrome
  extensions.
- Every change needs Face ID: adding, editing or deleting a secret, approving, accepting a
  deposit, allowing a device, adding a notification device, pairing a Chrome extension. Deny,
  reject, revoke and lock don't, because they only reduce access.
- If Tailscale gives an allowed device a new key (reinstalled, or the key expired), that device
  shows only "Confirm this device" until you confirm it with Face ID on it.

## Threat model

**Guards against:** other code running as your login user (npm/pip install scripts, editor
extensions, a prompt-injected agent's commands), and mistakes.
- That code can't read the store, approve anything, change the daemon, rewrite the audit log, or
  serve a page at the vault's hostname.
- It can *ask*, with any reason text. Every ask shows on the phone. Asks are rate-limited (30 a
  minute reach the phone), but it can still fill your phone with asks, or slow or restart the
  daemon: denial of service by code running as you is not something assentd tries to stop.
- It can receive what you release in `command` mode.
- It can't receive what you approve for `fill`: that goes, encrypted, to the paired extension.

**Doesn't protect:**
- **Released values.** Once a value is given to a command, that command, and anything else
  running as you during a grant, can use it.
- **Session scoping, against code running as you.** Grants are tied to a Claude process tree.
  Code running as you can start or replace a `claude` process, or run inside the session, so
  scoping prevents accidents, not attacks. Prefer **Once**, and `assentd revoke --all` before
  running untrusted code.
- **Installing.** Your login user is usually an admin, so code running as you could capture your
  password through a `sudo` alias and become root, or edit the checkout after you reviewed it.
  Install from a separate admin account if you can; at least from a clean shell with
  `/usr/bin/sudo`.
- **Filled passwords, once on the page.** The login page's own scripts can read a filled value, as
  with any password manager, and so can other extensions with access to that site. The site check
  relies on the extension being the real one: code running as you can, with effort, read the
  extension's key from Chrome's profile, or load a look-alike extension in its place, and then
  receive fills you approve (it can't approve them, and the phone still shows each one). An
  extension must prove it holds the key it names before it counts as that key. The
  daemon also only accepts the native messaging host as the installed, root-owned binary started
  by Google Chrome (checked by its code signature); a user-level host manifest (Chrome reads
  `~/Library/Application Support/Google/Chrome/NativeMessagingHosts` first) can't get past that,
  but those checks are defense in depth, not a boundary.
- **Root on the Mac,** and a compromised daemon: it serves the phone page, so it could take the
  vault key on your next Face ID. The crypto protects data at rest; the daemon is the runtime
  trust root.
- **Tailscale.** The vault's hostname and certificate come from Tailscale's control plane, and an
  admin of your tailnet can rename machines. Enable
  [Tailnet Lock](https://tailscale.com/kb/1226/tailnet-lock) so no new machine joins without
  your signature. Devices are allowed by Tailscale's stable node ID, node key and login.
- **Your Apple account.** The passkey syncs through iCloud Keychain. Someone who takes over the
  account (password, SMS code and a device passcode) gets the passkey. Use Stolen Device
  Protection and Advanced Data Protection, and keep the vault's backups (below) outside iCloud.
- **Lockout.** There are reports of passkey PRF outputs changing across OS updates and devices.
  An iPhone-made passkey gives a different PRF on a Mac (an Apple bug), so approve on the iPhone.
  The recovery code always works: keep a copy outside your Apple account and run `sudo
  assentd-admin recover-check` after iOS updates. `sudo assentd-admin reenroll` replaces the
  passkey: it needs the recovery code, proven with a signature only the vault key can make.
- **A lost phone.** Re-enrolling replaces the passkey, removes every allowed device and turns off
  notifications (they name secrets and reasons), but it doesn't change the vault key itself: the
  old passkey together with an old copy of `store.json` still opens what was in that copy. If the
  passkey may be in someone else's hands, also rotate the secrets that matter.

**Backups.** `/var/db/assentd/store.json` is encrypted, so ordinary system backups can hold it.
To restore, stop the daemon, copy the file back, and start it. Keep backups away from the
recovery code, and don't keep the only copy in the same Apple account as the passkey.

## Design notes

- `http` is the default for API keys because it's the only mode where the value never reaches
  a process on the Mac. Secret placement is policy, not request: a requester that could choose
  where the value goes could pick a header a server echoes back, or a URL or body a site stores.
- The phone page asks the daemon for ciphertext only after a Face ID assertion, and each unlock
  authorizes one action.
- `fill` replaced an older mode that typed into Chrome through AppleScript, which needed Chrome's
  "Allow JavaScript from Apple Events": a setting that lets any process running as you script every
  tab. The extension can only fill password fields, the site comes from Chrome rather than the
  agent, and the value never passes through a process the agent controls.
- The daemon builds what the phone shows from the exact host and path it will send, and sends
  those bytes unchanged. The phone never re-parses or decodes the URL.
- The crypto is standard primitives (AES-256-GCM, HKDF-SHA256, P-256 ECDH and ECDSA, WebAuthn),
  put together in a small format of our own; [docs/crypto.md](docs/crypto.md) describes it.
- Go's strings can't be reliably wiped. Released values live in the daemon's memory until
  garbage collection; reading that memory needs root or `_assentd`.

## Similar projects

- [Infisical Agent Vault](https://github.com/Infisical/agent-vault): a credential proxy for
  agents; approval is for configuration, not each use.
- [latchkey](https://github.com/imbue-ai/latchkey): injects credentials into curl for agents.
- 1Password's `op run` and agentic autofill.

assentd's differences: a human approves each use on a separate device, the Mac never holds a key
that decrypts the store, and agent-created secrets are sealed to the phone.

## Tests

```
go test ./...                                 # unit tests, phone JS crypto vs Go (needs node), a vault made by the old Python version
python3 -m venv .venv && .venv/bin/pip install -r tests/requirements.txt
.venv/bin/python tests/test_e2e.py            # the real binary (daemon + CLI), software passkey with PRF, fake push service
cd tests/ui && npm ci && npx playwright install chromium-headless-shell && node tour.mjs ./shots
                                              # every phone flow in headless Chrome, screenshots at iPhone size
cd tests/ui && npx playwright install chromium && node fill-extension.mjs
                                              # the real extension in Chromium: pairing and a fill into an https page
```

## License

MIT. See [LICENSE](LICENSE).
