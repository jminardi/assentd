# Using assentd (for coding agents)

Paste this into your CLAUDE.md / AGENTS.md so your agent uses the vault well.

- Secrets live in assentd. Before asking the user for a credential, run `assentd list` (names,
  policies, allowed hosts; never values). Never ask the user to paste a secret into the chat.
- For API calls, prefer `http` mode: the vault sends the request and the key never reaches you.
  `assentd http --secret NAME --reason "why" [-X POST] [--json '{...}'] https://host/path`.
  The secret goes in the header its policy names; don't put it in the URL, body or `-H`.
- Use `assentd run --need NAME --reason "why" -- sh -c '... "$NAME" ...'` only when a command
  really needs the value. Reference it inside the child shell, as shown.
- To log in to a site in Chrome, never type a password yourself. Open the login page, click the
  password field, then run `assentd fill NAME --reason "why"` (the secret's policy must allow
  `fill` on that site). It prints only whether the fill worked; then click the sign-in button.
- Every use waits for the user to approve it with Face ID, for up to 5 minutes: give the Bash tool
  a timeout of at least 330000 ms, and don't retry while a request is pending.
- Write the reason for a person reading it on a phone: what you are doing and why, in one line.
  Don't dress it up and don't repeat what the screen already shows.
- A secret that doesn't exist yet: `assentd ask NAME --description "what it is" --reason "why"`
  (add `--hosts api.example.com` for an API key, or `--modes fill --fill-origin https://site` for a
  website password). The user types it on the phone.
- A secret you create (a new API key, a webhook URL, a generated password): put it straight into
  the vault without printing it. `some-command | assentd deposit NAME --json-field path.to.key
  --description D --reason R`, or `assentd generate NAME --description D --reason R` (for a new
  account's password, add `--modes fill --fill-origin https://site`, then `assentd fill` it into
  the sign-up form).
- Exit 77 means the user denied it: stop and ask what they want. 75: timed out or cancelled.
- If a secret's value ever reaches your context or output, say so, and recommend rotating it.
