#!/bin/bash
# Install or upgrade assentd:  sudo ./install.sh
#
# The binary is built from this checkout with a checksum-pinned Go, installed root-owned, and runs
# as _assentd, so nothing running as your login user can modify the code that guards the secrets.
# Upgrades always go through this script, under sudo, so review `git diff` before running it. An
# upgrade keeps the vault (/var/db/assentd) and the tailnet node: no re-enrollment.
#
# Your login user is the threat this design guards against, and on most Macs it is an admin: code
# running as you could alias `sudo` in your shell startup files, or edit this checkout after you
# reviewed it. The safest install is from a separate admin account, from a checkout that account
# owns. At least start from a clean shell:  env -i /bin/bash --noprofile --norc, then /usr/bin/sudo ./install.sh
#
# One service, org.assentd.daemon: the daemon, which also runs the tailnet node "assentd" (tsnet)
# that serves the phone page over HTTPS. Also installed: the assentd Chrome extension (load it
# unpacked from /usr/local/libexec/assentd/extension) and its native messaging host.
#
# Don't paste this script's output into an AI session: on first install it shows the enrollment link.
set -euo pipefail

[ "$(id -u)" = 0 ] || { echo "run with sudo: sudo $0" >&2; exit 1; }
# Start over with an empty environment, so nothing from the invoking shell (Go settings, HOME,
# PATH) can steer what runs as root.
if [ -z "${ASSENTD_INSTALL_CLEAN:-}" ]; then
  exec /usr/bin/env -i ASSENTD_INSTALL_CLEAN=1 SUDO_USER="${SUDO_USER:-}" HOME=/var/root \
    PATH=/usr/bin:/bin:/usr/sbin:/sbin TERM="${TERM:-dumb}" LANG=en_US.UTF-8 /bin/bash "$0" "$@"
fi
die() { echo "$*" >&2; exit 1; }
CLIENT_USER=${SUDO_USER:?run this via sudo from your own account}
CLIENT_UID=$(id -u "$CLIENT_USER")
[ "$(uname -m)" = arm64 ] || die "this installer pins an Apple Silicon (arm64) Go toolchain"

SRC="$(cd "$(dirname "$0")" && pwd -P)"
PREFIX=/usr/local/libexec/assentd
BUILD=/usr/local/libexec/assentd-build   # root-owned: pinned Go toolchain + build caches
DATA=/var/db/assentd                     # vault store, config, audit log
SOCKDIR=/var/db/assentd-sock             # CLI socket (peer-uid checked)
TSDIR=/var/db/assentd-ts                 # tsnet node state: _assentd only
LOG=/var/log/assentd.log
LABEL=org.assentd.daemon
SVC=_assentd
NODE_NAME=assentd
# Official Go release, pinned by checksum, so assentd is never built with a Go your user controls.
GO_VERSION=go1.24.13
GO_SHA256=f282d882c3353485e2fc6c634606d85caf36e855167d59b996dbeae19fa7629a
# Exactly what gets built. Anything else in the checkout (untracked files, stray modules) is ignored.
FILES="go.mod go.sum
  cmd/assentd/main.go cmd/assentd/daemon.go cmd/assentd/phone.go cmd/assentd/sock.go cmd/assentd/vault.go
  cmd/assentd/policy.go cmd/assentd/outbound.go cmd/assentd/scrub.go cmd/assentd/session.go cmd/assentd/cli.go
  cmd/assentd/admin.go cmd/assentd/vcrypto.go cmd/assentd/webauthn.go cmd/assentd/webpush.go
  cmd/assentd/fill.go cmd/assentd/chromehost.go
  web/embed.go web/index.html web/app.mjs web/vcrypto.mjs web/style.css web/sw.js web/manifest.webmanifest
  web/icon-32.png web/icon-180.png web/icon-192.png web/icon-512.png"
# The Chrome extension, installed as is (Chrome loads it from $PREFIX/extension).
EXT_FILES="extension/manifest.json extension/background.js extension/fillcrypto.js extension/popup.html
  extension/popup.js extension/icon-32.png extension/icon-128.png"
# Where Chrome looks for native messaging hosts machine-wide (root-owned).
NMH_DIR="/Library/Google/Chrome/NativeMessagingHosts"
EXT_ID=jcbnicpanjmggphgoonehlalfmjcfmmi

# Everything below is written as root into these directories. If any of them, or a directory
# above them, could be changed by another user (say /usr/local/bin left user-owned by an old
# Homebrew), code running as you could swap in its own assentd-admin and get root on the next sudo.
safe_dir() {  # $1: an absolute path; creates what's missing root-owned, refuses anything unsafe
  local want=$1 d real
  [ -d "$want" ] || install -d -m 755 -o root -g wheel "$want"
  real=$(cd -P "$want" && pwd -P)
  d=$real
  while :; do
    [ -d "$d" ] && [ ! -L "$d" ] || die "refusing to install: $d is not a plain directory"
    [ "$(stat -f %u "$d")" = 0 ] || die "refusing to install: $d is not owned by root (fix: sudo chown root:wheel $d)"
    (( 8#$(stat -f %Lp "$d") & 8#022 )) && die "refusing to install: $d is writable by others (fix: sudo chmod go-w $d)"
    [ "$d" = / ] && break
    d=$(dirname "$d")
  done
  return 0
}
NMH_DIR_CHECK="/Library/Google/Chrome/NativeMessagingHosts"
for dir in /usr/local/bin /usr/local/libexec /Library/LaunchDaemons "$NMH_DIR_CHECK" /var/db /var/log; do safe_dir "$dir"; done

echo "== service user"
if ! dscl . -read /Users/$SVC >/dev/null 2>&1; then
  used=$( (dscl . -list /Users UniqueID; dscl . -list /Groups PrimaryGroupID) | awk '{print $2}')
  ID=""
  for i in $(seq 450 499); do
    if ! grep -qx "$i" <<<"$used"; then ID=$i; break; fi
  done
  [ -n "$ID" ] || die "no free uid/gid in 450-499"
  dscl . -create /Groups/$SVC
  dscl . -create /Groups/$SVC PrimaryGroupID "$ID"
  dscl . -create /Groups/$SVC RealName "assentd daemon"
  dscl . -create /Groups/$SVC Password "*"
  dscl . -create /Users/$SVC
  dscl . -create /Users/$SVC UniqueID "$ID"
  dscl . -create /Users/$SVC PrimaryGroupID "$ID"
  dscl . -create /Users/$SVC UserShell /usr/bin/false
  dscl . -create /Users/$SVC NFSHomeDirectory /var/empty
  dscl . -create /Users/$SVC RealName "assentd daemon"
  dscl . -create /Users/$SVC Password "*"
  dscl . -create /Users/$SVC IsHidden 1
  echo "created $SVC (uid/gid $ID)"
else
  echo "$SVC exists"
fi

echo "== Go toolchain ($GO_VERSION, root-owned)"
GOROOT_DIR=$BUILD/$GO_VERSION/go
if [ ! -x "$GOROOT_DIR/bin/go" ]; then
  install -d -m 755 -o root -g wheel "$BUILD"
  tmp=$(mktemp "$BUILD/.go.XXXXXX")
  /usr/bin/curl -fsSL --max-time 600 -o "$tmp" "https://go.dev/dl/$GO_VERSION.darwin-arm64.tar.gz"
  if ! echo "$GO_SHA256  $tmp" | /usr/bin/shasum -a 256 -c - >/dev/null; then
    rm -f "$tmp"; die "Go download failed its checksum"
  fi
  rm -rf "${BUILD:?}/$GO_VERSION"; mkdir -p "$BUILD/$GO_VERSION"
  tar -xzf "$tmp" -C "$BUILD/$GO_VERSION"; rm -f "$tmp"
  chown -R root:wheel "$BUILD"; chmod -R go-w "$BUILD"
fi

echo "== build (root-owned)"
STAGE=$(mktemp -d /usr/local/libexec/.assentd.XXXXXX 2>/dev/null || { mkdir -p /usr/local/libexec; mktemp -d /usr/local/libexec/.assentd.XXXXXX; })
for f in $FILES; do
  mkdir -p "$STAGE/src/$(dirname "$f")"
  cp -P "$SRC/$f" "$STAGE/src/$f"   # -P: a symlink is copied as a link (and refused below), never followed as root
done
mkdir -p "$STAGE/extension" "$STAGE/bin"
for f in $EXT_FILES; do cp -P "$SRC/$f" "$STAGE/extension/"; done
chown -R root:wheel "$STAGE"
if [ -n "$(find "$STAGE" ! -type f ! -type d)" ]; then
  rm -rf "$STAGE"; die "refusing to install: the checkout has symlinks or special files where code should be"
fi
if grep -Eq '^[[:space:]]*replace([[:space:]]|\()' "$STAGE/src/go.mod"; then
  rm -rf "$STAGE"; die "refusing to build: go.mod has a replace directive"
fi
# Record what is installed (shown in the phone's Settings).
ver=$(sudo -H -u "$CLIENT_USER" /usr/bin/git -C "$SRC" rev-parse --short HEAD 2>/dev/null || echo unknown)
[ -n "$(sudo -H -u "$CLIENT_USER" /usr/bin/git -C "$SRC" status --porcelain 2>/dev/null)" ] && ver="$ver+local"
echo "building assentd $ver (the first build downloads modules, checked against go.sum)"
(cd "$STAGE/src" && env -i PATH=/usr/bin:/bin HOME="$BUILD/home" GOPATH="$BUILD/gopath" \
  GOCACHE="$BUILD/cache" GOMODCACHE="$BUILD/mod" GOTOOLCHAIN=local GOENV=off GOWORK=off GOFLAGS=-mod=readonly \
  CGO_ENABLED=0 "$GOROOT_DIR/bin/go" build -trimpath -ldflags "-X main.version=${ver// /_}" -o "$STAGE/assentd" ./cmd/assentd)
rm -rf "$STAGE/src"
# The native messaging host is the same binary under its own name (main.go dispatches on it).
cp "$STAGE/assentd" "$STAGE/bin/assentd-chrome-host"
chown -R root:wheel "$STAGE"; chmod 755 "$STAGE" "$STAGE/assentd" "$STAGE/bin" "$STAGE/bin/assentd-chrome-host" "$STAGE/extension"
chmod 644 "$STAGE"/extension/*
rm -rf "$PREFIX.old"
[ -d "$PREFIX" ] && mv "$PREFIX" "$PREFIX.old"
mv "$STAGE" "$PREFIX"
rm -rf "$PREFIX.old"   # also removes the Python version's code and venv

install -m 755 -o root -g wheel "$PREFIX/assentd" /usr/local/bin/assentd
cat > /usr/local/bin/assentd-admin <<EOF
#!/bin/sh
[ "\$(id -u)" = 0 ] || { echo "assentd-admin must run as root (sudo)" >&2; exit 1; }
exec $PREFIX/assentd admin "\$@"
EOF
chown root:wheel /usr/local/bin/assentd-admin
chmod 755 /usr/local/bin/assentd-admin

install -d -m 755 -o root -g wheel "$NMH_DIR"
cat > "$NMH_DIR/org.assentd.fill.json" <<EOF
{
  "name": "org.assentd.fill",
  "description": "assentd: fills passwords you approve with Face ID",
  "path": "$PREFIX/bin/assentd-chrome-host",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://$EXT_ID/"]
}
EOF
chown root:wheel "$NMH_DIR/org.assentd.fill.json"; chmod 644 "$NMH_DIR/org.assentd.fill.json"

# Before the Go version, a separate service served the page to a Python daemon.
if [ -f /Library/LaunchDaemons/org.assentd.front.plist ]; then
  launchctl bootout system/org.assentd.front 2>/dev/null || true
  rm -f /Library/LaunchDaemons/org.assentd.front.plist /var/log/assentd-front.log
  rm -rf /var/db/assentd-run
  echo "removed the old front-end service (the daemon serves the page itself now)"
fi

echo "== directories"
install -d -m 755 -o $SVC -g $SVC "$SOCKDIR"
install -d -m 700 -o $SVC -g $SVC "$TSDIR"
install -d -m 700 -o $SVC -g $SVC "$DATA"
touch "$LOG"; chown $SVC:$SVC "$LOG"; chmod 640 "$LOG"

echo "== daemon and tailnet node '$NODE_NAME'"
mark=$(wc -c < "$LOG" | tr -d ' ')
newlog() { tail -c +"$((mark + 1))" "$LOG"; }
launchctl bootout "system/$LABEL" 2>/dev/null || true
sleep 1
cat > "/Library/LaunchDaemons/$LABEL.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>UserName</key><string>$SVC</string>
  <key>GroupName</key><string>$SVC</string>
  <key>WorkingDirectory</key><string>/var/empty</string>
  <key>ProgramArguments</key><array><string>$PREFIX/assentd</string><string>daemon</string></array>
  <key>EnvironmentVariables</key><dict><key>HOME</key><string>/var/empty</string></dict>
  <key>Umask</key><integer>63</integer>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>5</integer>
  <key>StandardOutPath</key><string>$LOG</string>
  <key>StandardErrorPath</key><string>$LOG</string>
</dict>
</plist>
EOF
chown root:wheel "/Library/LaunchDaemons/$LABEL.plist"; chmod 644 "/Library/LaunchDaemons/$LABEL.plist"
launchctl bootstrap system "/Library/LaunchDaemons/$LABEL.plist"

shown=""
RP_ID=""
for _ in $(seq 1 900); do
  RP_ID=$(newlog | grep -o 'tailnet name https://[^ ]*' | tail -1 | sed 's#tailnet name https://##' || true)
  [ -n "$RP_ID" ] && break
  url=$(newlog | grep -o 'https://login\.tailscale\.com/a/[A-Za-z0-9]*' | tail -1 || true)
  if [ -n "$url" ] && [ "$url" != "$shown" ]; then
    echo "First run: approve the new '$NODE_NAME' machine in your browser (signed in to your tailnet):"
    echo "    $url"
    echo "Then, in the Tailscale admin console, open the machine and choose 'Disable key expiry'."
    shown=$url
  fi
  sleep 1
done
[ -n "$RP_ID" ] || { echo "the daemon did not join the tailnet; see $LOG" >&2; tail -20 "$LOG" >&2; exit 1; }
echo "page: https://$RP_ID"

echo "== vault data"
if [ -f "$DATA/config.json" ]; then
  old_rp=$(/usr/bin/plutil -extract rp_id raw -o - "$DATA/config.json")
  if [ "$old_rp" != "$RP_ID" ]; then
    echo "The existing vault is bound to $old_rp. Its passkey can be used by any page served at that"
    echo "name, which this install no longer controls, so it is retired, not migrated: you get a fresh"
    echo "vault (new key, new recovery code, new passkey) at $RP_ID."
    read -r -p "Type RETIRE to move the old vault aside: " ans
    if [ "$ans" != RETIRE ]; then
      launchctl bootout "system/$LABEL" 2>/dev/null || true
      die "aborted; nothing changed in $DATA (the daemon is stopped)"
    fi
    retired="$DATA.retired-$(date +%Y%m%d-%H%M%S)"
    mv "$DATA" "$retired"
    install -d -m 700 -o $SVC -g $SVC "$DATA"
    echo "old vault moved to $retired (delete it when you're satisfied)"
  fi
fi
if [ ! -f "$DATA/config.json" ]; then
  echo "Only one tailnet login may use the vault: the one signed in to Tailscale on your phone."
  read -r -p "Your tailnet login (e.g. you@example.com, or you@github): " login
  [ -n "$login" ] || die "a login is required"
  ASSENTD_DATA="$DATA" /usr/local/bin/assentd-admin init-config --rp-id "$RP_ID" --client-uid "$CLIENT_UID" --allowed-login "$login"
fi
# _assentd owns $DATA and could have put links in it: -h changes a link itself, never what it
# points at, so this can't be turned on a file elsewhere.
for f in "$DATA"/*; do
  [ -e "$f" ] || [ -L "$f" ] || continue
  [ -f "$f" ] && [ ! -L "$f" ] || echo "warning: $f is not a regular file; leaving it alone" >&2
  chown -h $SVC:$SVC "$f"; chmod -h 600 "$f"
done

# With the config in place the daemon gets the page's certificate before serving anything, so the
# phone's first visit isn't a long blank page.
echo "waiting for the page's HTTPS certificate (the first one can take a minute)"
for _ in $(seq 1 300); do
  newlog | grep -q "serving https://$RP_ID" && break
  sleep 1
done
newlog | grep -q "serving https://$RP_ID" || { echo "the page did not come up; see $LOG" >&2; tail -20 "$LOG" >&2; exit 1; }
if sudo -H -u "$CLIENT_USER" /usr/local/bin/assentd list >/dev/null 2>&1; then
  echo "daemon is up"
else
  echo "daemon did not answer; last log lines:" >&2; tail -20 "$LOG" >&2; exit 1
fi
# This Mac is usually on the tailnet too: check that the page answers before showing the link.
answered=""
for _ in $(seq 1 30); do
  code=$(/usr/bin/curl -s -o /dev/null -w '%{http_code}' --max-time 10 "https://$RP_ID/enroll" || true)
  case "$code" in 200|403) answered=1; break;; esac
  sleep 2
done
[ -n "$answered" ] && echo "the page answers at https://$RP_ID" \
  || echo "couldn't reach https://$RP_ID from this Mac (fine if this Mac isn't on the tailnet)"

if ! /usr/bin/plutil -extract creds.0 json -o - "$DATA/store.json" >/dev/null 2>&1; then
  echo
  echo "== enrollment"
  echo "Make sure Tailscale is connected on the phone."
  read -r -p "Press Enter to show the one-time enrollment link... " _
  /usr/local/bin/assentd-admin enroll-link
  echo "Show it again any time with: sudo assentd-admin enroll-link"
fi
echo
echo "Optional, to let Claude fill passwords in Chrome (assentd fill): in Chrome open chrome://extensions,"
echo "turn on Developer mode, Load unpacked, and choose $PREFIX/extension. Open its popup, then pair it"
echo "on your phone (Settings) after checking the key matches. Restart Chrome if it says assentd isn't installed."
echo "done"
