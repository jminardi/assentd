#!/bin/bash
# Remove assentd:  sudo ./uninstall.sh
# Stops the service and removes the code, logs, socket, tailnet node state and service user. The
# vault itself (/var/db/assentd: encrypted secrets, config, audit log) is only removed if you type
# DELETE. Remove the "assentd" machine from your Tailscale admin console, and the assentd extension
# from chrome://extensions, yourself.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo: sudo $0" >&2; exit 1; }
export PATH=/usr/bin:/bin:/usr/sbin:/sbin

for label in org.assentd.daemon org.assentd.front; do   # .front: the pre-Go front end, if still there
  launchctl bootout "system/$label" 2>/dev/null || true
  rm -f "/Library/LaunchDaemons/$label.plist"
done
rm -rf /usr/local/libexec/assentd /usr/local/libexec/assentd-build /var/db/assentd-sock /var/db/assentd-run \
  /var/db/assentd-ts /usr/local/bin/assentd /usr/local/bin/assentd-admin /var/log/assentd.log /var/log/assentd-front.log \
  /Library/Google/Chrome/NativeMessagingHosts/org.assentd.fill.json
echo "service, code, tailnet node state and logs removed"

if [ -d /var/db/assentd ]; then
  read -r -p "Also destroy the vault in /var/db/assentd? Its secrets are gone for good. Type DELETE: " ans
  if [ "$ans" = DELETE ]; then rm -rf /var/db/assentd; echo "vault destroyed"; else echo "vault kept in /var/db/assentd"; fi
fi

if dscl . -read /Users/_assentd >/dev/null 2>&1 && [ ! -d /var/db/assentd ]; then
  dscl . -delete /Users/_assentd
  dscl . -delete /Groups/_assentd 2>/dev/null || true
  echo "removed the _assentd user"
fi
