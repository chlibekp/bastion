#!/bin/sh
# After removal: reload systemd's view of the units. The `bastion` user, /etc/bastion (on a
# plain remove) and /var/lib/bastion stay: they may hold the user's config, ACME account and
# certificates. `apt purge` removes the config files dpkg tracks.
set -e
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
