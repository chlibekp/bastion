#!/bin/sh
# Runs after install and after every upgrade (.deb: configure; .rpm: %post with $1 = 1 or 2).
# Creates the unprivileged `bastion` user the default config drops workers to, hands it the
# config directory read-only, and tells systemd about the unit. It never starts or restarts the
# server: an upgrade takes effect on `systemctl reload bastion` (same-PID re-exec) or a restart.
set -e

if ! getent group bastion >/dev/null 2>&1; then
	groupadd --system bastion 2>/dev/null || addgroup --system bastion
fi
if ! getent passwd bastion >/dev/null 2>&1; then
	nologin=/usr/sbin/nologin
	[ -x "$nologin" ] || nologin=/sbin/nologin
	useradd --system --gid bastion --home-dir /nonexistent --no-create-home \
		--shell "$nologin" --comment "Bastion web server" bastion 2>/dev/null \
		|| adduser --system --ingroup bastion --home /nonexistent --no-create-home \
			--shell "$nologin" --gecos "Bastion web server" bastion
fi

# Master reads the config as root; group read lets `bastion -t` run as the service user too.
chown root:bastion /etc/bastion /etc/bastion/bastion.conf
chmod 0750 /etc/bastion
chmod 0640 /etc/bastion/bastion.conf

# The unit's StateDirectory=, CacheDirectory= and LogsDirectory= make these only when systemd
# starts the service. Made here too, with the same owner and mode, so that `bastion -t` before
# the first start (it creates the ACME storage below /var/lib/bastion) and a start without
# systemd work on a fresh install. Existing directories are left as they are.
for d in /var/lib/bastion /var/cache/bastion /var/log/bastion; do
	[ -d "$d" ] || install -d -m 0750 -o root -g root "$d"
done

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload || true
fi
exit 0
