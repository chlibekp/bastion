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

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload || true
fi
exit 0
