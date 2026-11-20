#!/bin/sh
# Stops the service before its files go, on removal only: an upgrade (.deb: "upgrade";
# .rpm: $1 = 1) leaves the running server alone.
set -e
case "${1:-}" in
	upgrade|1) exit 0 ;;
esac
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
	systemctl disable --now bastion.service >/dev/null 2>&1 || true
fi
exit 0
