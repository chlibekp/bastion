#!/usr/bin/env bash
# Forces the all-URLs-fail path of scripts/vm-run.sh and checks the message and exit status.
# Run inside the dev container: ./dev tests/vm/check_pin_failure.sh
set -u
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
dl="$root/build/deps/vm-cache/dl"
deb=linux-image-6.1.0-50-arm64_6.1.176-1_arm64.deb
[ "$(uname -m)" = aarch64 ] || { echo "skip: arm64 pin only"; exit 0; }
keep=
[ -f "$dl/$deb" ] && { mv "$dl/$deb" "$dl/$deb.keep"; keep=1; }
out=$(KERNEL=floor VM_POOL_URL=http://127.0.0.1:1/p VM_SNAP_URL=http://127.0.0.1:1/s "$root/scripts/vm-run.sh" true 2>&1)
rc=$?
[ -n "$keep" ] && mv "$dl/$deb.keep" "$dl/$deb"
fail() { echo "FAIL: $1"; echo "$out"; exit 1; }
[ "$rc" -ne 0 ] || fail "expected non-zero exit"
for want in "KERNEL=floor" "http://127.0.0.1:1/p/" "http://127.0.0.1:1/s/" "bump it"; do
	case "$out" in *"$want"*) ;; *) fail "message lacks '$want'" ;; esac
done
echo "ok: exit $rc with actionable message"
