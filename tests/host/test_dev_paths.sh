#!/usr/bin/env bash
# Host-side check: ./dev works from a copy of the tree in a path containing a space.
# Needs the docker CLI, so it cannot run inside the test container.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
dest="$tmp/path with space/bastion tree"
mkdir -p "$dest"
(cd "$root" && tar --exclude=./.git --exclude=./build --exclude=./.superpowers -cf - .) | tar -xf - -C "$dest"

out=$("$dest/dev" sh -c 'pwd && test -x ./dev && test -f Makefile && echo mounted-ok')
echo "$out"
case "$out" in *mounted-ok) echo "PASS: ./dev works from a path with spaces" ;; *) echo "FAIL" >&2; exit 1 ;; esac
