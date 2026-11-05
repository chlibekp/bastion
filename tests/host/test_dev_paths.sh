#!/usr/bin/env bash
# Host-side checks of ./dev and of build staleness. Needs the docker CLI, so it cannot run
# inside the test container. Uses fixed scratch paths so the per-tree Docker volumes that
# ./dev names after the path are reused between runs instead of piling up.
#
#   1. ./dev works from a copy of the tree in a path containing a space.
#   2. Changing a -D flag recompiles; the same flags do not.
#   3. A second tree whose sources are older than another tree's objects builds its own
#      code (build output is per tree).
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
scratch=${TMPDIR:-/tmp}/bastion-host-test
scratch=${scratch//\/\//\/}
rm -rf "$scratch"
mkdir -p "$scratch"
trap 'rm -rf "$scratch"' EXIT

copy_tree() { # dest
	mkdir -p "$1"
	(cd "$root" && tar --exclude=./.git --exclude=./build --exclude=./.superpowers -cf - .) | tar -xf - -C "$1"
}

# 1. Path with spaces.
a="$scratch/path with space/bastion tree"
copy_tree "$a"
out=$("$a/dev" sh -c 'pwd && test -x ./dev && test -f Makefile && echo mounted-ok')
echo "$out"
case "$out" in *mounted-ok) echo "PASS: ./dev works from a path with spaces" ;; *) echo "FAIL: mount" >&2; exit 1 ;; esac

# 2. Flag changes recompile.
obj=build/debug/obj/src/core/buf.o
first=$("$a/dev" make "$obj")
case "$first" in *"-c -o $obj"*) ;; *) echo "FAIL: first build did not compile" >&2; exit 1 ;; esac
same=$("$a/dev" make "$obj")
case "$same" in *"-c -o"*) echo "FAIL: unchanged flags recompiled" >&2; exit 1 ;; esac
changed=$("$a/dev" make "$obj" EXTRA_CFLAGS=-DBST_STALE_PROBE=1)
case "$changed" in *"-DBST_STALE_PROBE=1"*"-c -o $obj"*) echo "PASS: changing -D recompiles, same flags do not" ;;
	*) echo "FAIL: -D change did not recompile" >&2; echo "$changed" >&2; exit 1 ;; esac

# 3. A second tree with older sources builds its own code. Tree b differs only in VERSION
# and its Makefile and sources are older than everything tree a has built.
"$a/dev" make build/debug/bastion >/dev/null
b="$scratch/second tree"
copy_tree "$b"
sed -i.bak 's/^VERSION := .*/VERSION := 9.9.9/' "$b/Makefile"
rm "$b/Makefile.bak"
find "$b" -type f -exec touch -t 200001010000 {} +
va=$("$a/dev" build/debug/bastion --version)
vb=$("$b/dev" sh -c 'make build/debug/bastion >/dev/null && build/debug/bastion --version')
echo "tree a: $va, tree b: $vb"
case "$vb" in *9.9.9*) echo "PASS: an older tree builds its own code" ;; *) echo "FAIL: tree b ran stale objects" >&2; exit 1 ;; esac
case "$va" in *9.9.9*) echo "FAIL: trees share objects" >&2; exit 1 ;; esac
