#!/usr/bin/env bash
# Is the seccomp allowlist minimal? Removes each row of src/proc/seccomp_tables.c in turn, in a copy
# of this tree, and runs the integration tests that exercise workers until one fails. A row no test
# misses is reported. Phase 15 repeats this, once per libc:
#
#   ./dev scripts/seccomp-minimality.sh [BUILD=asan|debug|musltest] [ONLY=name,name] [OUT=file]
#
# Exit 0 when every row some test needs was needed, or is in SURVIVORS below with its reason. Rows
# with no number on this architecture cannot be run here and are listed as such (ruling N).
# The copy lives in build/, the tree is never touched. Results go to OUT as they come in.
set -uo pipefail

BUILD=asan ONLY= OUT=
for a in "$@"; do
	case "$a" in
	BUILD=*) BUILD=${a#BUILD=} ;;
	ONLY=*) ONLY=${a#ONLY=} ;;
	OUT=*) OUT=${a#OUT=} ;;
	*) echo "usage: $0 [BUILD=b] [ONLY=name,name] [OUT=file]" >&2; exit 2 ;;
	esac
done

# Rows no test on this host can fail for, and why that is acceptable. Keep this short.
declare -A SURVIVORS=(
	[clock_gettime]="vDSO serves it on this host; the syscall is the fallback on a clocksource without one"
)

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
arch=$(uname -m)
work=$root/build/minimality.$$
trap 'rm -rf "$work"' EXIT
mkdir -p "$work"
tar -C "$root" --exclude=./build --exclude=./.git --exclude=./.superpowers -cf - . | tar -C "$work" -xf -
mkdir "$work/build"
ln -s "$root/build/deps" "$work/build/deps"
cd "$work" || exit 1
cp src/proc/seccomp_tables.c "$work/tables.orig"

emit() {
	echo "$*"
	if [ -n "$OUT" ]; then echo "$*" >>"$OUT"; fi
}

fixture=build/$BUILD/fixtures/seccomp_no_uring
# A row's argument conditions go unused when the row goes.
build() {
	make -s -j"$(nproc)" BUILD="$BUILD" EXTRA_CFLAGS=-Wno-unused-const-variable \
		"build/$BUILD/bastion" "$fixture" >"$work/build.log" 2>&1
}

build || { cat "$work/build.log" >&2; exit 1; }

# name x86_64 aarch64 for each row, read from the table itself.
rows=$(python3 - "$work/tables.orig" <<'PY'
import re, sys
for m in re.finditer(r'(ROW|BST_SAN_ROW)\("(\w+)", (-?\d+), (-?\d+),', open(sys.argv[1]).read()):
    print(m.group(2), m.group(3), m.group(4), "san" if m.group(1) == "BST_SAN_ROW" else "all")
PY
)

remove_row() {
	python3 - "$work/tables.orig" src/proc/seccomp_tables.c "$1" <<'PY'
import re, sys
src, dst, name = sys.argv[1:]
text = open(src).read()
out, n = re.subn(r'\t(?:ROW|BST_SAN_ROW)\("%s",.*?\),\n(?=\t(?:ROW|BST_SAN_ROW|/\*)|#|\};)' % name,
                 '', text, count=1, flags=re.S)
assert n == 1, name
open(dst, "w").write(out)
PY
}

tests="tests/integration/test_process.py tests/integration/test_sandbox.py \
	tests/integration/test_process_security.py tests/integration/test_process_config.py"
env_vars=(BASTION_BUILD="$BUILD" BASTION_BIN="$work/build/$BUILD/bastion" SECCOMP_WRAP="$work/$fixture")

bad=0 needed=0 skipped=0 survived=0
while read -r name x a kind; do
	if [ -n "$ONLY" ] && ! [[ ",$ONLY," == *",$name,"* ]]; then continue; fi
	if [ "$kind" = san ] && [ "$BUILD" != asan ]; then continue; fi # not compiled in
	nr=$a
	[ "$arch" = x86_64 ] && nr=$x
	if [ "$nr" = -1 ]; then
		emit "n/a      $name: no number on $arch"
		skipped=$((skipped + 1))
		continue
	fi
	remove_row "$name" || exit 1
	if ! build; then
		cat "$work/build.log" >&2
		exit 1
	fi
	# shellcheck disable=SC2086
	if res=$(env "${env_vars[@]}" python3 -m pytest $tests -x -q --no-header -p no:cacheprovider \
		--tb=no 2>&1); then
		if [ -n "${SURVIVORS[$name]:-}" ]; then
			emit "survived $name: ${SURVIVORS[$name]}"
		else
			emit "SURVIVED $name: nothing failed without it"
			bad=$((bad + 1))
		fi
		survived=$((survived + 1))
	else
		emit "needed   $name: $(grep -m1 -E '^(FAILED|ERROR)' <<<"$res" | cut -c1-100)"
		needed=$((needed + 1))
	fi
done <<<"$rows"
emit "---- BUILD=$BUILD on $arch: $needed needed, $survived survived ($bad unexplained), $skipped not runnable here"
[ "$bad" = 0 ]
