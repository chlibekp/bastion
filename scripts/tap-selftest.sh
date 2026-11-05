#!/usr/bin/env bash
# Checks the TAP harness itself. Usage: scripts/tap-selftest.sh <outdir> <smoke-binary>
# Needs CC, CFLAGS and LDFLAGS in the environment (the Makefile exports them).
set -euo pipefail
out=$1 smoke=$2
mkdir -p "$out"
build() { # name
	# shellcheck disable=SC2086
	$CC $CFLAGS -Itests/unit $LDFLAGS -o "$out/$1" "tests/fixtures/$1.c"
}

# 1. A failing test makes the binary exit 1.
rc=0
TAP_SELFTEST_FAIL=1 "$smoke" >"$out/fail.out" || rc=$?
[ "$rc" -eq 1 ] || { echo "tap-selftest: failing test exited $rc, want 1" >&2; exit 1; }
grep -q '^not ok .* selftest_forced_failure' "$out/fail.out"

# 2. No tests registered is a failure.
printf '#include "tap.h"\nTAP_MAIN()\n' >"$out/tap_empty.c"
# shellcheck disable=SC2086
$CC $CFLAGS -Itests/unit $LDFLAGS -o "$out/tap_empty" "$out/tap_empty.c"
rc=0
"$out/tap_empty" 2>/dev/null || rc=$?
[ "$rc" -eq 1 ] || { echo "tap-selftest: empty binary exited $rc, want 1" >&2; exit 1; }

# 3. Registering past capacity aborts with a message.
build tap_overflow
# The subshell takes the shell's "Aborted" notice with it.
(
	rc=0
	"$out/tap_overflow" 2>"$out/overflow.err" || rc=$?
	echo "$rc" >"$out/overflow.rc"
) 2>/dev/null
rc=$(cat "$out/overflow.rc")
[ "$rc" -ne 0 ] && grep -q 'too many tests' "$out/overflow.err" ||
	{ echo "tap-selftest: overflow not reported (rc=$rc)" >&2; exit 1; }

# 4. A child that returns from a test is killed and prints no TAP lines.
build tap_fork
rc=0
"$out/tap_fork" >"$out/fork.out" 2>"$out/fork.err" || rc=$?
[ "$rc" -eq 0 ] || { echo "tap-selftest: fork case rc=$rc" >&2; cat "$out/fork.out" >&2; exit 1; }
[ "$(grep -c '^ok 1 - first' "$out/fork.out")" -eq 1 ] && [ "$(grep -c '^1\.\.2' "$out/fork.out")" -eq 1 ] ||
	{ echo "tap-selftest: duplicated TAP lines" >&2; cat "$out/fork.out" >&2; exit 1; }
grep -q 'forked child returned' "$out/fork.err"
echo "tap-selftest: ok"
