#!/usr/bin/env bash
# scripts/check-directives-linked.sh must fail on a binary with too few directive tables
# (or none), and pass with enough; the same for post-hook registrations (the "bst_cfg_post"
# section, third argument). Builds tiny ELF binaries carrying N table and M hook pointers.
set -eu
cd "$(dirname "$0")/../.."
CC=${CC:-clang}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mk() { # name ntables [nhooks]
	{
		echo 'int main(void){return 0;}'
		for i in $(seq 1 "$2"); do
			echo "static const void *const t$i __attribute__((used, section(\"bst_directives\"))) = 0;"
		done
		for i in $(seq 1 "${3:-0}"); do
			echo "static const void *const h$i __attribute__((used, section(\"bst_cfg_post\"))) = 0;"
		done
	} >"$tmp/$1.c"
	"$CC" -o "$tmp/$1" "$tmp/$1.c"
}
mk two 2
mk none 0
chk=scripts/check-directives-linked.sh
$chk "$tmp/two" 2 >/dev/null || { echo "FAIL: 2 tables, min 2 should pass"; exit 1; }
if $chk "$tmp/two" 3 >/dev/null 2>&1; then echo "FAIL: 2 tables, min 3 should fail"; exit 1; fi
if $chk "$tmp/none" 1 >/dev/null 2>&1; then echo "FAIL: no section should fail"; exit 1; fi
# Hooks: a release binary that lost them fails, one that has enough passes.
mk hooks 2 3
mk nohooks 2 0
$chk "$tmp/hooks" 2 3 >/dev/null || { echo "FAIL: 3 hooks, min 3 should pass"; exit 1; }
if $chk "$tmp/hooks" 2 4 >/dev/null 2>&1; then echo "FAIL: 3 hooks, min 4 should fail"; exit 1; fi
if $chk "$tmp/nohooks" 2 1 >/dev/null 2>&1; then echo "FAIL: no hook section, min 1 should fail"; exit 1; fi
$chk "$tmp/nohooks" 2 0 >/dev/null || { echo "FAIL: min 0 hooks needs no section"; exit 1; }
$chk "$tmp/two" 2 >/dev/null || { echo "FAIL: hooks unchecked when no minimum is given"; exit 1; }
echo "test_linked_check: ok"
