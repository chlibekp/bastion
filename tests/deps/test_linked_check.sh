#!/usr/bin/env bash
# scripts/check-directives-linked.sh must fail on a binary with too few directive tables
# (or none), and pass with enough. Builds tiny ELF binaries carrying N table pointers.
set -eu
cd "$(dirname "$0")/../.."
CC=${CC:-clang}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mk() { # name ntables
	{
		echo 'int main(void){return 0;}'
		for i in $(seq 1 "$2"); do
			echo "static const void *const t$i __attribute__((used, section(\"bst_directives\"))) = 0;"
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
echo "test_linked_check: ok"
