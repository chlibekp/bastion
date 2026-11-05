#!/usr/bin/env bash
# Fails if a binary has no registered directive tables: usage check-directives-linked.sh BIN
# [MIN_TABLES]. Directive tables are pointers in the "bst_directives" ELF section; a static
# link that dropped the objects holding them leaves the section empty or absent.
# MIN_TABLES defaults to 1. Run it on build/release/bastion once core directives register.
set -eu
bin=${1:?usage: check-directives-linked.sh BIN [MIN_TABLES]}
min=${2:-1}
size=$(readelf -SW "$bin" | awk '{ for (i = 1; i <= NF; i++) if ($i == "bst_directives") { print $(i + 4); exit } }')
if [ -z "$size" ]; then
	echo "check-directives-linked: $bin has no bst_directives section" >&2
	exit 1
fi
tables=$(( 0x$size / 8 ))
if [ "$tables" -lt "$min" ]; then
	echo "check-directives-linked: $bin has $tables tables, expected at least $min" >&2
	exit 1
fi
echo "check-directives-linked: $bin has $tables directive tables"
