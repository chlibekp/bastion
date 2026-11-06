#!/usr/bin/env bash
# Fails if a binary lost its registrations: usage check-directives-linked.sh BIN [MIN_TABLES
# [MIN_HOOKS]]. Directive tables are pointers in the "bst_directives" ELF section and post-apply
# config hooks are pointers in "bst_cfg_post"; a static link that dropped the objects holding
# them leaves the section short, empty or absent.
# MIN_TABLES defaults to 1. MIN_HOOKS defaults to 0: the hook section is checked only when a
# minimum is given (a binary may have no hooks). Run it on build/release/bastion.
set -eu
bin=${1:?usage: check-directives-linked.sh BIN [MIN_TABLES [MIN_HOOKS]]}
min=${2:-1}
minhooks=${3:-0}
sections=$(readelf -SW "$bin")

# Entries in a pointer section: its size in bytes over 8; empty when the section is absent.
entries() {
	local size
	size=$(awk -v s="$1" '{ for (i = 1; i <= NF; i++) if ($i == s) { print $(i + 4); exit } }' <<<"$sections")
	[ -n "$size" ] && echo $(( 0x$size / 8 ))
	return 0
}

tables=$(entries bst_directives)
if [ -z "$tables" ]; then
	echo "check-directives-linked: $bin has no bst_directives section" >&2
	exit 1
fi
if [ "$tables" -lt "$min" ]; then
	echo "check-directives-linked: $bin has $tables tables, expected at least $min" >&2
	exit 1
fi
hooks=$(entries bst_cfg_post)
if [ "$minhooks" -gt 0 ]; then
	if [ -z "$hooks" ]; then
		echo "check-directives-linked: $bin has no bst_cfg_post section" >&2
		exit 1
	fi
	if [ "$hooks" -lt "$minhooks" ]; then
		echo "check-directives-linked: $bin has $hooks post hooks, expected at least $minhooks" >&2
		exit 1
	fi
fi
echo "check-directives-linked: $bin has $tables directive tables and ${hooks:-0} post hooks"
