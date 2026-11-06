#!/usr/bin/env bash
# Fails unless a binary carries mimalloc and malloc itself resolves to it: usage
# check-mimalloc-linked.sh BIN. Run on build/release/bastion by make check-release. mimalloc's
# override makes malloc an alias of mi_malloc, so the two symbols share an address.
set -eu
bin=${1:?usage: check-mimalloc-linked.sh BIN}
syms=$(nm "$bin")
addr() { awk -v s="$1" '$3 == s { print $1; exit }' <<<"$syms"; }
mi=$(addr mi_malloc)
libc=$(addr malloc)
if [ -z "$mi" ]; then
	echo "check-mimalloc-linked: $bin has no mi_malloc" >&2
	exit 1
fi
if [ "$mi" != "$libc" ]; then
	echo "check-mimalloc-linked: malloc (${libc:-absent}) is not mi_malloc ($mi)" >&2
	exit 1
fi
echo "check-mimalloc-linked: malloc is mi_malloc at 0x$mi"
