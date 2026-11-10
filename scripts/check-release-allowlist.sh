#!/usr/bin/env bash
# Reads a release build's allowlist on stdin and fails on anything only a sanitizer build may have,
# or anything no build may. A row kept for a sanitizer must never reach the shipped binary.
set -euo pipefail

list=$(sort -u)
n=$(grep -c . <<<"$list")
[ "$n" -ge 20 ] || { echo "check-release: the allowlist has only $n names" >&2; exit 1; }
for name in openat open newfstatat stat lstat access faccessat ioctl prctl clone fork vfork execve \
	execveat ptrace bpf mount memfd_create io_uring_setup seccomp kill; do
	if grep -qx "$name" <<<"$list"; then
		echo "check-release: $name is on the release allowlist" >&2
		exit 1
	fi
done
echo "check-release: release allowlist clean ($n names)"
