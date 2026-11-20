#!/usr/bin/env bash
# Release build, run on the host: scripts/build-release.sh <version> <amd64|arm64> [outdir]
#
# Builds in the release container (./dev, Alpine/musl) for <arch>, natively or under QEMU user
# mode when <arch> is not the host's, then writes to <outdir> (default dist/):
#   bastion-<v>-linux-<arch>        static PIE binary (bastionctl is a symlink in the packages)
#   bastion_<v>-1_<arch>.deb, bastion-<v>-1.<x86_64|aarch64>.rpm
#   bastion-<v>-linux-<arch>.spdx.json   SBOM
#   SHA256SUMS
# and a scratch image bastion:<v>-<arch> holding only the binary (docker/scratch.Dockerfile).
set -euo pipefail

[ $# -ge 2 ] || { echo "usage: scripts/build-release.sh <version> <amd64|arm64> [outdir]" >&2; exit 2; }
version=$1 arch=$2
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
out=${3:-dist}
case $out in /*) echo "build-release: outdir must be relative to the tree (it is bind-mounted)" >&2; exit 2 ;; esac
case $arch in amd64|arm64) ;; *) echo "build-release: arch must be amd64 or arm64" >&2; exit 2 ;; esac

case $(uname -m) in x86_64) host=amd64 ;; aarch64|arm64) host=arm64 ;; *) host=other ;; esac
plat=()
[ "$arch" = "$host" ] || plat=(--platform "linux/$arch")

rev=$(git -C "$root" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
if [ "$rev" != unknown ] && ! git -C "$root" diff --quiet HEAD -- 2>/dev/null; then
	echo "build-release: warning: the tree has uncommitted changes; the binary says git $rev" >&2
fi

"$root/dev" ${plat[@]+"${plat[@]}"} scripts/package.sh "$version" "$rev" "$out" BUILD=release

docker build ${plat[@]+"${plat[@]}"} -q -t "bastion:$version-$arch" -f "$root/docker/scratch.Dockerfile" \
	--build-arg "BIN=$out/bastion-$version-linux-$arch" "$root" >/dev/null
echo "image bastion:$version-$arch"
