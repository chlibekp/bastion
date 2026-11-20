#!/usr/bin/env bash
# Docker-level package tests (Phase 14 Task 10), run on the host after
#   scripts/build-release.sh <version> <arch>
# Usage: tests/host/test_packages_host.sh <version> [distdir]
#
#   deb: install in fresh debian:trixie and ubuntu:24.04, check, start, serve the default page,
#        upgrade to a rebuilt <version+patch> keeping an edited config, remove cleanly.
#   rpm: the same in almalinux:9 (RHEL family).
#   scratch image: `serve /www` with no shell, as uid 65534 with only NET_BIND_SERVICE, on port 80.
#   foreign architecture: if dist/ holds the other architecture's binary, run its --version
#        under QEMU user mode (docker --platform); otherwise reported as not run.
set -euo pipefail

[ $# -ge 1 ] || { echo "usage: tests/host/test_packages_host.sh <version> [distdir]" >&2; exit 2; }
version=$1
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
dist=${2:-dist}
cd "$root"

case $(uname -m) in x86_64) arch=amd64 rpmarch=x86_64 other=arm64 ;; *) arch=arm64 rpmarch=aarch64 other=amd64 ;; esac
deb=$dist/bastion_${version}-1_${arch}.deb
rpm=$dist/bastion-${version}-1.${rpmarch}.rpm
for f in "$deb" "$rpm"; do [ -f "$f" ] || { echo "FAIL: $f missing: run scripts/build-release.sh $version $arch" >&2; exit 1; }; done

IFS=. read -r ma mi pa <<<"$version"
next=$ma.$mi.$((pa + 1))
up=$dist/upgrade
rm -rf "$up"
# The upgrade package: same binary (build/pkg/bastion, staged by scripts/package.sh), next version.
"$root/dev" bash -c 'set -e; mkdir -p "$3"; for f in deb rpm; do BST_PKG_VERSION=$1 BST_PKG_ARCH=$2 \
	nfpm package --config packaging/nfpm.yaml --packager $f --target "$3/" >/dev/null; done' \
	_ "$next" "$arch" "$up" BUILD=release
deb2=$up/bastion_${next}-1_${arch}.deb
rpm2=$up/bastion-${next}-1.${rpmarch}.rpm

containers=()
cleanup() { [ ${#containers[@]} -eq 0 ] || docker rm -f "${containers[@]}" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# Runs inside the distro container: $1 = install command, $2 = remove command, $3 $4 = packages.
lifecycle='
set -eu
install=$1 remove=$2 p1=$3 p2=$4
$install "/pkg/$p1" >/dev/null
test -x /usr/bin/bastion && test -L /usr/bin/bastionctl
getent passwd bastion >/dev/null
test "$(stat -c %U:%G:%a /etc/bastion/bastion.conf)" = root:bastion:640
/usr/bin/bastion -t -c /etc/bastion/bastion.conf
mkdir -p /var/log/bastion
/usr/bin/bastion -c /etc/bastion/bastion.conf &
pid=$!
ok=0
for i in $(seq 1 50); do
	if exec 3<>/dev/tcp/127.0.0.1/80 2>/dev/null; then
		printf "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n" >&3
		resp=$(cat <&3); exec 3<&-
		case $resp in "HTTP/1.1 200"*"Bastion is running"*) ok=1; break ;; esac
	fi
	sleep 0.2
done
[ $ok = 1 ] || { echo "FAIL: default page not served"; kill $pid; exit 1; }
echo "served default page"
kill -QUIT $pid; wait $pid || true
echo "# local edit" >>/etc/bastion/bastion.conf
$install "/pkg/$p2" >/dev/null
grep -q "^# local edit" /etc/bastion/bastion.conf || { echo "FAIL: upgrade replaced the config"; exit 1; }
echo "config kept on upgrade"
$remove bastion >/dev/null
test ! -e /usr/bin/bastion && test ! -e /usr/bin/bastionctl && test ! -e /usr/lib/systemd/system/bastion.service \
	|| { echo "FAIL: files left after remove"; exit 1; }
echo "removed cleanly"
'

run_distro() { # image install remove pkg1 pkg2
	local img=$1
	echo "== $img"
	docker run --rm -v "$root/$dist:/pkg:ro" "$img" bash -c "$lifecycle" _ "$2" "$3" "$4" "$5"
	echo "PASS: $img"
}

ddeb=${deb#$dist/} ddeb2=${deb2#$dist/} drpm=${rpm#$dist/} drpm2=${rpm2#$dist/}
apt_inst='env DEBIAN_FRONTEND=noninteractive apt-get install -y -q'
run_distro debian:trixie "$apt_inst" "apt-get remove -y -q" "$ddeb" "$ddeb2"
run_distro ubuntu:24.04 "$apt_inst" "apt-get remove -y -q" "$ddeb" "$ddeb2"
run_distro almalinux:9 "dnf install -y -q" "dnf remove -y -q" "$drpm" "$drpm2"

echo "== scratch image"
www=$dist/.hosttest-www
rm -rf "$www"; mkdir -p "$www"
echo "scratch ok" >"$www/index.html"
img=bastion:$version-$arch
docker image inspect "$img" >/dev/null || { echo "FAIL: $img missing: run scripts/build-release.sh" >&2; exit 1; }
cid=$(docker run -d --cap-drop ALL --cap-add NET_BIND_SERVICE --security-opt no-new-privileges \
	-v "$root/$www:/www:ro" "$img" serve /www --port 80)
containers+=("$cid")
ok=0
for i in $(seq 1 30); do
	if out=$(docker run --rm --network "container:$cid" debian:trixie bash -c \
		'exec 3<>/dev/tcp/127.0.0.1/80 && printf "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n" >&3 && cat <&3' 2>/dev/null); then
		case $out in *"scratch ok"*) ok=1; break ;; esac
	fi
	sleep 0.5
done
uid=$(docker inspect -f '{{.Config.User}}' "$cid")
[ $ok = 1 ] || { docker logs "$cid" >&2; echo "FAIL: scratch image did not serve" >&2; exit 1; }
[ "$uid" = 65534:65534 ] || { echo "FAIL: scratch image user is $uid" >&2; exit 1; }
if docker exec "$cid" /bin/sh -c true >/dev/null 2>&1; then echo "FAIL: the scratch image has a shell" >&2; exit 1; fi
echo "PASS: scratch image serves as 65534 with NET_BIND_SERVICE only, no shell"
rm -rf "$www"

echo "== foreign architecture ($other)"
fbin=$dist/bastion-$version-linux-$other
if [ -f "$fbin" ]; then
	docker run --rm --platform "linux/$other" -v "$root/$dist:/d:ro" debian:trixie "/d/${fbin#$dist/}" --version
	echo "PASS: $other binary runs under QEMU user mode"
else
	echo "NOT RUN: $fbin absent (scripts/build-release.sh $version $other builds it under QEMU)"
fi
rm -rf "$up"
echo "ALL PASS"
