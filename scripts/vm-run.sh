#!/usr/bin/env bash
# Run a command inside a QEMU guest booted with a stock Debian kernel.
# Usage: [KERNEL=current|floor] scripts/vm-run.sh <cmd> [args...]
#
# Why: Docker Desktop's kernel lacks kTLS, Landlock, BBR and busy poll. The guest runs Debian's
# own kernel (floor = bookworm 6.1 series, proving the Linux 6.1 floor; current = trixie).
#
# Design: the kernel .deb is downloaded, SHA-256 verified, and only extracted, never installed.
# A tiny initramfs (dash, mount, kmod, chroot, copied from this container) loads the 9p modules,
# then chroots into THIS container's root filesystem, shared read-only over 9p. So the guest has the
# same glibc, python3 and pytest as the dev image. /work (the repo, writable) and /work/build are
# shared too, and the kernel's own modules are bind-mounted over /lib/modules so `modprobe tls` works.
# The command's exit status comes back through build/vm/run.*/result; no result file means failure.
# The whole run is limited to VM_TIMEOUT seconds (default 600), after which a hung guest is killed.
#
# TCG notes (arm64 Mac, no /dev/kvm): `-cpu max,pauth-impdef=on` because the default pointer-auth
# algorithm (QARMA) is very slow under TCG; the impdef one is what QEMU documents for emulation.
# KVM is used instead when /dev/kvm is usable and the host arch matches.
#
# Measured (arm64 TCG in Docker Desktop, no KVM, 2 GiB guest): `make test-vm` for the five kernel_features
# tests takes about 7 s wall clock end to end, of which the guest boots to the command in about 5 s
# (both floor and current). Cheap enough to keep this tier in the default workflow.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
KERNEL=${KERNEL:-current}
VM_TIMEOUT=${VM_TIMEOUT:-600}

# ---------------------------------------------------------------- guest stage (runs in the VM)
if [ "${1:-}" = --guest ]; then
	run=$2 # path below /work/build
	mount -t tmpfs tmpfs /tmp
	mount -t tmpfs tmpfs /run
	mount -t tmpfs tmpfs /root
	mount -t tmpfs tmpfs /var/tmp
	mount -t securityfs securityfs /sys/kernel/security
	touch /run/bastion-vm
	ip link set lo up || true
	export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root TMPDIR=/tmp PYTHONDONTWRITEBYTECODE=1
	cd /work
	rc=0
	eval "$(cat "/work/build/$run/cmd")" || rc=$?
	echo "$rc" >"/work/build/$run/result.tmp"
	mv "/work/build/$run/result.tmp" "/work/build/$run/result"
	sync
	exit 0
fi

# ---------------------------------------------------------------- pinned stock kernels
# Hashes are the SHA256 fields of Debian's published Packages index
# (https://deb.debian.org/debian/dists/<suite>/main/binary-<arch>/Packages.xz), read 2026-11-05.
# Pool URLs disappear when Debian supersedes a kernel; snapshot.debian.org keeps them, so it is
# the fallback (hash verification makes the mirror choice irrelevant for trust). The snapshot URL
# was verified for the floor kernel (hash matched); the snapshot service is often 503/504, so retry later.
#
# Bumping a pin (do this when the fetch fails with "could not fetch a verified ..."):
#   1. Find the new version: curl -s https://deb.debian.org/debian/dists/<bookworm|trixie>/main/binary-<arch>/Packages.xz \
#        | xz -dc | grep -A30 '^Package: linux-image-.*-<arch>$'   (floor: the 6.1.0-N image, current: the 6.12.x+deb13 image)
#   2. Copy its Filename (deb name; path stays pool/main/l/linux-signed-<arch>) and SHA256 into the matching case below,
#      for both arch lines of that kernel. The snapshot timestamp needs no change while it is later than the upload.
#   3. rm -rf build/deps/vm-cache/<kernel>-<arch>-* and rerun `make test-vm KERNEL=<kernel>`.
# POOL and SNAP can be overridden in the environment (used by tests/vm/check_pin_failure.sh).
SNAP=${VM_SNAP_URL:-https://snapshot.debian.org/archive/debian/20261105T000000Z}
POOL=${VM_POOL_URL:-https://deb.debian.org/debian}
arch=$(uname -m)
case "$KERNEL-$arch" in
floor-aarch64)
	deb=linux-image-6.1.0-50-arm64_6.1.176-1_arm64.deb
	path=pool/main/l/linux-signed-arm64
	sha=914f75b57a8e165d85fb910c3e2dcc7000a05a9fea3f42f90b26e8dd590d5f06 ;;
floor-x86_64)
	deb=linux-image-6.1.0-50-amd64_6.1.176-1_amd64.deb
	path=pool/main/l/linux-signed-amd64
	sha=7b5597492a0a65aee61985a492e6bcc3f2cde830072a0e3b3d8c7e1b90279bd3 ;;
current-aarch64)
	deb=linux-image-6.12.107+deb13-arm64_6.12.107-1_arm64.deb
	path=pool/main/l/linux-signed-arm64
	sha=20c92f3f97dd466e0400a6fcb792bde85af842fbb5e8b471370065e3de9d9fc9 ;;
current-x86_64)
	deb=linux-image-6.12.107+deb13-amd64_6.12.107-1_amd64.deb
	path=pool/main/l/linux-signed-amd64
	sha=7794643cf4560de2a7e3b069e8ca8511ad2a568d652ea285f0fe051f79bc9e99 ;;
*) echo "vm-run: unsupported KERNEL=$KERNEL on $arch (KERNEL is floor or current; arch aarch64 or x86_64)" >&2; exit 2 ;;
esac
[ $# -gt 0 ] || { echo "usage: KERNEL=floor|current $0 <cmd> [args...]" >&2; exit 2; }

# Kernel debs, extracted trees and initramfs images are the same for every checkout, so they
# live in the shared deps volume (build/deps), keyed by the kernel pin (deb name and hash).
# Per-run scratch stays in this tree's build/vm.
vm="$root/build/vm"
# VM_CACHE overrides the cache directory (tests use a scratch one); the guest binds modules from it
# relative to build/, so only the default is usable for a real run.
cache=${VM_CACHE:-$root/build/deps/vm-cache}
cache_rel="deps/vm-cache"
dl="$cache/dl"
kkey="$KERNEL-$arch-${sha:0:12}"
kdir="$cache/$kkey"
mkdir -p "$dl" "$vm"

fetch_kernel() {
	local file="$dl/$deb" url
	if [ -f "$file" ] && ! echo "$sha  $file" | sha256sum -c - >/dev/null 2>&1; then
		echo "vm-run: cached $deb fails SHA-256; removing" >&2
		rm -f "$file"
	fi
	if [ ! -f "$file" ]; then
		for url in "$POOL/$path/$deb" "$SNAP/$path/$deb"; do
			curl -fsSL --retry 3 -o "$file.part" "$url" || { rm -f "$file.part"; continue; }
			if echo "$sha  $file.part" | sha256sum -c - >&2; then
				mv "$file.part" "$file"
				break
			fi
			echo "vm-run: SHA-256 mismatch from $url" >&2
			rm -f "$file.part"
		done
		[ -f "$file" ] || {
			echo "vm-run: could not fetch a verified $deb (KERNEL=$KERNEL, $arch)." >&2
			echo "vm-run: tried $POOL/$path/$deb and $SNAP/$path/$deb" >&2
			echo "vm-run: the pin is probably superseded; bump it as described above the pin table in scripts/vm-run.sh." >&2
			exit 1
		}
	fi
	if [ ! -f "$kdir/.extracted" ]; then
		# Extract beside the final place and rename, so a killed run leaves no half tree and
		# the marker is only ever seen on a complete one.
		local tmp="$cache/.tmp-$kkey.$$"
		rm -rf "$tmp"
		mkdir -p "$tmp/root"
		dpkg-deb -x "$file" "$tmp/root"
		# Debian packages are usr-merged: modules land in usr/lib/modules; give kmod its lib/modules path.
		# Bookworm's package is not usr-merged (lib/modules); normalise to the trixie layout.
		if [ -d "$tmp/root/lib/modules" ] && [ ! -e "$tmp/root/usr/lib/modules" ]; then
			mkdir -p "$tmp/root/usr/lib"
			mv "$tmp/root/lib/modules" "$tmp/root/usr/lib/modules"
		fi
		mkdir -p "$tmp/root/lib"
		ln -s ../usr/lib/modules "$tmp/root/lib/modules"
		# The package ships no modules.dep (its postinst runs depmod); do that here.
		depmod -b "$tmp/root" "$(basename "$tmp"/root/usr/lib/modules/*)"
		touch "$tmp/.extracted"
		rm -rf "$kdir"
		mv "$tmp" "$kdir"
	fi
}

# ---------------------------------------------------------------- initramfs (host side)
copy_bin() { # binary path: copies it and its shared libraries into the staging tree
	local b=$1 l
	cp --parents -L "$b" "$stage"
	for l in $(ldd "$b" | grep -o '/[^ ]*'); do
		[ -e "$stage$l" ] || cp --parents -L "$l" "$stage"
	done
}

build_initramfs() {
	local kver=$1 out=$2 stage m n=0 list=
	stage=$(mktemp -d "$vm/initramfs.XXXXXX")
	mkdir -p "$stage"/{usr/bin,usr/sbin,usr/lib,usr/lib64,proc,sys,dev,mnt/root,m}
	ln -s usr/bin "$stage/bin"; ln -s usr/sbin "$stage/sbin"
	ln -s usr/lib "$stage/lib"; ln -s usr/lib64 "$stage/lib64"
	for b in /usr/bin/dash /usr/bin/mount /usr/bin/kmod /usr/sbin/chroot /usr/bin/mkdir /usr/bin/cat /usr/bin/sleep /usr/bin/sync; do copy_bin "$b"; done
	ln -s dash "$stage/usr/bin/sh"
	ln -s kmod "$stage/usr/bin/insmod"
	# Only the modules needed to reach the 9p root; everything else loads later from the shared root.
	for m in virtio_pci 9pnet_virtio 9p; do
		while read -r _ f; do
			case "$list" in *" $f "*) continue ;; esac
			list="$list $f "
			n=$((n + 1))
			cp "$f" "$stage/m/$(printf %02d "$n")-$(basename "$f")"
		done < <(modprobe -d "$kdir/root" -S "$kver" --show-depends "$m" | grep '^insmod')
	done
	cat >"$stage/init" <<'EOF'
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
for f in /m/*; do insmod "$f" || echo "vm-run: insmod $f failed" >/dev/console; done
fail() { echo "vm-run: $1" >/dev/console; echo o >/proc/sysrq-trigger; sleep 600; }
for a in $(cat /proc/cmdline); do
	case "$a" in bst_run=*) run=${a#bst_run=} ;; bst_mods=*) mods=${a#bst_mods=} ;; esac
done
O="trans=virtio,version=9p2000.L,msize=1048576,cache=loose"
mount -t 9p -o "$O,ro" root /mnt/root || fail "cannot mount 9p root"
mount -t 9p -o "$O" work /mnt/root/work || fail "cannot mount /work"
mount -t 9p -o "$O" build /mnt/root/work/build || fail "cannot mount /work/build"
mount --bind "/mnt/root/work/build/$mods" /mnt/root/lib/modules || fail "cannot bind modules"
mount -t proc proc /mnt/root/proc
mount -t sysfs sys /mnt/root/sys
mount -t devtmpfs dev /mnt/root/dev
chroot /mnt/root /work/scripts/vm-run.sh --guest "$run"
sync
echo o >/proc/sysrq-trigger
sleep 600
EOF
	chmod +x "$stage/init"
	(cd "$stage" && find . | cpio -o -H newc --quiet | gzip -1) >"$out"
	rm -rf "$stage"
}

# ---------------------------------------------------------------- host stage
# Prepare the shared cache under a lock (held only for this, not while QEMU runs, so VM tests
# can run in parallel). A killed run leaves only .tmp-* or *.part files, swept here.
exec 8>"$cache/.lock"
flock 8
rm -rf "$cache"/.tmp-*
find "$cache" -name '*.part' -delete
fetch_kernel
vmlinuz=$(ls "$kdir"/root/boot/vmlinuz-*)
kver=$(basename "$vmlinuz")
kver=${kver#vmlinuz-}
initrd="$kdir/initrd-$(sha256sum <"$root/scripts/vm-run.sh" | cut -c1-12).gz"
if [ ! -f "$initrd" ]; then
	build_initramfs "$kver" "$initrd.part"
	mv "$initrd.part" "$initrd"
fi
exec 8>&-
[ -z "${VM_PREPARE_ONLY:-}" ] || exit 0

runrel="vm/run.$$"
rundir="$root/build/$runrel"
rm -rf "$rundir"
mkdir -p "$rundir"
trap 'rm -rf "$rundir"' EXIT
printf '%q ' "$@" >"$rundir/cmd"

smp=$(nproc); [ "$smp" -le 4 ] || smp=4
case "$arch" in
aarch64)
	qemu=qemu-system-aarch64; console=ttyAMA0
	machine=(-machine virt); cpu=max,pauth-impdef=on; kvmcpu=host ;;
x86_64)
	qemu=qemu-system-x86_64; console=ttyS0
	machine=(-machine q35); cpu=max; kvmcpu=host ;;
esac
if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
	machine+=(-accel kvm); cpu=$kvmcpu
else
	machine+=(-accel tcg)
fi

fs() { echo "-fsdev local,id=$1,path=$2,security_model=none,multidevs=remap${3:-} -device virtio-9p-pci,fsdev=$1,mount_tag=$1"; }
# shellcheck disable=SC2046
set +e
timeout --foreground --signal=KILL "$VM_TIMEOUT" "$qemu" "${machine[@]}" -cpu "$cpu" -smp "$smp" -m 2G \
	-nographic -monitor none -serial stdio -no-reboot -nic none \
	-kernel "$vmlinuz" -initrd "$initrd" \
	-append "console=$console quiet loglevel=3 panic=-1 bst_run=$runrel bst_mods=$cache_rel/$kkey/root/usr/lib/modules" \
	$(fs root / ,readonly=on) $(fs work "$root") $(fs build "$root/build") </dev/null
qrc=$?
set -e

if [ -f "$rundir/result" ]; then
	rc=$(cat "$rundir/result")
	case "$rc" in '' | *[!0-9]*) echo "vm-run: unreadable result file" >&2; exit 1 ;; esac
	exit "$rc"
fi
if [ "$qrc" -eq 137 ] || [ "$qrc" -eq 124 ]; then
	echo "vm-run: guest hung, killed after ${VM_TIMEOUT}s" >&2
else
	echo "vm-run: guest exited (qemu status $qrc) without a result file" >&2
fi
exit 1
