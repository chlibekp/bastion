#!/usr/bin/env bash
# The VM cache lives in a volume shared by every tree, so preparing it must be race-free:
# two concurrent preparations both succeed with a complete tree and initrd, and a preparation
# killed part-way is recovered by the next run. No QEMU runs and nothing is downloaded: the
# scratch cache is seeded by hard link from the verified debs already cached.
# Run inside the dev container: ./dev tests/vm/check_cache_race.sh
set -u
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
[ "$(uname -m)" = aarch64 ] || { echo "skip: arm64 pins only"; exit 0; }
src="$root/build/deps/vm-cache/dl"
ls "$src"/*.deb >/dev/null 2>&1 || { echo "skip: no cached kernel debs (run make test-vm once)"; exit 0; }
scratch=$(mktemp -d "$root/build/deps/vm-race.XXXXXX") # same volume as the seed, so hard links work
trap 'rm -rf "$scratch"' EXIT
fail() { echo "FAIL: $1"; exit 1; }

fresh() { rm -rf "$scratch/cache"; mkdir -p "$scratch/cache/dl"; ln "$src"/*6.1.0-50*.deb "$scratch/cache/dl/"; }
prep() { VM_CACHE="$scratch/cache" VM_PREPARE_ONLY=1 KERNEL=floor "$root/scripts/vm-run.sh" true; }
check_complete() {
	local k
	k=$(ls -d "$scratch"/cache/floor-*/ 2>/dev/null | head -1)
	[ -n "$k" ] || fail "$1: no kernel tree"
	[ -f "$k/.extracted" ] || fail "$1: no marker"
	ls "$k"/root/boot/vmlinuz-* >/dev/null 2>&1 || fail "$1: no vmlinuz"
	ls "$k"/root/usr/lib/modules/*/modules.dep >/dev/null 2>&1 || fail "$1: no modules.dep"
	local i n=0
	for i in "$k"/initrd-*.gz; do n=$((n + 1)); gzip -t "$i" || fail "$1: initrd truncated"; done
	[ "$n" -eq 1 ] || fail "$1: want exactly one initrd, have $n"
	ls "$scratch"/cache/.tmp-* "$scratch"/cache/floor-*/*.part >/dev/null 2>&1 && fail "$1: leftovers"
	echo "ok   $1"
}

# 1. Two preparations at once.
fresh
prep >"$scratch/a.log" 2>&1 & pa=$!
prep >"$scratch/b.log" 2>&1 & pb=$!
wait $pa; ra=$?; wait $pb; rb=$?
[ $ra -eq 0 ] && [ $rb -eq 0 ] || { cat "$scratch/a.log" "$scratch/b.log"; fail "concurrent runs exited $ra and $rb"; }
check_complete "two concurrent preparations"

# 2. Killed mid-extraction (leftover temp tree), then recovery.
fresh
setsid bash -c "VM_CACHE='$scratch/cache' VM_PREPARE_ONLY=1 KERNEL=floor '$root/scripts/vm-run.sh' true" >/dev/null 2>&1 &
pid=$!
for _ in $(seq 1 2000); do ls -d "$scratch"/cache/.tmp-* >/dev/null 2>&1 && break; sleep 0.01; done
kill -9 -- "-$pid" 2>/dev/null; wait $pid 2>/dev/null
echo "killed run left: $(ls -A "$scratch/cache" | tr '\n' ' ')"
# Make the damage deterministic whether or not the kill landed in time.
mkdir -p "$scratch/cache/.tmp-dead.1/root/partial"
prep >"$scratch/c.log" 2>&1 || { cat "$scratch/c.log"; fail "recovery after extraction kill"; }
check_complete "recovery after a kill during extraction"

# 3. Truncated initrd.part and a stale half tree without marker.
k=$(ls -d "$scratch"/cache/floor-*/ | head -1)
rm -f "$k"/initrd-*.gz
head -c 100 /dev/urandom >"$k/initrd-deadbeef0000.gz.part"
prep >"$scratch/d.log" 2>&1 || { cat "$scratch/d.log"; fail "recovery after initrd kill"; }
check_complete "recovery after a kill during initrd build"
echo "PASS: cache preparation is race-free and recovers from kills"
