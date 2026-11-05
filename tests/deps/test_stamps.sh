#!/usr/bin/env bash
# Dep stamps must follow the recipe: recipe A, then B, then A again rebuilds; and `make deps`
# runs the script even when the script is older than .built. Uses a scratch prefix and
# builds only zstd (archive reused from the shared download cache). Run via make test-deps.
set -euo pipefail
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/tree/scripts" "$tmp/p"
ln -s "$repo/deps" "$tmp/tree/deps"
ln -s "$(cd "$repo/${DEPS:?}/.." && pwd)/dl" "$tmp/p/dl"
cp "$repo/scripts/build-deps.sh" "$tmp/tree/scripts/a.sh"
# Recipe B: same build plus a marker file.
sed 's|^build_zstd() {|build_zstd() {\n\ttouch "$prefix/recipe-B-ran"|' "$repo/scripts/build-deps.sh" >"$tmp/tree/scripts/b.sh"
chmod +x "$tmp/tree/scripts/"*.sh
prefix=$tmp/p/x

run() { "$tmp/tree/scripts/$1.sh" "$prefix" zstd 2>&1; }
out=$(run a);  echo "$out" | grep -q 'zstd 1.5.7: building' || { echo "FAIL: A did not build" >&2; exit 1; }
out=$(run a);  echo "$out" | grep -q 'zstd 1.5.7: up to date' || { echo "FAIL: A rerun not up to date" >&2; exit 1; }
out=$(run b);  echo "$out" | grep -q 'zstd 1.5.7: building' || { echo "FAIL: B did not rebuild" >&2; exit 1; }
[ -f "$prefix/recipe-B-ran" ] || { echo "FAIL: B recipe did not run" >&2; exit 1; }
rm -f "$prefix/recipe-B-ran"
out=$(run a);  echo "$out" | grep -q 'zstd 1.5.7: building' || { echo "FAIL: A,B,A reported up to date" >&2; echo "$out" >&2; exit 1; }
[ "$(ls "$prefix"/.stamp-zstd-* | wc -l)" -eq 1 ] || { echo "FAIL: stale stamps left" >&2; exit 1; }
echo "ok   stamps follow the recipe (A, B, A rebuilds)"

# An old-mtime script edit still runs: make must invoke the script although .built is newer.
mkdir -p "$tmp/m/build/deps/x86_64-glibc" "$tmp/m/scripts" "$tmp/m/deps"
cp "$repo/Makefile" "$tmp/m/"; cp -r "$repo/fuzz" "$tmp/m/fuzz"; mkdir -p "$tmp/m/src"
touch -t 200001010000 "$tmp/m/scripts/build-deps.sh" "$tmp/m/deps/versions.env"
mkdir -p "$tmp/m/build/deps/x86_64-glibc/lib/pkgconfig"
printf 'Name: openssl\nDescription: stub\nVersion: 1\nLibs: -lssl\nCflags:\n' >"$tmp/m/build/deps/x86_64-glibc/lib/pkgconfig/openssl.pc"
touch "$tmp/m/build/deps/x86_64-glibc/.built"
if (cd "$tmp/m" && make -n deps DEPS=build/deps/x86_64-glibc) | grep -q 'scripts/build-deps.sh'; then
	echo "ok   make deps runs the script despite an older script mtime"
else
	echo "FAIL: make deps skipped the script" >&2
	exit 1
fi
