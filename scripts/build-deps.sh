#!/usr/bin/env bash
# Build the pinned dependencies as static libraries into a prefix.
# Usage: scripts/build-deps.sh <prefix> [dep ...]
# Archives are downloaded to <prefix>/../dl, hash-verified, and only then extracted.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
[ $# -ge 1 ] || { echo "usage: $0 <prefix> [dep ...]" >&2; exit 2; }
mkdir -p "$1"
prefix=$(cd "$1" && pwd)
shift

# shellcheck source=../deps/versions.env
. "$root/deps/versions.env"

dl="$prefix/../dl"
src="$prefix/src"
mkdir -p "$dl" "$src"
jobs=$(nproc)
export PKG_CONFIG_PATH="$prefix/lib/pkgconfig"
export PKG_CONFIG_LIBDIR="$prefix/lib/pkgconfig"
export CC=${CC:-clang}

want=("$@")
[ ${#want[@]} -gt 0 ] || read -ra want <<<"$DEP_ORDER"

fetch() { # name -> prints verified archive path
	local name=$1 up
	up=$(echo "$name" | tr '[:lower:]' '[:upper:]')
	local url_var="${up}_URL" sha_var="${up}_SHA256" ver_var="${up}_VERSION"
	local url=${!url_var} sha=${!sha_var} ver=${!ver_var}
	local file="$dl/$name-$ver-$(basename "$url")"
	if [ ! -f "$file" ]; then
		curl -fsSL --retry 3 -o "$file.part" "$url"
		mv "$file.part" "$file"
	fi
	if ! echo "$sha  $file" | sha256sum -c - >&2; then
		echo "SHA-256 mismatch for $name; removing $file" >&2
		rm -f "$file"
		exit 1
	fi
	echo "$file"
}

unpack() { # name archive -> prints source dir (archive already verified)
	local name=$1 archive=$2 dir="$src/$1"
	rm -rf "$dir"
	mkdir -p "$dir"
	tar -xf "$archive" -C "$dir" --strip-components=1
	echo "$dir"
}

cmake_static() { # srcdir extra-args...
	local s=$1
	shift
	cmake -S "$s" -B "$s/_b" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$prefix" \
		-DCMAKE_INSTALL_LIBDIR=lib -DBUILD_SHARED_LIBS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
		-DCMAKE_C_COMPILER="$CC" "$@"
	cmake --build "$s/_b" -j"$jobs"
	cmake --install "$s/_b"
}

build_openssl() {
	cd "$1"
	./Configure --prefix="$prefix" --libdir=lib no-shared no-tests no-docs
	make -j"$jobs"
	make install_sw
}
build_nghttp3() {
	cd "$1"
	./configure --prefix="$prefix" --libdir="$prefix/lib" --enable-lib-only --disable-shared --enable-static
	make -j"$jobs"
	make install
}
build_ngtcp2() {
	cd "$1"
	./configure --prefix="$prefix" --libdir="$prefix/lib" --enable-lib-only --disable-shared --enable-static --with-openssl
	make -j"$jobs"
	make install
}
build_liburing() {
	cd "$1"
	./configure --prefix="$prefix" --libdir="$prefix/lib" --cc="$CC"
	make -j"$jobs" -C src
	make -C src install
	rm -f "$prefix"/lib/liburing*.so*
}
build_libbpf() {
	cd "$1/src"
	make -j"$jobs" BUILD_STATIC_ONLY=y PREFIX="$prefix" LIBDIR="$prefix/lib" install
}
build_pcre2() {
	cd "$1"
	./configure --prefix="$prefix" --libdir="$prefix/lib" --disable-shared --enable-static --enable-jit
	make -j"$jobs"
	make install
}
build_zstd() {
	cd "$1"
	make -j"$jobs" -C lib PREFIX="$prefix" LIBDIR="$prefix/lib" libzstd.a
	make -C lib PREFIX="$prefix" LIBDIR="$prefix/lib" install-static install-includes install-pc
}
build_brotli() { cmake_static "$1" -DBROTLI_DISABLE_TESTS=ON; }
build_zlibng() { cmake_static "$1" -DZLIB_COMPAT=OFF -DWITH_GTEST=OFF -DBUILD_TESTING=OFF; }
build_mimalloc() { cmake_static "$1" -DMI_BUILD_SHARED=OFF -DMI_BUILD_TESTS=OFF -DMI_BUILD_OBJECT=OFF; }

for name in "${want[@]}"; do
	up=$(echo "$name" | tr '[:lower:]' '[:upper:]')
	ver_var="${up}_VERSION"
	sha_var="${up}_SHA256"
	stamp="$prefix/.stamp-$name-${!ver_var}-${!sha_var:0:12}"
	if [ -f "$stamp" ]; then
		echo "== $name ${!ver_var}: up to date"
		continue
	fi
	echo "== $name ${!ver_var}: building"
	archive=$(fetch "$name")
	dir=$(unpack "$name" "$archive")
	(build_"$name" "$dir")
	touch "$stamp"
done
echo "deps ready in $prefix"
