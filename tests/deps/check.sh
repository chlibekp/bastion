#!/usr/bin/env bash
# Every pinned dependency must resolve through pkg-config (static) and link into a program.
# Run through `make test-deps` (needs DEPS=<prefix> and CC).
set -euo pipefail
: "${DEPS:?}" "${CC:?}"
prefix=$(cd "$DEPS" && pwd)
export PKG_CONFIG_PATH="$prefix/lib/pkgconfig"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

pkgs="openssl libnghttp3 libngtcp2 libngtcp2_crypto_ossl liburing libbpf libpcre2-8 libzstd libbrotlienc libbrotlidec zlib-ng mimalloc"
fail=0
for p in $pkgs; do
	if out=$(pkg-config --static --libs --cflags "$p" 2>&1); then
		echo "ok   pkg-config $p"
	else
		echo "FAIL pkg-config $p: $out" >&2
		fail=1
	fi
done
[ $fail -eq 0 ] || exit 1

link() { # name pkg-list source
	local name=$1 pk=$2
	cat >"$tmp/$name.c"
	# shellcheck disable=SC2046
	if $CC -std=gnu17 -Wall -Werror $(pkg-config --static --cflags $pk) -o "$tmp/$name" "$tmp/$name.c" \
		$(pkg-config --static --libs $pk) 2>"$tmp/$name.err"; then
		"$tmp/$name" && echo "ok   link+run $name"
	else
		echo "FAIL link $name" >&2
		cat "$tmp/$name.err" >&2
		fail=1
	fi
}

link uring liburing <<'C'
#include <liburing.h>
int main(void) { struct io_uring r; int rc = io_uring_queue_init(2, &r, 0); if (rc == 0) io_uring_queue_exit(&r); (void)rc; return io_uring_major_version() >= 2 ? 0 : 1; }
C
link bpf libbpf <<'C'
#include <bpf/libbpf.h>
int main(void) { return libbpf_major_version() >= 1 ? 0 : 1; }
C
link mimalloc mimalloc <<'C'
#include <mimalloc.h>
int main(void) { void *p = mi_malloc(64); if (!p) return 1; mi_free(p); return 0; }
C
link ssl openssl <<'C'
#include <openssl/ssl.h>
int main(void) { SSL_CTX *c = SSL_CTX_new(TLS_server_method()); if (!c) return 1; SSL_CTX_free(c); return 0; }
C
link zstd libzstd <<'C'
#include <zstd.h>
int main(void) { return ZSTD_versionNumber() > 0 ? 0 : 1; }
C
link pcre2 libpcre2-8 <<'C'
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
int main(void) { int e; PCRE2_SIZE o; pcre2_code *c = pcre2_compile((PCRE2_SPTR)"a+", 2, 0, &e, &o, NULL); if (!c) return 1; pcre2_code_free(c); return 0; }
C
exit $fail
