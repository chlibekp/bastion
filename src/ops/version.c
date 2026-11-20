#include "ops/version.h"
#include <stdio.h>
#include <brotli/encode.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wshadow"
#include <bpf/libbpf.h>
#include <liburing.h>
#pragma GCC diagnostic pop
#include <mimalloc.h>
#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>
#include <openssl/crypto.h>
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include <zlib-ng.h>
#include <zstd.h>

#ifndef BST_VERSION
#define BST_VERSION "0.0.0"
#endif
/* Set by the Makefile for this file only (GIT_REV, from `git rev-parse` or the release script). */
#ifndef BST_GIT_REV
#define BST_GIT_REV "unknown"
#endif

void bst_version_print(void)
{
	/* Versions come from the linked libraries themselves, not from the pins, so a stale
	 * prefix shows up here. */
	char pcre[32] = "?";
	if (pcre2_config(PCRE2_CONFIG_VERSION, pcre) < 0)
		pcre[0] = '?', pcre[1] = '\0';
	uint32_t br = BrotliEncoderVersion();
	const ngtcp2_info *nq = ngtcp2_version(0);
	const nghttp3_info *nh = nghttp3_version(0);
	int mv = mi_version();
	/* First line keeps its long-standing shape: "bastion <v> (<detail>)", OpenSSL on it. Only
	 * (tests/host/test_dev_paths.sh locates and edits this printf). */
	char detail[160];
	snprintf(detail, sizeof detail, "git %s, %s", BST_GIT_REV, OpenSSL_version(OPENSSL_VERSION));
	printf("bastion %s (%s)\n", BST_VERSION, detail);
	FILE *f = stdout;
	fprintf(f, "  ngtcp2 %s, nghttp3 %s\n", nq ? nq->version_str : "?", nh ? nh->version_str : "?");
	fprintf(f, "  liburing %d.%d, libbpf %s\n", io_uring_major_version(), io_uring_minor_version(),
		libbpf_version_string());
	fprintf(f, "  pcre2 %s, zstd %s, brotli %u.%u.%u, zlib-ng %s, mimalloc %d.%d.%d\n", pcre,
		ZSTD_versionString(), br >> 24, (br >> 12) & 0xfffu, br & 0xfffu, zlibng_version(),
		mv / 10000, (mv / 100) % 100, mv % 100); /* mimalloc 3.x: major*10000 + minor*100 + patch */
}
