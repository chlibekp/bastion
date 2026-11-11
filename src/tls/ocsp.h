/* OCSP stapling (architecture section 6).
 *
 * Master, before any fork, finds every certificate that is to be stapled (its issuer from the
 * chain, the responder URL from the certificate or `ocsp_responder_override`), builds the request
 * and gives each one a slot in a shared memory region. `ocsp_file` responses are validated and
 * published right there. The helper fetches the rest over plain HTTP, validates each response with
 * OCSP_basic_verify against the certificate's own chain, and publishes it under a seqlock: it is the
 * only writer. A worker's status callback copies the staple of the certificate being served and
 * attaches it; it never opens a socket or a file. A response that fails validation is never
 * stapled; a staple is served only until its nextUpdate; a certificate without an OCSP URL (current
 * Let's Encrypt ones) is never fetched and never warns again. */
#ifndef BST_TLS_OCSP_H
#define BST_TLS_OCSP_H

#include "config/compile.h"
#include "core/addr.h"
#include "core/err.h"
#include "io/loop.h"

#include <openssl/ocsp.h>
#include <openssl/ssl.h>
#include <stdbool.h>

#define BST_OCSP_SLOTS 32
#define BST_OCSP_MAX 8192 /* bytes of one stapled response */

typedef struct bst_ocsp_cert bst_ocsp_cert;

/* Bytes of the shared region. */
size_t bst_ocsp_region_size(void);

/* Master: collects the certificates to staple from the built contexts, publishes `ocsp_file`
 * responses, and remembers the rest for the helper. region is zeroed shared memory. 0, or -1 with
 * err set (an ocsp_file that matches no certificate is an error). */
int bst_ocsp_setup(bst_config *cfg, void *region, bst_err *err);

/* Whether anything is to be stapled: master allocates the region only then. */
bool bst_ocsp_wanted(const bst_config *cfg);

/* Worker: installs the status callback on a context being built. */
void bst_ocsp_ctx(SSL_CTX *ctx);

/* Helper: starts the fetch schedule on its loop. Does nothing without fetchable certificates. */
void bst_ocsp_helper_start(bst_loop *loop);

/* Validates der as the response for cert i (0 on success, else why in *why) and publishes it. */
int bst_ocsp_accept(bst_ocsp_cert *c, const unsigned char *der, size_t len, const char **why);

/* The table, for the fetcher (ocsp_fetch.c). */
size_t bst_ocsp_count(void);
bst_ocsp_cert *bst_ocsp_at(size_t i);
/* One fetch: GET the response over plain HTTP, validate, publish. done(ok) runs once. */
void bst_ocsp_fetch(bst_loop *loop, bst_ocsp_cert *c, void (*done)(bst_ocsp_cert *, bool ok));
const char *bst_ocsp_name(const bst_ocsp_cert *c);
bool bst_ocsp_fetchable(const bst_ocsp_cert *c);
/* Request details for the fetcher. */
const unsigned char *bst_ocsp_request(const bst_ocsp_cert *c, int *len);
const char *bst_ocsp_host(const bst_ocsp_cert *c);
const char *bst_ocsp_path(const bst_ocsp_cert *c);
bst_sockaddr bst_ocsp_addr(const bst_ocsp_cert *c);
/* The staple's expiry (ms since the epoch) of what is published, 0 when none. */
unsigned long long bst_ocsp_expiry(const bst_ocsp_cert *c);

#endif
