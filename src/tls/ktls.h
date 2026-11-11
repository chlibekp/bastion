/* Kernel TLS (architecture section 6; findings in spikes/ktls/README.md).
 *
 * OpenSSL does the setsockopt calls itself (TCP_ULP, then TLS_TX and TLS_RX) once the handshake
 * keys exist, from inside the worker: those calls are in the worker's seccomp allowlist for that
 * reason (proc/seccomp_tables.c). With TX in the kernel, the data path is plain bst_io_send, so a
 * file goes out with sendfile or splice and is encrypted by the kernel.
 *
 * `ktls tx` (the default) keeps RX in user space on TLS 1.3, because a client KeyUpdate would
 * otherwise end the connection (finding 4): an info callback clears SSL_OP_ENABLE_KTLS once TX is
 * up. `ktls tx+rx` leaves it on. Where the kernel cannot do it OpenSSL silently stays in user
 * space; this module notices, counts and warns once. */
#ifndef BST_TLS_KTLS_H
#define BST_TLS_KTLS_H

#include "config/compile.h"
#include "core/err.h"

#include <openssl/ssl.h>
#include <stdbool.h>

/* Counters; master, before fork. */
void bst_tls_ktls_init(void);

/* Applies profile->ktls to a context being built. */
void bst_tls_ktls_ctx(SSL_CTX *ctx, const bst_cfg_tls_profile *p);

/* After a handshake: which directions went to the kernel. Counts the connection by mode and warns
 * once per process start when kTLS was asked for and did not activate. */
void bst_tls_ktls_note(SSL *ssl, const bst_cfg_tls_profile *p, bool *tx, bool *rx);

/* A connection that ended because kernel TLS cannot follow the peer (a KeyUpdate). */
void bst_tls_ktls_closed(void);

/* Whether this kernel can run kTLS TX with AES-128-GCM: a throwaway loopback connection. 0, or -1
 * with err naming the missing piece (`modprobe tls`, or a crypto module). */
int bst_tls_ktls_probe(bst_err *err);

/* Startup check: every profile that says `ktls ... require` needs the probe to pass. */
int bst_tls_ktls_check(const bst_config *cfg, bst_err *err);

#endif
