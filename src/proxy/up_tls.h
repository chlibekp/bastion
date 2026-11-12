/* TLS to upstreams (`proxy https://...`, or `tls ...` in an upstream block).
 *
 * Configuration. Each TLS upstream gets its own client SSL_CTX, built when the configuration
 * loads (in master, before any sandbox), with its CA bundle (`tls ca`, else the system's default
 * bundle), its client certificate (`tls cert` and `tls key`, for upstream mTLS) and its versions
 * (`tls versions`, default TLS 1.2 and 1.3). Verification is on by default: the chain must lead to
 * a trusted CA and the certificate must name the server (`tls sni`, else the server's host as
 * written; an IP literal is checked against IP SANs and is not sent as SNI). `tls verify off`
 * is allowed but `bastion -t` warns about it.
 *
 * Connections. bst_uptls wraps one connected upstream socket: the handshake and every read and
 * write run on the loop, driven by one-shot readiness (bst_io_poll), with no blocking call. It
 * offers the same three operations the proxy uses on a plain socket (recv stream, send of a
 * chain, done callbacks never from inside the call). Sessions are kept per peer in each worker,
 * so later connections resume instead of doing a full handshake. */
#ifndef BST_PROXY_UP_TLS_H
#define BST_PROXY_UP_TLS_H

#include "config/compile.h"
#include "core/chain.h"
#include "io/net.h"
#include "io/sock.h"
#include "proxy/upstream.h"

/* The post hook's part: builds the SSL_CTX of every TLS upstream. 0, or -1 with e set. */
int bst_uptls_setup(bst_config *cfg, bst_cfg_ctx *c, bst_err *e);

typedef struct bst_uptls bst_uptls;

/* A TLS client over sk (connected). NULL on exhaustion. */
bst_uptls *bst_uptls_new(bst_loop *l, bst_sock *sk, const bst_cfg_upstream *u, const bst_peer *p);
/* Runs the handshake; cb(ud, 0, 0) when done, or a negative errno (-EPROTO when the
 * certificate failed verification, which is logged). */
void bst_uptls_handshake(bst_uptls *t, bst_done_cb cb, void *ud);
int bst_uptls_recv_start(bst_uptls *t, bst_recv_cb cb, void *ud);
int bst_uptls_recv_stop(bst_uptls *t);
int bst_uptls_send(bst_uptls *t, bst_chain *c, bst_done_cb cb, void *ud);
/* Before the socket is closed; safe from inside any of its callbacks. */
void bst_uptls_free(bst_uptls *t);
/* The last handshake resumed a session. */
bool bst_uptls_resumed(const bst_uptls *t);

#ifdef BST_TEST
extern unsigned long bst_test_uptls_full, bst_test_uptls_resumed;
#endif

#endif
