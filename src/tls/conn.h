/* A non-blocking TLS connection over an accepted socket (architecture section 5).
 *
 * bst_tls_accept runs the server handshake on the loop (bst_io_poll on both backends, no thread,
 * no blocking call) and then hands the caller a bst_transport that HTTP/1.1 uses exactly as it
 * uses the plain one. A handshake that does not finish within the profile's handshake_timeout is
 * closed. Every OpenSSL call is preceded by clearing the thread's error queue, so one
 * connection's failure never shows up as another's.
 *
 * Memory per connection: SSL_MODE_RELEASE_BUFFERS, and a file segment is staged through one
 * 64 KiB buffer read on the aio pool (a read from disk never blocks the loop). */
#ifndef BST_TLS_CONN_H
#define BST_TLS_CONN_H

#include "config/compile.h"
#include "http/transport.h"
#include "route/vhost.h"

#include <openssl/ssl.h>

/* Registers the TLS counters. Master, before any fork (the counter table has one registering
 * writer). */
void bst_tls_conn_init(void);

/* t is the ready transport, or NULL when the handshake failed or timed out; the connection is
 * then already closed. Called at most once, never from inside bst_tls_accept. */
typedef void (*bst_tls_ready_cb)(void *ud, bst_transport *t);

/* Takes fd (it is closed on every failure). `policy` says what a plaintext HTTP request on the
 * port gets: nothing (close) or a 400 page. 0, or -1 on exhaustion (fd closed, no callback). */
int bst_tls_accept(bst_loop *loop, int fd, SSL_CTX *ctx, const bst_cfg_tls_profile *profile,
		   const bst_listener_set *set, bst_http_on_tls policy, bst_tls_ready_cb cb, void *ud);

/* The value of a TLS variable for a transport: "protocol", "cipher", "session_reused". NULL for
 * a plain transport or an unknown name; the string lives as long as the transport. */
const char *bst_tls_var(const bst_transport *t, const char *name);

/* A client certificate was presented and verified (tls_client_auth); false for a plain transport. */
bool bst_tls_client_verified(const bst_transport *t);

/* True while the handshake is not complete but the connection already serves: what is read now
 * arrived as TLS 1.3 early data (tls/early.h). */
bool bst_tls_early_active(const bst_transport *t);

/* The server whose context the handshake used (NULL for a plain transport). */
const bst_cfg_server *bst_tls_chosen_server(const bst_transport *t);

/* The server the client's SNI named (NULL: none did, or the transport is plain). */
const bst_cfg_server *bst_tls_sni_server(const bst_transport *t);

#endif
