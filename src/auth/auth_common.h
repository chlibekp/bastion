/* The early-phase authentication hook every mechanism shares (Phase 11, Tasks 4-6).
 *
 * The router calls bst_auth_check once the location is known and before the handler (and so
 * before the cache lookup): nothing about a protected location is answered before
 * authentication passed. Mechanisms run in a fixed order, cheapest first: mTLS, JWT, Basic,
 * forward auth. With `auth_require any` (the default) the first that passes lets the request
 * in; with `auth_require all` every configured one must pass. A failed check answers with the
 * first denial (its status and, for Basic, WWW-Authenticate).
 *
 * Mechanisms may be asynchronous (Basic hashes on the aio pool, forward auth asks a service).
 * While one runs, the stream's handler is a placeholder whose on_reset marks the run dead and
 * cancels the pending work, so a late completion never touches a freed stream. Every failure
 * path denies: there is no fail-open. */
#ifndef BST_AUTH_COMMON_H
#define BST_AUTH_COMMON_H

#include "http/stream.h"

#include <stdbool.h>

typedef struct bst_auth_run bst_auth_run;

/* status 0: authenticated, go on; else the status to answer with, plus one optional header. */
typedef void (*bst_auth_done_cb)(bst_stream *s, int status, bst_str hname, bst_str hval);

/* Is any authentication configured for this request's scope? */
bool bst_auth_required(const bst_stream *s);
/* Runs the scope's mechanisms; cb gets the verdict exactly once, unless the stream ends first. */
void bst_auth_check(bst_stream *s, bst_auth_done_cb cb);

/* ---- for the mechanisms ---- */

bst_stream *bst_auth_stream(bst_auth_run *r);
/* A mechanism's verdict: 0 passes, else a denial. Call exactly once per start. */
void bst_auth_step(bst_auth_run *r, int status, bst_str hname, bst_str hval);
/* A denial answered with a whole response (forward auth returns the service's own 401, 403 or
 * redirect, with its body): h's fields and body (may be NULL) are sent as they are. */
void bst_auth_deny_response(bst_auth_run *r, int status, const bst_headers *h, bst_buf *body);
/* An asynchronous mechanism registers how to cancel its pending work when the stream ends. */
void bst_auth_set_pending(bst_auth_run *r, void (*cancel)(void *), void *pending);

/* The mechanisms' entry points. */
void bst_auth_basic_start(bst_auth_run *r);
void bst_auth_jwt_start(bst_auth_run *r);
void bst_auth_forward_start(bst_auth_run *r);
void bst_auth_mtls_start(bst_auth_run *r);
bool bst_auth_mtls_configured(const bst_stream *s);

#endif
