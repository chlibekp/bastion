/* L7 security (Phase 12, architecture section 7): what runs between routing and the handler.
 *
 * The router calls bst_sec_check once the location is known and the client address is final
 * (real_ip applied), before authentication and the handler, so before any cache lookup or
 * upstream: rate limits (sec/limit.h). Shared state lives in memory master maps before the
 * first fork (bst_sec_setup), so every worker sees the same tables. */
#ifndef BST_SEC_SEC_H
#define BST_SEC_SEC_H

#include "config/compile.h"
#include "core/err.h"
#include "http/stream.h"

#include <stdbool.h>

/* Master, before any fork: maps the shared tables of every zone and registers the counters. 0,
 * or -1 with e set. */
int bst_sec_setup(bst_config *cfg, int nworkers, bst_err *e);

/* Continues a request that passed the checks. */
typedef void (*bst_sec_cont)(bst_stream *s);

/* Is anything to check configured for this request's scope? */
bool bst_sec_required(const bst_stream *s);
/* Runs the scope's checks. False: the request passed at once, carry on. True: the checks took the
 * request over: it was answered (refused), or it is held (`mode delay`) and cont runs later,
 * unless the stream ends first. */
bool bst_sec_check(bst_stream *s, bst_sec_cont cont);

#endif
