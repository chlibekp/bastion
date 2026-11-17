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

struct bst_loop;
/* In a worker, before it accepts: rebuilds its connection counts and starts their sweep. */
void bst_sec_worker_start(int slot, struct bst_loop *l);
/* At accept, before TLS or any read, with the listener's default server and the client address
 * (the PROXY header's when there is one). False: close the connection. */
bool bst_sec_accept(const bst_cfg_common *srv, const bst_ip *peer, int fd);

/* In the helper: the 1 Hz sample that turns `challenge auto` on and off (sec/attack.h). */
void bst_sec_helper_start(struct bst_loop *l);
/* Every request the router dispatches, before the checks (counted for `challenge auto`). */
void bst_sec_request(void);

/* Master: drains the workers' block requests, applies and expires blocks (sec/block.h). Returns
 * when it wants to run next (ms on now_ms's clock), or 0 when escalation is not configured. */
uint64_t bst_sec_master_tick(uint64_t now_ms);
/* Is ip under an escalation block (any process)? */
bool bst_sec_blocked(const bst_ip *ip);
/* A strike (sec/escalate.h, kind a bst_strike_kind) of ip under cfg: validated false for a peer
 * not proven (a QUIC path before address validation), l7_only for an address from a PROXY header
 * or real_ip. */
void bst_sec_strike(const bst_escalate_cfg *cfg, const bst_ip *ip, unsigned kind, bool validated, bool l7_only);
/* The same for a request's client (bst_sec_check's address), IPv6 keyed by v6p. */
void bst_sec_strike_stream(const bst_escalate_cfg *cfg, const bst_stream *s, unsigned kind, unsigned v6p);

/* Continues a request that passed the checks. */
typedef void (*bst_sec_cont)(bst_stream *s);

/* Is anything to check configured for this request's scope? */
bool bst_sec_required(const bst_stream *s);
/* Runs the scope's checks. False: the request passed at once, carry on. True: the checks took the
 * request over: it was answered (refused), or it is held (`mode delay`) and cont runs later,
 * unless the stream ends first. */
bool bst_sec_check(bst_stream *s, bst_sec_cont cont);

#endif
