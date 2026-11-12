/* The circuit breaker of one upstream in one worker (`circuit_breaker`). Two parts:
 *
 *  - Limits: requests waiting for a response head (max_pending), requests in flight
 *    (max_active) and retries in flight (max_retries). A request over a limit is answered 503 with
 *    Retry-After at once: nothing queues, so an overloaded upstream cannot grow the queue.
 *  - States: closed (traffic flows); after `fails` consecutive failures, open (every request is
 *    refused for `for`); then half-open (exactly one request goes through as a probe: its success
 *    closes the breaker, its failure opens it again).
 *
 * Per worker, so no lock: each worker protects the upstream from its own share of the load. */
#ifndef BST_PROXY_BREAKER_H
#define BST_PROXY_BREAKER_H

#include "proxy/upstream.h"

#include <stdbool.h>
#include <stdint.h>

typedef enum bst_brk_state {
	BST_BRK_CLOSED = 0,
	BST_BRK_OPEN,
	BST_BRK_HALF_OPEN,
} bst_brk_state;

typedef struct bst_breaker {
	const bst_up_breaker *cfg;
	bst_brk_state st;
	unsigned pending, active, retries;
	unsigned consec_fail;
	uint64_t open_until;
	bool probe_out; /* half-open: the one probe is in flight */
} bst_breaker;

/* The breaker of u in this worker (made on first use); NULL when out of memory. */
bst_breaker *bst_breaker_of(const bst_cfg_upstream *u);
void bst_breaker_init(bst_breaker *b, const bst_up_breaker *cfg);
/* May a new request go to the upstream now? true counts it active and pending; *probe is set
 * when it is the half-open probe. */
bool bst_breaker_admit(bst_breaker *b, uint64_t now, bool *probe);
/* The request got its response head (no longer pending). */
void bst_breaker_answered(bst_breaker *b);
/* The request is over: ok when the upstream did its part (a head below 500). */
void bst_breaker_done(bst_breaker *b, bool pending, bool ok, bool probe, uint64_t now);
/* A retry may start (counted until bst_breaker_retry_done). */
bool bst_breaker_retry(bst_breaker *b);
void bst_breaker_retry_done(bst_breaker *b);
/* Seconds for Retry-After when refusing: what is left of the open time, at least 1. */
unsigned bst_breaker_retry_after(const bst_breaker *b, uint64_t now);

#ifdef BST_TEST
void bst_breaker_test_reset(void);
#endif

#endif
