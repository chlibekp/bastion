/* Escalation (Phase 12, Task 3; architecture section 7): from repeated L7 refusals to a block.
 *
 * A strike is one thing a client did that a rule with `escalate after= window= block=` counts: a
 * limit_zone refusal, a WAF deny, an http2_abuse budget used up, an invalid challenge answer.
 * Strikes are counted per client (IPv4 address, IPv6 prefix) and rule in a table shared by every
 * worker, so `after` holds across workers; the strike that reaches `after` within `window` sends
 * one block request to master, through this worker's ring. Workers never block anything
 * themselves (sec/block.h).
 *
 * A strike is ignored when the peer is not proven: a QUIC path before address validation could
 * name any victim. A client address that came from a PROXY header or real_ip is not the packet
 * source, so its request carries BST_BLOCK_L7 (no network-level block).
 *
 * A ring is single producer (its worker) and single consumer (master). A full ring drops the
 * request and counts it; the worker never waits. */
#ifndef BST_SEC_ESCALATE_H
#define BST_SEC_ESCALATE_H

#include "config/compile.h"
#include "core/addr.h"
#include "sec/block.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BST_ESC_RING 256u	   /* requests a worker can have in flight */
#define BST_ESC_STRIKE_SLOTS 65536u /* the shared strike table */

typedef enum bst_strike_kind {
	BST_STRIKE_LIMIT = 0, /* a limit_zone refused */
	BST_STRIKE_WAF,	      /* a waf_rule denied */
	BST_STRIKE_H2,	      /* an http2_abuse budget ran out */
	BST_STRIKE_CHALLENGE, /* an invalid challenge answer */
	BST_STRIKE_KINDS
} bst_strike_kind;

_Static_assert(BST_STRIKE_KINDS <= BST_BLOCK_KINDS, "a strike kind fits a block request");

/* Where the address comes from. */
typedef struct bst_strike_src {
	bool validated; /* a completed TCP handshake, or a QUIC path past address validation */
	bool l7_only;	/* from a PROXY header or real_ip: not the packet source */
} bst_strike_src;

typedef enum bst_strike_rc {
	BST_STRIKE_OFF = 0, /* no escalation configured (or not attached) */
	BST_STRIKE_IGNORED, /* an unvalidated peer */
	BST_STRIKE_COUNTED, /* below the threshold */
	BST_STRIKE_SENT,    /* reached it: one request is in the ring */
	BST_STRIKE_DROPPED, /* reached it, but the ring was full */
} bst_strike_rc;

/* Bytes of shared memory for nworkers rings and the strike table. */
size_t bst_escalate_bytes(int nworkers);
/* Master, before any fork (or a test): points this process at zeroed memory and draws the hash
 * key. 0, or -1 without randomness. */
int bst_escalate_attach(void *mem, int nworkers);
/* In a worker, before it accepts: the ring it writes. */
void bst_escalate_worker(int slot);

/* One strike of ip under cfg (IPv6 keyed by ipv6_prefix, 64 when 0) at now_us (monotonic). */
bst_strike_rc bst_escalate_strike(const bst_escalate_cfg *cfg, const bst_ip *ip, bst_strike_kind kind,
				  const bst_strike_src *src, unsigned ipv6_prefix, uint64_t now_us);

/* Master: takes up to cap requests from slot's ring. */
size_t bst_escalate_drain(int slot, bst_block_req *out, size_t cap);
/* Requests this process dropped on a full ring. */
uint64_t bst_escalate_dropped(void);

#endif
