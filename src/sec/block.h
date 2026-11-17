/* Address blocks (Phase 12, Task 3; architecture section 7, escalation rules).
 *
 * Only master decides a block. Workers ask for one through their escalation ring
 * (sec/escalate.h); master validates each request (bst_block_apply) and hands what it accepts to
 * a block backend: an interface of add, remove and list, so Phase 13 can put XDP behind it. This
 * phase ships the user-space backend: a table in shared memory that workers read at accept and
 * per request (bst_block_lookup), never write.
 *
 * Master's rules, each a guard against the mechanism blocking the wrong address:
 *   - a request is a fixed 32-byte record; anything malformed (family, prefix, host bits, flags,
 *     kind, TTL out of range) is refused and counted, so a compromised worker can ask for no more
 *     than single addresses (IPv4 /32, IPv6 /48 to /128) for at most a day;
 *   - an address in `escalation_allow` or in any `real_ip_from` is never blocked;
 *   - every block has a TTL, and past `escalation_ceiling` active blocks new requests are refused
 *     and counted while the existing blocks stay;
 *   - BST_BLOCK_L7 marks an address that came from a PROXY header or real_ip, not from the packet
 *     source: a network backend (XDP) must skip it; the user-space backend enforces it at L7.
 *
 * The shared table is two halves: master rebuilds the inactive half from its list and flips the
 * active index under a sequence counter, so a reader never sees a half-written table. */
#ifndef BST_SEC_BLOCK_H
#define BST_SEC_BLOCK_H

#include "core/addr.h"
#include "core/cidr.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BST_BLOCK_L7 0x01u    /* the address is not the packet source: L7 only */
#define BST_BLOCK_FLAGS 0x01u /* every known flag */
#define BST_BLOCK_TTL_MIN_US 1000000ull
#define BST_BLOCK_TTL_MAX_US (86400ull * 1000000ull)
#define BST_BLOCK_CEILING_DEFAULT 10000u
#define BST_BLOCK_CEILING_MAX 262144u
#define BST_BLOCK_KINDS 8u    /* bst_strike_kind values a request may carry */

/* What a worker writes into its ring: plain bytes, validated field by field by master. */
typedef struct bst_block_req {
	uint8_t family; /* 4 or 6 */
	uint8_t prefix; /* 32 for IPv4; 48..128 for IPv6 */
	uint8_t flags;	/* BST_BLOCK_* */
	uint8_t kind;	/* bst_strike_kind: what the client did, for the log */
	uint32_t pad;	/* zero */
	uint8_t addr[16];
	uint64_t ttl_us;
} bst_block_req;

_Static_assert(sizeof(bst_block_req) == 32, "a ring entry is 32 bytes");

typedef struct bst_block_entry {
	bst_ip ip; /* host bits below prefix zero */
	uint8_t prefix, flags;
	uint64_t expires_us; /* monotonic */
} bst_block_entry;

/* A place blocks are enforced. add replaces an entry of the same address and prefix; commit
 * publishes a batch of adds and removes. Each returns 0, or -1 when it could not. */
typedef struct bst_block_backend {
	const char *name;
	void *ctx;
	int (*add)(void *ctx, const bst_block_entry *e);
	int (*remove)(void *ctx, const bst_block_entry *e);
	size_t (*list)(void *ctx, bst_block_entry *out, size_t cap);
	void (*commit)(void *ctx);
} bst_block_backend;

/* ---- the user-space backend: a shared table ---- */

typedef struct bst_block_table bst_block_table;

size_t bst_block_table_bytes(unsigned ceiling);
/* Over zeroed memory of bst_block_table_bytes(ceiling). */
bst_block_table *bst_block_table_attach(void *mem, unsigned ceiling);
/* True when ip (any form; ::ffff: is IPv4) is under a block that has not expired. Lock-free,
 * for workers. */
bool bst_block_lookup(const bst_block_table *t, const bst_ip *ip, uint64_t now_us);
/* True when the table holds any block (a cheap test before bst_block_lookup). */
bool bst_block_any(const bst_block_table *t);

/* Makes b the user-space backend over t (master's side). 0, or -1 out of memory. */
int bst_block_shm_backend(bst_block_backend *b, bst_block_table *t, unsigned ceiling);
void bst_block_shm_backend_free(bst_block_backend *b);

/* ---- master ---- */

typedef enum bst_block_rc {
	BST_BLOCK_ADDED = 0,
	BST_BLOCK_EXTENDED,  /* already blocked: the TTL was renewed */
	BST_BLOCK_MALFORMED, /* refused: not a well-formed request */
	BST_BLOCK_EXEMPT,    /* refused: an allowlisted or trusted address */
	BST_BLOCK_CEILING,   /* refused: escalation_ceiling active blocks */
	BST_BLOCK_FAILED,    /* the backend refused */
} bst_block_rc;

typedef struct bst_block_master bst_block_master;

/* exempt: CIDRs never blocked, copied (a block overlapping one is refused). The backend is
 * borrowed. */
bst_block_master *bst_block_master_new(unsigned ceiling, const bst_cidr *exempt, size_t nexempt,
					bst_block_backend *backend);
void bst_block_master_free(bst_block_master *m);
/* Validates r and blocks its address until now + ttl. Call bst_block_commit after a batch. */
bst_block_rc bst_block_apply(bst_block_master *m, const bst_block_req *r, uint64_t now_us);
/* Removes the blocks that expired by now; returns how many. */
size_t bst_block_expire(bst_block_master *m, uint64_t now_us);
/* Publishes what changed since the last commit to the backend. */
void bst_block_commit(bst_block_master *m);
size_t bst_block_active(const bst_block_master *m);
/* The active entry i (< bst_block_active), for logs and tests. */
const bst_block_entry *bst_block_at(const bst_block_master *m, size_t i);
/* Fills e from a request master accepted. False when r is malformed. */
bool bst_block_req_valid(const bst_block_req *r, bst_block_entry *e);

#endif
