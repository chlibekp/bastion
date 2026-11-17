/* "Under attack" for `challenge auto` (Phase 12, Task 6): one shared flag, nothing more.
 *
 * Every worker adds its requests and its refusals (limit_zone rejects, escalation blocks, WAF
 * denies) to its own row of shared counters. Once a second the helper sums the rows, and turns
 * the flag on when the last second's requests reach `challenge_auto_rps` or its refusals reach
 * `challenge_auto_block_rate`. It turns it off only after both stayed below for
 * `challenge_auto_hold` (60 s by default), so a load that oscillates around the threshold keeps it
 * on instead of flapping. Workers read the flag on each request of a `challenge auto` scope;
 * `challenge on` and `off` ignore it. The admin API (Phase 14) can force it. */
#ifndef BST_SEC_ATTACK_H
#define BST_SEC_ATTACK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Bytes of shared memory for nworkers rows and the flag. */
size_t bst_attack_bytes(int nworkers);
/* Points this process at zeroed memory (master before any fork, or a test). */
void bst_attack_attach(void *mem, int nworkers);
/* In a worker: the row it adds to. */
void bst_attack_worker(int slot);

/* Worker side: one request, one refusal. Cheap: a relaxed add to the worker's own row. */
void bst_attack_request(void);
void bst_attack_refusal(void);
/* Anyone: is the flag on (or forced)? */
bool bst_attack_on(void);

/* The helper's 1 Hz decision. */
typedef struct bst_attack_cfg {
	uint64_t rps;	     /* 0: no request threshold */
	uint64_t block_rate; /* 0: no refusal threshold */
	uint64_t hold_s;
} bst_attack_cfg;

typedef struct bst_attack_state {
	uint64_t last_req, last_ref; /* totals at the last sample */
	uint64_t last_us;	     /* when it was taken, 0: none yet */
	uint64_t below_since_us;     /* under the thresholds since, 0: not below */
	uint64_t rps, refusals_ps;   /* the last second's rates (for logs) */
} bst_attack_state;

/* Samples the counters at now_us (monotonic) and updates the flag. Returns +1 when the flag
 * turned on, -1 when it turned off, 0 otherwise. */
int bst_attack_sample(const bst_attack_cfg *c, bst_attack_state *st, uint64_t now_us);

/* Phase 14 (admin): force the flag on (1), off (-1) or back to automatic (0). */
void bst_attack_force(int how);

#endif
