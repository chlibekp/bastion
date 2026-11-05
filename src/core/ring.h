/* Single-producer single-consumer byte-message ring over shared memory.
 *
 * Shared memory holds only the two indices and the data; the capacity and each side's
 * own index live in a process-local handle, because the peer process may be hostile.
 * Everything pop reads from shared memory is validated, so a corrupt ring yields
 * BST_SPSC_CORRUPT and never an out-of-bounds access. Pop keeps returning CORRUPT until
 * the consumer calls bst_spsc_resync. Each side re-asserts its own index, writing only
 * when the shared value differs: pop on a ring that looks empty republishes rd, and every
 * failed push (after reloading rd) republishes wr. A dead peer's wild index therefore
 * heals, but only if the consumer polls on a periodic tick, not just on wakeups. */
#ifndef BST_RING_H
#define BST_RING_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BST_SPSC_EMPTY (-3)   /* pop: no message available */
#define BST_SPSC_CORRUPT (-1) /* pop: shared state is inconsistent */
#define BST_SPSC_SMALL (-2)   /* pop: out buffer smaller than the message; not consumed */

#define BST_SPSC_HDR 128u
#define BST_SPSC_BYTES(cap) (BST_SPSC_HDR + (size_t)(cap))

/* Layout of the start of the shared region. Exposed for tests and sizing only. */
struct bst_spsc_shm {
	_Alignas(64) _Atomic uint64_t wr; /* total bytes ever written; producer owned */
	_Alignas(64) _Atomic uint64_t rd; /* total bytes ever read; consumer owned */
};

_Static_assert(sizeof(struct bst_spsc_shm) == BST_SPSC_HDR, "ring header layout");

typedef struct bst_spsc bst_spsc;

/* mem: 64-byte aligned, BST_SPSC_BYTES(cap) bytes. cap: power of two, >= 8, and always
 * from trusted state, never read from the region. Handles are malloc'd and process-local
 * (release with bst_spsc_free); NULL on a bad cap, bad alignment or no memory.
 *
 * init formats a NEW region (zeroes the indices). Master calls it once, before anything
 * uses the ring, never on a live ring.
 * attach writes nothing to shared memory and seeds the local indices from it. Every
 * process calls it for its role after fork or respawn, so a successor producer or
 * consumer resumes where the old one stopped: unread records stay readable and bytes a
 * crashed producer never published are ignored. */
bst_spsc *bst_spsc_init(void *mem, size_t cap);
bst_spsc *bst_spsc_attach(void *mem, size_t cap);
/* Consumer only: clear the corrupt state and skip to the current shared wr, dropping
 * unread records. Call it only after pop returned CORRUPT or SMALL, per ring, at most
 * once per drain tick, never in a loop. max must equal the protocol's record bound, so
 * SMALL means the peer broke framing. Replacing a producer does not call it: unread
 * records stay readable. */
void bst_spsc_resync(bst_spsc *r);
void bst_spsc_free(bst_spsc *r);
/* False if the message (4 + len bytes) does not fit right now or can never fit. */
bool bst_spsc_push(bst_spsc *r, const void *msg, uint32_t len);
/* Length of the message copied to out, or a negative BST_SPSC_* code. */
int32_t bst_spsc_pop(bst_spsc *r, void *out, uint32_t max);

#endif
