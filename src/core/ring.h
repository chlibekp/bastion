/* Single-producer single-consumer byte-message ring over shared memory.
 *
 * Shared memory holds only the two indices and the data; the capacity and each side's
 * own index live in a process-local handle, because the peer process may be hostile.
 * Everything pop reads from shared memory is validated, so a corrupt ring yields
 * BST_SPSC_CORRUPT and never an out-of-bounds access. Once corrupt, a ring stays
 * corrupt for the reader; the owner should discard it. */
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

/* mem: 64-byte aligned, BST_SPSC_BYTES(cap) bytes. cap: power of two, >= 8. Zeroes the
 * indices. Returns a malloc'd local handle (release with bst_spsc_free) or NULL. Call
 * before fork; each process then uses its inherited handle for one role only. */
bst_spsc *bst_spsc_init(void *mem, size_t cap);
void bst_spsc_free(bst_spsc *r);
/* False if the message (4 + len bytes) does not fit right now or can never fit. */
bool bst_spsc_push(bst_spsc *r, const void *msg, uint32_t len);
/* Length of the message copied to out, or a negative BST_SPSC_* code. */
int32_t bst_spsc_pop(bst_spsc *r, void *out, uint32_t max);

#endif
