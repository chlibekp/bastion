/* Per-client connection limits (Phase 12, Task 2): `limit_conn per_ip= subnet4= subnet6=`.
 *
 * Counts live in shared memory as one row per worker slot, so a worker only ever writes its own
 * row and a total is the sum over the rows. A row is a count-min sketch: each key (an address,
 * or its /p subnet) bumps two buckets chosen by two keyed hashes, and its count is the smaller
 * sum. Two keys share both buckets only by a rare double collision, which can only make a limit
 * stricter. A worker that dies (kill -9) leaves its row behind; its replacement zeroes the row
 * before it accepts, so the counts are rebuilt from the connections that really exist.
 *
 * The check runs before TLS and before any byte is read. Each admitted connection is remembered
 * by its fd and released when the socket is closed (bst_sock_close), when its fd number is
 * accepted again, or by a sweep that finds the fd gone, so every exit path gives the count
 * back. */
#ifndef BST_SEC_CONNLIMIT_H
#define BST_SEC_CONNLIMIT_H

#include "core/addr.h"
#include "core/err.h"

#include <stdbool.h>
#include <stdint.h>

#define BST_CONNLIMIT_BUCKETS 65536u

typedef struct bst_connlimit_cfg {
	bool set;
	unsigned per_ip;      /* 0: no per-address limit */
	unsigned subnet4_len; /* prefix of the IPv4 subnet key */
	unsigned subnet4;     /* connections per subnet, 0: none */
	unsigned subnet6_len;
	unsigned subnet6;
} bst_connlimit_cfg;

/* Bytes of shared memory for nworkers rows. */
size_t bst_connlimit_bytes(int nworkers);
/* Points the module at its memory (zeroed) and draws the hash keys. 0, or -1 without
 * randomness. */
int bst_connlimit_attach(void *mem, int nworkers);
/* In a worker, before it accepts: zeroes the row of this slot (a crashed predecessor's). */
void bst_connlimit_worker(int slot);

/* Admits a connection of ip on fd (true: counted; false: over a limit, close it). */
bool bst_connlimit_acquire(const bst_connlimit_cfg *c, const bst_ip *ip, int fd);
/* Gives back what fd holds, if anything. */
void bst_connlimit_release(int fd);
/* Gives back what is held by fds that are no longer the socket that was admitted. */
void bst_connlimit_sweep(void);

/* The current total of ip's own key (for tests and logs). */
unsigned bst_connlimit_count(const bst_ip *ip);

#endif
