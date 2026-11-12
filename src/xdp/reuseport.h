/* Worker-aware routing of QUIC datagrams (architecture section 4).
 *
 * Master makes one UDP socket per worker slot for each QUIC listener, all in one SO_REUSEPORT
 * group, and attaches the sk_reuseport program of reuseport_quic.bpf.c to the group: socket i is
 * slot i, and a datagram goes to the slot named in its destination connection ID
 * (http/h3/cid.h), so a connection keeps reaching its worker when the client's address changes.
 * Datagrams without a usable ID (a client's first Initial) are spread by 4-tuple hash over the
 * slots of the active generation; Phase 14's reload calls bst_reuseport_set_active with the new
 * generation's slots while the old ones keep receiving their own connections' packets.
 *
 * Attaching needs CAP_BPF (or CAP_SYS_ADMIN) and CAP_NET_ADMIN, so master does it before any
 * sandbox. Without BPF (no privilege, an old kernel, a seccomp-confined container) the caller
 * falls back to `quic_routing hash`: the kernel's reuseport hash, where packets from a new client
 * address can reach another worker, which then answers with a stateless reset (connection
 * migration across workers is unsupported). That fallback is logged by the caller. */
#ifndef BST_XDP_REUSEPORT_H
#define BST_XDP_REUSEPORT_H

#include "core/err.h"

#include <stddef.h>
#include <stdint.h>

typedef struct bst_slot_map {
	const uint16_t *slots; /* slots of the active generation, each < the attached socket count */
	size_t n;	       /* at least 1 */
} bst_slot_map;

typedef struct bst_reuseport bst_reuseport;

/* Loads the embedded program, puts fds[i] at slot i of its socket map, sets the active slots and
 * attaches it to the group (SO_ATTACH_REUSEPORT_EBPF on fds[0]). All fds are bound UDP sockets
 * of one reuseport group; nfds is 1 to 8192. NULL with err set (the libbpf or kernel reason) on
 * any failure, with nothing attached. */
bst_reuseport *bst_reuseport_attach(const int *fds, int nfds, const bst_slot_map *active, bst_err *err);

/* Replaces the slots hashed-to datagrams go to. 0, or -1 with err set (the old set stays). */
int bst_reuseport_set_active(bst_reuseport *r, const bst_slot_map *active, bst_err *err);

/* Datagrams routed by connection ID, by hash over the active slots, and left to the kernel,
 * summed over CPUs. */
void bst_reuseport_stats(const bst_reuseport *r, uint64_t out[3]);

/* Releases the maps and the program fd. The program stays attached to the group for as long as
 * any of its sockets lives (the kernel holds its own reference). */
void bst_reuseport_free(bst_reuseport *r);

#endif
