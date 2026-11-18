/* Worker-aware routing of QUIC datagrams (architecture section 4).
 *
 * Master makes one UDP socket per worker slot for each QUIC listener, all in one SO_REUSEPORT
 * group, and attaches the sk_reuseport program of reuseport_quic.bpf.c to the group: socket i is
 * slot i, and a datagram goes to the slot named in its destination connection ID
 * (http/h3/cid.h), so a connection keeps reaching its worker when the client's address changes.
 * Datagrams without a usable ID (a client's first Initial) are spread by 4-tuple hash over the
 * slots of the active generation. On a reload (proc/reload.h) the new generation gets fresh
 * sockets in the same group at keys BST_QUIC_GEN_SLOTS apart from the previous generation's, its
 * connection IDs name those keys, and the new map keeps the previous generation's sockets at
 * theirs: new connections reach the new processes while the old ones keep their own packets.
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

/* Keys per generation half: generation g routes slot s at s + (g odd ? this : 0). */
#define BST_QUIC_GEN_SLOTS 4096

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

/* The same with fds[i] at key keys[i] (NULL: i) of a socket map of nkeys entries (nfds to 8192).
 * A reload puts the new generation's sockets at its own key range and the draining generation's
 * at theirs, so each connection's datagrams keep reaching the process that holds it. */
bst_reuseport *bst_reuseport_attach_at(const int *fds, const uint32_t *keys, int nfds, uint32_t nkeys,
				       const bst_slot_map *active, bst_err *err);

/* Replaces the slots hashed-to datagrams go to. 0, or -1 with err set (the old set stays). */
int bst_reuseport_set_active(bst_reuseport *r, const bst_slot_map *active, bst_err *err);

/* Datagrams routed by connection ID, by hash over the active slots, and left to the kernel,
 * summed over CPUs. */
void bst_reuseport_stats(const bst_reuseport *r, uint64_t out[3]);

/* The socket map, active slots and stats map fds, for the reload hand-over (proc/reload.h). */
void bst_reuseport_map_fds(const bst_reuseport *r, int out[3]);

/* Takes over maps[3] from a previous image (the program is still attached to the group and reads
 * them): puts fds[i] at keys[i] and makes `active` the hashed-to slots. On success the maps are
 * the result's (bst_reuseport_free closes them); NULL with err set leaves them the caller's. */
bst_reuseport *bst_reuseport_adopt(const int maps[3], const int *fds, const uint32_t *keys, int nfds,
				   const bst_slot_map *active, bst_err *err);

/* Releases the maps and the program fd. The program stays attached to the group for as long as
 * any of its sockets lives (the kernel holds its own reference). */
void bst_reuseport_free(bst_reuseport *r);

#endif
