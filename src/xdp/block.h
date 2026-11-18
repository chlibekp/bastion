/* The XDP block backend (Phase 13, Task 7): escalation blocks (sec/block.h) enforced in the XDP
 * filter's dyn_block4/dyn_block6 maps, in front of the network stack.
 *
 * It wraps the user-space backend rather than replacing it: every block still goes to the shared
 * table, so L7 enforcement stays the same, an L7-only block (BST_BLOCK_L7: the address came from
 * a PROXY header or real_ip, not the packet source) never leaves user space, and when XDP is not
 * attached nothing changes. Only master writes the maps; workers have no bpf().
 *
 * Guards on top of master's own (allowlist, trusted proxies, ceiling, TTL): the backend refuses
 * to put into the maps any address under its exempt CIDRs, which master builds from the `xdp`
 * allow list, loopback, and the upstream servers written as IP literals, so a mistake upstream of
 * it can not cut Bastion off from its operators or its own backends. IPv6 blocks go in at their
 * prefix when it is one the program looks up (48, 56, 64, 128); any other stays L7 only. */
#ifndef BST_XDP_BLOCK_H
#define BST_XDP_BLOCK_H

#include "core/cidr.h"
#include "sec/block.h"
#include "xdp/loader.h"

/* Makes out the XDP backend over inner (borrowed, the user-space one) and x's maps. exempt is
 * copied. 0, or -1 out of memory. */
int bst_block_backend_xdp(bst_block_backend *out, bst_block_backend *inner, bst_xdp *x, const bst_cidr *exempt,
			  size_t nexempt);
void bst_block_backend_xdp_free(bst_block_backend *b);

/* Blocks the backend refused to put into the maps (exempt address, unsupported prefix) and map
 * writes that failed, for the log and tests. */
uint64_t bst_block_xdp_skipped(const bst_block_backend *b);

#endif
