// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/* sk_reuseport program for QUIC listeners: picks the worker socket of a datagram's destination
 * connection ID (http/h3/cid_wire.h). Built for the BPF target by tools/embed.mk and embedded
 * in the binary; xdp/reuseport.c loads it. The license string is GPL because
 * bpf_sk_select_reuseport is a GPL-only helper; the source is dual licensed.
 *
 * Choice, in order:
 *   1. a short header, or a long header whose DCID has Bastion's length: the slot in the ID, if
 *      that slot has a socket in `socks`;
 *   2. otherwise (a client-chosen Initial DCID, a slot out of range or with no socket, a datagram
 *      too short to read): `hash` of the 4-tuple over the slots of the active generation in
 *      `active`, so the packets of one handshake keep reaching the same worker;
 *   3. if even that fails, SK_PASS without a selection: the kernel's own reuseport hash.
 * Nothing is ever dropped here: a worker that gets a packet it cannot use answers or drops it
 * itself. Data starts at the UDP header for sk_reuseport programs. */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "http/h3/cid_wire.h"

#define MAX_SLOTS 8192 /* io/listener.h BST_LISTENER_MAX_SLOTS; the loader shrinks socks */
#define UDP_HDR 8

struct {
	__uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
	__uint(max_entries, MAX_SLOTS);
	__type(key, __u32);
	__type(value, __u64);
} socks SEC(".maps");

/* [0] = number of active slots n, [1..n] = the slots */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_SLOTS + 1);
	__type(key, __u32);
	__type(value, __u32);
} active SEC(".maps");

/* [0] by connection ID, [1] by hash, [2] kernel fallback (read by tests and logged) */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 3);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

static __always_inline void count(__u32 k)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &k);
	if (v)
		*v += 1;
}

static __always_inline int by_hash(struct sk_reuseport_md *md)
{
	__u32 zero = 0;
	__u32 *n = bpf_map_lookup_elem(&active, &zero);
	if (n && *n > 0 && *n <= MAX_SLOTS) {
		__u32 idx = md->hash % *n + 1;
		__u32 *slot = bpf_map_lookup_elem(&active, &idx);
		if (slot) {
			__u32 key = *slot;
			if (bpf_sk_select_reuseport(md, &socks, &key, 0) == 0) {
				count(1);
				return SK_PASS;
			}
		}
	}
	count(2);
	return SK_PASS;
}

SEC("sk_reuseport")
int bst_quic_select(struct sk_reuseport_md *md)
{
	/* Constant offsets only: the 6.1 verifier is the floor. */
	__u8 b[BST_QUIC_LONG_DCID_OFF + BST_CID_MASK_OFF + 2];
	__u32 key;
#define SLOT_AT(o) ((((__u32)b[(o) + BST_CID_SLOT_OFF] << 8) | b[(o) + BST_CID_SLOT_OFF + 1]) ^ \
		    (((__u32)b[(o) + BST_CID_MASK_OFF] << 8) | b[(o) + BST_CID_MASK_OFF + 1]))
	if (bpf_skb_load_bytes(md, UDP_HDR, b, 1) != 0)
		return by_hash(md);
	if (b[0] & 0x80) { /* long header */
		if (bpf_skb_load_bytes(md, UDP_HDR, b, sizeof b) != 0)
			return by_hash(md);
		if (b[BST_QUIC_LONG_DCID_LEN_OFF] != BST_CID_LEN)
			return by_hash(md);
		key = SLOT_AT(BST_QUIC_LONG_DCID_OFF);
	} else {
		if (bpf_skb_load_bytes(md, UDP_HDR, b, BST_QUIC_SHORT_DCID_OFF + BST_CID_MASK_OFF + 2) != 0)
			return by_hash(md);
		key = SLOT_AT(BST_QUIC_SHORT_DCID_OFF);
	}
#undef SLOT_AT
	if (key < MAX_SLOTS && bpf_sk_select_reuseport(md, &socks, &key, 0) == 0) {
		count(0);
		return SK_PASS;
	}
	return by_hash(md);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
