// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/* The XDP DDoS filter (architecture section 7). Built for the BPF target by tools/embed.mk and
 * embedded in the binary as bst_embed_xdp_bastion; xdp/loader.c loads and attaches it. No CO-RE
 * and no kernel struct reads: the program touches only packet bytes and its own maps, so one
 * object runs on every supported kernel (6.1 and later).
 *
 * Packet path, cheapest check first, no per-connection state. */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "xdp/xdp_common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct bst_xdp_config);
} cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, BST_XDP_NREASONS);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

#define VLAN_MAX 2

struct vlan_hdr {
	__be16 tci;
	__be16 proto;
};

static __always_inline int verdict(__u32 reason, int action)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &reason);
	if (v)
		*v += 1;
	return action;
}

SEC("xdp")
int bst_xdp(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data, *end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > end)
		return verdict(BST_XDP_DROP_MALFORMED, XDP_DROP);
	__u16 proto = eth->h_proto;
	void *p = eth + 1;
	for (int i = 0; i < VLAN_MAX; i++) {
		if (proto != bpf_htons(ETH_P_8021Q) && proto != bpf_htons(ETH_P_8021AD))
			break;
		struct vlan_hdr *v = p;
		if ((void *)(v + 1) > end)
			return verdict(BST_XDP_DROP_MALFORMED, XDP_DROP);
		proto = v->proto;
		p = v + 1;
	}
	if (proto != bpf_htons(ETH_P_IP) && proto != bpf_htons(ETH_P_IPV6))
		return verdict(BST_XDP_PASS_NON_IP, XDP_PASS);
	return verdict(BST_XDP_PASS, XDP_PASS);
}
