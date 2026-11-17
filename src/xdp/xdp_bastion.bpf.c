// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/* The XDP DDoS filter (architecture section 7). Built for the BPF target by tools/embed.mk and
 * embedded in the binary as bst_embed_xdp_bastion; xdp/loader.c loads and attaches it. No CO-RE
 * and no kernel struct reads: the program touches only packet bytes and its own maps, so one
 * object runs on every supported kernel (6.1 and later).
 *
 * Packet path, cheapest check first, no per-connection state:
 *   1. Ethernet, up to two VLAN tags (802.1Q, 802.1ad). Not IPv4/IPv6, or a third tag: PASS.
 *   2. IPv4 or IPv6 header. A header that does not fit the frame or its own lengths: DROP
 *      (malformed). IPv6 hop-by-hop, destination options, routing and fragment headers are walked
 *      up to BST_XDP_V6_EXT_MAX; past that PASS, or DROP with drop_v6_ext.
 *   3. Fragments: non-first fragments have no L4 header and can not be port matched: PASS, or
 *      DROP with drop_fragments (which drops first fragments too).
 *   4. ICMP and ICMPv6 (PMTUD, neighbour discovery) and every other protocol: PASS.
 *   5. TCP and UDP headers checked against the frame and the IP length: DROP when they do not fit.
 *      A destination port that is not protected: PASS, or DROP with drop_unprotected.
 *   6. TCP flags: null, xmas (FIN+PSH+URG), SYN+FIN, SYN+RST: DROP with drop_bad_tcp_flags.
 * Every verdict is counted in `stats` by reason (xdp/xdp_common.h). */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
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
#define IPPROTO_HOPOPTS_ 0
#define IPPROTO_ROUTING_ 43
#define IPPROTO_FRAGMENT_ 44
#define IPPROTO_ICMPV6_ 58
#define IPPROTO_DSTOPTS_ 60

struct vlan_hdr {
	__be16 tci;
	__be16 proto;
};

/* What parsing found. */
struct pkt {
	void *l4, *end;
	__u32 l4len;   /* bytes of L4 header and payload by the IP header's own length */
	__u8 proto;    /* L4 protocol */
	__u8 v4;       /* 1: an IPv4 source (also an IPv4-mapped IPv6 one), in src[0..3] */
	__u8 frag;     /* 0: not a fragment, 1: first fragment, 2: a later one */
	__u8 src[16];
};

static __always_inline int verdict(__u32 reason, int action)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &reason);
	if (v)
		*v += 1;
	return action;
}

/* A byte-swapped 16-bit field is an unbounded scalar to the 6.1 verifier, which then refuses
 * packet pointer math with it: the mask behind a compiler barrier gives it its real bound. */
static __always_inline __u32 len16(__be16 v)
{
	__u32 x = bpf_ntohs(v);
	asm volatile("" : "+r"(x));
	return x & 0xffff;
}

#define DROP(r) verdict(r, XDP_DROP)
#define PASS(r) verdict(r, XDP_PASS)

static __always_inline int port_in(const __u16 *list, __u16 n, __u16 max, __u16 port)
{
	for (int i = 0; i < BST_XDP_MAX_REFL_PORTS; i++) {
		if (i >= n || i >= max)
			break;
		if (list[i] == port)
			return 1;
	}
	return 0;
}

/* 0 parsed, 1 PASS (not ours), -1 DROP malformed. */
static __always_inline int parse_ip4(struct pkt *k, void *p)
{
	struct iphdr *ip = p;
	if ((void *)(ip + 1) > k->end)
		return -1;
	__u32 ihl = ip->ihl * 4u, tot = len16(ip->tot_len);
	if (ip->version != 4 || ihl < sizeof(*ip) || tot < ihl || (void *)p + tot > k->end)
		return -1;
	__u16 fo = bpf_ntohs(ip->frag_off);
	if (fo & 0x1fff)
		k->frag = 2;
	else if (fo & 0x2000)
		k->frag = 1;
	k->proto = ip->protocol;
	k->v4 = 1;
	__builtin_memcpy(k->src, &ip->saddr, 4);
	k->l4 = p + ihl;
	k->l4len = tot - ihl;
	return 0;
}

static __always_inline int parse_ip6(struct pkt *k, void *p, const struct bst_xdp_config *c)
{
	struct ipv6hdr *ip = p;
	if ((void *)(ip + 1) > k->end)
		return -1;
	__u32 plen = len16(ip->payload_len);
	if (ip->version != 6 || (void *)(ip + 1) + plen > k->end)
		return -1;
	__builtin_memcpy(k->src, &ip->saddr, 16);
	/* ::ffff:a.b.c.d is checked as a.b.c.d */
	__u32 *w = (__u32 *)k->src;
	if (w[0] == 0 && w[1] == 0 && w[2] == bpf_htonl(0xffff)) {
		__builtin_memcpy(k->src, &w[3], 4);
		__builtin_memset(k->src + 4, 0, 12);
		k->v4 = 1;
	}
	__u8 nh = ip->nexthdr;
	void *h = ip + 1;
	__u32 used = 0;
	for (int i = 0; i < BST_XDP_V6_EXT_MAX; i++) {
		if (nh == IPPROTO_FRAGMENT_) {
			__u8 *f = h;
			if ((void *)(f + 8) > k->end)
				return -1;
			__u16 off = ((__u16)f[2] << 8 | f[3]);
			k->frag = (off & 0xfff8) ? 2 : (off & 1) ? 1 : k->frag;
			nh = f[0];
			h = f + 8;
			used += 8;
		} else if (nh == IPPROTO_HOPOPTS_ || nh == IPPROTO_DSTOPTS_ || nh == IPPROTO_ROUTING_) {
			__u8 *e = h;
			if ((void *)(e + 2) > k->end)
				return -1;
			__u32 len = ((__u32)e[1] + 1) * 8;
			if ((void *)e + len > k->end)
				return -1;
			nh = e[0];
			h = (void *)e + len;
			used += len;
		} else {
			break;
		}
	}
	if (used > plen)
		return -1;
	if (nh == IPPROTO_FRAGMENT_ || nh == IPPROTO_HOPOPTS_ || nh == IPPROTO_DSTOPTS_ ||
	    nh == IPPROTO_ROUTING_)
		return (c->flags & BST_XDP_F_DROP_V6_EXT) ? -2 : 1;
	k->proto = nh;
	k->l4 = h;
	k->l4len = plen - used;
	return 0;
}

static __always_inline int bad_flags(__u8 f)
{
	if ((f & 0x3f) == 0)
		return 1; /* null */
	if ((f & 0x29) == 0x29)
		return 1; /* xmas: FIN, PSH, URG */
	if ((f & 0x03) == 0x03 || (f & 0x06) == 0x06)
		return 1; /* SYN+FIN, SYN+RST */
	return 0;
}

SEC("xdp")
int bst_xdp(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data, *end = (void *)(long)ctx->data_end;
	__u32 zero = 0;
	const struct bst_xdp_config *c = bpf_map_lookup_elem(&cfg, &zero);
	if (!c)
		return XDP_PASS;
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > end)
		return DROP(BST_XDP_DROP_MALFORMED);
	__u16 proto = eth->h_proto;
	void *p = eth + 1;
	for (int i = 0; i < VLAN_MAX; i++) {
		if (proto != bpf_htons(ETH_P_8021Q) && proto != bpf_htons(ETH_P_8021AD))
			break;
		struct vlan_hdr *v = p;
		if ((void *)(v + 1) > end)
			return DROP(BST_XDP_DROP_MALFORMED);
		proto = v->proto;
		p = v + 1;
	}
	struct pkt k = { .end = end };
	int r;
	if (proto == bpf_htons(ETH_P_IP))
		r = parse_ip4(&k, p);
	else if (proto == bpf_htons(ETH_P_IPV6))
		r = parse_ip6(&k, p, c);
	else
		return PASS(BST_XDP_PASS_NON_IP);
	if (r == -1)
		return DROP(BST_XDP_DROP_MALFORMED);
	if (r == -2)
		return DROP(BST_XDP_DROP_V6EXT);
	if (r == 1)
		return PASS(BST_XDP_PASS);

	if (k.frag && (c->flags & BST_XDP_F_DROP_FRAGMENTS))
		return DROP(BST_XDP_DROP_FRAGMENT);
	if (k.frag == 2)
		return PASS(BST_XDP_PASS);

	if (k.proto == IPPROTO_TCP) {
		struct tcphdr *t = k.l4;
		if ((void *)(t + 1) > end)
			return DROP(BST_XDP_DROP_MALFORMED);
		__u32 doff = t->doff * 4u;
		if (doff < sizeof(*t) || doff > k.l4len || k.l4 + doff > end)
			return DROP(BST_XDP_DROP_MALFORMED);
		if (!port_in(c->tcp_ports, c->ntcp, BST_XDP_MAX_PORTS, bpf_ntohs(t->dest)))
			return (c->flags & BST_XDP_F_DROP_UNPROTECTED) ? DROP(BST_XDP_DROP_UNPROTECTED)
								       : PASS(BST_XDP_PASS);
		__u8 flags = ((__u8 *)t)[13];
		if ((c->flags & BST_XDP_F_DROP_BAD_TCP_FLAGS) && bad_flags(flags))
			return DROP(BST_XDP_DROP_TCP_FLAGS);
		return PASS(BST_XDP_PASS);
	}
	if (k.proto == IPPROTO_UDP) {
		struct udphdr *u = k.l4;
		if ((void *)(u + 1) > end)
			return DROP(BST_XDP_DROP_MALFORMED);
		__u32 ulen = len16(u->len);
		if (ulen < sizeof(*u) || ulen > k.l4len)
			return DROP(BST_XDP_DROP_MALFORMED);
		if (!port_in(c->udp_ports, c->nudp, BST_XDP_MAX_PORTS, bpf_ntohs(u->dest)))
			return (c->flags & BST_XDP_F_DROP_UNPROTECTED) ? DROP(BST_XDP_DROP_UNPROTECTED)
								       : PASS(BST_XDP_PASS);
		return PASS(BST_XDP_PASS);
	}
	return PASS(BST_XDP_PASS); /* ICMP, ICMPv6 and the rest */
}
