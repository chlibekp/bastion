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
 *      up to BST_XDP_V6_EXT_MAX; past that PASS, or DROP with drop_v6_ext (after the lists).
 *   2b. Source lists (an IPv4-mapped IPv6 source is checked as IPv4): allow4/allow6 PASS and skip
 *      every later check; deny4/deny6 DROP; an unexpired dyn_block4/dyn_block6 entry DROP.
 *   3. Fragments: non-first fragments have no L4 header and can not be port matched: PASS, or
 *      DROP with drop_fragments (which drops first fragments too).
 *   4. ICMP and ICMPv6 (PMTUD, neighbour discovery) and every other protocol: PASS.
 *   5. TCP and UDP headers checked against the frame and the IP length: DROP when they do not fit.
 *      A destination port that is not protected: PASS, or DROP with drop_unprotected.
 *   6. TCP flags: null, xmas (FIN+PSH+URG), SYN+FIN, SYN+RST: DROP with drop_bad_tcp_flags.
 *   6b. UDP to a protected port: from an amplification source port (refl_ports) DROP with
 *      drop_reflection; on a QUIC port (an `http3` listener) a datagram that is not the shape of
 *      QUIC (bad_quic) DROP. Replies to Bastion's own DNS queries go to ephemeral ports, which
 *      are not protected, so they are never touched.
 *   7. Per-source rates (GCRA, per CPU): SYN without ACK against syn_rate, UDP against udp_rate,
 *      every protected packet against pps_rate. With auto_block, a source dropped auto_after
 *      times within a second goes into dyn_block for auto_ns (off by default: spoofed sources
 *      can trigger it, so it only ever blocks the over-limit source key, briefly).
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

/* Static lists: `allow`/`deny` (and their _file forms) in `xdp {}`. Value unused (1). */
#define LIST_MAX 262144
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, LIST_MAX);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct bst_xdp_lpm4);
	__type(value, __u8);
} allow4 SEC(".maps"), deny4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, LIST_MAX);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct bst_xdp_lpm6);
	__type(value, __u8);
} allow6 SEC(".maps"), deny6 SEC(".maps");

/* Dynamic blocks (escalation, auto_block): value = expiry in ns. An expired entry is ignored and
 * may stay until master removes it or the LRU evicts it. The loader sizes both. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, __u64);
} dyn_block4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct bst_xdp_dyn6);
	__type(value, __u64);
} dyn_block6 SEC(".maps");

/* Per-source buckets for syn_rate, udp_rate and pps_rate, one per CPU (see bst_xdp_per_cpu). A
 * random-source flood churns it; LRU eviction forgets the oldest sources, never fails. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct bst_xdp_rkey);
	__type(value, struct bst_xdp_rval);
} rate SEC(".maps");

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

/* Word i (bytes 4i..4i+3) of the address, keeping the first `keep` bytes of the whole address:
 * assembled in a register from byte loads (src is not 4-aligned) and masked with a constant. */
_Static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "dyn6_word assumes little endian");
static __always_inline __u32 dyn6_word(const __u8 *src, int i, int keep)
{
	int n = keep - 4 * i;
	if (n <= 0)
		return 0;
	__u32 w;
	__builtin_memcpy(&w, src + 4 * i, 4);
	return n >= 4 ? w : w & ((1u << (8 * n)) - 1); /* little endian: the first n bytes */
}

/* dyn_block6 holds the source at `pfx` (a literal multiple of 8). The key is written as five
 * whole, aligned 32-bit words. Byte-wise keys (a mask computed per byte, or a partial memcpy
 * over a zeroed key) left each stack byte zero or unknown in varying patterns, so the
 * verifier could not prune states and hit its 1M-instruction limit on Linux 7.0 (E2BIG). No
 * initializer either: clang copies an initialized aggregate from a .rodata template, and the
 * daemon then failed to create the bst_xdp.rodata map (EPERM). */
#define DYN6_HIT(src, pfx, now)                                                              \
	({                                                                                   \
		_Static_assert((pfx) % 8 == 0 && (pfx) <= 128, "dyn6 prefix");                \
		_Static_assert(sizeof(struct bst_xdp_dyn6) == 20, "dyn6 key layout");         \
		union {                                                                      \
			struct bst_xdp_dyn6 k;                                               \
			__u32 w[5];                                                          \
		} u_;                                                                        \
		u_.w[0] = (pfx); /* prefix in byte 0, pad zero (little endian) */            \
		u_.w[1] = dyn6_word((src), 0, (pfx) / 8);                                    \
		u_.w[2] = dyn6_word((src), 1, (pfx) / 8);                                    \
		u_.w[3] = dyn6_word((src), 2, (pfx) / 8);                                    \
		u_.w[4] = dyn6_word((src), 3, (pfx) / 8);                                    \
		__u64 *e_ = bpf_map_lookup_elem(&dyn_block6, &u_.k);                         \
		e_ && (now) < *e_;                                                           \
	})

/* The list verdict for the source: 1 allowlisted, -1 DROP_DENY, -2 DROP_DYN, 0 none. */
static __always_inline int lists(const struct pkt *k, __u64 now)
{
	if (k->v4) {
		struct bst_xdp_lpm4 l = { .prefixlen = 32 };
		__builtin_memcpy(l.addr, k->src, 4);
		if (bpf_map_lookup_elem(&allow4, &l))
			return 1;
		if (bpf_map_lookup_elem(&deny4, &l))
			return -1;
		__u32 a;
		__builtin_memcpy(&a, k->src, 4);
		__u64 *exp = bpf_map_lookup_elem(&dyn_block4, &a);
		if (exp && now < *exp)
			return -2;
		return 0;
	}
	struct bst_xdp_lpm6 l = { .prefixlen = 128 };
	__builtin_memcpy(l.addr, k->src, 16);
	if (bpf_map_lookup_elem(&allow6, &l))
		return 1;
	if (bpf_map_lookup_elem(&deny6, &l))
		return -1;
	/* the BST_XDP_DYN6_PREFIXES prefixes, longest first */
	_Static_assert(BST_XDP_DYN6_PREFIXES == 4, "the lookups below list every prefix");
	if (DYN6_HIT(k->src, 128, now) || DYN6_HIT(k->src, 64, now) ||
	    DYN6_HIT(k->src, 56, now) || DYN6_HIT(k->src, 48, now))
		return -2;
	return 0;
}

#define NS 1000000000ull

/* auto_block: puts the source (its rate key) in dyn_block for c->auto_ns. */
static __always_inline void auto_block(const struct bst_xdp_rkey *key, const struct bst_xdp_config *c,
				       __u64 now)
{
	__u64 exp = now + c->auto_ns;
	if (key->family == 4) {
		__u32 a;
		__builtin_memcpy(&a, key->addr, 4);
		bpf_map_update_elem(&dyn_block4, &a, &exp, BPF_ANY);
	} else {
		struct bst_xdp_dyn6 d = { .prefix = (__u8)c->v6_prefix };
		__builtin_memcpy(d.addr, key->addr, 16);
		bpf_map_update_elem(&dyn_block6, &d, &exp, BPF_ANY);
	}
	verdict(BST_XDP_AUTO_BLOCKED, 0);
}

/* GCRA: emission interval T = 1 s / rate, tolerance (burst - 1) * T. 1 when over the limit. */
static __always_inline int over_rate(const struct pkt *k, __u8 kind, __u64 r, __u64 burst,
				     const struct bst_xdp_config *c, __u64 now)
{
	if (r == 0)
		return 0;
	__u64 t = NS / r;
	if (t == 0)
		t = 1;
	__u64 tau = t * (burst > 1 ? burst - 1 : 0);
	struct bst_xdp_rkey key = { .family = k->v4 ? 4 : 6, .kind = kind };
	if (k->v4)
		__builtin_memcpy(key.addr, k->src, 4);
	else
		for (int i = 0; i < 16; i++)
			key.addr[i] = k->src[i] & c->v6_mask[i];
	struct bst_xdp_rval *v = bpf_map_lookup_elem(&rate, &key);
	if (!v) {
		struct bst_xdp_rval n = { .tat = now + t };
		bpf_map_update_elem(&rate, &key, &n, BPF_ANY);
		return 0;
	}
	__u64 tat = v->tat > now ? v->tat : now;
	if (tat - now <= tau) {
		v->tat = tat + t;
		return 0;
	}
	if (c->auto_after) {
		if (now - v->over_start >= NS) {
			v->over_start = now;
			v->over = 0;
		}
		if (++v->over >= c->auto_after) {
			v->over = 0;
			auto_block(&key, c, now);
		}
	}
	return 1;
}

#define QUIC_V1 0x00000001u
#define QUIC_V2 0x6b3343cfu
#define QUIC_MIN_INITIAL 1200 /* RFC 9000 section 14.1: a client Initial's UDP payload */

/* 1 when a datagram to a QUIC port can not be QUIC: empty; a short header, or a long header of a
 * version Bastion speaks, with the fixed bit clear; an Initial of such a version under 1200 bytes.
 * A long header of any other version passes untouched, so version negotiation keeps working. */
static __always_inline int bad_quic(__u8 *q, void *end, __u32 len)
{
	if ((void *)(q + 1) > end || len == 0)
		return 1;
	__u8 b0 = q[0];
	if (!(b0 & 0x80))
		return !(b0 & 0x40);
	if ((void *)(q + 5) > end || len < 5)
		return 1;
	__u32 ver = (__u32)q[1] << 24 | (__u32)q[2] << 16 | (__u32)q[3] << 8 | q[4];
	if (ver != QUIC_V1 && ver != QUIC_V2)
		return 0;
	if (!(b0 & 0x40))
		return 1;
	__u8 type = (b0 >> 4) & 3;
	int initial = ver == QUIC_V1 ? type == 0 : type == 1;
	return initial && len < QUIC_MIN_INITIAL;
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

/* What the parse hands the L4 checks (bst_l4). */
struct scratch {
	__u8 src[16];
	__u8 v4, proto, pad[2];
	__u32 l4off, l4len;
	__u64 now;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct scratch);
} scratch SEC(".maps");

int bst_l4(struct xdp_md *ctx);

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
	/* the source lists, before anything that looks past the IP header */
	__u64 now = c->now_ns ? c->now_ns : bpf_ktime_get_coarse_ns();
	int l = lists(&k, now);
	if (l == 1)
		return PASS(BST_XDP_PASS_ALLOW);
	if (l == -1)
		return DROP(BST_XDP_DROP_DENY);
	if (l == -2)
		return DROP(BST_XDP_DROP_DYN);
	if (r == -2)
		return DROP(BST_XDP_DROP_V6EXT);
	if (r == 1)
		return PASS(BST_XDP_PASS);

	if (k.frag && (c->flags & BST_XDP_F_DROP_FRAGMENTS))
		return DROP(BST_XDP_DROP_FRAGMENT);
	if (k.frag == 2)
		return PASS(BST_XDP_PASS);

	struct scratch *s = bpf_map_lookup_elem(&scratch, &zero);
	if (!s)
		return PASS(BST_XDP_PASS);
	__builtin_memcpy(s->src, k.src, 16);
	s->v4 = k.v4;
	s->proto = k.proto;
	s->l4off = (__u32)(k.l4 - data);
	s->l4len = k.l4len;
	s->now = now;
	return bst_l4(ctx);
}

/* Steps 5 to 7, a global function: the verifier checks it once, on its own, instead of once per
 * path through the IPv6 header walk above (which took 6.12 past its 1M instruction limit). Its
 * inputs come through the per-CPU `scratch` entry the caller just wrote. */
__attribute__((noinline)) int bst_l4(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data, *end = (void *)(long)ctx->data_end;
	__u32 zero = 0;
	const struct bst_xdp_config *c = bpf_map_lookup_elem(&cfg, &zero);
	struct scratch *s = bpf_map_lookup_elem(&scratch, &zero);
	if (!c || !s)
		return XDP_PASS;
	__u32 off = s->l4off;
	/* the verifier keeps packet bounds only for offsets well under 64K: headers never get near */
	if (off > 0x3fff)
		return PASS(BST_XDP_PASS);
	struct pkt k = { .end = end, .l4 = data + (off & 0x3fff), .l4len = s->l4len, .proto = s->proto, .v4 = s->v4 };
	__builtin_memcpy(k.src, s->src, 16);
	__u64 now = s->now;
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
		/* only a connection's first packet is charged to the SYN bucket */
		if ((flags & 0x12) == 0x02 && over_rate(&k, BST_XDP_B_SYN, c->syn_rate, c->syn_burst, c, now))
			return DROP(BST_XDP_DROP_SYN_RATE);
		if (over_rate(&k, BST_XDP_B_PPS, c->pps_rate, c->pps_burst, c, now))
			return DROP(BST_XDP_DROP_PPS_RATE);
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
		if ((c->flags & BST_XDP_F_DROP_REFLECTION) &&
		    port_in(c->refl_ports, c->nrefl, BST_XDP_MAX_REFL_PORTS, bpf_ntohs(u->source)))
			return DROP(BST_XDP_DROP_REFLECTION);
		if ((c->flags & BST_XDP_F_QUIC_CHECK) &&
		    port_in(c->quic_ports, c->nquic, BST_XDP_MAX_PORTS, bpf_ntohs(u->dest)) &&
		    bad_quic((__u8 *)(u + 1), end, ulen - sizeof(*u)))
			return DROP(BST_XDP_DROP_QUIC);
		if (over_rate(&k, BST_XDP_B_UDP, c->udp_rate, c->udp_burst, c, now))
			return DROP(BST_XDP_DROP_UDP_RATE);
		if (over_rate(&k, BST_XDP_B_PPS, c->pps_rate, c->pps_burst, c, now))
			return DROP(BST_XDP_DROP_PPS_RATE);
		return PASS(BST_XDP_PASS);
	}
	return PASS(BST_XDP_PASS); /* ICMP, ICMPv6 and the rest */
}
