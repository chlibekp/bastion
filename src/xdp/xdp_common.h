/* Definitions shared by the XDP filter (xdp/xdp_bastion.bpf.c) and its user-space side (the
 * loader, the block backend, the tests). Plain fixed-width layouts only: the same header is
 * compiled for the BPF target and for the host, and every map key and value below crosses that
 * boundary byte for byte. */
#ifndef BST_XDP_COMMON_H
#define BST_XDP_COMMON_H

#include <linux/types.h>

/* What happened to a packet, counted per CPU in the `stats` map (index = reason). The PASS
 * reasons let the tests and metrics tell "passed by allowlist" from "passed, nothing matched". */
enum bst_xdp_reason {
	BST_XDP_PASS = 0,	     /* nothing matched */
	BST_XDP_PASS_ALLOW,	     /* source in allow4/allow6: every later check skipped */
	BST_XDP_PASS_NON_IP,	     /* not IPv4 or IPv6 (ARP, LLDP, a third VLAN tag, ...) */
	BST_XDP_DROP_MALFORMED,	     /* a header that does not fit the frame or its own lengths */
	BST_XDP_DROP_TCP_FLAGS,	     /* null, xmas, SYN+FIN, SYN+RST */
	BST_XDP_DROP_FRAGMENT,	     /* drop_fragments on */
	BST_XDP_DROP_DENY,	     /* source in deny4/deny6 */
	BST_XDP_DROP_DYN,	     /* source under an unexpired dyn_block4/dyn_block6 entry */
	BST_XDP_DROP_UNPROTECTED,    /* drop_unprotected on, destination port not protected */
	BST_XDP_DROP_SYN_RATE,	     /* over syn_rate */
	BST_XDP_DROP_UDP_RATE,	     /* over udp_rate */
	BST_XDP_DROP_PPS_RATE,	     /* over pps_rate */
	BST_XDP_DROP_REFLECTION,     /* UDP from an amplification port to a protected port */
	BST_XDP_DROP_QUIC,	     /* not the shape of a QUIC packet on a QUIC port */
	BST_XDP_DROP_V6EXT,	     /* more IPv6 extension headers than walked, drop_v6_ext on */
	BST_XDP_AUTO_BLOCKED,	     /* not a verdict: dyn_block entries the rate limiter added */
	BST_XDP_NREASONS
};

#define BST_XDP_MAX_PORTS 16	  /* protected TCP, UDP and QUIC ports each */
#define BST_XDP_MAX_REFL_PORTS 32 /* amplification source ports */
#define BST_XDP_V6_EXT_MAX 6	  /* IPv6 extension headers walked */

/* bst_xdp_config.flags */
#define BST_XDP_F_DROP_FRAGMENTS (1u << 0)
#define BST_XDP_F_DROP_BAD_TCP_FLAGS (1u << 1)
#define BST_XDP_F_DROP_UNPROTECTED (1u << 2)
#define BST_XDP_F_DROP_REFLECTION (1u << 3)
#define BST_XDP_F_QUIC_CHECK (1u << 4)
#define BST_XDP_F_DROP_V6_EXT (1u << 5)

/* The one entry of the `cfg` array. Rates are packets per second PER CPU (the loader divides the
 * configured total by the online CPU count), 0 = off; bursts are packets. */
struct bst_xdp_config {
	__u32 flags;
	__u16 ntcp, nudp, nquic, nrefl;
	__u16 tcp_ports[BST_XDP_MAX_PORTS];
	__u16 udp_ports[BST_XDP_MAX_PORTS];
	__u16 quic_ports[BST_XDP_MAX_PORTS];
	__u16 refl_ports[BST_XDP_MAX_REFL_PORTS];
	__u16 v6_prefix; /* rate and auto-block key length for IPv6 sources: 48, 56, 64 or 128 */
	__u16 pad0;
	/* v6_prefix as a byte mask (bst_xdp_v6_mask): the program ANDs with it instead of branching
	 * per byte on a variable prefix, which the 6.1 verifier can not follow within its limit. */
	__u8 v6_mask[16];
	__u64 syn_rate, syn_burst;
	__u64 udp_rate, udp_burst;
	__u64 pps_rate, pps_burst;
	/* auto_block: a source dropped by a rate limit auto_after times within one second is put in
	 * dyn_block for auto_ns. 0 = off (the default). */
	__u32 auto_after, pad1;
	__u64 auto_ns;
	/* Test clock: when non-zero, the program uses it instead of bpf_ktime_get_coarse_ns. The
	 * loader always writes 0; only the unit tests set it, through the map. */
	__u64 now_ns;
};

/* LPM_TRIE keys: prefixlen in bits, then the address in network order. */
struct bst_xdp_lpm4 {
	__u32 prefixlen;
	__u8 addr[4];
};

struct bst_xdp_lpm6 {
	__u32 prefixlen;
	__u8 addr[16];
};

/* dyn_block6 key: the address masked to prefix (one of 48, 56, 64, 128). dyn_block4 keys are
 * the bare IPv4 address (__u32, network order); both maps hold the expiry, in
 * CLOCK_MONOTONIC_COARSE nanoseconds (bpf_ktime_get_coarse_ns), as a __u64. */
struct bst_xdp_dyn6 {
	__u8 prefix, pad[3];
	__u8 addr[16];
};

/* The prefixes dyn_block6 is looked up at, longest first. */
#define BST_XDP_DYN6_PREFIXES 4

/* `rate` key: one bucket per source and kind. IPv4 sources (and ::ffff: mapped ones) are keyed by
 * the address, IPv6 by the address masked to cfg.v6_prefix. */
enum bst_xdp_bucket { BST_XDP_B_SYN = 0, BST_XDP_B_UDP, BST_XDP_B_PPS };

struct bst_xdp_rkey {
	__u8 family, kind, pad[2];
	__u8 addr[16];
};

/* GCRA state of one bucket on one CPU, plus the over-limit run for auto_block. */
struct bst_xdp_rval {
	__u64 tat;	  /* theoretical arrival time, ns */
	__u64 over_start; /* start of the current one-second over-limit window */
	__u32 over;	  /* drops in that window */
	__u32 pad;
};

#ifndef __bpf__
/* The per-CPU share of a configured total (rate or burst): the buckets are per CPU, so a source
 * whose packets land on several CPUs (RSS spreads by flow) gets up to ncpu shares. Rounded up and
 * at least 1, so a small limit never becomes "drop everything"; 0 stays 0 (off). */
static inline __u64 bst_xdp_per_cpu(__u64 total, unsigned ncpu)
{
	if (total == 0)
		return 0;
	if (ncpu == 0)
		ncpu = 1;
	return (total + ncpu - 1) / ncpu;
}

/* The 16-byte mask of an IPv6 prefix length (for bst_xdp_config.v6_mask). */
static inline void bst_xdp_v6_mask(unsigned prefix, __u8 out[16])
{
	for (unsigned i = 0; i < 16; i++) {
		unsigned bits = prefix > i * 8 ? prefix - i * 8 : 0;
		out[i] = bits >= 8 ? 0xff : (__u8)(0xff00u >> bits);
	}
}
#endif

#endif
