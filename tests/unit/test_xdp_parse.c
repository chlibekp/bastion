/* XDP filter, Phase 13 Task 2: packet parsing and the drops of malformed traffic. Every test runs
 * real packets through the loaded program (BPF_PROG_TEST_RUN). */
#include "tap.h"
#include "xdp_harness.h"

#include <errno.h>
#include <linux/bpf.h>
#include <string.h>

static uint32_t run(const uint8_t *b, size_t n)
{
	uint32_t act = 99;
	if (xdp_run(b, n, &act) != 0)
		return 98;
	return act;
}

static void protect(uint32_t flags)
{
	struct bst_xdp_config c;
	xdp_cfg_reset();
	xdp_cfg_get(&c);
	xdp_cfg_protect_443(&c);
	c.flags |= flags;
	xdp_cfg_set(&c);
}

TEST(vlan_tags)
{
	XDP_REQUIRE();
	protect(0);
	uint8_t b[256];
	for (int v = 0; v <= 2; v++) {
		pkt_opts o = { .vlans = v, .flags_zero = true }; /* a null scan: dropped only once parsed */
		xdp_stats_reset();
		ASSERT_EQ(run(b, pkt_tcp4(b, sizeof b, &o)), XDP_DROP);
		ASSERT_EQ(run(b, pkt_tcp6(b, sizeof b, &o)), XDP_DROP);
		ASSERT_EQ(xdp_stat(BST_XDP_DROP_TCP_FLAGS), 2);
		o.flags_zero = false;
		ASSERT_EQ(run(b, pkt_udp4(b, sizeof b, &o)), XDP_PASS);
	}
}

TEST(truncated_at_each_offset)
{
	XDP_REQUIRE();
	protect(0);
	uint8_t full[256];
	pkt_opts o = { .vlans = 2, .payload = 16 };
	size_t (*build[4])(uint8_t *, size_t, const pkt_opts *) = { pkt_tcp4, pkt_tcp6, pkt_udp4, pkt_udp6 };
	for (int i = 0; i < 4; i++) {
		size_t n = build[i](full, sizeof full, &o);
		for (size_t len = 0; len < n; len++) {
			uint32_t act = 99;
			int rc = xdp_run(full, len, &act);
			if (len < 14) { /* the kernel refuses a run shorter than an Ethernet header */
				ASSERT(rc == 0 || rc == -EINVAL);
				if (rc != 0)
					continue;
			}
			ASSERT_EQ(rc, 0);
			ASSERT(act == XDP_PASS || act == XDP_DROP);
			/* past the tags every prefix lacks bytes the IP length promises: dropped */
			if (len >= 22)
				ASSERT_EQ(act, XDP_DROP);
		}
		ASSERT_EQ(run(full, n), XDP_PASS);
	}
}

TEST(ip_bad_lengths)
{
	XDP_REQUIRE();
	protect(0);
	uint8_t b[256];
	size_t n = pkt_tcp4(b, sizeof b, NULL);
	b[14] = 0x44; /* IHL 4 */
	ASSERT_EQ(run(b, n), XDP_DROP);
	b[14] = 0x45;
	b[16] = 0x01; /* tot_len 256 + 40 > frame */
	ASSERT_EQ(run(b, n), XDP_DROP);
	b[16] = 0;
	b[17] = 10; /* tot_len below IHL */
	ASSERT_EQ(run(b, n), XDP_DROP);
	n = pkt_tcp6(b, sizeof b, NULL);
	b[18] = 0x10; /* payload_len past the frame */
	ASSERT_EQ(run(b, n), XDP_DROP);
	ASSERT(xdp_stat(BST_XDP_DROP_MALFORMED) >= 4);
}

TEST(tcp_bad_doff)
{
	XDP_REQUIRE();
	protect(0);
	uint8_t b[256];
	size_t n = pkt_tcp4(b, sizeof b, NULL);
	b[14 + 20 + 12] = 4 << 4;
	ASSERT_EQ(run(b, n), XDP_DROP);
	b[14 + 20 + 12] = 15 << 4; /* 60 bytes, past the frame */
	ASSERT_EQ(run(b, n), XDP_DROP);
	b[14 + 20 + 12] = 5 << 4;
	ASSERT_EQ(run(b, n), XDP_PASS);
}

TEST(tcp_flags)
{
	XDP_REQUIRE();
	protect(0);
	uint8_t b[256];
	static const uint8_t bad[] = { TCP_F_FIN | TCP_F_PSH | TCP_F_URG, TCP_F_SYN | TCP_F_FIN,
				       TCP_F_SYN | TCP_F_RST };
	pkt_opts o = { .flags_zero = true };
	ASSERT_EQ(run(b, pkt_tcp4(b, sizeof b, &o)), XDP_DROP);
	for (size_t i = 0; i < sizeof bad; i++) {
		pkt_opts x = { .tcp_flags = bad[i] };
		ASSERT_EQ(run(b, pkt_tcp4(b, sizeof b, &x)), XDP_DROP);
		ASSERT_EQ(run(b, pkt_tcp6(b, sizeof b, &x)), XDP_DROP);
	}
	static const uint8_t good[] = { TCP_F_SYN, TCP_F_SYN | TCP_F_ACK, TCP_F_ACK, TCP_F_ACK | TCP_F_PSH,
					TCP_F_FIN | TCP_F_ACK, TCP_F_RST, TCP_F_RST | TCP_F_ACK };
	for (size_t i = 0; i < sizeof good; i++) {
		pkt_opts x = { .tcp_flags = good[i] };
		ASSERT_EQ(run(b, pkt_tcp4(b, sizeof b, &x)), XDP_PASS);
	}
	/* drop_bad_tcp_flags off: a null scan passes */
	struct bst_xdp_config c;
	xdp_cfg_get(&c);
	c.flags &= ~(uint32_t)BST_XDP_F_DROP_BAD_TCP_FLAGS;
	xdp_cfg_set(&c);
	ASSERT_EQ(run(b, pkt_tcp4(b, sizeof b, &o)), XDP_PASS);
}

TEST(ipv4_fragments)
{
	XDP_REQUIRE();
	protect(0);
	uint8_t b[256];
	/* a later fragment: no L4 header to match (its "port" bytes are payload), passes */
	pkt_opts later = { .frag_off = 0x0010, .flags_zero = true };
	pkt_opts first = { .frag_off = 0x2000 };
	ASSERT_EQ(run(b, pkt_tcp4(b, sizeof b, &later)), XDP_PASS);
	ASSERT_EQ(run(b, pkt_tcp4(b, sizeof b, &first)), XDP_PASS);
	pkt_opts first_bad = { .frag_off = 0x2000, .flags_zero = true }; /* L4 checks still apply */
	ASSERT_EQ(run(b, pkt_tcp4(b, sizeof b, &first_bad)), XDP_DROP);
	protect(BST_XDP_F_DROP_FRAGMENTS);
	xdp_stats_reset();
	ASSERT_EQ(run(b, pkt_tcp4(b, sizeof b, &later)), XDP_DROP);
	ASSERT_EQ(run(b, pkt_tcp4(b, sizeof b, &first)), XDP_DROP);
	pkt_opts v6 = { .v6_frag = true, .v6_frag_off = 10 };
	ASSERT_EQ(run(b, pkt_udp6(b, sizeof b, &v6)), XDP_DROP);
	ASSERT_EQ(xdp_stat(BST_XDP_DROP_FRAGMENT), 3);
	ASSERT_EQ(run(b, pkt_tcp4(b, sizeof b, NULL)), XDP_PASS);
}

TEST(ipv6_extension_headers)
{
	XDP_REQUIRE();
	protect(0);
	uint8_t b[512];
	for (int n = 0; n <= BST_XDP_V6_EXT_MAX; n++) {
		pkt_opts o = { .v6_ext = n, .flags_zero = true };
		/* within the bound the TCP header is reached, so the null scan is seen */
		ASSERT_EQ(run(b, pkt_tcp6(b, sizeof b, &o)), XDP_DROP);
	}
	pkt_opts beyond = { .v6_ext = BST_XDP_V6_EXT_MAX + 1, .flags_zero = true };
	xdp_stats_reset();
	ASSERT_EQ(run(b, pkt_tcp6(b, sizeof b, &beyond)), XDP_PASS);
	protect(BST_XDP_F_DROP_V6_EXT);
	ASSERT_EQ(run(b, pkt_tcp6(b, sizeof b, &beyond)), XDP_DROP);
	ASSERT_EQ(xdp_stat(BST_XDP_DROP_V6EXT), 1);
	/* an extension header longer than the frame */
	pkt_opts one = { .v6_ext = 1 };
	size_t n = pkt_tcp6(b, sizeof b, &one);
	b[14 + 40 + 1] = 200;
	ASSERT_EQ(run(b, n), XDP_DROP);
	/* a later IPv6 fragment passes without drop_fragments */
	protect(0);
	pkt_opts f = { .v6_frag = true, .v6_frag_off = 3, .flags_zero = true };
	ASSERT_EQ(run(b, pkt_tcp6(b, sizeof b, &f)), XDP_PASS);
}

TEST(icmp_pass)
{
	XDP_REQUIRE();
	protect(BST_XDP_F_DROP_UNPROTECTED);
	uint8_t b[256];
	ASSERT_EQ(run(b, pkt_icmp4(b, sizeof b, NULL)), XDP_PASS);
	ASSERT_EQ(run(b, pkt_icmp6(b, sizeof b, NULL)), XDP_PASS);
	pkt_opts ext = { .v6_ext = 1 };
	ASSERT_EQ(run(b, pkt_icmp6(b, sizeof b, &ext)), XDP_PASS);
}

TEST(non_protected_port)
{
	XDP_REQUIRE();
	protect(0);
	uint8_t b[256];
	pkt_opts o = { .dport = 8080, .flags_zero = true }; /* not protected: no flag check either */
	ASSERT_EQ(run(b, pkt_tcp4(b, sizeof b, &o)), XDP_PASS);
	ASSERT_EQ(run(b, pkt_udp6(b, sizeof b, &o)), XDP_PASS);
	protect(BST_XDP_F_DROP_UNPROTECTED);
	xdp_stats_reset();
	ASSERT_EQ(run(b, pkt_tcp4(b, sizeof b, &o)), XDP_DROP);
	ASSERT_EQ(run(b, pkt_udp6(b, sizeof b, &o)), XDP_DROP);
	ASSERT_EQ(xdp_stat(BST_XDP_DROP_UNPROTECTED), 2);
	ASSERT_EQ(run(b, pkt_tcp4(b, sizeof b, NULL)), XDP_PASS);
}

TEST(udp_bad_length)
{
	XDP_REQUIRE();
	protect(0);
	uint8_t b[256];
	size_t n = pkt_udp4(b, sizeof b, NULL);
	b[14 + 20 + 5] = 4; /* below the header */
	ASSERT_EQ(run(b, n), XDP_DROP);
	b[14 + 20 + 5] = 200; /* past the IP length */
	ASSERT_EQ(run(b, n), XDP_DROP);
}

TAP_MAIN()
