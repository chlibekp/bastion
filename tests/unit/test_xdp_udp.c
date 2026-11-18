/* XDP filter, Phase 13 Task 5: the reflection filter and the QUIC shape checks. */
#include "tap.h"
#include "xdp_harness.h"

#include <linux/bpf.h>
#include <string.h>

static uint32_t run(const uint8_t *b, size_t n)
{
	uint32_t act = 99;
	return xdp_run(b, n, &act) == 0 ? act : 98;
}

static void setup(bool quic)
{
	struct bst_xdp_config c;
	xdp_cfg_reset();
	xdp_cfg_get(&c);
	xdp_cfg_protect_443(&c);
	static const uint16_t refl[] = { 53, 123, 389, 1900, 11211, 19, 161 };
	memcpy(c.refl_ports, refl, sizeof refl);
	c.nrefl = sizeof refl / sizeof *refl;
	c.flags |= BST_XDP_F_DROP_REFLECTION;
	if (quic) {
		c.quic_ports[0] = 443;
		c.nquic = 1;
		c.flags |= BST_XDP_F_QUIC_CHECK;
	}
	xdp_cfg_set(&c);
	xdp_stats_reset();
}

/* A QUIC long header of version ver and packet type bits typ, in a datagram of len bytes. */
static size_t quic_long(uint8_t *b, size_t cap, uint32_t ver, unsigned typ, bool fixed, size_t len)
{
	static uint8_t d[1500];
	memset(d, 0, len);
	d[0] = (uint8_t)(0x80 | (fixed ? 0x40 : 0) | (typ << 4));
	d[1] = (uint8_t)(ver >> 24);
	d[2] = (uint8_t)(ver >> 16);
	d[3] = (uint8_t)(ver >> 8);
	d[4] = (uint8_t)ver;
	pkt_opts o = { .payload = len, .data = d };
	return pkt_udp4(b, cap, &o);
}

TEST(reflection_drop)
{
	XDP_REQUIRE();
	setup(false);
	uint8_t b[256];
	pkt_opts o = { .sport = 11211 };
	ASSERT_EQ(run(b, pkt_udp4(b, sizeof b, &o)), XDP_DROP);
	o.sport = 53;
	ASSERT_EQ(run(b, pkt_udp6(b, sizeof b, &o)), XDP_DROP);
	ASSERT_EQ(xdp_stat(BST_XDP_DROP_REFLECTION), 2);
	o.sport = 40001;
	ASSERT_EQ(run(b, pkt_udp4(b, sizeof b, &o)), XDP_PASS);
	/* off: passes */
	struct bst_xdp_config c;
	xdp_cfg_get(&c);
	c.flags &= ~(uint32_t)BST_XDP_F_DROP_REFLECTION;
	xdp_cfg_set(&c);
	o.sport = 11211;
	ASSERT_EQ(run(b, pkt_udp4(b, sizeof b, &o)), XDP_PASS);
}

TEST(reflection_other_dst)
{
	XDP_REQUIRE();
	setup(false);
	uint8_t b[256];
	pkt_opts o = { .sport = 53, .dport = 51234 }; /* a DNS reply to Bastion's resolver */
	ASSERT_EQ(run(b, pkt_udp4(b, sizeof b, &o)), XDP_PASS);
	ASSERT_EQ(run(b, pkt_udp6(b, sizeof b, &o)), XDP_PASS);
	ASSERT_EQ(xdp_stat(BST_XDP_DROP_REFLECTION), 0);
}

TEST(quic_short_initial)
{
	XDP_REQUIRE();
	setup(true);
	uint8_t b[1600];
	ASSERT_EQ(run(b, quic_long(b, sizeof b, 1, 0, true, 500)), XDP_DROP);
	ASSERT_EQ(run(b, quic_long(b, sizeof b, 0x6b3343cf, 1, true, 500)), XDP_DROP); /* v2 Initial */
	ASSERT_EQ(xdp_stat(BST_XDP_DROP_QUIC), 2);
	ASSERT_EQ(run(b, quic_long(b, sizeof b, 1, 0, true, 1200)), XDP_PASS);
	ASSERT_EQ(run(b, quic_long(b, sizeof b, 1, 2, true, 100)), XDP_PASS); /* v1 Handshake: small is fine */
	pkt_opts empty = { 0 };
	ASSERT_EQ(run(b, pkt_udp4(b, sizeof b, &empty)), XDP_DROP);
}

TEST(quic_fixed_bit_clear)
{
	XDP_REQUIRE();
	setup(true);
	uint8_t b[1600];
	ASSERT_EQ(run(b, quic_long(b, sizeof b, 1, 0, false, 1200)), XDP_DROP);
	uint8_t d[40] = { 0x01 }; /* short header without the fixed bit */
	pkt_opts o = { .payload = sizeof d, .data = d };
	ASSERT_EQ(run(b, pkt_udp4(b, sizeof b, &o)), XDP_DROP);
}

TEST(quic_unknown_version)
{
	XDP_REQUIRE();
	setup(true);
	uint8_t b[1600];
	ASSERT_EQ(run(b, quic_long(b, sizeof b, 0x1a2a3a4a, 0, true, 300)), XDP_PASS);
	ASSERT_EQ(run(b, quic_long(b, sizeof b, 0xff00001d, 0, false, 300)), XDP_PASS);
	ASSERT_EQ(xdp_stat(BST_XDP_DROP_QUIC), 0);
}

TEST(quic_short_header_small)
{
	XDP_REQUIRE();
	setup(true);
	uint8_t b[256];
	uint8_t d[30] = { 0x40 | 0x01 };
	pkt_opts o = { .payload = sizeof d, .data = d };
	ASSERT_EQ(run(b, pkt_udp4(b, sizeof b, &o)), XDP_PASS);
	ASSERT_EQ(run(b, pkt_udp6(b, sizeof b, &o)), XDP_PASS);
}

TEST(udp_no_quic_config)
{
	XDP_REQUIRE();
	setup(false); /* no http3 listener: no QUIC port */
	uint8_t b[1600];
	ASSERT_EQ(run(b, quic_long(b, sizeof b, 1, 0, true, 500)), XDP_PASS);
	ASSERT_EQ(run(b, quic_long(b, sizeof b, 1, 0, false, 50)), XDP_PASS);
	/* a QUIC port with the check flag off: inactive too */
	struct bst_xdp_config c;
	xdp_cfg_get(&c);
	c.quic_ports[0] = 443;
	c.nquic = 1;
	xdp_cfg_set(&c);
	ASSERT_EQ(run(b, quic_long(b, sizeof b, 1, 0, true, 500)), XDP_PASS);
}

TAP_MAIN()
