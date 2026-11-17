/* XDP filter, Phase 13 Task 3: the allow and deny tries and the dynamic block maps. */
#include "tap.h"
#include "xdp_harness.h"

#include <linux/bpf.h>

static uint32_t run(const uint8_t *b, size_t n)
{
	uint32_t act = 99;
	return xdp_run(b, n, &act) == 0 ? act : 98;
}

static void fresh(uint64_t now)
{
	static const char *const maps[] = { "allow4", "allow6", "deny4", "deny6", "dyn_block4", "dyn_block6" };
	for (size_t i = 0; i < sizeof maps / sizeof *maps; i++)
		(void)xdp_map_clear(maps[i]);
	struct bst_xdp_config c;
	xdp_cfg_reset();
	xdp_cfg_get(&c);
	xdp_cfg_protect_443(&c);
	c.now_ns = now;
	xdp_cfg_set(&c);
	xdp_stats_reset();
}

TEST(allow_beats_deny)
{
	XDP_REQUIRE();
	fresh(1000);
	ASSERT_EQ(xdp_map_set_list("deny4", "192.0.2.0/24"), 0);
	ASSERT_EQ(xdp_map_set_list("allow4", "192.0.2.1/32"), 0);
	ASSERT_EQ(xdp_map_set_dyn("192.0.2.1", 32, 1u << 30), 0);
	uint8_t b[256];
	pkt_opts o = { .flags_zero = true }; /* a null scan: later checks would drop it */
	ASSERT_EQ(run(b, pkt_tcp4(b, sizeof b, &o)), XDP_PASS);
	ASSERT_EQ(xdp_stat(BST_XDP_PASS_ALLOW), 1);
	pkt_opts other = { .src = "192.0.2.2" };
	ASSERT_EQ(run(b, pkt_tcp4(b, sizeof b, &other)), XDP_DROP);
	ASSERT_EQ(xdp_stat(BST_XDP_DROP_DENY), 1);
}

TEST(deny_prefix)
{
	XDP_REQUIRE();
	fresh(1000);
	ASSERT_EQ(xdp_map_set_list("deny4", "10.0.0.0/8"), 0);
	ASSERT_EQ(xdp_map_set_list("allow4", "10.1.0.0/16"), 0);
	ASSERT_EQ(xdp_map_set_list("deny4", "10.1.2.0/24"), 0);
	uint8_t b[256];
	pkt_opts a = { .src = "10.9.9.9" }, c = { .src = "10.1.9.9" }, d = { .src = "11.0.0.1" };
	ASSERT_EQ(run(b, pkt_tcp4(b, sizeof b, &a)), XDP_DROP);
	ASSERT_EQ(run(b, pkt_tcp4(b, sizeof b, &c)), XDP_PASS);
	ASSERT_EQ(run(b, pkt_tcp4(b, sizeof b, &d)), XDP_PASS);
	/* the allow /16 is checked first: an allowlisted network can not be denied by a longer deny */
	pkt_opts e = { .src = "10.1.2.3" };
	ASSERT_EQ(run(b, pkt_tcp4(b, sizeof b, &e)), XDP_PASS);
	ASSERT_EQ(xdp_map_set_list("deny6", "2001:db8:bad::/48"), 0);
	pkt_opts f = { .src = "2001:db8:bad:1::5" }, g = { .src = "2001:db8:bae::5" };
	ASSERT_EQ(run(b, pkt_tcp6(b, sizeof b, &f)), XDP_DROP);
	ASSERT_EQ(run(b, pkt_tcp6(b, sizeof b, &g)), XDP_PASS);
}

TEST(dyn_block_active)
{
	XDP_REQUIRE();
	fresh(5000);
	ASSERT_EQ(xdp_map_set_dyn("192.0.2.1", 32, 6000), 0);
	uint8_t b[256];
	ASSERT_EQ(run(b, pkt_tcp4(b, sizeof b, NULL)), XDP_DROP);
	ASSERT_EQ(run(b, pkt_udp4(b, sizeof b, NULL)), XDP_DROP);
	ASSERT_EQ(xdp_stat(BST_XDP_DROP_DYN), 2);
	pkt_opts o = { .src = "192.0.2.9" };
	ASSERT_EQ(run(b, pkt_tcp4(b, sizeof b, &o)), XDP_PASS);
}

TEST(dyn_block_expired)
{
	XDP_REQUIRE();
	fresh(5000);
	ASSERT_EQ(xdp_map_set_dyn("192.0.2.1", 32, 5000), 0); /* expires at now: no longer active */
	uint8_t b[256];
	ASSERT_EQ(run(b, pkt_tcp4(b, sizeof b, NULL)), XDP_PASS);
	const uint8_t a[4] = { 192, 0, 2, 1 };
	uint64_t v = 0;
	ASSERT_EQ(xdp_map_get("dyn_block4", a, &v), 0); /* the entry may remain */
	ASSERT_EQ(v, 5000);
}

TEST(ipv6_prefix_block)
{
	XDP_REQUIRE();
	fresh(5000);
	ASSERT_EQ(xdp_map_set_dyn("2001:db8:1:2::", 64, 9000), 0);
	uint8_t b[256];
	pkt_opts a = { .src = "2001:db8:1:2::1" }, c = { .src = "2001:db8:1:2:ffff:ffff:ffff:ffff" },
		 d = { .src = "2001:db8:1:3::1" };
	ASSERT_EQ(run(b, pkt_tcp6(b, sizeof b, &a)), XDP_DROP);
	ASSERT_EQ(run(b, pkt_udp6(b, sizeof b, &c)), XDP_DROP);
	ASSERT_EQ(run(b, pkt_tcp6(b, sizeof b, &d)), XDP_PASS);
	ASSERT_EQ(xdp_map_set_dyn("2001:db8:9::", 48, 9000), 0);
	pkt_opts e = { .src = "2001:db8:9:ffff::1" };
	ASSERT_EQ(run(b, pkt_tcp6(b, sizeof b, &e)), XDP_DROP);
	ASSERT_EQ(xdp_map_set_dyn("2001:db8:7::7", 128, 9000), 0);
	pkt_opts f = { .src = "2001:db8:7::7" }, g = { .src = "2001:db8:7::8" };
	ASSERT_EQ(run(b, pkt_tcp6(b, sizeof b, &f)), XDP_DROP);
	ASSERT_EQ(run(b, pkt_tcp6(b, sizeof b, &g)), XDP_PASS);
}

TEST(mapped_v4_in_v6)
{
	XDP_REQUIRE();
	fresh(5000);
	ASSERT_EQ(xdp_map_set_list("deny4", "1.2.3.0/24"), 0);
	uint8_t b[256];
	pkt_opts a = { .src = "::ffff:1.2.3.4" }, c = { .src = "::ffff:1.2.4.4" };
	ASSERT_EQ(run(b, pkt_tcp6(b, sizeof b, &a)), XDP_DROP);
	ASSERT_EQ(run(b, pkt_tcp6(b, sizeof b, &c)), XDP_PASS);
	ASSERT_EQ(xdp_map_set_dyn("1.2.4.4", 32, 9000), 0);
	ASSERT_EQ(run(b, pkt_tcp6(b, sizeof b, &c)), XDP_DROP);
	ASSERT_EQ(xdp_map_set_list("allow4", "1.2.3.4/32"), 0);
	ASSERT_EQ(run(b, pkt_tcp6(b, sizeof b, &a)), XDP_PASS);
}

TEST(counters_per_reason)
{
	XDP_REQUIRE();
	fresh(5000);
	ASSERT_EQ(xdp_map_set_list("allow4", "192.0.2.10/32"), 0);
	ASSERT_EQ(xdp_map_set_list("deny4", "192.0.2.20/32"), 0);
	ASSERT_EQ(xdp_map_set_dyn("192.0.2.30", 32, 9000), 0);
	uint8_t b[256];
	const char *src[] = { "192.0.2.10", "192.0.2.20", "192.0.2.30", "192.0.2.40" };
	for (int round = 1; round <= 3; round++) {
		for (int i = 0; i < 4; i++) {
			pkt_opts o = { .src = src[i] };
			(void)run(b, pkt_tcp4(b, sizeof b, &o));
		}
		ASSERT_EQ(xdp_stat(BST_XDP_PASS_ALLOW), round);
		ASSERT_EQ(xdp_stat(BST_XDP_DROP_DENY), round);
		ASSERT_EQ(xdp_stat(BST_XDP_DROP_DYN), round);
		ASSERT_EQ(xdp_stat(BST_XDP_PASS), round);
		ASSERT_EQ(xdp_stat(BST_XDP_DROP_MALFORMED), 0);
	}
}

TAP_MAIN()
