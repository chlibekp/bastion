/* XDP filter, Phase 13 Task 4: per-source packet rate limits, run on a fake clock (cfg.now_ns). */
#include "tap.h"
#include "xdp_harness.h"

#include <linux/bpf.h>
#include <stdio.h>

#define MS 1000000ull
#define T0 (1000ull * 1000 * MS)

static uint32_t run(const uint8_t *b, size_t n)
{
	uint32_t act = 99;
	return xdp_run(b, n, &act) == 0 ? act : 98;
}

static struct bst_xdp_config base(uint64_t now)
{
	static const char *const maps[] = { "allow4", "allow6", "deny4", "deny6", "dyn_block4", "dyn_block6", "rate" };
	for (size_t i = 0; i < sizeof maps / sizeof *maps; i++)
		(void)xdp_map_clear(maps[i]);
	struct bst_xdp_config c;
	xdp_cfg_reset();
	xdp_cfg_get(&c);
	xdp_cfg_protect_443(&c);
	c.now_ns = now;
	xdp_stats_reset();
	return c;
}

static void at(struct bst_xdp_config *c, uint64_t now)
{
	c->now_ns = now;
	xdp_cfg_set(c);
}

/* Sends n packets built by f with o; returns how many passed. */
static int send_n(size_t (*f)(uint8_t *, size_t, const pkt_opts *), const pkt_opts *o, int n)
{
	uint8_t b[256];
	size_t len = f(b, sizeof b, o);
	int passed = 0;
	for (int i = 0; i < n; i++)
		passed += run(b, len) == XDP_PASS;
	return passed;
}

TEST(syn_bucket)
{
	XDP_REQUIRE();
	struct bst_xdp_config c = base(T0);
	c.syn_rate = 10; /* T = 100 ms */
	c.syn_burst = 5;
	at(&c, T0);
	ASSERT_EQ(send_n(pkt_tcp4, NULL, 8), 5);
	ASSERT_EQ(xdp_stat(BST_XDP_DROP_SYN_RATE), 3);
	at(&c, T0 + 250 * MS); /* 2.5 intervals: two more */
	ASSERT_EQ(send_n(pkt_tcp4, NULL, 5), 2);
	at(&c, T0 + 10000 * MS); /* long idle: a full burst again, never more */
	ASSERT_EQ(send_n(pkt_tcp4, NULL, 9), 5);
	/* another source has its own bucket; an IPv6 /64 shares one */
	pkt_opts o = { .src = "192.0.2.77" };
	ASSERT_EQ(send_n(pkt_tcp4, &o, 6), 5);
	pkt_opts a = { .src = "2001:db8:5::1" }, b = { .src = "2001:db8:5::2" };
	ASSERT_EQ(send_n(pkt_tcp6, &a, 3) + send_n(pkt_tcp6, &b, 3), 5);
}

TEST(udp_bucket)
{
	XDP_REQUIRE();
	struct bst_xdp_config c = base(T0);
	c.syn_rate = 1;
	c.syn_burst = 1;
	c.udp_rate = 100;
	c.udp_burst = 20;
	at(&c, T0);
	ASSERT_EQ(send_n(pkt_tcp4, NULL, 4), 1);
	ASSERT_EQ(send_n(pkt_udp4, NULL, 30), 20); /* the SYN bucket being empty does not matter */
	ASSERT_EQ(xdp_stat(BST_XDP_DROP_UDP_RATE), 10);
	ASSERT_EQ(xdp_stat(BST_XDP_DROP_SYN_RATE), 3);
}

TEST(ack_not_syn_limited)
{
	XDP_REQUIRE();
	struct bst_xdp_config c = base(T0);
	c.syn_rate = 1;
	c.syn_burst = 1;
	at(&c, T0);
	pkt_opts ack = { .tcp_flags = TCP_F_ACK }, synack = { .tcp_flags = TCP_F_SYN | TCP_F_ACK };
	ASSERT_EQ(send_n(pkt_tcp4, NULL, 3), 1);
	ASSERT_EQ(send_n(pkt_tcp4, &ack, 50), 50);
	ASSERT_EQ(send_n(pkt_tcp4, &synack, 5), 5);
	/* pps_rate charges every protected packet */
	c.pps_rate = 1;
	c.pps_burst = 10;
	at(&c, T0);
	ASSERT_EQ(send_n(pkt_tcp4, &ack, 15), 10);
	ASSERT_EQ(xdp_stat(BST_XDP_DROP_PPS_RATE), 5);
}

TEST(lru_churn)
{
	XDP_REQUIRE();
	struct bst_xdp_config c = base(T0);
	c.syn_rate = 1;
	c.syn_burst = 1;
	at(&c, T0);
	uint8_t b[256];
	uint32_t seed = 12345;
	int errors = 0;
	for (int i = 0; i < 80000; i++) { /* more sources than the map holds */
		seed = seed * 1103515245u + 12345u;
		char src[32];
		snprintf(src, sizeof src, "10.%u.%u.%u", (seed >> 8) & 0xff, (seed >> 16) & 0xff, (seed >> 24) & 0xff);
		pkt_opts o = { .src = src };
		uint32_t act = 99;
		if (xdp_run(b, pkt_tcp4(b, sizeof b, &o), &act) != 0 || (act != XDP_PASS && act != XDP_DROP))
			errors++;
	}
	ASSERT_EQ(errors, 0);
	/* a known source still gets exactly its bucket */
	pkt_opts o = { .src = "203.0.113.5" };
	ASSERT_EQ(send_n(pkt_tcp4, &o, 3), 1);
}

TEST(per_cpu_scaling)
{
	XDP_REQUIRE();
	/* The configured total is split over the CPUs: one CPU gets it all, N CPUs a share each. */
	ASSERT_EQ(bst_xdp_per_cpu(100, 1), 100);
	ASSERT_EQ(bst_xdp_per_cpu(100, 4), 25);
	ASSERT_EQ(bst_xdp_per_cpu(10, 4), 3); /* rounded up */
	ASSERT_EQ(bst_xdp_per_cpu(1, 64), 1); /* never 0 for a set limit */
	ASSERT_EQ(bst_xdp_per_cpu(0, 4), 0);
	/* Simulated N = 4: each CPU's bucket admits its share; four CPUs together admit about the
	 * total (each CPU here is a fresh run of the map at the same instant). */
	for (unsigned n = 1; n <= 4; n *= 4) {
		struct bst_xdp_config c = base(T0);
		c.syn_rate = bst_xdp_per_cpu(20, n);
		c.syn_burst = bst_xdp_per_cpu(20, n);
		at(&c, T0);
		int total = 0;
		for (unsigned cpu = 0; cpu < n; cpu++) {
			(void)xdp_map_clear("rate"); /* another CPU: an empty per-CPU slot */
			total += send_n(pkt_tcp4, NULL, 30);
		}
		ASSERT_EQ(total, 20);
	}
}

TEST(allowlist_unlimited)
{
	XDP_REQUIRE();
	struct bst_xdp_config c = base(T0);
	c.syn_rate = c.udp_rate = c.pps_rate = 1;
	c.syn_burst = c.udp_burst = c.pps_burst = 1;
	at(&c, T0);
	ASSERT_EQ(xdp_map_set_list("allow4", "192.0.2.0/24"), 0);
	ASSERT_EQ(send_n(pkt_tcp4, NULL, 100), 100);
	ASSERT_EQ(send_n(pkt_udp4, NULL, 100), 100);
	pkt_opts o = { .src = "198.18.0.1" };
	ASSERT_EQ(send_n(pkt_tcp4, &o, 5), 1);
}

TEST(auto_block)
{
	XDP_REQUIRE();
	struct bst_xdp_config c = base(T0);
	c.syn_rate = 1;
	c.syn_burst = 1;
	at(&c, T0);
	/* off by default: drops go on, nothing is added */
	ASSERT_EQ(send_n(pkt_tcp4, NULL, 20), 1);
	ASSERT_EQ(xdp_stat(BST_XDP_AUTO_BLOCKED), 0);
	c.auto_after = 5;
	c.auto_ns = 2000 * MS;
	at(&c, T0);
	ASSERT_EQ(send_n(pkt_tcp4, NULL, 5), 0);
	ASSERT_EQ(xdp_stat(BST_XDP_AUTO_BLOCKED), 1);
	/* now in dyn_block: even an ACK is dropped, and only this source */
	pkt_opts ack = { .tcp_flags = TCP_F_ACK }, other = { .src = "192.0.2.2" };
	ASSERT_EQ(send_n(pkt_tcp4, &ack, 1), 0);
	ASSERT_EQ(xdp_stat(BST_XDP_DROP_DYN), 1);
	ASSERT_EQ(send_n(pkt_tcp4, &other, 1), 1);
	at(&c, T0 + 2001 * MS); /* the short TTL ran out */
	ASSERT_EQ(send_n(pkt_tcp4, &ack, 1), 1);
}

TAP_MAIN()
