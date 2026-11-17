/* XDP filter, Phase 13 Task 1: the embedded object loads (the verifier accepts it on this
 * kernel; tests/vm/test_xdp_vm.py runs this binary on the floor and current kernels too) and a
 * clean packet and a non-IP frame pass. */
#include "tap.h"
#include "xdp_harness.h"

#include <linux/bpf.h>

TEST(verifier_accepts)
{
	if (xdp_skip())
		return;
	ASSERT(xdp_map_fd("cfg") >= 0);
	ASSERT(xdp_map_fd("stats") >= 0);
}

TEST(passes_clean_tcp)
{
	if (xdp_skip())
		return;
	uint8_t b[256];
	uint32_t act = 99;
	xdp_stats_reset();
	ASSERT_EQ(xdp_run(b, pkt_tcp4(b, sizeof b, NULL), &act), 0);
	ASSERT_EQ(act, XDP_PASS);
	ASSERT_EQ(xdp_run(b, pkt_tcp6(b, sizeof b, NULL), &act), 0);
	ASSERT_EQ(act, XDP_PASS);
	ASSERT_EQ(xdp_stat(BST_XDP_PASS), 2);
}

TEST(non_ip_pass)
{
	if (xdp_skip())
		return;
	uint8_t b[64];
	uint32_t act = 99;
	xdp_stats_reset();
	ASSERT_EQ(xdp_run(b, pkt_arp(b, sizeof b), &act), 0);
	ASSERT_EQ(act, XDP_PASS);
	ASSERT_EQ(xdp_stat(BST_XDP_PASS_NON_IP), 1);
}

TAP_MAIN()
