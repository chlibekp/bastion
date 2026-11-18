/* XDP loader (xdp/loader.h), Phase 13 Task 6: load, attach to the loopback of a private network
 * namespace (generic mode), reconfigure without a gap or a detach, detach. Config reload itself
 * arrives in Phase 14; this is the reload path it will call. Needs root (skipped, loudly,
 * without it). */
#include "tap.h"

#include "core/str.h"
#include "xdp/loader.h"

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

static bool in_netns(void)
{
	static int state; /* 0 untried, 1 ok, -1 failed */
	if (state == 0) {
		state = -1;
		if (geteuid() == 0 && unshare(CLONE_NEWNET) == 0) {
			int s = socket(AF_INET, SOCK_DGRAM, 0);
			struct ifreq r;
			memset(&r, 0, sizeof r);
			snprintf(r.ifr_name, sizeof r.ifr_name, "lo");
			if (s >= 0 && ioctl(s, SIOCGIFFLAGS, &r) == 0) {
				r.ifr_flags |= IFF_UP;
				if (ioctl(s, SIOCSIFFLAGS, &r) == 0)
					state = 1;
			}
			if (s >= 0)
				close(s);
		}
	}
	if (state != 1)
		printf("# SKIP: needs root and a private network namespace\n");
	return state == 1;
}

static bst_cidr cidr(const char *s)
{
	bst_cidr c;
	memset(&c, 0, sizeof c);
	if (!bst_cidr_parse((bst_str){ s, (uint32_t)strlen(s) }, &c))
		abort();
	return c;
}

static bst_cfg_xdp base(void)
{
	bst_cfg_xdp c;
	memset(&c, 0, sizeof c);
	c.ifaces[0] = "lo";
	c.nifaces = 1;
	c.mode = BST_XDP_GENERIC;
	c.pin_path = "/nonexistent/not-bpffs"; /* nothing pinned: the link ends with x */
	c.ipv6_prefix = 64;
	c.dyn_size = 1024;
	c.flags = BST_XDP_F_DROP_BAD_TCP_FLAGS;
	return c;
}

static uint32_t attached_id(void)
{
	__u32 id = 0;
	LIBBPF_OPTS(bpf_xdp_query_opts, q);
	if (bpf_xdp_query((int)if_nametoindex("lo"), XDP_FLAGS_SKB_MODE, &q) == 0)
		id = q.skb_prog_id;
	return id;
}

static bool has4(bst_xdp *x, const char *map, const char *c)
{
	bst_cidr v = cidr(c);
	struct bst_xdp_lpm4 k = { .prefixlen = v.prefix };
	memcpy(k.addr, v.ip.b, 4);
	uint8_t val;
	return bpf_map_lookup_elem(bst_xdp_map_fd(x, map), &k, &val) == 0;
}

TEST(load_attach_detach)
{
	if (!in_netns())
		return;
	bst_cfg_xdp c = base();
	bst_err e = { .msg = "" };
	bst_xdp *x = bst_xdp_load(&c, &e);
	if (x == NULL)
		printf("# %s\n", e.msg);
	ASSERT(x != NULL);
	ASSERT_STR(bst_xdp_mode_of(x, 0), "generic");
	ASSERT(attached_id() != 0);
	bst_xdp_detach(x);
	ASSERT_EQ(attached_id(), 0);
}

TEST(no_interface_error)
{
	if (!in_netns())
		return;
	bst_cfg_xdp c = base();
	c.ifaces[0] = "bst-none0";
	bst_err e = { .msg = "" };
	ASSERT(bst_xdp_load(&c, &e) == NULL);
	ASSERT(strstr(e.msg, "bst-none0") != NULL);
	ASSERT_EQ(attached_id(), 0);
}

TEST(native_require_on_lo)
{
	if (!in_netns())
		return;
	bst_cfg_xdp c = base();
	c.mode = BST_XDP_NATIVE;
	c.require = true;
	bst_err e = { .msg = "" };
	ASSERT(bst_xdp_load(&c, &e) == NULL); /* lo has no driver XDP */
	ASSERT(strstr(e.msg, "native mode refused") != NULL);
	c.require = false; /* without require: generic, warned */
	bst_xdp *x = bst_xdp_load(&c, &e);
	ASSERT(x != NULL);
	ASSERT_STR(bst_xdp_mode_of(x, 0), "generic");
	bst_xdp_detach(x);
}

TEST(reconfigure_no_gap)
{
	if (!in_netns())
		return;
	bst_cfg_xdp c = base();
	bst_cidr a1[2] = { cidr("192.0.2.0/24"), cidr("2001:db8::/32") }, d1[1] = { cidr("198.51.100.7/32") };
	c.allow = a1;
	c.nallow = 2;
	c.deny = d1;
	c.ndeny = 1;
	bst_err e = { .msg = "" };
	bst_xdp *x = bst_xdp_load(&c, &e);
	ASSERT(x != NULL);
	uint32_t id = attached_id();
	ASSERT(has4(x, "allow4", "192.0.2.0/24"));
	ASSERT(has4(x, "deny4", "198.51.100.7/32"));
	/* new lists: one kept, one replaced, one added */
	bst_cidr a2[1] = { cidr("192.0.2.0/24") }, d2[2] = { cidr("198.51.100.8/32"), cidr("203.0.113.0/24") };
	c.allow = a2;
	c.nallow = 1;
	c.deny = d2;
	c.ndeny = 2;
	c.syn_rate = 100;
	ASSERT_EQ(bst_xdp_reconfigure(x, &c, &e), 0);
	ASSERT_EQ(attached_id(), id); /* the same program, never detached */
	ASSERT(has4(x, "allow4", "192.0.2.0/24"));
	ASSERT(!has4(x, "deny4", "198.51.100.7/32"));
	ASSERT(has4(x, "deny4", "198.51.100.8/32"));
	ASSERT(has4(x, "deny4", "203.0.113.0/24"));
	struct bst_xdp_lpm6 k6 = { .prefixlen = 32, .addr = { 0x20, 0x01, 0x0d, 0xb8 } };
	uint8_t v;
	ASSERT(bpf_map_lookup_elem(bst_xdp_map_fd(x, "allow6"), &k6, &v) != 0); /* removed */
	struct bst_xdp_config cfg;
	uint32_t zero = 0;
	ASSERT_EQ(bpf_map_lookup_elem(bst_xdp_map_fd(x, "cfg"), &zero, &cfg), 0);
	ASSERT(cfg.syn_rate >= 1 && cfg.syn_rate <= 100);
	bst_xdp_detach(x);
}

TEST(stats_read)
{
	if (!in_netns())
		return;
	bst_cfg_xdp c = base();
	bst_err e = { .msg = "" };
	bst_xdp *x = bst_xdp_load(&c, &e);
	ASSERT(x != NULL);
	/* traffic over lo passes through the generic hook */
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in to = { .sin_family = AF_INET, .sin_port = htons(9), .sin_addr.s_addr = htonl(0x7f000001) };
	for (int i = 0; i < 10; i++)
		(void)sendto(s, "x", 1, 0, (struct sockaddr *)&to, sizeof to);
	close(s);
	bst_xdp_stats st;
	ASSERT_EQ(bst_xdp_read_stats(x, &st), 0);
	ASSERT(st.n[BST_XDP_PASS] >= 10);
	ASSERT_STR(bst_xdp_reason_name(BST_XDP_DROP_DENY), "deny");
	bst_xdp_detach(x);
}

TAP_MAIN()
