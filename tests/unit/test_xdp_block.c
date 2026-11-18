/* The XDP block backend (xdp/block.h), Phase 13 Task 7, under the real block master (sec/block.h)
 * and a loaded filter on the loopback of a private network namespace. Covers what a compromised
 * worker can reach (its ring entries go through bst_block_apply) and that the backend's list is
 * the maps' real state. Needs root (skipped, loudly, without it). */
#include "tap.h"

#include "core/str.h"
#include "sec/block.h"
#include "xdp/block.h"
#include "xdp/loader.h"

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#define NOW 1000000000ull /* us */
#define CEIL 16u

typedef struct rig {
	bst_xdp *x;
	void *mem;
	bst_block_table *t;
	bst_block_backend shm, xb;
	bst_block_master *m;
} rig;

static bool netns(void)
{
	static int st;
	if (st == 0) {
		st = -1;
		if (geteuid() == 0 && unshare(CLONE_NEWNET) == 0) {
			int s = socket(AF_INET, SOCK_DGRAM, 0);
			struct ifreq r;
			memset(&r, 0, sizeof r);
			snprintf(r.ifr_name, sizeof r.ifr_name, "lo");
			if (s >= 0 && ioctl(s, SIOCGIFFLAGS, &r) == 0) {
				r.ifr_flags |= IFF_UP;
				st = ioctl(s, SIOCSIFFLAGS, &r) == 0 ? 1 : -1;
			}
			if (s >= 0)
				close(s);
		}
	}
	if (st != 1)
		printf("# SKIP: needs root and a private network namespace\n");
	return st == 1;
}

static bst_cidr cidr(const char *s)
{
	bst_cidr c;
	memset(&c, 0, sizeof c);
	if (!bst_cidr_parse((bst_str){ s, (uint32_t)strlen(s) }, &c))
		abort();
	return c;
}

static int open_rig(rig *r, const bst_cidr *master_ex, size_t nmex, const bst_cidr *xdp_ex, size_t nxex)
{
	memset(r, 0, sizeof *r);
	bst_cfg_xdp c;
	memset(&c, 0, sizeof c);
	c.ifaces[0] = "lo";
	c.nifaces = 1;
	c.mode = BST_XDP_GENERIC;
	c.pin_path = "/nonexistent/not-bpffs";
	c.ipv6_prefix = 64;
	c.dyn_size = 1024;
	bst_err e = { .msg = "" };
	r->x = bst_xdp_load(&c, &e);
	if (r->x == NULL) {
		printf("# %s\n", e.msg);
		return -1;
	}
	size_t sz = bst_block_table_bytes(CEIL);
	r->mem = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	r->t = bst_block_table_attach(r->mem, CEIL);
	if (bst_block_shm_backend(&r->shm, r->t, CEIL) != 0 ||
	    bst_block_backend_xdp(&r->xb, &r->shm, r->x, xdp_ex, nxex) != 0)
		return -1;
	r->m = bst_block_master_new(CEIL, master_ex, nmex, &r->xb);
	return r->m == NULL ? -1 : 0;
}

static void close_rig(rig *r)
{
	bst_block_master_free(r->m);
	bst_block_backend_xdp_free(&r->xb);
	bst_block_shm_backend_free(&r->shm);
	munmap(r->mem, bst_block_table_bytes(CEIL));
	bst_xdp_detach(r->x);
}

static bst_block_req req4(const char *a, uint8_t flags)
{
	bst_block_req q;
	memset(&q, 0, sizeof q);
	q.family = 4;
	q.prefix = 32;
	q.flags = flags;
	q.ttl_us = 60000000;
	if (inet_pton(AF_INET, a, q.addr) != 1)
		abort();
	return q;
}

static size_t map_count(rig *r, const char *map)
{
	int fd = bst_xdp_map_fd(r->x, map);
	uint8_t k[32], n[32];
	size_t c = 0;
	void *p = NULL;
	while (bpf_map_get_next_key(fd, p, n) == 0) {
		memcpy(k, n, sizeof k);
		p = k;
		c++;
	}
	return c;
}

static bool in_map4(rig *r, const char *a)
{
	uint8_t k[4];
	uint64_t v;
	inet_pton(AF_INET, a, k);
	return bpf_map_lookup_elem(bst_xdp_map_fd(r->x, "dyn_block4"), k, &v) == 0;
}

TEST(block_goes_to_map_with_ttl)
{
	if (!netns())
		return;
	rig r;
	ASSERT_EQ(open_rig(&r, NULL, 0, NULL, 0), 0);
	bst_block_req q = req4("192.0.2.9", 0);
	ASSERT_EQ(bst_block_apply(r.m, &q, NOW), BST_BLOCK_ADDED);
	bst_block_commit(r.m);
	uint8_t k[4] = { 192, 0, 2, 9 };
	uint64_t exp = 0;
	ASSERT_EQ(bpf_map_lookup_elem(bst_xdp_map_fd(r.x, "dyn_block4"), k, &exp), 0);
	ASSERT_EQ(exp, (NOW + 60000000ull) * 1000ull);
	/* expiry removes it from the map too */
	ASSERT_EQ(bst_block_expire(r.m, NOW + 61000000ull), 1);
	bst_block_commit(r.m);
	ASSERT(!in_map4(&r, "192.0.2.9"));
	close_rig(&r);
}

TEST(l7_only_never_in_map)
{
	if (!netns())
		return;
	rig r;
	ASSERT_EQ(open_rig(&r, NULL, 0, NULL, 0), 0);
	bst_block_req q = req4("198.51.100.9", BST_BLOCK_L7);
	ASSERT_EQ(bst_block_apply(r.m, &q, NOW), BST_BLOCK_ADDED);
	bst_block_commit(r.m);
	ASSERT(!in_map4(&r, "198.51.100.9"));
	bst_ip ip = { .family = BST_IP_V4, .b = { 198, 51, 100, 9 } };
	ASSERT(bst_block_lookup(r.t, &ip, NOW)); /* still enforced at L7 */
	close_rig(&r);
}

TEST(allowlist_protected)
{
	if (!netns())
		return;
	rig r;
	bst_cidr xex[2] = { cidr("203.0.113.0/24"), cidr("127.0.0.0/8") };
	ASSERT_EQ(open_rig(&r, NULL, 0, xex, 2), 0);
	bst_block_req a = req4("203.0.113.5", 0), b = req4("127.0.0.1", 0);
	(void)bst_block_apply(r.m, &a, NOW);
	(void)bst_block_apply(r.m, &b, NOW);
	bst_block_commit(r.m);
	ASSERT(!in_map4(&r, "203.0.113.5"));
	ASSERT(!in_map4(&r, "127.0.0.1"));
	ASSERT_EQ(bst_block_xdp_skipped(&r.xb), 2);
	close_rig(&r);
}

TEST(worker_compromise_limits)
{
	if (!netns())
		return;
	rig r;
	bst_cidr mex[1] = { cidr("10.0.0.0/8") };
	ASSERT_EQ(open_rig(&r, mex, 1, NULL, 0), 0);
	/* a fake worker floods its ring: whole networks, garbage, allowlisted, and far past the ceiling */
	int refused = 0;
	for (int i = 0; i < 1000; i++) {
		char a[32];
		snprintf(a, sizeof a, "198.18.%d.%d", i / 250, i % 250);
		bst_block_req q = req4(a, 0);
		if (i % 4 == 1)
			q.prefix = 8; /* a network, not an address */
		if (i % 4 == 2)
			q = req4("10.1.2.3", 0); /* allowlisted (escalation_allow / trusted proxy) */
		if (i % 4 == 3)
			q.ttl_us = 365ull * 86400 * 1000000; /* a year */
		bst_block_rc rc = bst_block_apply(r.m, &q, NOW);
		refused += rc != BST_BLOCK_ADDED && rc != BST_BLOCK_EXTENDED;
	}
	bst_block_commit(r.m);
	ASSERT(map_count(&r, "dyn_block4") <= CEIL);
	ASSERT(!in_map4(&r, "10.1.2.3"));
	ASSERT(refused >= 1000 - (int)CEIL);
	close_rig(&r);
}

TEST(list_matches_map)
{
	if (!netns())
		return;
	rig r;
	ASSERT_EQ(open_rig(&r, NULL, 0, NULL, 0), 0);
	const char *addrs[] = { "192.0.2.1", "192.0.2.2", "192.0.2.3" };
	for (int i = 0; i < 3; i++) {
		bst_block_req q = req4(addrs[i], 0);
		(void)bst_block_apply(r.m, &q, NOW);
	}
	bst_block_req l7 = req4("192.0.2.4", BST_BLOCK_L7);
	(void)bst_block_apply(r.m, &l7, NOW);
	bst_block_req v6;
	memset(&v6, 0, sizeof v6);
	v6.family = 6;
	v6.prefix = 64;
	v6.ttl_us = 60000000;
	inet_pton(AF_INET6, "2001:db8:1:2::", v6.addr);
	(void)bst_block_apply(r.m, &v6, NOW);
	bst_block_commit(r.m);
	/* someone removes one entry behind master's back: list shows the map, not master's memory */
	uint8_t k[4] = { 192, 0, 2, 2 };
	ASSERT_EQ(bpf_map_delete_elem(bst_xdp_map_fd(r.x, "dyn_block4"), k), 0);
	bst_block_entry out[16];
	size_t n = r.xb.list(r.xb.ctx, out, 16);
	ASSERT_EQ(n, 4); /* two IPv4 and one IPv6 in the maps, one L7 only */
	ASSERT_EQ(map_count(&r, "dyn_block4") + map_count(&r, "dyn_block6"), 3);
	int l7s = 0, v6s = 0;
	for (size_t i = 0; i < n; i++) {
		l7s += (out[i].flags & BST_BLOCK_L7) != 0;
		v6s += out[i].ip.family == BST_IP_V6 && out[i].prefix == 64;
		ASSERT(!(out[i].ip.family == BST_IP_V4 && out[i].ip.b[3] == 2 && !(out[i].flags & BST_BLOCK_L7)));
	}
	ASSERT_EQ(l7s, 1);
	ASSERT_EQ(v6s, 1);
	close_rig(&r);
}

TAP_MAIN()
