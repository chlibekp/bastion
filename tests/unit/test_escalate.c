/* Escalation (sec/escalate.h) and master's block decisions (sec/block.h): one request per window,
 * exempt addresses, the ceiling, TTLs, a full ring, malformed entries, unvalidated peers and the
 * IPv6 prefix a block covers. */
#include "sec/block.h"
#include "sec/escalate.h"
#include "tap.h"

#include <stdlib.h>
#include <string.h>

#define S 1000000ull

static void *g_mem;

static void attach(int nworkers)
{
	free(g_mem);
	g_mem = calloc(1, bst_escalate_bytes(nworkers));
	if (bst_escalate_attach(g_mem, nworkers) != 0)
		abort();
	bst_escalate_worker(0);
}

static bst_ip ip(const char *s)
{
	bst_ip a;
	if (!bst_addr_parse((bst_str){ s, (uint32_t)strlen(s) }, &a))
		abort();
	return a;
}

static const bst_strike_src TCP = { .validated = true, .l7_only = false };

static bst_block_req req4(const char *a, uint64_t ttl)
{
	bst_block_req r;
	memset(&r, 0, sizeof r);
	bst_ip x = ip(a);
	r.family = 4;
	r.prefix = 32;
	memcpy(r.addr, x.b, 16);
	r.ttl_us = ttl;
	return r;
}

/* A master over a fresh shared table. */
typedef struct rig {
	void *mem;
	bst_block_table *t;
	bst_block_backend be;
	bst_block_master *m;
} rig;

static void rig_new(rig *r, unsigned ceiling, const bst_cidr *ex, size_t nex)
{
	r->mem = calloc(1, bst_block_table_bytes(ceiling));
	r->t = bst_block_table_attach(r->mem, ceiling);
	if (bst_block_shm_backend(&r->be, r->t, ceiling) != 0)
		abort();
	r->m = bst_block_master_new(ceiling, ex, nex, &r->be);
}

static void rig_free(rig *r)
{
	bst_block_master_free(r->m);
	bst_block_shm_backend_free(&r->be);
	free(r->mem);
}

TEST(strike_window)
{
	attach(2);
	bst_escalate_cfg cfg = { .after = 5, .window_us = 10 * S, .block_us = 60 * S };
	bst_ip a = ip("198.51.100.7");
	uint64_t t = 1000 * S;
	for (int i = 0; i < 4; i++)
		ASSERT_EQ(bst_escalate_strike(&cfg, &a, BST_STRIKE_LIMIT, &TCP, 64, t + (uint64_t)i * S), BST_STRIKE_COUNTED);
	/* the strikes of another worker count toward the same total */
	bst_escalate_worker(1);
	ASSERT_EQ(bst_escalate_strike(&cfg, &a, BST_STRIKE_LIMIT, &TCP, 64, t + 5 * S), BST_STRIKE_SENT);
	for (int i = 0; i < 20; i++) /* past the threshold: no second request this window */
		ASSERT_EQ(bst_escalate_strike(&cfg, &a, BST_STRIKE_LIMIT, &TCP, 64, t + 6 * S), BST_STRIKE_COUNTED);
	bst_block_req out[8];
	ASSERT_EQ(bst_escalate_drain(0, out, 8), 0);
	ASSERT_EQ(bst_escalate_drain(1, out, 8), 1);
	ASSERT_EQ(out[0].family, 4);
	ASSERT_EQ(out[0].prefix, 32);
	ASSERT_EQ(out[0].ttl_us, 60 * S);
	ASSERT_EQ(out[0].kind, BST_STRIKE_LIMIT);
	/* strikes spread wider than the window never add up */
	bst_ip b = ip("198.51.100.8");
	for (int i = 0; i < 10; i++)
		ASSERT_EQ(bst_escalate_strike(&cfg, &b, BST_STRIKE_LIMIT, &TCP, 64, t + (uint64_t)i * 3 * S), BST_STRIKE_COUNTED);
	/* another rule counts on its own */
	bst_escalate_cfg other = cfg;
	ASSERT_EQ(bst_escalate_strike(&other, &a, BST_STRIKE_LIMIT, &TCP, 64, t + 7 * S), BST_STRIKE_COUNTED);
	/* off */
	bst_escalate_cfg off = { 0 };
	ASSERT_EQ(bst_escalate_strike(&off, &a, BST_STRIKE_LIMIT, &TCP, 64, t), BST_STRIKE_OFF);
}

TEST(quic_unvalidated_no_strike)
{
	attach(1);
	bst_escalate_cfg cfg = { .after = 1, .window_us = 10 * S, .block_us = 60 * S };
	bst_ip a = ip("203.0.113.9");
	bst_strike_src spoofable = { .validated = false };
	for (int i = 0; i < 10; i++)
		ASSERT_EQ(bst_escalate_strike(&cfg, &a, BST_STRIKE_H2, &spoofable, 64, 1000 * S), BST_STRIKE_IGNORED);
	bst_block_req out[2];
	ASSERT_EQ(bst_escalate_drain(0, out, 2), 0);
	/* once validated, the first strike is enough */
	ASSERT_EQ(bst_escalate_strike(&cfg, &a, BST_STRIKE_H2, &TCP, 64, 1000 * S), BST_STRIKE_SENT);
}

TEST(proxy_protocol_l7_flag)
{
	attach(1);
	bst_escalate_cfg cfg = { .after = 1, .window_us = 10 * S, .block_us = 60 * S };
	bst_ip a = ip("192.0.2.44");
	bst_strike_src from_header = { .validated = true, .l7_only = true };
	ASSERT_EQ(bst_escalate_strike(&cfg, &a, BST_STRIKE_LIMIT, &from_header, 64, 1000 * S), BST_STRIKE_SENT);
	bst_block_req out[1];
	ASSERT_EQ(bst_escalate_drain(0, out, 1), 1);
	ASSERT_EQ(out[0].flags, BST_BLOCK_L7);
	rig r;
	rig_new(&r, 16, NULL, 0);
	ASSERT_EQ(bst_block_apply(r.m, &out[0], 0), BST_BLOCK_ADDED);
	bst_block_entry list[4];
	ASSERT_EQ(r.be.list(r.be.ctx, list, 4), 1);
	ASSERT_EQ(list[0].flags, BST_BLOCK_L7); /* what a network backend reads to skip it */
	rig_free(&r);
}

TEST(never_blocks_allowlisted)
{
	bst_cidr ex[3];
	ASSERT(bst_cidr_parse(BST_S("10.0.0.0/8"), &ex[0]));		/* escalation_allow */
	ASSERT(bst_cidr_parse(BST_S("192.0.2.1/32"), &ex[1]));		/* real_ip_from */
	ASSERT(bst_cidr_parse(BST_S("2001:db8:5:5:1::/80"), &ex[2])); /* inside a /64 */
	rig r;
	rig_new(&r, 16, ex, 3);
	bst_block_req q = req4("10.9.8.7", 60 * S);
	ASSERT_EQ(bst_block_apply(r.m, &q, 0), BST_BLOCK_EXEMPT);
	q = req4("192.0.2.1", 60 * S);
	ASSERT_EQ(bst_block_apply(r.m, &q, 0), BST_BLOCK_EXEMPT);
	q = req4("192.0.2.2", 60 * S);
	ASSERT_EQ(bst_block_apply(r.m, &q, 0), BST_BLOCK_ADDED);
	/* a /64 that contains an exempt /80 is refused as a whole */
	bst_block_req v6;
	memset(&v6, 0, sizeof v6);
	bst_ip x = ip("2001:db8:5:5::");
	v6.family = 6;
	v6.prefix = 64;
	memcpy(v6.addr, x.b, 16);
	v6.ttl_us = 60 * S;
	ASSERT_EQ(bst_block_apply(r.m, &v6, 0), BST_BLOCK_EXEMPT);
	bst_block_commit(r.m);
	bst_ip p = ip("10.9.8.7");
	ASSERT(!bst_block_lookup(r.t, &p, 1));
	p = ip("192.0.2.2");
	ASSERT(bst_block_lookup(r.t, &p, 1));
	ASSERT_EQ(bst_block_active(r.m), 1);
	rig_free(&r);
}

TEST(ceiling)
{
	rig r;
	rig_new(&r, 3, NULL, 0);
	char a[32];
	for (int i = 1; i <= 3; i++) {
		snprintf(a, sizeof a, "198.51.100.%d", i);
		bst_block_req q = req4(a, 60 * S);
		ASSERT_EQ(bst_block_apply(r.m, &q, 0), BST_BLOCK_ADDED);
	}
	bst_block_req q = req4("198.51.100.4", 60 * S);
	ASSERT_EQ(bst_block_apply(r.m, &q, 0), BST_BLOCK_CEILING);
	/* existing blocks stay, and renewing one is not a new block */
	q = req4("198.51.100.2", 60 * S);
	ASSERT_EQ(bst_block_apply(r.m, &q, 5 * S), BST_BLOCK_EXTENDED);
	bst_block_commit(r.m);
	bst_ip p = ip("198.51.100.1");
	ASSERT(bst_block_lookup(r.t, &p, 1));
	p = ip("198.51.100.4");
	ASSERT(!bst_block_lookup(r.t, &p, 1));
	ASSERT_EQ(bst_block_active(r.m), 3);
	rig_free(&r);
}

TEST(ttl_expiry)
{
	rig r;
	rig_new(&r, 16, NULL, 0);
	bst_block_req q = req4("203.0.113.5", 10 * S);
	ASSERT_EQ(bst_block_apply(r.m, &q, 100 * S), BST_BLOCK_ADDED);
	bst_block_commit(r.m);
	bst_ip p = ip("203.0.113.5"), mapped = ip("::ffff:203.0.113.5");
	ASSERT(bst_block_lookup(r.t, &p, 105 * S));
	ASSERT(bst_block_lookup(r.t, &mapped, 105 * S));
	/* readers stop honouring it at its expiry even before master removes it */
	ASSERT(!bst_block_lookup(r.t, &p, 110 * S));
	ASSERT_EQ(bst_block_expire(r.m, 109 * S), 0);
	ASSERT_EQ(bst_block_expire(r.m, 110 * S), 1);
	bst_block_commit(r.m);
	ASSERT_EQ(bst_block_active(r.m), 0);
	ASSERT(!bst_block_any(r.t));
	ASSERT(!bst_block_lookup(r.t, &p, 0));
	rig_free(&r);
}

TEST(ring_full)
{
	attach(1);
	bst_escalate_cfg cfg = { .after = 1, .window_us = 10 * S, .block_us = 60 * S };
	char a[32];
	unsigned sent = 0, dropped = 0;
	for (unsigned i = 0; i < BST_ESC_RING + 10; i++) {
		snprintf(a, sizeof a, "10.%u.%u.1", i / 256, i % 256);
		bst_ip x = ip(a);
		bst_strike_rc rc = bst_escalate_strike(&cfg, &x, BST_STRIKE_LIMIT, &TCP, 64, 1000 * S);
		sent += rc == BST_STRIKE_SENT;
		dropped += rc == BST_STRIKE_DROPPED;
	}
	ASSERT_EQ(sent, BST_ESC_RING);
	ASSERT_EQ(dropped, 10);
	ASSERT(bst_escalate_dropped() >= 10);
	static bst_block_req out[BST_ESC_RING + 10];
	ASSERT_EQ(bst_escalate_drain(0, out, BST_ESC_RING + 10), BST_ESC_RING);
	/* drained: room again */
	bst_ip x = ip("172.16.0.1");
	ASSERT_EQ(bst_escalate_strike(&cfg, &x, BST_STRIKE_LIMIT, &TCP, 64, 1000 * S), BST_STRIKE_SENT);
}

TEST(malformed_ring_entry)
{
	rig r;
	rig_new(&r, 16, NULL, 0);
	bst_block_req good = req4("198.51.100.20", 60 * S), q;
	ASSERT_EQ(bst_block_apply(r.m, &good, 0), BST_BLOCK_ADDED);
	q = good, q.family = 5;
	ASSERT_EQ(bst_block_apply(r.m, &q, 0), BST_BLOCK_MALFORMED);
	q = good, q.prefix = 8; /* a whole network: never from a worker */
	ASSERT_EQ(bst_block_apply(r.m, &q, 0), BST_BLOCK_MALFORMED);
	q = good, q.addr[10] = 1; /* bytes past an IPv4 address */
	ASSERT_EQ(bst_block_apply(r.m, &q, 0), BST_BLOCK_MALFORMED);
	q = good, q.flags = 0x80;
	ASSERT_EQ(bst_block_apply(r.m, &q, 0), BST_BLOCK_MALFORMED);
	q = good, q.kind = 200;
	ASSERT_EQ(bst_block_apply(r.m, &q, 0), BST_BLOCK_MALFORMED);
	q = good, q.pad = 7;
	ASSERT_EQ(bst_block_apply(r.m, &q, 0), BST_BLOCK_MALFORMED);
	q = good, q.ttl_us = 0;
	ASSERT_EQ(bst_block_apply(r.m, &q, 0), BST_BLOCK_MALFORMED);
	q = good, q.ttl_us = 365ull * 86400 * S; /* longer than a day */
	ASSERT_EQ(bst_block_apply(r.m, &q, 0), BST_BLOCK_MALFORMED);
	memset(&q, 0, sizeof q);
	bst_ip x = ip("2001:db8::1");
	q.family = 6, q.prefix = 64, q.ttl_us = 60 * S;
	memcpy(q.addr, x.b, 16); /* host bits below the /64 */
	ASSERT_EQ(bst_block_apply(r.m, &q, 0), BST_BLOCK_MALFORMED);
	q.prefix = 16; /* wider than /48 */
	ASSERT_EQ(bst_block_apply(r.m, &q, 0), BST_BLOCK_MALFORMED);
	/* garbage bytes */
	unsigned char junk[sizeof q];
	for (unsigned i = 0; i < sizeof junk; i++)
		junk[i] = (unsigned char)(i * 37 + 11);
	memcpy(&q, junk, sizeof q);
	ASSERT_EQ(bst_block_apply(r.m, &q, 0), BST_BLOCK_MALFORMED);
	ASSERT_EQ(bst_block_active(r.m), 1);
	rig_free(&r);
}

TEST(ipv6_prefix_block)
{
	attach(1);
	bst_escalate_cfg cfg = { .after = 1, .window_us = 10 * S, .block_us = 60 * S };
	bst_ip a = ip("2001:db8:aa:bb:1:2:3:4");
	ASSERT_EQ(bst_escalate_strike(&cfg, &a, BST_STRIKE_LIMIT, &TCP, 64, 1000 * S), BST_STRIKE_SENT);
	/* another address of the same /64 is the same client in the same window */
	bst_ip a2 = ip("2001:db8:aa:bb::99");
	ASSERT_EQ(bst_escalate_strike(&cfg, &a2, BST_STRIKE_LIMIT, &TCP, 64, 1000 * S), BST_STRIKE_COUNTED);
	bst_block_req out[2];
	ASSERT_EQ(bst_escalate_drain(0, out, 2), 1);
	ASSERT_EQ(out[0].family, 6);
	ASSERT_EQ(out[0].prefix, 64);
	rig r;
	rig_new(&r, 16, NULL, 0);
	ASSERT_EQ(bst_block_apply(r.m, &out[0], 0), BST_BLOCK_ADDED);
	bst_block_commit(r.m);
	bst_ip in = ip("2001:db8:aa:bb:ffff:ffff:ffff:ffff"), out64 = ip("2001:db8:aa:bc::1"),
	       v4 = ip("192.0.2.1");
	ASSERT(bst_block_lookup(r.t, &a, 1));
	ASSERT(bst_block_lookup(r.t, &in, 1));
	ASSERT(!bst_block_lookup(r.t, &out64, 1));
	ASSERT(!bst_block_lookup(r.t, &v4, 1));
	rig_free(&r);
}

TEST(table_flip_keeps_entries)
{
	rig r;
	rig_new(&r, 64, NULL, 0);
	char a[32];
	for (int round = 0; round < 5; round++) {
		for (int i = 0; i < 40; i++) {
			snprintf(a, sizeof a, "100.64.%d.%d", round, i);
			bst_block_req q = req4(a, 60 * S);
			ASSERT_EQ(bst_block_apply(r.m, &q, (uint64_t)round * S), BST_BLOCK_ADDED);
			if (bst_block_active(r.m) > 60)
				break;
		}
		bst_block_commit(r.m);
		(void)bst_block_expire(r.m, (uint64_t)round * S + 60 * S); /* everything of this round */
		bst_block_commit(r.m);
	}
	ASSERT_EQ(bst_block_active(r.m), 0);
	bst_block_req q = req4("100.64.9.9", 60 * S);
	ASSERT_EQ(bst_block_apply(r.m, &q, 0), BST_BLOCK_ADDED);
	bst_block_commit(r.m);
	bst_ip p = ip("100.64.9.9"), old = ip("100.64.0.1");
	ASSERT(bst_block_lookup(r.t, &p, 1));
	ASSERT(!bst_block_lookup(r.t, &old, 1));
	rig_free(&r);
}

/* What a new master reads back from a table a reload kept: every live entry, flags and expiry. */
TEST(table_snapshot)
{
	rig r;
	rig_new(&r, 64, NULL, 0);
	bst_block_req q = req4("198.51.100.7", 60 * S);
	ASSERT_EQ(bst_block_apply(r.m, &q, 0), BST_BLOCK_ADDED);
	q = req4("198.51.100.8", 30 * S);
	q.flags = BST_BLOCK_L7;
	ASSERT_EQ(bst_block_apply(r.m, &q, 0), BST_BLOCK_ADDED);
	bst_block_commit(r.m);
	bst_block_entry v[8];
	ASSERT_EQ(bst_block_table_snapshot(r.t, v, 8), 2);
	ASSERT_EQ(bst_block_table_snapshot(r.t, v, 1), 1); /* bounded by cap */
	ASSERT_EQ(bst_block_table_snapshot(r.t, v, 8), 2);
	bst_ip a = ip("198.51.100.7"), b = ip("198.51.100.8");
	int seen = 0;
	for (int i = 0; i < 2; i++) {
		ASSERT_EQ(v[i].prefix, 32);
		if (bst_ip_eq(&v[i].ip, &a)) {
			ASSERT_EQ(v[i].expires_us, 60 * S);
			ASSERT_EQ(v[i].flags, 0);
			seen |= 1;
		} else if (bst_ip_eq(&v[i].ip, &b)) {
			ASSERT_EQ(v[i].expires_us, 30 * S);
			ASSERT_EQ(v[i].flags, BST_BLOCK_L7);
			seen |= 2;
		}
	}
	ASSERT_EQ(seen, 3);
	/* an empty list forced out empties the table (a reload that kept nothing) */
	bst_block_master *m2 = bst_block_master_new(64, NULL, 0, &r.be);
	ASSERT(bst_block_remove(r.m, &v[0]) && bst_block_remove(r.m, &v[1]));
	bst_block_commit_force(m2);
	ASSERT_EQ(bst_block_table_snapshot(r.t, v, 8), 0);
	bst_block_master_free(m2);
	rig_free(&r);
}

TAP_MAIN()
