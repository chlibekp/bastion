/* The GCRA of limit_zone (sec/limit.c) on a simulated clock: exact counts, eight threads on one
 * key, a full table and a clock that went backwards. */
#include "sec/limit.h"
#include "tap.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

static bst_limit_zone *zone(uint64_t count, uint64_t period_us, uint64_t burst, uint32_t size)
{
	bst_limit_zone *z = calloc(1, sizeof *z);
	z->rate = (bst_rate){ count, period_us };
	z->burst = burst;
	z->size = size;
	z->status = 429;
	z->ipv6_prefix = 64;
	z->key_is_addr = true;
	void *mem = calloc(1, bst_limit_zone_bytes(z));
	if (bst_limit_zone_attach(z, mem) != 0)
		abort();
	return z;
}

static void zone_free(bst_limit_zone *z)
{
	free(z->slots);
	free(z);
}

static unsigned admitted_at(bst_limit_zone *z, bst_str key, uint64_t t, unsigned tries)
{
	unsigned ok = 0;
	for (unsigned i = 0; i < tries; i++)
		if (bst_limit_check(z, key, t).verdict == BST_LIMIT_ALLOW)
			ok++;
	return ok;
}

TEST(gcra_rate)
{
	static const struct { uint64_t count, period, burst; } cases[] = {
		{ 10, 1000000, 1 }, { 10, 1000000, 5 }, { 100, 1000000, 200 }, { 5, 60000000, 10 },
		{ 1, 1000000, 1 },
	};
	for (size_t c = 0; c < sizeof cases / sizeof cases[0]; c++) {
		bst_limit_zone *z = zone(cases[c].count, cases[c].period, cases[c].burst, 1024);
		uint64_t t0 = 1000000000ull;
		/* a fresh key: exactly burst at once */
		ASSERT_EQ(admitted_at(z, BST_S("k"), t0, (unsigned)cases[c].burst * 3), cases[c].burst);
		/* then exactly one per emission interval */
		uint64_t T = cases[c].period / cases[c].count;
		for (unsigned i = 1; i <= 5; i++)
			ASSERT_EQ(admitted_at(z, BST_S("k"), t0 + i * T, 3), 1);
		/* the refusal says when */
		bst_limit_result r = bst_limit_check(z, BST_S("k"), t0 + 5 * T);
		ASSERT_EQ(r.verdict, BST_LIMIT_REJECT);
		ASSERT(r.retry_after_us > 0 && r.retry_after_us <= T);
		/* another key is not affected */
		ASSERT_EQ(admitted_at(z, BST_S("other"), t0, 1), 1);
		zone_free(z);
	}
}

TEST(gcra_delay)
{
	bst_limit_zone *z = zone(10, 1000000, 2, 1024);
	z->delay = true;
	uint64_t t0 = 5000000;
	ASSERT_EQ(bst_limit_check(z, BST_S("k"), t0).verdict, BST_LIMIT_ALLOW);
	ASSERT_EQ(bst_limit_check(z, BST_S("k"), t0).verdict, BST_LIMIT_ALLOW);
	bst_limit_result r = bst_limit_check(z, BST_S("k"), t0);
	ASSERT_EQ(r.verdict, BST_LIMIT_DELAY);
	ASSERT_EQ(r.delay_us, 100000);
	ASSERT_EQ(bst_limit_check(z, BST_S("k"), t0).verdict, BST_LIMIT_DELAY);
	ASSERT_EQ(bst_limit_check(z, BST_S("k"), t0).verdict, BST_LIMIT_REJECT);
	zone_free(z);
}

typedef struct thr {
	bst_limit_zone *z;
	uint64_t t0;
	unsigned ok;
} thr;

/* One simulated clock for all threads: each check moves it 25 us on, over one second. */
static _Atomic uint64_t g_clock;

static void *hammer(void *ud)
{
	thr *t = ud;
	for (;;) {
		uint64_t us = atomic_fetch_add(&g_clock, 25);
		if (us >= 1000000)
			break;
		if (bst_limit_check(t->z, BST_S("shared"), t->t0 + us).verdict == BST_LIMIT_ALLOW)
			t->ok++;
	}
	return NULL;
}

TEST(gcra_cas_threads)
{
	bst_limit_zone *z = zone(1000, 1000000, 100, 1024);
	thr t[8];
	pthread_t id[8];
	for (int i = 0; i < 8; i++) {
		t[i] = (thr){ .z = z, .t0 = 10000000 };
		ASSERT_EQ(pthread_create(&id[i], NULL, hammer, &t[i]), 0);
	}
	unsigned total = 0;
	for (int i = 0; i < 8; i++) {
		pthread_join(id[i], NULL);
		total += t[i].ok;
	}
	/* the burst plus one per ms over the second: 1100, within 1% */
	printf("# admitted %u of a theoretical 1100\n", total);
	ASSERT(total >= 1089 && total <= 1111);
	zone_free(z);
}

TEST(table_full)
{
	bst_limit_zone *z = zone(1, 1000000, 1, 64);
	uint64_t t = 1000000;
	char k[32];
	/* far more keys than slots: every check returns, none spins */
	for (unsigned i = 0; i < 100000; i++) {
		int n = snprintf(k, sizeof k, "key-%u", i);
		bst_limit_result r = bst_limit_check(z, (bst_str){ k, (uint32_t)n }, t + i);
		ASSERT(r.verdict == BST_LIMIT_ALLOW || r.verdict == BST_LIMIT_REJECT);
	}
	/* a key that was pushed out is fresh again: its burst is back */
	ASSERT_EQ(bst_limit_check(z, BST_S("key-0"), t + 200000).verdict, BST_LIMIT_ALLOW);
	/* and a key in steady use survives an LRU replacement of the oldest slot */
	ASSERT_EQ(bst_limit_check(z, BST_S("hot"), t + 300000).verdict, BST_LIMIT_ALLOW);
	ASSERT_EQ(bst_limit_check(z, BST_S("hot"), t + 300000).verdict, BST_LIMIT_REJECT);
	zone_free(z);
}

TEST(clock_backwards)
{
	bst_limit_zone *z = zone(1, 1000000, 2, 1024);
	uint64_t late = 1000000000000ull;
	ASSERT_EQ(admitted_at(z, BST_S("k"), late, 5), 2);
	/* the clock now reads far earlier: the TAT is far ahead of any real sequence */
	uint64_t early = 1000000;
	ASSERT_EQ(bst_limit_check(z, BST_S("k"), early).verdict, BST_LIMIT_ALLOW);
	/* and from there on it behaves as a fresh, rate-limited key: no permanent lockout */
	ASSERT_EQ(admitted_at(z, BST_S("k"), early + 2000000, 5), 2);
	zone_free(z);
}

TEST(ipv6_prefix_key)
{
	bst_limit_zone *z = zone(1, 1000000, 1, 1024);
	bst_ip a, b, c, m, v4;
	ASSERT(bst_addr_parse(BST_S("2001:db8:1:2::1"), &a));
	ASSERT(bst_addr_parse(BST_S("2001:db8:1:2:ffff::9"), &b));
	ASSERT(bst_addr_parse(BST_S("2001:db8:1:3::1"), &c));
	ASSERT(bst_addr_parse(BST_S("::ffff:192.0.2.7"), &m));
	ASSERT(bst_addr_parse(BST_S("192.0.2.7"), &v4));
	ASSERT_EQ(bst_limit_key_ip(z, &a), bst_limit_key_ip(z, &b));
	ASSERT(bst_limit_key_ip(z, &a) != bst_limit_key_ip(z, &c));
	ASSERT_EQ(bst_limit_key_ip(z, &m), bst_limit_key_ip(z, &v4));
	zone_free(z);
}

TAP_MAIN()
