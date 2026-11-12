/* Load balancing (proxy/balance.c) on hand-built upstreams, with a private health region and
 * injected loads. */
#include "config/compile.h"
#include "config/parser.h"
#include "proxy/balance.h"
#include "proxy/upstream.h"
#include "tap.h"

#include <stdio.h>
#include <string.h>

#define MAXP 16
static bst_up_server SV[MAXP];
static bst_peer P[MAXP];
static bst_cfg_upstream U;
static unsigned LOAD[MAXP];
static char HOSTS[MAXP][16];

static unsigned load(const bst_peer *p)
{
	return LOAD[p - P];
}

static void mk(size_t n, const unsigned *w, bst_balance_algo algo)
{
	memset(&U, 0, sizeof U);
	memset(SV, 0, sizeof SV);
	memset(P, 0, sizeof P);
	memset(LOAD, 0, sizeof LOAD);
	for (size_t i = 0; i < n; i++) {
		snprintf(HOSTS[i], sizeof HOSTS[i], "10.0.0.%zu", i + 1);
		SV[i] = (bst_up_server){ .host = HOSTS[i], .port = 80, .weight = w ? w[i] : 1,
					 .first_peer = i, .npeers = 1 };
		P[i].addr.ip.family = BST_IP_V4;
		P[i].addr.ip.b[0] = 10;
		P[i].addr.ip.b[3] = (uint8_t)(i + 1);
		P[i].addr.port = 80;
		P[i].weight = w ? w[i] : 1;
		P[i].state = i;
		P[i].server = i;
	}
	U.name = "t";
	U.servers = SV;
	U.nservers = n;
	U.peers = P;
	U.npeers = n;
	U.balance = algo;
	bst_balance_test_reset();
	bst_upstate_test_map(MAXP);
	bst_test_balance_load = load;
}

static int pick_at(uint64_t now, const char *key)
{
	bst_sockaddr a;
	bst_pick_ctx c = { .now_ms = now ? now : 1, .key = { key ? key : "", key ? (uint32_t)strlen(key) : 0 } };
	const bst_peer *p = bst_balance_pick(&U, &c, &a);
	return p == NULL ? -1 : (int)(p - P);
}

static int pick(void)
{
	return pick_at(1, NULL);
}

TEST(rr_weights)
{
	unsigned w[] = { 2, 1 };
	mk(2, w, BST_BAL_ROUND_ROBIN);
	int a = 0, prev = -1;
	for (int k = 1; k <= 300; k++) {
		int p = pick();
		ASSERT(p == 0 || p == 1);
		a += p == 0;
		ASSERT(!(p == 1 && prev == 1)); /* smooth: the light one never twice in a row */
		double want = 2.0 * k / 3.0;
		ASSERT(a >= want - 1.0 && a <= want + 1.0);
		prev = p;
	}
	ASSERT_EQ(a, 200);
}

TEST(least_conn_prefers_idle)
{
	mk(3, NULL, BST_BAL_LEAST_CONN);
	LOAD[0] = 5;
	LOAD[1] = 0;
	LOAD[2] = 3;
	for (int i = 0; i < 10; i++)
		ASSERT_EQ(pick(), 1);
	/* relative to weight: 4 open on weight 4 beats 2 open on weight 1 */
	unsigned w[] = { 4, 1 };
	mk(2, w, BST_BAL_LEAST_CONN);
	LOAD[0] = 4;
	LOAD[1] = 2;
	ASSERT_EQ(pick(), 0);
	/* equal: they take turns */
	mk(2, NULL, BST_BAL_LEAST_CONN);
	int seen[2] = { 0 };
	for (int i = 0; i < 10; i++)
		seen[pick()]++;
	ASSERT(seen[0] > 0 && seen[1] > 0);
}

TEST(hash_stable)
{
	for (int consistent = 0; consistent < 2; consistent++) {
		mk(5, NULL, BST_BAL_HASH);
		U.hash_consistent = consistent;
		int first = pick_at(1, "user-42");
		ASSERT(first >= 0);
		for (int i = 0; i < 100; i++)
			ASSERT_EQ(pick_at(1, "user-42"), first);
		int other = 0;
		char k[32];
		for (int i = 0; i < 200; i++) {
			snprintf(k, sizeof k, "key-%d", i);
			other += pick_at(1, k) != first;
		}
		ASSERT(other > 100); /* different keys spread */
	}
}

TEST(hash_minimal_movement)
{
	mk(10, NULL, BST_BAL_HASH);
	U.hash_consistent = true;
	enum { KEYS = 10000 };
	static int before[KEYS];
	char k[32];
	int per[10] = { 0 };
	for (int i = 0; i < KEYS; i++) {
		snprintf(k, sizeof k, "k%d", i);
		before[i] = pick_at(1, k);
		per[before[i]]++;
	}
	for (int i = 0; i < 10; i++)
		ASSERT(per[i] > KEYS / 20); /* every peer has a share */
	bst_peer_set_down(&P[3], true);
	int moved = 0;
	for (int i = 0; i < KEYS; i++) {
		snprintf(k, sizeof k, "k%d", i);
		int now = pick_at(1, k);
		if (now != before[i]) {
			moved++;
			ASSERT_EQ(before[i], 3); /* only the removed peer's keys move */
		}
	}
	printf("# moved %d of %d\n", moved, KEYS);
	ASSERT(moved >= KEYS / 20 && moved <= KEYS * 15 / 100);
	/* bounded load: a peer far over the average passes keys on */
	bst_peer_set_down(&P[3], false);
	int target = pick_at(1, "hot");
	LOAD[target] = 100;
	ASSERT(pick_at(1, "hot") != target);
}

TEST(ewma_avoids_slow)
{
	mk(2, NULL, BST_BAL_PEAK_EWMA);
	int slow = 0;
	uint64_t now = 1000;
	for (int i = 0; i < 2000; i++) {
		int p = pick_at(now, NULL);
		ASSERT(p == 0 || p == 1);
		slow += p == 1;
		bst_balance_observe(&U, &P[p], p == 1 ? 100 : 10, now);
		now += 5;
	}
	printf("# slow peer got %d of 2000\n", slow);
	ASSERT(slow < 2000 * 30 / 100);
}

TEST(slow_start_ramp)
{
	mk(2, NULL, BST_BAL_ROUND_ROBIN);
	P[0].slow_start_ms = 10000;
	bst_peer_set_down(&P[0], true);
	ASSERT_EQ(pick_at(1000, NULL), 1);
	bst_peer_set_down(&P[0], false);
	(void)pick_at(2000, NULL); /* seen up again at 2 s: the ramp starts */
	int share[3];
	uint64_t at[3] = { 3000, 8000, 13000 };
	for (int t = 0; t < 3; t++) {
		share[t] = 0;
		for (int i = 0; i < 1000; i++)
			share[t] += pick_at(at[t], NULL) == 0;
		printf("# share at %llu ms: %d/1000\n", (unsigned long long)at[t], share[t]);
	}
	ASSERT(share[0] >= 50 && share[0] <= 150);  /* 10% of its weight: about 9% */
	ASSERT(share[1] >= 300 && share[1] <= 450); /* 60%: about 37% */
	ASSERT(share[2] >= 450 && share[2] <= 550); /* full weight: half */
}

TEST(skips_unhealthy)
{
	mk(3, NULL, BST_BAL_ROUND_ROBIN);
	bst_peer_set_down(&P[1], true);
	for (int i = 0; i < 30; i++)
		ASSERT(pick() != 1);
	for (int a = BST_BAL_LEAST_CONN; a <= BST_BAL_PEAK_EWMA; a++) {
		U.balance = (bst_balance_algo)a;
		for (int i = 0; i < 30; i++)
			ASSERT(pick_at(1, "k") != 1);
	}
}

TEST(backup_only_when_needed)
{
	mk(2, NULL, BST_BAL_ROUND_ROBIN);
	P[1].backup = true;
	for (int i = 0; i < 20; i++)
		ASSERT_EQ(pick(), 0);
	bst_peer_set_down(&P[0], true);
	ASSERT_EQ(pick(), 1);
	/* max_conns full is the same as not available */
	bst_peer_set_down(&P[0], false);
	P[0].max_conns = 2;
	LOAD[0] = 2;
	ASSERT_EQ(pick(), 1);
}

TEST(no_peer_returns_null)
{
	mk(2, NULL, BST_BAL_ROUND_ROBIN);
	bst_peer_set_down(&P[0], true);
	bst_peer_set_down(&P[1], true);
	ASSERT_EQ(pick(), -1);
	mk(0, NULL, BST_BAL_ROUND_ROBIN);
	ASSERT_EQ(pick(), -1);
	/* a dynamic peer with no address yet */
	mk(1, NULL, BST_BAL_ROUND_ROBIN);
	P[0].dynamic = true;
	ASSERT_EQ(pick(), -1);
	bst_upstate_test_reset();
	bst_balance_test_reset();
}

TEST(balance_directive)
{
	bst_err e;
	bst_arena *a = bst_arena_new(1 << 16);
	const char *src = "upstream u { balance hash $remote_addr consistent; "
			  "server 127.0.0.1:1 slow_start=10s; server 127.0.0.1:2; }\n"
			  "upstream v { balance peak_ewma; server 127.0.0.1:3; }\nserver { listen 80; }";
	bst_ast *ast = bst_cfg_parse_string(src, strlen(src), "t.conf", NULL, a, &e);
	ASSERT(ast != NULL);
	bst_config *c = bst_cfg_compile(ast, &e);
	ASSERT(c != NULL);
	ASSERT_EQ(c->global.upstreams[0]->balance, BST_BAL_HASH);
	ASSERT(c->global.upstreams[0]->hash_consistent && c->global.upstreams[0]->hash_key != NULL);
	ASSERT_EQ(c->global.upstreams[0]->peers[0].slow_start_ms, 10000);
	ASSERT_EQ(c->global.upstreams[1]->balance, BST_BAL_PEAK_EWMA);
	bst_config_free(c);
	/* one balance per upstream */
	src = "upstream u { balance least_conn; balance peak_ewma; server 127.0.0.1:1; }\n"
	      "server { listen 80; }";
	ast = bst_cfg_parse_string(src, strlen(src), "t.conf", NULL, a, &e);
	ASSERT(ast != NULL && bst_cfg_compile(ast, &e) == NULL);
	bst_arena_free(a);
}

TAP_MAIN()
