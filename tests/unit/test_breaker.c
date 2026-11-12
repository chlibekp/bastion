/* The circuit breaker, retry budget, passive ejection, panic threshold and the resilience
 * directives (proxy/breaker.c, retry.c, upstream.c, health.c). */
#include "config/compile.h"
#include "config/parser.h"
#include "proxy/balance.h"
#include "proxy/breaker.h"
#include "proxy/health.h"
#include "proxy/retry.h"
#include "proxy/upstream.h"
#include "tap.h"

#include <string.h>

TEST(breaker_states)
{
	bst_up_breaker cfg = { .fails = 3, .for_ms = 1000 };
	bst_breaker b;
	bst_breaker_init(&b, &cfg);
	bool probe;
	uint64_t t = 1000;
	/* closed: three failures in a row open it */
	for (int i = 0; i < 3; i++) {
		ASSERT(bst_breaker_admit(&b, t, &probe) && !probe);
		bst_breaker_done(&b, true, false, probe, t);
	}
	ASSERT_EQ(b.st, BST_BRK_OPEN);
	ASSERT(!bst_breaker_admit(&b, t + 10, &probe));
	ASSERT_EQ(bst_breaker_retry_after(&b, t + 10), 1);
	/* half-open after `for`: one probe, the next request waits for it */
	ASSERT(bst_breaker_admit(&b, t + 1000, &probe) && probe);
	ASSERT_EQ(b.st, BST_BRK_HALF_OPEN);
	ASSERT(!bst_breaker_admit(&b, t + 1001, &probe));
	/* the probe fails: open again */
	bst_breaker_done(&b, true, false, true, t + 1002);
	ASSERT_EQ(b.st, BST_BRK_OPEN);
	/* the next probe succeeds: closed */
	ASSERT(bst_breaker_admit(&b, t + 2100, &probe) && probe);
	bst_breaker_done(&b, true, true, true, t + 2101);
	ASSERT_EQ(b.st, BST_BRK_CLOSED);
	ASSERT(bst_breaker_admit(&b, t + 2102, &probe) && !probe);
	/* a success resets the run */
	bst_breaker_done(&b, true, true, false, t);
	ASSERT_EQ(b.consec_fail, 0);
	ASSERT_EQ(b.active, 0);
}

TEST(breaker_limits)
{
	bst_up_breaker cfg = { .max_pending = 2, .max_active = 3, .max_retries = 1, .for_ms = 1000 };
	bst_breaker b;
	bst_breaker_init(&b, &cfg);
	bool probe;
	ASSERT(bst_breaker_admit(&b, 1, &probe));
	ASSERT(bst_breaker_admit(&b, 1, &probe));
	ASSERT(!bst_breaker_admit(&b, 1, &probe)); /* two pending */
	bst_breaker_answered(&b);
	ASSERT(bst_breaker_admit(&b, 1, &probe));
	bst_breaker_answered(&b);
	ASSERT(!bst_breaker_admit(&b, 1, &probe)); /* three active */
	ASSERT(bst_breaker_retry(&b));
	ASSERT(!bst_breaker_retry(&b));
	bst_breaker_retry_done(&b);
	ASSERT(bst_breaker_retry(&b));
	ASSERT_EQ(b.st, BST_BRK_CLOSED); /* limits refuse without opening */
}

TEST(retry_budget)
{
	bst_cfg_upstream u;
	memset(&u, 0, sizeof u);
	u.retry.budget_pct = 20;
	bst_retry_test_reset();
	unsigned retries = 0;
	for (int i = 0; i < 1000; i++) {
		bst_retry_note_request(&u);
		retries += bst_retry_take(&u) ? 1u : 0u; /* every request fails and wants a retry */
	}
	ASSERT(retries <= 200 + 3);
	ASSERT(retries >= 190);
	bst_retry_test_reset();
	u.retry.budget_pct = 0;
	retries = 0;
	for (int i = 0; i < 100; i++) {
		bst_retry_note_request(&u);
		retries += bst_retry_take(&u) ? 1u : 0u;
	}
	ASSERT_EQ(retries, 3); /* only the reserve */
	bst_retry_test_reset();
}

TEST(passive_eject_and_panic)
{
	static bst_up_server sv[2];
	static bst_peer p[2];
	bst_cfg_upstream u;
	memset(&u, 0, sizeof u);
	memset(sv, 0, sizeof sv);
	memset(p, 0, sizeof p);
	for (int i = 0; i < 2; i++) {
		sv[i] = (bst_up_server){ .host = "h", .port = (uint16_t)(1 + i), .weight = 1,
					 .first_peer = (size_t)i, .npeers = 1 };
		p[i] = (bst_peer){ .weight = 1, .state = (size_t)i, .server = (size_t)i };
		p[i].addr.ip.family = BST_IP_V4;
		p[i].addr.port = (uint16_t)(1 + i);
	}
	u.servers = sv;
	u.nservers = 2;
	u.peers = p;
	u.npeers = 2;
	u.name = "u";
	bst_upstate_test_map(2);
	bst_up_passive pc = { .fails = 3, .window_ms = 1000, .for_ms = 60000 };
	uint64_t now = bst_mono_ms();
	ASSERT(!bst_peer_passive_fail(&p[0], &pc, now));
	ASSERT(!bst_peer_passive_fail(&p[0], &pc, now + 1));
	ASSERT(bst_peer_passive_fail(&p[0], &pc, now + 2));
	ASSERT(!bst_peer_up(&p[0]));
	/* failures spread wider than the window never eject */
	ASSERT(!bst_peer_passive_fail(&p[1], &pc, now));
	ASSERT(!bst_peer_passive_fail(&p[1], &pc, now + 2000));
	ASSERT(!bst_peer_passive_fail(&p[1], &pc, now + 4000));
	ASSERT(bst_peer_up(&p[1]));
	/* both down: no pick (the handler answers 503); with panic_threshold every peer is used */
	bst_peer_set_down(&p[1], true);
	bst_sockaddr a;
	bst_pick_ctx ctx = { .key = { "k", 1 } };
	ASSERT(bst_balance_pick(&u, &ctx, &a) == NULL);
	ASSERT(bst_upstream_any_addr(&u));
	u.panic_pct = 50;
	ASSERT(bst_balance_pick(&u, &ctx, &a) != NULL);
	/* a retry avoids the peers already tried */
	const bst_peer *av[1] = { &p[0] };
	ctx.avoid = av;
	ctx.navoid = 1;
	ASSERT(bst_balance_pick(&u, &ctx, &a) == &p[1]);
	bst_upstate_test_reset();
	bst_balance_test_reset();
}

TEST(health_expect)
{
	unsigned lo, hi;
	ASSERT(bst_health_parse_expect("200", 3, &lo, &hi) && lo == 200 && hi == 200);
	ASSERT(bst_health_parse_expect("200-399", 7, &lo, &hi) && lo == 200 && hi == 399);
	ASSERT(!bst_health_parse_expect("399-200", 7, &lo, &hi));
	ASSERT(!bst_health_parse_expect("2000", 4, &lo, &hi));
	ASSERT(!bst_health_parse_expect("abc", 3, &lo, &hi));
	ASSERT(!bst_health_parse_expect("", 0, &lo, &hi));
}

TEST(resilience_directives)
{
	bst_err e;
	bst_arena *ar = bst_arena_new(1 << 16);
	const char *src =
		"upstream u { server 127.0.0.1:1; server 127.0.0.1:2;\n"
		"  health_check path=/hz interval=2s timeout=500ms fails=2 passes=3 expect=204;\n"
		"  passive_eject fails=4 window=5s for=20s;\n"
		"  retry attempts=2 budget=10% on=error,timeout,5xx timeout=3s;\n"
		"  circuit_breaker max_pending=10 max_active=20 max_retries=3 fails=5 for=7s;\n"
		"  panic_threshold 30%; }\n"
		"upstream v { server 127.0.0.1:3; }\nserver { listen 80; }";
	bst_ast *ast = bst_cfg_parse_string(src, strlen(src), "t.conf", NULL, ar, &e);
	ASSERT(ast != NULL);
	bst_config *c = bst_cfg_compile(ast, &e);
	ASSERT(c != NULL);
	const bst_cfg_upstream *u = c->global.upstreams[0];
	ASSERT(u->health.on);
	ASSERT_STR(u->health.path, "/hz");
	ASSERT_EQ(u->health.interval_ms, 2000);
	ASSERT_EQ(u->health.timeout_ms, 500);
	ASSERT_EQ(u->health.expect_lo, 204);
	ASSERT_EQ(u->passive.fails, 4);
	ASSERT_EQ(u->passive.for_ms, 20000);
	ASSERT_EQ(u->retry.attempts, 2);
	ASSERT_EQ(u->retry.budget_pct, 10);
	ASSERT_EQ(u->retry.on, BST_RETRY_ON_ERROR | BST_RETRY_ON_TIMEOUT | BST_RETRY_ON_5XX);
	ASSERT_EQ(u->breaker.max_pending, 10);
	ASSERT_EQ(u->breaker.for_ms, 7000);
	ASSERT_EQ(u->panic_pct, 30);
	const bst_cfg_upstream *v = c->global.upstreams[1];
	ASSERT(!v->health.on);
	ASSERT_EQ(v->retry.attempts, 1);
	ASSERT_EQ(v->retry.on, BST_RETRY_ON_ERROR);
	ASSERT_EQ(v->passive.fails, 0);
	bst_config_free(c);
	src = "upstream u { server 127.0.0.1:1; retry on=bogus; }\nserver { listen 80; }";
	ast = bst_cfg_parse_string(src, strlen(src), "t.conf", NULL, ar, &e);
	ASSERT(ast != NULL && bst_cfg_compile(ast, &e) == NULL);
	src = "upstream u { server 127.0.0.1:1; health_check expect=abc; }\nserver { listen 80; }";
	ast = bst_cfg_parse_string(src, strlen(src), "t.conf", NULL, ar, &e);
	ASSERT(ast != NULL && bst_cfg_compile(ast, &e) == NULL);
	bst_arena_free(ar);
}

TAP_MAIN()
