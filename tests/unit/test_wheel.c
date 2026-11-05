#include "core/time.h"
#include "core/wheel.h"
#include "tap.h"

#include <stdlib.h>

#define MS_PER_HOUR UINT64_C(3600000)
#define MS_PER_DAY (24 * MS_PER_HOUR)

typedef struct {
	bst_wheel *w;
	int fired;
	uint64_t at;
} probe;

static void on_fire(void *ud)
{
	probe *p = ud;
	p->fired++;
	p->at = p->w->now;
}

TEST(clock_is_monotonic)
{
	uint64_t a = bst_now_ms();
	uint64_t b = bst_now_ms();
	ASSERT(a > 0);
	ASSERT(b >= a);
}

TEST(fires_on_time)
{
	bst_wheel w;
	bst_timer t = {0};
	probe p = {&w, 0, 0};
	bst_wheel_init(&w, 0);
	bst_timer_arm(&w, &t, 100, on_fire, &p);
	bst_wheel_advance(&w, 99);
	ASSERT_EQ(p.fired, 0);
	bst_wheel_advance(&w, 100);
	ASSERT_EQ(p.fired, 1);
	ASSERT_EQ(p.at, 100);
	bst_wheel_advance(&w, 500);
	ASSERT_EQ(p.fired, 1);
}

TEST(fires_exactly_when_stepped)
{
	static const uint64_t delays[] = {1, 2, 255, 256, 257, 511, 512, 65535, 65536, 65537, 70000};
	enum { N = sizeof delays / sizeof delays[0] };
	bst_wheel w;
	bst_timer t[N] = {{0}};
	probe p[N];
	bst_wheel_init(&w, 1000);
	for (int i = 0; i < N; i++) {
		p[i] = (probe){&w, 0, 0};
		bst_timer_arm(&w, &t[i], delays[i], on_fire, &p[i]);
	}
	for (uint64_t now = 1001; now <= 1000 + 70001; now++)
		bst_wheel_advance(&w, now);
	for (int i = 0; i < N; i++) {
		ASSERT_EQ(p[i].fired, 1);
		ASSERT_EQ(p[i].at, 1000 + delays[i]);
	}
}

TEST(long_timer_cascades)
{
	bst_wheel w;
	bst_timer t = {0};
	probe p = {&w, 0, 0};
	bst_wheel_init(&w, 12345);
	bst_timer_arm(&w, &t, MS_PER_HOUR, on_fire, &p);
	bst_wheel_advance(&w, 12345 + MS_PER_HOUR - 1);
	ASSERT_EQ(p.fired, 0);
	bst_wheel_advance(&w, 12345 + MS_PER_HOUR);
	ASSERT_EQ(p.fired, 1);
	ASSERT_EQ(p.at, 12345 + MS_PER_HOUR);
}

typedef struct {
	bst_timer *victims[2];
	int fired;
} canceller;

static void cancel_others(void *ud)
{
	canceller *c = ud;
	c->fired++;
	for (int i = 0; i < 2; i++)
		if (c->victims[i] != NULL)
			bst_timer_cancel(c->victims[i]);
}

TEST(cancel_in_callback)
{
	/* Three timers share one tick, so whichever is first on the slot list cancels the
	 * other two, including the one that would be next on the list. Exactly one fires. */
	bst_wheel w;
	bst_timer t[3] = {{0}};
	canceller c[3];
	bst_wheel_init(&w, 0);
	for (int i = 0; i < 3; i++) {
		c[i].fired = 0;
		c[i].victims[0] = &t[(i + 1) % 3];
		c[i].victims[1] = &t[(i + 2) % 3];
		bst_timer_arm(&w, &t[i], 50, cancel_others, &c[i]);
	}
	bst_wheel_advance(&w, 50);
	ASSERT_EQ(c[0].fired + c[1].fired + c[2].fired, 1);
	ASSERT_EQ(w.count, 0);
	ASSERT_EQ(bst_wheel_next_ms(&w), -1);
}

TEST(cancel_next_in_callback)
{
	/* B is armed first, A second; arming pushes to the list head, so A runs first and B
	 * is the very next node. A cancels B: B must not fire. */
	bst_wheel w;
	bst_timer a = {0}, b = {0};
	canceller ca = {{&b, NULL}, 0};
	probe pb = {&w, 0, 0};
	bst_wheel_init(&w, 0);
	bst_timer_arm(&w, &b, 10, on_fire, &pb);
	bst_timer_arm(&w, &a, 10, cancel_others, &ca);
	bst_wheel_advance(&w, 10);
	ASSERT_EQ(ca.fired, 1);
	ASSERT_EQ(pb.fired, 0);
	ASSERT_EQ(w.count, 0);
}

TEST(cancel_before_fire)
{
	bst_wheel w;
	bst_timer t = {0};
	probe p = {&w, 0, 0};
	bst_wheel_init(&w, 0);
	bst_timer_arm(&w, &t, 5000, on_fire, &p);
	bst_timer_cancel(&t);
	bst_timer_cancel(&t);
	ASSERT_EQ(bst_wheel_next_ms(&w), -1);
	bst_wheel_advance(&w, 10000);
	ASSERT_EQ(p.fired, 0);
}

typedef struct {
	bst_wheel *w;
	bst_timer *self;
	int fired;
	int limit;
	uint64_t period;
	uint64_t at[8];
} rearmer;

static void rearm_cb(void *ud)
{
	rearmer *r = ud;
	r->at[r->fired] = r->w->now;
	if (++r->fired < r->limit)
		bst_timer_arm(r->w, r->self, r->period, rearm_cb, r);
}

TEST(rearm_in_callback)
{
	bst_wheel w;
	bst_timer t = {0};
	rearmer r = {&w, &t, 0, 5, 100, {0}};
	bst_wheel_init(&w, 0);
	bst_timer_arm(&w, &t, 100, rearm_cb, &r);
	bst_wheel_advance(&w, 250);
	ASSERT_EQ(r.fired, 2);
	bst_wheel_advance(&w, 1000);
	ASSERT_EQ(r.fired, 5);
	for (int i = 0; i < 5; i++)
		ASSERT_EQ(r.at[i], 100 * (i + 1));
	ASSERT_EQ(bst_wheel_next_ms(&w), -1);
}

TEST(rearm_while_armed_moves_timer)
{
	bst_wheel w;
	bst_timer t = {0};
	probe p = {&w, 0, 0};
	bst_wheel_init(&w, 0);
	bst_timer_arm(&w, &t, 100, on_fire, &p);
	bst_timer_arm(&w, &t, 300, on_fire, &p);
	bst_wheel_advance(&w, 299);
	ASSERT_EQ(p.fired, 0);
	bst_wheel_advance(&w, 300);
	ASSERT_EQ(p.fired, 1);
	ASSERT_EQ(w.count, 0);
}

TEST(next_ms)
{
	bst_wheel w;
	bst_timer a = {0}, b = {0};
	probe p = {&w, 0, 0};
	bst_wheel_init(&w, 1000);
	ASSERT_EQ(bst_wheel_next_ms(&w), -1);
	bst_timer_arm(&w, &a, 200, on_fire, &p);
	ASSERT_EQ(bst_wheel_next_ms(&w), 200);
	bst_timer_arm(&w, &b, 50, on_fire, &p);
	ASSERT_EQ(bst_wheel_next_ms(&w), 50);
	bst_wheel_advance(&w, 1020);
	ASSERT_EQ(bst_wheel_next_ms(&w), 30);
	bst_timer_cancel(&b);
	ASSERT_EQ(bst_wheel_next_ms(&w), 180);
	bst_wheel_advance(&w, 1200);
	ASSERT_EQ(bst_wheel_next_ms(&w), -1);
}

TEST(next_ms_never_late_for_far_timer)
{
	bst_wheel w;
	bst_timer t = {0};
	probe p = {&w, 0, 0};
	bst_wheel_init(&w, 0);
	bst_timer_arm(&w, &t, MS_PER_HOUR, on_fire, &p);
	/* Following next_ms must reach the expiry without ever overshooting it. */
	while (p.fired == 0) {
		int64_t d = bst_wheel_next_ms(&w);
		ASSERT(d > 0);
		ASSERT((uint64_t)d + w.now <= MS_PER_HOUR);
		bst_wheel_advance(&w, w.now + (uint64_t)d);
	}
	ASSERT_EQ(p.at, MS_PER_HOUR);
}

#define JUMP_TIMERS 10000

TEST(large_clock_jump)
{
	static bst_timer t[JUMP_TIMERS];
	static probe p[JUMP_TIMERS];
	bst_wheel w;
	bst_wheel_init(&w, 5000);
	srand(1);
	for (int i = 0; i < JUMP_TIMERS; i++) {
		uint64_t d = 1 + ((uint64_t)rand() * 7919u + (uint64_t)rand()) % (7 * MS_PER_DAY);
		p[i] = (probe){&w, 0, 0};
		bst_timer_arm(&w, &t[i], d, on_fire, &p[i]);
		p[i].at = 5000 + d; /* expected time; overwritten when it fires */
	}
	bst_wheel_advance(&w, 5000 + 7 * MS_PER_DAY);
	int bad = 0;
	for (int i = 0; i < JUMP_TIMERS; i++)
		bad += p[i].fired != 1;
	ASSERT_EQ(bad, 0);
	ASSERT_EQ(w.count, 0);
	ASSERT_EQ(w.now, 5000 + 7 * MS_PER_DAY);
}

TEST(delay_beyond_wheel_range_clamps_and_fires)
{
	const uint64_t range = UINT64_C(1) << 32;
	bst_wheel w;
	bst_timer a = {0}, b = {0}, c = {0};
	probe pa = {&w, 0, 0}, pb = {&w, 0, 0}, pc = {&w, 0, 0};
	bst_wheel_init(&w, 777);
	bst_timer_arm(&w, &a, range, on_fire, &pa);
	bst_timer_arm(&w, &b, 3 * range + 5, on_fire, &pb);
	bst_timer_arm(&w, &c, UINT64_MAX, on_fire, &pc);
	ASSERT(bst_wheel_next_ms(&w) > 0);
	bst_wheel_advance(&w, 777 + range - 1);
	ASSERT_EQ(pa.fired, 0);
	bst_wheel_advance(&w, 777 + range);
	ASSERT_EQ(pa.fired, 1);
	ASSERT_EQ(pa.at, 777 + range);
	bst_wheel_advance(&w, 777 + 3 * range + 4);
	ASSERT_EQ(pb.fired, 0);
	bst_wheel_advance(&w, 777 + 3 * range + 5);
	ASSERT_EQ(pb.fired, 1);
	ASSERT_EQ(pb.at, 777 + 3 * range + 5);
	ASSERT_EQ(pc.fired, 0);
	bst_timer_cancel(&c);
	ASSERT_EQ(w.count, 0);
}

TAP_MAIN()
