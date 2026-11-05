/* Hierarchical timer wheel: O(1) arm and cancel, intrusive timers, no allocation.
 *
 * Geometry is a compile-time constant, not a tunable: BST_WHEEL_LEVELS levels of
 * BST_WHEEL_SLOTS slots at 1 ms resolution, so the wheel spans 2^32 ms (about 49.7
 * days). A longer delay is clamped into the top level and re-placed on each cascade
 * until its real expiry, so it still fires on time rather than wrapping.
 *
 * Single-threaded. A callback may arm, rearm or cancel any timer, including its own
 * and ones due in the same tick; a timer cancelled before its callback starts never
 * fires. */
#ifndef BST_WHEEL_H
#define BST_WHEEL_H

#include <stdint.h>

#define BST_WHEEL_LEVELS 4
#define BST_WHEEL_SLOT_BITS 8
#define BST_WHEEL_SLOTS (1u << BST_WHEEL_SLOT_BITS)

typedef struct bst_wheel bst_wheel;

typedef struct bst_timer {
	struct bst_timer *next;
	struct bst_timer **pprev; /* NULL when not armed */
	bst_wheel *wheel;
	uint64_t expires;
	void (*cb)(void *);
	void *ud;
} bst_timer;

struct bst_wheel {
	uint64_t now;
	uint64_t count;
	uint64_t ticks_run; /* ticks processed so far; work metric, one increment per tick */
	bst_timer *slot[BST_WHEEL_LEVELS][BST_WHEEL_SLOTS];
};

void bst_wheel_init(bst_wheel *w, uint64_t now);

/* Every timer must go through bst_timer_init before first use: slab and arena memory is
 * not zeroed, and an unarmed timer must have pprev NULL. */
void bst_timer_init(bst_timer *t);

/* Fire cb(ud) once, ms from the wheel's current time (minimum 1 ms). Rearms if the
 * timer is already armed. The timer must stay valid until it fires or is cancelled. */
void bst_timer_arm(bst_wheel *w, bst_timer *t, uint64_t ms, void (*cb)(void *), void *ud);

/* Safe on an unarmed timer, a fired timer, or from inside any callback. */
void bst_timer_cancel(bst_timer *t);

/* Move time forward to now, firing every timer due on the way. A jump costs work
 * proportional to the timers and slots it crosses, not to the milliseconds skipped.
 * A now at or before the wheel's time is ignored. */
void bst_wheel_advance(bst_wheel *w, uint64_t now);

/* A strictly positive lower bound on the delay to the earliest timer, or -1 if none is
 * armed: the earliest timer is never due sooner than this, but may be due later. It is
 * the distance to the next slot that holds any timer, which is cheap to find (at most
 * 1024 slot checks) where the exact earliest expiry would mean scanning a slot's list.
 * That makes it safe as a sleep bound; the caller may wake early, advance, and ask
 * again. Advancing by it repeatedly reaches every timer's exact tick in a few wakes. */
int64_t bst_wheel_next_ms(const bst_wheel *w);

#endif
