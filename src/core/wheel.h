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
	bst_timer *slot[BST_WHEEL_LEVELS][BST_WHEEL_SLOTS];
};

void bst_wheel_init(bst_wheel *w, uint64_t now);

/* Timers must be zero-initialised before first use.
 * Fire cb(ud) once, ms from the wheel's current time (minimum 1 ms). Rearms if the
 * timer is already armed. The timer must stay valid until it fires or is cancelled. */
void bst_timer_arm(bst_wheel *w, bst_timer *t, uint64_t ms, void (*cb)(void *), void *ud);

/* Safe on an unarmed timer, a fired timer, or from inside any callback. */
void bst_timer_cancel(bst_timer *t);

/* Move time forward to now, firing every timer due on the way. A jump costs work
 * proportional to the timers and slots it crosses, not to the milliseconds skipped.
 * A now at or before the wheel's time is ignored. */
void bst_wheel_advance(bst_wheel *w, uint64_t now);

/* Delay until the wheel next needs advancing, or -1 if no timer is armed. Exact for
 * timers within 256 ms; for later ones it may be early (never late), because the
 * wheel wakes at the cascade point. */
int64_t bst_wheel_next_ms(const bst_wheel *w);

#endif
