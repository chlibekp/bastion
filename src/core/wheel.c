#include "core/wheel.h"

#include <stddef.h>

#define SPAN_BITS (BST_WHEEL_LEVELS * BST_WHEEL_SLOT_BITS)
#define MAX_DELTA ((UINT64_C(1) << SPAN_BITS) - 1)

static void link_front(bst_timer **head, bst_timer *t)
{
	t->next = *head;
	t->pprev = head;
	if (*head != NULL)
		(*head)->pprev = &t->next;
	*head = t;
}

static void unlink_timer(bst_timer *t)
{
	*t->pprev = t->next;
	if (t->next != NULL)
		t->next->pprev = t->pprev;
	t->next = NULL;
	t->pprev = NULL;
}

/* Place t by its distance from w->now. Requires t->expires > w->now. */
static void place(bst_wheel *w, bst_timer *t)
{
	uint64_t delta = t->expires - w->now;
	uint64_t at = t->expires;
	if (delta > MAX_DELTA) {
		delta = MAX_DELTA;
		at = w->now + MAX_DELTA; /* clamp: re-placed at the cascade, fires at expires */
	}
	unsigned level = 0;
	while (level < BST_WHEEL_LEVELS - 1 &&
	       delta >= (UINT64_C(1) << (BST_WHEEL_SLOT_BITS * (level + 1))))
		level++;
	unsigned idx = (unsigned)(at >> (BST_WHEEL_SLOT_BITS * level)) & (BST_WHEEL_SLOTS - 1);
	link_front(&w->slot[level][idx], t);
}

void bst_wheel_init(bst_wheel *w, uint64_t now)
{
	w->now = now;
	w->count = 0;
	w->ticks_run = 0;
	for (unsigned l = 0; l < BST_WHEEL_LEVELS; l++)
		for (unsigned i = 0; i < BST_WHEEL_SLOTS; i++)
			w->slot[l][i] = NULL;
}

void bst_timer_arm(bst_wheel *w, bst_timer *t, uint64_t ms, void (*cb)(void *), void *ud)
{
	bst_timer_cancel(t);
	if (ms == 0)
		ms = 1;
	t->wheel = w;
	t->cb = cb;
	t->ud = ud;
	t->expires = ms > UINT64_MAX - w->now ? UINT64_MAX : w->now + ms;
	place(w, t);
	w->count++;
}

void bst_timer_cancel(bst_timer *t)
{
	if (t->pprev == NULL)
		return;
	unlink_timer(t);
	t->wheel->count--;
}

/* Re-place every timer in a higher-level slot. Reinsertion always lands in a lower
 * level (or fires this tick), never back in the slot being drained. */
static void cascade(bst_wheel *w, unsigned level)
{
	unsigned idx = (unsigned)(w->now >> (BST_WHEEL_SLOT_BITS * level)) & (BST_WHEEL_SLOTS - 1);
	bst_timer **head = &w->slot[level][idx];
	while (*head != NULL) {
		bst_timer *t = *head;
		unlink_timer(t);
		place(w, t);
	}
}

static void run_tick(bst_wheel *w)
{
	w->ticks_run++;
	for (unsigned l = BST_WHEEL_LEVELS - 1; l >= 1; l--) {
		uint64_t mask = (UINT64_C(1) << (BST_WHEEL_SLOT_BITS * l)) - 1;
		if ((w->now & mask) == 0)
			cascade(w, l);
	}
	/* Always pop the head: a callback may cancel any other timer, so no saved next
	 * pointer is ever held across a callback. A timer cancelled before it reaches
	 * the head is gone from the list and cannot fire. */
	bst_timer **head = &w->slot[0][w->now & (BST_WHEEL_SLOTS - 1)];
	while (*head != NULL) {
		bst_timer *t = *head;
		unlink_timer(t);
		w->count--;
		t->cb(t->ud);
	}
}

/* Earliest tick after w->now at which a slot needs work (a fire or a cascade). */
static uint64_t next_event(const bst_wheel *w)
{
	uint64_t best = UINT64_MAX;
	for (unsigned l = 0; l < BST_WHEEL_LEVELS; l++) {
		unsigned shift = BST_WHEEL_SLOT_BITS * l;
		uint64_t base = w->now >> shift;
		for (uint64_t k = 1; k <= BST_WHEEL_SLOTS; k++) {
			uint64_t b = base + k;
			if (w->slot[l][b & (BST_WHEEL_SLOTS - 1)] != NULL) {
				uint64_t t = b << shift;
				if (t < best)
					best = t;
				break;
			}
		}
	}
	return best;
}

void bst_wheel_advance(bst_wheel *w, uint64_t now)
{
	while (w->now < now) {
		if (w->count == 0) {
			w->now = now;
			return;
		}
		uint64_t t = next_event(w);
		if (t > now)
			t = now;
		w->now = t;
		run_tick(w);
	}
}

int64_t bst_wheel_next_ms(const bst_wheel *w)
{
	if (w->count == 0)
		return -1;
	uint64_t d = next_event(w) - w->now;
	return d > (uint64_t)INT64_MAX ? INT64_MAX : (int64_t)d;
}
