/* See limit.h. */
#include "sec/limit.h"

#include "core/hash.h"

#include <string.h>
#include <sys/random.h>
#include <time.h>

size_t bst_limit_zone_bytes(const bst_limit_zone *z)
{
	return (size_t)z->size * sizeof(bst_limit_slot);
}

int bst_limit_zone_attach(bst_limit_zone *z, void *mem)
{
	uint64_t burst = z->burst > 0 ? z->burst : 1;
	uint64_t count = z->rate.count > 0 ? z->rate.count : 1;
	uint64_t period = z->rate.period_us > 0 ? z->rate.period_us : 1000000;
	z->t_ns = period * 1000 / count;
	if (z->t_ns == 0)
		z->t_ns = 1;
	z->l_ns = burst * z->t_ns;
	z->slots = mem;
	if (getrandom(z->sipkey, sizeof z->sipkey, 0) != (ssize_t)sizeof z->sipkey)
		return -1;
	return 0;
}

uint64_t bst_limit_key_ip(const bst_limit_zone *z, const bst_ip *ip)
{
	bst_ip c = bst_ip_canon(ip);
	uint8_t buf[17];
	memset(buf, 0, sizeof buf);
	buf[0] = c.family;
	if (c.family == BST_IP_V4) {
		memcpy(buf + 1, c.b, 4);
	} else {
		unsigned p = z->ipv6_prefix > 0 && z->ipv6_prefix <= 128 ? z->ipv6_prefix : 64;
		for (unsigned i = 0; i < 16; i++) {
			unsigned bits = p > i * 8 ? p - i * 8 : 0;
			uint8_t m = bits >= 8 ? 0xff : (uint8_t)(0xff00u >> bits);
			buf[1 + i] = c.b[i] & m;
		}
	}
	return bst_siphash13(z->sipkey, buf, sizeof buf) | 1u;
}

uint64_t bst_limit_key_str(const bst_limit_zone *z, bst_str key)
{
	return bst_siphash13(z->sipkey, key.p, key.len) | 1u;
}

/* The slot of key: its own, a free one, or the least recently due of the probed ones. */
static bst_limit_slot *find_slot(bst_limit_zone *z, uint64_t key)
{
	uint32_t mask = z->size - 1;
	uint32_t i0 = (uint32_t)(key >> 32) & mask;
	bst_limit_slot *oldest = NULL;
	uint64_t oldest_tat = UINT64_MAX;
	unsigned probe = z->size < BST_LIMIT_PROBE ? z->size : BST_LIMIT_PROBE;
	for (unsigned k = 0; k < probe; k++) {
		bst_limit_slot *sl = &z->slots[(i0 + k) & mask];
		uint64_t t = atomic_load_explicit(&sl->tag, memory_order_acquire);
		if (t == key)
			return sl;
		if (t == 0) {
			uint64_t zero = 0;
			if (atomic_compare_exchange_strong(&sl->tag, &zero, key))
				return sl;
			if (zero == key)
				return sl;
			continue;
		}
		uint64_t tat = atomic_load_explicit(&sl->tat, memory_order_relaxed);
		if (tat < oldest_tat) {
			oldest_tat = tat;
			oldest = sl;
		}
	}
	if (oldest == NULL)
		oldest = &z->slots[i0];
	/* Take over the oldest: whoever wins the tag gets a fresh TAT. A loser shares the slot with
	 * the winner for this check, which can only make it stricter. */
	uint64_t cur = atomic_load_explicit(&oldest->tag, memory_order_acquire);
	if (cur != key && atomic_compare_exchange_strong(&oldest->tag, &cur, key))
		atomic_store_explicit(&oldest->tat, 0, memory_order_release);
	return oldest;
}

bst_limit_result bst_limit_check_hash(bst_limit_zone *z, uint64_t key, uint64_t now_us)
{
	bst_limit_result r = { .verdict = BST_LIMIT_ALLOW };
	bst_limit_slot *sl = find_slot(z, key);
	uint64_t now = now_us * 1000, T = z->t_ns, L = z->l_ns;
	uint64_t over = z->delay ? L : 0; /* the delay queue holds another burst */
	uint64_t tat = atomic_load_explicit(&sl->tat, memory_order_acquire);
	for (;;) {
		uint64_t base = tat;
		/* No sequence of checks puts a TAT more than L + over + T ahead of the clock (plus the
		 * skew of a worker that read the clock a while before its CAS, far below a second):
		 * anything beyond is a clock that went back or a stale slot, never a lockout. */
		if (base > now + L + over + T + 1000000000ull)
			base = now;
		if (base < now)
			base = now;
		uint64_t ntat = base + T;
		uint64_t ahead = ntat - now;
		if (ahead > L + over) {
			r.verdict = BST_LIMIT_REJECT;
			r.retry_after_us = (ahead - L + 999) / 1000;
			r.remaining = 0;
			if (base != tat) /* repair a clamped TAT even when refusing */
				(void)atomic_compare_exchange_strong(&sl->tat, &tat, base);
			return r;
		}
		if (atomic_compare_exchange_weak_explicit(&sl->tat, &tat, ntat, memory_order_acq_rel,
							   memory_order_acquire)) {
			if (ahead > L) {
				r.verdict = BST_LIMIT_DELAY;
				r.delay_us = (ahead - L + 999) / 1000;
				r.remaining = 0;
			} else {
				r.remaining = (L - ahead) / T;
			}
			return r;
		}
	}
}

bst_limit_result bst_limit_check(bst_limit_zone *z, bst_str key, uint64_t now_us)
{
	return bst_limit_check_hash(z, bst_limit_key_str(z, key), now_us);
}

uint64_t bst_limit_now_us(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}
