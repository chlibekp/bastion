#include "config/values.h"

#include <string.h>

/* Leading run of decimal digits. Returns the count consumed (0 if none); *over is set if
 * the value does not fit 64 bits. */
static size_t digits_u64(bst_str s, uint64_t *v, bool *over)
{
	size_t i = 0;
	uint64_t acc = 0;
	*over = false;
	while (i < s.len && s.p[i] >= '0' && s.p[i] <= '9') {
		uint64_t d = (uint64_t)(s.p[i] - '0');
		if (acc > (UINT64_MAX - d) / 10)
			*over = true;
		else
			acc = acc * 10 + d;
		i++;
	}
	*v = acc;
	return i;
}

static bool mul_ok(uint64_t a, uint64_t b, uint64_t *out)
{
	if (b != 0 && a > UINT64_MAX / b)
		return false;
	*out = a * b;
	return true;
}

bool bst_parse_size(bst_str s, uint64_t *out)
{
	uint64_t v;
	bool over;
	size_t n = digits_u64(s, &v, &over);
	if (n == 0 || over)
		return false;
	uint64_t mult = 1;
	if (n + 1 == s.len) {
		switch (s.p[n]) {
		case 'k': mult = 1ull << 10; break;
		case 'm': mult = 1ull << 20; break;
		case 'g': mult = 1ull << 30; break;
		default: return false;
		}
	} else if (n != s.len) {
		return false;
	}
	return mul_ok(v, mult, out);
}

bool bst_parse_duration_us(bst_str s, uint64_t *out)
{
	uint64_t v;
	bool over;
	size_t n = digits_u64(s, &v, &over);
	if (n == 0 || over)
		return false;
	const char *u = s.p + n;
	size_t ul = s.len - n;
	uint64_t mult;
	if (ul == 2 && u[0] == 'u' && u[1] == 's')
		mult = 1;
	else if (ul == 2 && u[0] == 'm' && u[1] == 's')
		mult = 1000;
	else if (ul == 1 && u[0] == 's')
		mult = 1000000ull;
	else if (ul == 1 && u[0] == 'm')
		mult = 60ull * 1000000ull;
	else if (ul == 1 && u[0] == 'h')
		mult = 3600ull * 1000000ull;
	else if (ul == 1 && u[0] == 'd')
		mult = 86400ull * 1000000ull;
	else
		return false;
	return mul_ok(v, mult, out);
}

bool bst_parse_rate(bst_str s, bst_rate *out)
{
	uint64_t v;
	bool over;
	size_t n = digits_u64(s, &v, &over);
	if (n == 0 || over)
		return false;
	if (n < s.len && s.p[n] == 'k') {
		if (!mul_ok(v, 1ull << 10, &v))
			return false;
		n++;
	}
	if (v == 0 || s.len - n != 2 || s.p[n] != '/')
		return false;
	uint64_t period;
	if (s.p[n + 1] == 's')
		period = 1000000ull;
	else if (s.p[n + 1] == 'm')
		period = 60ull * 1000000ull;
	else
		return false;
	out->count = v;
	out->period_us = period;
	return true;
}

bool bst_rate_eq(const bst_rate *a, const bst_rate *b)
{
	return (unsigned __int128)a->count * b->period_us ==
	       (unsigned __int128)b->count * a->period_us;
}

static bool lit_eq(bst_str s, const char *lit)
{
	size_t n = strlen(lit);
	return s.len == n && memcmp(s.p, lit, n) == 0;
}

bool bst_parse_bool(bst_str s, bool *out)
{
	if (lit_eq(s, "on"))
		*out = true;
	else if (lit_eq(s, "off"))
		*out = false;
	else
		return false;
	return true;
}

bool bst_parse_enum(bst_str s, const char *const *values, size_t *idx)
{
	for (size_t i = 0; values != NULL && values[i] != NULL; i++) {
		if (lit_eq(s, values[i])) {
			*idx = i;
			return true;
		}
	}
	return false;
}

bool bst_parse_int(bst_str s, int64_t min, int64_t max, int64_t *out)
{
	bool neg = s.len > 0 && s.p[0] == '-';
	bst_str d = { s.p + (neg ? 1 : 0), s.len - (neg ? 1u : 0u) };
	uint64_t v;
	bool over;
	size_t n = digits_u64(d, &v, &over);
	if (n == 0 || n != d.len || over)
		return false;
	int64_t r;
	if (neg) {
		if (v > (uint64_t)INT64_MAX + 1)
			return false;
		r = v == (uint64_t)INT64_MAX + 1 ? INT64_MIN : -(int64_t)v;
	} else {
		if (v > (uint64_t)INT64_MAX)
			return false;
		r = (int64_t)v;
	}
	if (r < min || r > max)
		return false;
	*out = r;
	return true;
}

bool bst_parse_percent(bst_str s, uint8_t *out)
{
	if (s.len < 2 || s.p[s.len - 1] != '%')
		return false;
	int64_t v;
	bst_str d = { s.p, s.len - 1 };
	if (d.p[0] == '-' || !bst_parse_int(d, 0, 100, &v))
		return false;
	*out = (uint8_t)v;
	return true;
}

int bst_parse_kv(bst_str arg, const char *key, bst_str *val, bool *seen)
{
	size_t kl = strlen(key);
	if (arg.len < kl || memcmp(arg.p, key, kl) != 0)
		return 0;
	if (arg.len == kl || *seen)
		return -1;
	*seen = true;
	val->p = arg.p + kl;
	val->len = (uint32_t)(arg.len - kl);
	return 1;
}
