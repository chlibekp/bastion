#include "core/str.h"

#include <string.h>

bool bst_str_eq(bst_str a, bst_str b)
{
	return a.len == b.len && (a.len == 0 || memcmp(a.p, b.p, a.len) == 0);
}

static unsigned char lower(unsigned char c)
{
	return (c >= 'A' && c <= 'Z') ? (unsigned char)(c + ('a' - 'A')) : c;
}

bool bst_str_ieq(bst_str a, bst_str b)
{
	if (a.len != b.len)
		return false;
	for (uint32_t i = 0; i < a.len; i++)
		if (lower((unsigned char)a.p[i]) != lower((unsigned char)b.p[i]))
			return false;
	return true;
}

bool bst_str_to_u64(bst_str s, uint64_t *out)
{
	if (s.len == 0)
		return false;
	uint64_t v = 0;
	for (uint32_t i = 0; i < s.len; i++) {
		unsigned d = (unsigned)((unsigned char)s.p[i]) - '0';
		if (d > 9 || v > (UINT64_MAX - d) / 10)
			return false;
		v = v * 10 + d;
	}
	*out = v;
	return true;
}
