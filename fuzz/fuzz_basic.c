/* libFuzzer harness for Basic authentication inputs (auth/basic.c): the Authorization value
 * decoder and the Argon2id PHC string parser (auth_basic_file entries). The input is copied to
 * an exact-size heap block. First byte selects the decoder's output capacity.
 * Properties: no crash; a decoded user and password lie inside buf, are NUL-terminated and the
 * user has no control byte or colon; an accepted PHC string has parameters and lengths within
 * the documented ranges, and formatting then parsing it gives the same values. */
#include "auth/basic.h"

#include <stdlib.h>
#include <string.h>

static void check_basic(const char *in, size_t n, size_t cap)
{
	char buf[1024];
	bst_str user = { 0 }, pass = { 0 };
	if (bst_basic_decode((bst_str){ in, (uint32_t)n }, buf, cap, &user, &pass) != 0)
		return;
	const char *end = buf + cap;
	if (user.p < buf || user.p + user.len >= end || pass.p < buf || pass.p + pass.len >= end)
		abort();
	if (user.p[user.len] != '\0' || pass.p[pass.len] != '\0')
		abort();
	for (uint32_t i = 0; i < user.len; i++) {
		unsigned char c = (unsigned char)user.p[i];
		if (c < 0x20 || c == 0x7f || c == ':')
			abort();
	}
}

static void check_phc(const char *in, size_t n)
{
	bst_phc h, again;
	if (bst_phc_parse((bst_str){ in, (uint32_t)n }, &h) != 0)
		return;
	if (h.m_kib > (1u << 20) || h.t < 1 || h.t > 64 || h.p < 1 || h.p > 64 || h.salt_len < 8 ||
	    h.salt_len > BST_PHC_SALT_MAX || h.hash_len < 16 || h.hash_len > BST_PHC_HASH_MAX)
		abort();
	(void)bst_phc_weak(&h);
	char out[512];
	size_t len = bst_phc_format(&h, out, sizeof out);
	if (len == 0 || len >= sizeof out || out[len] != '\0')
		abort();
	if (bst_phc_parse((bst_str){ out, (uint32_t)len }, &again) != 0)
		abort();
	if (again.m_kib != h.m_kib || again.t != h.t || again.p != h.p || again.salt_len != h.salt_len ||
	    again.hash_len != h.hash_len || memcmp(again.salt, h.salt, h.salt_len) != 0 ||
	    memcmp(again.hash, h.hash, h.hash_len) != 0)
		abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t size)
{
	if (size < 1 || size > 2048)
		return 0;
	size_t cap = 1 + d[0] % 1024;
	size_t n = size - 1;
	char *in = malloc(n > 0 ? n : 1);
	if (in == NULL)
		return 0;
	memcpy(in, d + 1, n);
	check_basic(in, n, cap);
	check_phc(in, n);
	free(in);
	return 0;
}
