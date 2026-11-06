#include "io/tcp_profile.h"

#include <string.h>

void bst_tcp_profile_defaults(bst_tcp_profile *p, const char *name)
{
	memset(p, 0, sizeof *p);
	p->name = name;
	p->nodelay = true;
	p->set |= 1u << BST_TCP_NODELAY;
	p->backlog = BST_TCP_DEFAULT_BACKLOG;
	p->set |= 1u << BST_TCP_BACKLOG;
}

static int hexval(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

bool bst_tcp_parse_key(const char *s, size_t len, uint8_t out[BST_TCP_KEY_LEN])
{
	uint8_t key[BST_TCP_KEY_LEN];
	bool dashed = len == 2 * BST_TCP_KEY_LEN + 3;
	if (len != 2 * BST_TCP_KEY_LEN && !dashed)
		return false;
	size_t nib = 0;
	for (size_t i = 0; i < len; i++) {
		if (dashed && i % 9 == 8) { /* a dash after each group of 8 digits */
			if (s[i] != '-')
				return false;
			continue;
		}
		int v = hexval(s[i]);
		if (v < 0)
			return false;
		if (nib % 2 == 0)
			key[nib / 2] = (uint8_t)(v << 4);
		else
			key[nib / 2] = (uint8_t)(key[nib / 2] | v);
		nib++;
	}
	memcpy(out, key, sizeof key);
	return true;
}
