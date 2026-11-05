#include "core/cidr.h"

#include <stdlib.h>
#include <string.h>

typedef struct node {
	uint8_t key[16]; /* masked to len bits */
	uint8_t len;
	void *value; /* NULL: internal branch node */
	struct node *child[2];
} node;

struct bst_cidrset {
	node *root[2]; /* [0] V4, [1] V6 */
};

static unsigned bit(const uint8_t *k, unsigned i)
{
	return (k[i >> 3] >> (7 - (i & 7))) & 1u;
}

static void mask_key(uint8_t *k, unsigned bits)
{
	for (unsigned i = 0; i < 16; i++) {
		if (bits >= (i + 1) * 8)
			continue;
		if (bits <= i * 8)
			k[i] = 0;
		else
			k[i] &= (uint8_t)(0xff00u >> (bits - i * 8));
	}
}

static unsigned common_bits(const uint8_t *a, const uint8_t *b, unsigned max)
{
	unsigned n = 0;
	while (n < max) {
		if ((n & 7) == 0 && n + 8 <= max && a[n >> 3] == b[n >> 3]) {
			n += 8;
			continue;
		}
		if (bit(a, n) != bit(b, n))
			break;
		n++;
	}
	return n;
}

static unsigned maxbits(uint8_t family)
{
	return family == BST_IP_V4 ? 32 : 128;
}

bool bst_cidr_parse(bst_str s, bst_cidr *out)
{
	if (s.p == NULL || s.len == 0)
		return false;
	const char *slash = memchr(s.p, '/', s.len);
	if (!slash)
		return false;
	size_t alen = (size_t)(slash - s.p);
	size_t plen = s.len - alen - 1;
	if (plen < 1 || plen > 3)
		return false;
	const char *pp = slash + 1;
	unsigned pre = 0;
	for (size_t i = 0; i < plen; i++) {
		if (pp[i] < '0' || pp[i] > '9')
			return false;
		pre = pre * 10 + (unsigned)(pp[i] - '0');
	}
	if (plen > 1 && pp[0] == '0')
		return false;

	bst_ip ip;
	if (!bst_addr_parse((bst_str){ s.p, (uint32_t)alen }, &ip))
		return false;
	if (pre > maxbits(ip.family))
		return false;
	uint8_t masked[16];
	memcpy(masked, ip.b, sizeof masked);
	mask_key(masked, pre);
	if (memcmp(masked, ip.b, sizeof masked) != 0)
		return false;

	if (ip.family == BST_IP_V6 && pre >= 96) {
		bst_ip c = bst_ip_canon(&ip);
		if (c.family == BST_IP_V4) {
			ip = c;
			pre -= 96;
		}
	}
	out->ip = ip;
	out->prefix = (uint8_t)pre;
	return true;
}

bst_cidrset *bst_cidrset_new(void)
{
	return calloc(1, sizeof(bst_cidrset));
}

static void free_tree(node *n)
{
	if (!n)
		return;
	free_tree(n->child[0]);
	free_tree(n->child[1]);
	free(n);
}

void bst_cidrset_free(bst_cidrset *set)
{
	if (!set)
		return;
	free_tree(set->root[0]);
	free_tree(set->root[1]);
	free(set);
}

static node *mknode(const uint8_t *key, unsigned len, void *value)
{
	node *n = calloc(1, sizeof *n);
	if (!n)
		return NULL;
	memcpy(n->key, key, sizeof n->key);
	mask_key(n->key, len);
	n->len = (uint8_t)len;
	n->value = value;
	return n;
}

int bst_cidrset_add(bst_cidrset *set, const bst_cidr *cidr, void *value)
{
	if (!set || !cidr || !value)
		return -1;
	if (cidr->ip.family != BST_IP_V4 && cidr->ip.family != BST_IP_V6)
		return -1;
	unsigned len = cidr->prefix;
	if (len > maxbits(cidr->ip.family))
		return -1;
	uint8_t key[16];
	memcpy(key, cidr->ip.b, sizeof key);
	mask_key(key, len);

	node **pp = &set->root[cidr->ip.family == BST_IP_V6];
	for (;;) {
		node *n = *pp;
		if (!n) {
			node *leaf = mknode(key, len, value);
			if (!leaf)
				return -1;
			*pp = leaf;
			return 0;
		}
		unsigned max = len < n->len ? len : n->len;
		unsigned common = common_bits(key, n->key, max);
		if (common == n->len) {
			if (len == n->len) {
				n->value = value;
				return 0;
			}
			pp = &n->child[bit(key, n->len)];
			continue;
		}
		/* Split n's edge at the first differing bit. */
		node *m = mknode(key, common, NULL);
		if (!m)
			return -1;
		m->child[bit(n->key, common)] = n;
		if (len == common) {
			m->value = value;
		} else {
			node *leaf = mknode(key, len, value);
			if (!leaf) {
				free(m);
				return -1;
			}
			m->child[bit(key, common)] = leaf;
		}
		*pp = m;
		return 0;
	}
}

void *bst_cidrset_match(const bst_cidrset *set, const bst_ip *ip)
{
	if (!set || !ip)
		return NULL;
	bst_ip c = bst_ip_canon(ip);
	if (c.family != BST_IP_V4 && c.family != BST_IP_V6)
		return NULL;
	unsigned total = maxbits(c.family);
	void *best = NULL;
	for (const node *n = set->root[c.family == BST_IP_V6]; n;) {
		if (common_bits(c.b, n->key, n->len) != n->len)
			break;
		if (n->value)
			best = n->value;
		if (n->len >= total)
			break;
		n = n->child[bit(c.b, n->len)];
	}
	return best;
}
