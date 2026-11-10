#include "http/headers.h"

#include "http/known_headers_table.h"

#include <string.h>

/* RFC 9110 section 5.6.2 as a range test, frozen into the table by the macros below. */
#define TC(c) ((c) == '!' || ((c) >= '#' && (c) <= '\'') || (c) == '*' || (c) == '+' ||        \
	       (c) == '-' || (c) == '.' || ((c) >= '0' && (c) <= '9') ||                        \
	       ((c) >= 'A' && (c) <= 'Z') || ((c) >= '^' && (c) <= 'z') || (c) == '|' ||        \
	       (c) == '~')
#define R4(n) TC(n), TC((n) + 1), TC((n) + 2), TC((n) + 3)
#define R16(n) R4(n), R4((n) + 4), R4((n) + 8), R4((n) + 12)
#define R64(n) R16(n), R16((n) + 16), R16((n) + 32), R16((n) + 48)

const unsigned char bst_tchar_tab[256] = { R64(0), R64(64), R64(128), R64(192) };

bool bst_is_field_value_clean(bst_str v)
{
	for (uint32_t i = 0; i < v.len; i++) {
		unsigned char c = (unsigned char)v.p[i];
		if ((c < 0x20 && c != '\t') || c == 0x7f)
			return false;
	}
	return true;
}

bool bst_is_token(bst_str s)
{
	if (s.len == 0)
		return false;
	for (uint32_t i = 0; i < s.len; i++)
		if (!bst_is_tchar((unsigned char)s.p[i]))
			return false;
	return true;
}

/* ---- known names ---- */

static const bst_str known_names[BST_H_COUNT_] = {
	{ "", 0 },
#define X(id, name) { name, sizeof(name) - 1 },
#include "http/known_headers.def"
#undef X
};

static uint32_t hash_lower(const char *p, size_t n)
{
	uint32_t h = BST_HDR_HASH_SEED;
	for (size_t i = 0; i < n; i++) {
		unsigned char c = (unsigned char)p[i];
		if (c >= 'A' && c <= 'Z')
			c = (unsigned char)(c + 32);
		h = (h ^ c) * 16777619u;
	}
	return h;
}

bst_hdr_id bst_hdr_lookup(const char *name, size_t len)
{
	if (len == 0 || len > 32) /* the longest known name is 25 bytes */
		return BST_H_UNKNOWN;
	bst_hdr_id id = bst_hdr_slots[hash_lower(name, len) & BST_HDR_HASH_MASK];
	if (id == BST_H_UNKNOWN)
		return BST_H_UNKNOWN;
	return bst_str_ieq(known_names[id], (bst_str){ name, (uint32_t)len }) ? id : BST_H_UNKNOWN;
}

bst_str bst_hdr_name(bst_hdr_id id)
{
	return id < BST_H_COUNT_ ? known_names[id] : known_names[0];
}

/* ---- the list ---- */

void bst_headers_init(bst_headers *h, bst_arena *arena)
{
	*h = (bst_headers){ .arena = arena };
}

int bst_headers_add(bst_headers *h, bst_str name, bst_str value)
{
	if (h->n == h->cap) {
		uint32_t cap = h->cap ? h->cap * 2 : 16;
		if (cap < h->cap)
			return -1;
		bst_header *nv = bst_arena_alloc(h->arena, (size_t)cap * sizeof *nv);
		if (nv == NULL)
			return -1;
		if (h->n > 0)
			memcpy(nv, h->v, (size_t)h->n * sizeof *nv);
		h->v = nv; /* the old array stays in the arena until it resets */
		h->cap = cap;
	}
	h->v[h->n++] = (bst_header){ name, value, bst_hdr_lookup(name.p, name.len) };
	return 0;
}

static const bst_header *scan(const bst_headers *h, const bst_header *after, bst_hdr_id id,
			      const bst_str *name)
{
	if (h->n == 0)
		return NULL; /* v may be NULL, and NULL + 0 is undefined */
	const bst_header *e = h->v + h->n;
	const bst_header *p = after ? after + 1 : h->v;
	for (; p < e; p++)
		if (id != BST_H_UNKNOWN ? p->id == id : bst_str_ieq(p->name, *name))
			return p;
	return NULL;
}

const bst_header *bst_headers_get(const bst_headers *h, bst_hdr_id id)
{
	return id == BST_H_UNKNOWN ? NULL : scan(h, NULL, id, NULL);
}

const bst_header *bst_headers_get_name(const bst_headers *h, bst_str name)
{
	return bst_headers_next_name(h, NULL, name);
}

const bst_header *bst_headers_next(const bst_headers *h, const bst_header *after, bst_hdr_id id)
{
	return id == BST_H_UNKNOWN ? NULL : scan(h, after, id, NULL);
}

const bst_header *bst_headers_next_name(const bst_headers *h, const bst_header *after,
					bst_str name)
{
	bst_hdr_id id = bst_hdr_lookup(name.p, name.len);
	return scan(h, after, id, &name);
}

size_t bst_headers_count(const bst_headers *h, bst_hdr_id id)
{
	size_t n = 0;
	for (const bst_header *p = bst_headers_get(h, id); p; p = bst_headers_next(h, p, id))
		n++;
	return n;
}

static size_t remove_matching(bst_headers *h, bst_hdr_id id, const bst_str *name)
{
	size_t out = 0;
	for (size_t i = 0; i < h->n; i++) {
		bool match = id != BST_H_UNKNOWN ? h->v[i].id == id : bst_str_ieq(h->v[i].name, *name);
		if (!match)
			h->v[out++] = h->v[i];
	}
	size_t gone = h->n - out;
	h->n = (uint32_t)out;
	return gone;
}

size_t bst_headers_remove(bst_headers *h, bst_hdr_id id)
{
	return id == BST_H_UNKNOWN ? 0 : remove_matching(h, id, NULL);
}

size_t bst_headers_remove_name(bst_headers *h, bst_str name)
{
	return remove_matching(h, bst_hdr_lookup(name.p, name.len), &name);
}

int bst_headers_set(bst_headers *h, bst_str name, bst_str value)
{
	bst_hdr_id id = bst_hdr_lookup(name.p, name.len);
	size_t first = h->n;
	for (size_t i = 0; i < h->n; i++)
		if (id != BST_H_UNKNOWN ? h->v[i].id == id : bst_str_ieq(h->v[i].name, name)) {
			first = i;
			break;
		}
	if (first == h->n)
		return bst_headers_add(h, name, value);
	h->v[first].value = value;
	/* drop later duplicates, keeping order */
	size_t out = first + 1;
	for (size_t i = first + 1; i < h->n; i++) {
		bool match = id != BST_H_UNKNOWN ? h->v[i].id == id : bst_str_ieq(h->v[i].name, name);
		if (!match)
			h->v[out++] = h->v[i];
	}
	h->n = (uint32_t)out;
	return 0;
}
