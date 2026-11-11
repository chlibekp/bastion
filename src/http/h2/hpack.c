#include "http/h2/hpack.h"

#include "http/h2/huffman.h"

#include <stdlib.h>
#include <string.h>

#define DEFAULT_TABLE 4096u /* RFC 9113 section 6.5.2: SETTINGS_HEADER_TABLE_SIZE starts here */

static const struct {
	const char *n;
	uint8_t nl;
	const char *v;
	uint8_t vl;
} stat_tab[BST_HPACK_STATIC_COUNT + 1] = {
	{ 0, 0, 0, 0 },
#define X(i, n, v) { n, sizeof n - 1, v, sizeof v - 1 },
#include "http/h2/hpack_static.def"
#undef X
};

/* ---- dynamic table ---- */

static void tab_init(bst_hpack_table *t, size_t max)
{
	memset(t, 0, sizeof *t);
	t->max = max;
}

static void tab_drop_all(bst_hpack_table *t)
{
	for (uint32_t i = 0; i < t->n; i++)
		free(t->ring[(t->head - i) & (t->cap - 1)].data);
	t->n = 0;
	t->size = 0;
}

static void tab_free(bst_hpack_table *t)
{
	tab_drop_all(t);
	free(t->ring);
	t->ring = NULL;
	t->cap = 0;
}

/* The entry at 1-based dynamic index i (1 is the newest); NULL when there is none. */
static const bst_hpack_entry *tab_at(const bst_hpack_table *t, uint32_t i)
{
	if (i == 0 || i > t->n)
		return NULL;
	return &t->ring[(t->head - (i - 1)) & (t->cap - 1)];
}

static void tab_evict_to(bst_hpack_table *t, size_t limit)
{
	while (t->n > 0 && t->size > limit) {
		bst_hpack_entry *old = &t->ring[(t->head - (t->n - 1)) & (t->cap - 1)];
		t->size -= (size_t)old->nlen + old->vlen + BST_HPACK_ENTRY_OVERHEAD;
		free(old->data);
		t->n--;
	}
}

static void tab_set_max(bst_hpack_table *t, size_t max)
{
	t->max = max;
	tab_evict_to(t, max);
}

/* RFC 7541 section 4.4: an entry larger than the table empties it and is not added. 0, or -1 on
 * exhaustion (the table is then unchanged except for evictions, which are legal). */
static int tab_add(bst_hpack_table *t, const char *name, uint32_t nlen, const char *val, uint32_t vlen)
{
	size_t esz = (size_t)nlen + vlen + BST_HPACK_ENTRY_OVERHEAD;
	if (esz > t->max) {
		tab_drop_all(t);
		return 0;
	}
	tab_evict_to(t, t->max - esz);
	if (t->n == t->cap) { /* grow: at most max / 32 + 1 entries can ever be live */
		uint32_t ncap = t->cap ? t->cap * 2 : 16;
		bst_hpack_entry *nr = malloc((size_t)ncap * sizeof *nr);
		if (nr == NULL)
			return -1;
		for (uint32_t i = 0; i < t->n; i++) /* oldest first, so the new head is n - 1 */
			nr[t->n - 1 - i] = t->ring[(t->head - i) & (t->cap - 1)];
		free(t->ring);
		t->ring = nr;
		t->cap = ncap;
		t->head = t->n ? t->n - 1 : 0;
		if (t->n == 0)
			t->head = ncap - 1; /* the first insert wraps to slot 0 */
	}
	char *d = malloc((size_t)nlen + vlen + 1);
	if (d == NULL)
		return -1;
	memcpy(d, name, nlen);
	memcpy(d + nlen, val, vlen);
	t->head = (t->head + 1) & (t->cap - 1);
	t->ring[t->head] = (bst_hpack_entry){ d, nlen, vlen };
	t->n++;
	t->size += esz;
	return 0;
}

size_t bst_hpack_table_size(const bst_hpack_table *t)
{
	return t->size;
}

uint32_t bst_hpack_table_count(const bst_hpack_table *t)
{
	return t->n;
}

/* ---- integers (RFC 7541 section 5.1) ---- */

int bst_hpack_int_encode(bst_h2_wr *w, uint8_t first_bits, unsigned prefix, uint32_t v)
{
	uint32_t mask = (1u << prefix) - 1;
	if (bst_h2_wr_reserve(w, 6) != 0)
		return -1;
	if (v < mask) {
		w->p[w->len++] = (uint8_t)(first_bits | v);
		return 0;
	}
	w->p[w->len++] = (uint8_t)(first_bits | mask);
	v -= mask;
	while (v >= 128) {
		w->p[w->len++] = (uint8_t)(v % 128 + 128);
		v /= 128;
	}
	w->p[w->len++] = (uint8_t)v;
	return 0;
}

int bst_hpack_int_decode(const uint8_t **p, const uint8_t *end, unsigned prefix, uint32_t *out)
{
	uint32_t mask = (1u << prefix) - 1;
	if (*p >= end)
		return -1;
	uint64_t v = **p & mask;
	(*p)++;
	if (v < mask) {
		*out = (uint32_t)v;
		return 0;
	}
	unsigned shift = 0;
	for (;;) {
		if (*p >= end || shift > 28) /* a sixth continuation byte cannot fit in 32 bits */
			return -1;
		uint8_t b = **p;
		(*p)++;
		v += (uint64_t)(b & 0x7f) << shift;
		if (v > UINT32_MAX)
			return -1;
		if (!(b & 0x80))
			break;
		shift += 7;
	}
	*out = (uint32_t)v;
	return 0;
}

/* ---- decoder ---- */

void bst_hpack_dec_init(bst_hpack_dec *d, uint32_t limit)
{
	tab_init(&d->t, DEFAULT_TABLE);
	d->limit = limit;
}

void bst_hpack_dec_free(bst_hpack_dec *d)
{
	tab_free(&d->t);
}

typedef struct field {
	const char *n, *v;
	uint32_t nl, vl;
} field;

/* The field at a combined index: 1..61 static, 62.. dynamic. False when there is none. */
static bool field_at(const bst_hpack_dec *d, uint32_t idx, field *f)
{
	if (idx >= 1 && idx <= BST_HPACK_STATIC_COUNT) {
		*f = (field){ stat_tab[idx].n, stat_tab[idx].v, stat_tab[idx].nl, stat_tab[idx].vl };
		return true;
	}
	const bst_hpack_entry *e = idx > BST_HPACK_STATIC_COUNT ? tab_at(&d->t, idx - BST_HPACK_STATIC_COUNT) : NULL;
	if (e == NULL)
		return false;
	*f = (field){ e->data, e->data + e->nlen, e->nlen, e->vlen };
	return true;
}

static const char *arena_copy(bst_arena *a, const char *p, uint32_t n)
{
	if (n == 0)
		return "";
	char *d = bst_arena_alloc(a, n);
	if (d != NULL)
		memcpy(d, p, n);
	return d;
}

/* A string literal (RFC 7541 section 5.2) copied or decoded into the arena. budget is what the
 * decoded list may still take; more is BST_HPACK_TOO_LARGE, decided before anything is copied. */
static int dec_string(const uint8_t **p, const uint8_t *end, bst_arena *arena, uint64_t budget,
		      const char **out, uint32_t *outlen)
{
	if (*p >= end)
		return BST_HPACK_ERR;
	bool huff = (**p & 0x80) != 0;
	uint32_t len;
	if (bst_hpack_int_decode(p, end, 7, &len) != 0 || len > (size_t)(end - *p))
		return BST_HPACK_ERR;
	if (!huff) {
		if (len > budget)
			return BST_HPACK_TOO_LARGE;
		const char *c = arena_copy(arena, (const char *)*p, len);
		if (c == NULL)
			return BST_HPACK_NOMEM;
		*out = c;
		*outlen = len;
		*p += len;
		return BST_HPACK_OK;
	}
	/* a code is at least 5 bits: len bytes decode to at most len * 8 / 5 */
	uint64_t cap = (uint64_t)len * 8 / 5;
	if (cap > budget)
		cap = budget;
	char *buf = cap > 0 ? bst_arena_alloc(arena, (size_t)cap) : (char *)"";
	if (buf == NULL)
		return BST_HPACK_NOMEM;
	ssize_t n = bst_huff_decode(*p, len, (uint8_t *)buf, (size_t)cap);
	if (n == BST_HUFF_TOO_BIG)
		return BST_HPACK_TOO_LARGE;
	if (n < 0)
		return BST_HPACK_ERR;
	*out = buf;
	*outlen = (uint32_t)n;
	*p += len;
	return BST_HPACK_OK;
}

/* copy: the field's bytes are in the table and may be evicted, so they go into the arena. */
static int emit(bst_headers *out, bst_arena *arena, const field *f, bool copy, uint64_t *total,
		uint32_t max)
{
	*total += (uint64_t)f->nl + f->vl + BST_HPACK_ENTRY_OVERHEAD;
	if (*total > max)
		return BST_HPACK_TOO_LARGE;
	const char *n = f->n, *v = f->v;
	if (copy && ((n = arena_copy(arena, f->n, f->nl)) == NULL || (v = arena_copy(arena, f->v, f->vl)) == NULL))
		return BST_HPACK_NOMEM;
	if (bst_headers_add(out, (bst_str){ n, f->nl }, (bst_str){ v, f->vl }) != 0)
		return BST_HPACK_NOMEM;
	return BST_HPACK_OK;
}

int bst_hpack_decode(bst_hpack_dec *d, const uint8_t *in, size_t n, bst_arena *arena,
		     bst_headers *out, const bst_hpack_limits *lim)
{
	if (n == 0) /* an empty block is no fields (and in may be NULL) */
		return BST_HPACK_OK;
	const uint8_t *p = in, *end = in + n;
	uint64_t total = 0;
	bool at_start = true;
	uint32_t max = lim->max_header_list_size;
	while (p < end) {
		uint8_t b = *p;
		int rc;
		if (b & 0x80) { /* indexed field */
			uint32_t idx;
			field f;
			if (bst_hpack_int_decode(&p, end, 7, &idx) != 0 || idx == 0 || !field_at(d, idx, &f))
				return BST_HPACK_ERR;
			at_start = false;
			rc = emit(out, arena, &f, idx > BST_HPACK_STATIC_COUNT, &total, max);
			if (rc != BST_HPACK_OK)
				return rc;
			continue;
		}
		if ((b & 0xe0) == 0x20) { /* dynamic table size update: only at the start of a block */
			uint32_t sz;
			if (!at_start || bst_hpack_int_decode(&p, end, 5, &sz) != 0 || sz > d->limit)
				return BST_HPACK_ERR;
			tab_set_max(&d->t, sz);
			continue;
		}
		at_start = false;
		bool incr = (b & 0xc0) == 0x40; /* else without indexing (0000) or never indexed (0001) */
		uint32_t idx;
		if (bst_hpack_int_decode(&p, end, incr ? 6 : 4, &idx) != 0)
			return BST_HPACK_ERR;
		field f;
		if (max <= total + BST_HPACK_ENTRY_OVERHEAD)
			return BST_HPACK_TOO_LARGE;
		uint64_t room = max - total - BST_HPACK_ENTRY_OVERHEAD;
		if (idx == 0) {
			rc = dec_string(&p, end, arena, room, &f.n, &f.nl);
			if (rc != BST_HPACK_OK)
				return rc;
		} else {
			if (!field_at(d, idx, &f))
				return BST_HPACK_ERR;
			if (f.nl > room)
				return BST_HPACK_TOO_LARGE;
			if (idx > BST_HPACK_STATIC_COUNT) { /* the table may evict this entry below: keep a copy */
				f.n = arena_copy(arena, f.n, f.nl);
				if (f.n == NULL)
					return BST_HPACK_NOMEM;
			}
		}
		rc = dec_string(&p, end, arena, room - f.nl, &f.v, &f.vl);
		if (rc != BST_HPACK_OK)
			return rc;
		total += (uint64_t)f.nl + f.vl + BST_HPACK_ENTRY_OVERHEAD;
		if (bst_headers_add(out, (bst_str){ f.n, f.nl }, (bst_str){ f.v, f.vl }) != 0)
			return BST_HPACK_NOMEM;
		if (incr && tab_add(&d->t, f.n, f.nl, f.v, f.vl) != 0)
			return BST_HPACK_NOMEM;
	}
	return BST_HPACK_OK;
}

/* ---- encoder ---- */

void bst_hpack_enc_init(bst_hpack_enc *e, uint32_t max)
{
	memset(e, 0, sizeof *e);
	tab_init(&e->t, DEFAULT_TABLE);
	if (max != DEFAULT_TABLE) /* the peer starts at the default: tell it the size we use */
		bst_hpack_enc_set_max(e, max);
}

void bst_hpack_enc_free(bst_hpack_enc *e)
{
	tab_free(&e->t);
}

void bst_hpack_enc_set_max(bst_hpack_enc *e, uint32_t max)
{
	if (!e->pending) {
		e->pending = true;
		e->pending_min = max;
	} else if (max < e->pending_min) {
		e->pending_min = max;
	}
	e->pending_cur = max;
	tab_set_max(&e->t, max);
}

static bool name_is(const char *n, size_t nl, const char *lit)
{
	return strlen(lit) == nl && memcmp(n, lit, nl) == 0;
}

/* Headers whose values are secrets: never indexed, and marked so intermediaries keep it so. */
static bool sensitive(const char *n, size_t nl)
{
	return name_is(n, nl, "set-cookie") || name_is(n, nl, "cookie") ||
	       name_is(n, nl, "authorization") || name_is(n, nl, "proxy-authorization");
}

/* Headers that differ on (almost) every response: indexing them would only churn the table. */
static bool volatile_field(const char *n, size_t nl)
{
	static const char *const v[] = { "date", "content-length", "content-range", "etag", "last-modified",
					 "location", "age", "expires", "retry-after", "refresh" };
	for (size_t i = 0; i < sizeof v / sizeof v[0]; i++)
		if (name_is(n, nl, v[i]))
			return true;
	return false;
}

/* huff: 0 never, 1 when it is shorter, 2 whenever it is not longer (the RFC's examples). */
static int enc_string(bst_h2_wr *w, const char *s, size_t n, int huff)
{
	if (huff != 0 && n > 0) {
		size_t hl = bst_huff_encoded_len((const uint8_t *)s, n);
		if (hl < n || (huff == 2 && hl == n)) {
			if (hl > UINT32_MAX || bst_hpack_int_encode(w, 0x80, 7, (uint32_t)hl) != 0 ||
			    bst_h2_wr_reserve(w, hl) != 0)
				return -1;
			w->len += bst_huff_encode((const uint8_t *)s, n, w->p + w->len);
			return 0;
		}
	}
	if (n > UINT32_MAX || bst_hpack_int_encode(w, 0, 7, (uint32_t)n) != 0 || bst_h2_wr_reserve(w, n) != 0)
		return -1;
	memcpy(w->p + w->len, s, n);
	w->len += n;
	return 0;
}

/* Combined index of an exact match, or of a name match when exact is false; 0 for none. Static
 * entries are preferred, as the RFC examples do. */
static uint32_t find(const bst_hpack_table *t, const char *n, size_t nl, const char *v, size_t vl,
		     bool exact)
{
	for (uint32_t i = 1; i <= BST_HPACK_STATIC_COUNT; i++)
		if (stat_tab[i].nl == nl && memcmp(stat_tab[i].n, n, nl) == 0 &&
		    (!exact || (stat_tab[i].vl == vl && memcmp(stat_tab[i].v, v, vl) == 0)))
			return i;
	for (uint32_t i = 1; i <= t->n; i++) {
		const bst_hpack_entry *e = tab_at(t, i);
		if (e->nlen == nl && memcmp(e->data, n, nl) == 0 &&
		    (!exact || (e->vlen == vl && memcmp(e->data + nl, v, vl) == 0)))
			return BST_HPACK_STATIC_COUNT + i;
	}
	return 0;
}

static int enc_field(bst_hpack_enc *e, bst_h2_wr *w, const char *n, size_t nl, const char *v, size_t vl)
{
	bool all = e->policy != BST_HPACK_POLICY_SERVER;
	int huff = e->policy == BST_HPACK_POLICY_INDEX_ALL_RAW ? 0 : e->policy == BST_HPACK_POLICY_INDEX_ALL ? 2 : 1;
	bool never = !all && sensitive(n, nl);
	uint32_t idx = never ? 0 : find(&e->t, n, nl, v, vl, true);
	if (idx != 0)
		return bst_hpack_int_encode(w, 0x80, 7, idx);
	/* index it when the policy allows, and the entry is a fraction of the table at most */
	size_t esz = nl + vl + BST_HPACK_ENTRY_OVERHEAD;
	bool index = all || (!never && !volatile_field(n, nl) && esz <= e->t.max / 4);
	uint32_t nidx = find(&e->t, n, nl, v, vl, false);
	uint8_t first = never ? 0x10 : index ? 0x40 : 0x00;
	if (bst_hpack_int_encode(w, first, index ? 6 : 4, nidx) != 0)
		return -1;
	if (nidx == 0 && enc_string(w, n, nl, huff) != 0)
		return -1;
	if (enc_string(w, v, vl, huff) != 0)
		return -1;
	if (index && tab_add(&e->t, n, (uint32_t)nl, v, (uint32_t)vl) != 0)
		return -1;
	return 0;
}

int bst_hpack_encode(bst_hpack_enc *e, const bst_headers *h, bst_h2_wr *out)
{
	if (e->pending) {
		if (e->pending_min < e->pending_cur &&
		    bst_hpack_int_encode(out, 0x20, 5, e->pending_min) != 0)
			return -1;
		if (bst_hpack_int_encode(out, 0x20, 5, e->pending_cur) != 0)
			return -1;
		e->pending = false;
	}
	for (uint32_t i = 0; i < h->n; i++) {
		const bst_header *f = &h->v[i];
		char small[128], *name = small;
		if (f->name.len > sizeof small && (name = malloc(f->name.len)) == NULL)
			return -1;
		for (uint32_t k = 0; k < f->name.len; k++)
			name[k] = (char)(f->name.p[k] >= 'A' && f->name.p[k] <= 'Z' ? f->name.p[k] + 32 : f->name.p[k]);
		int rc = enc_field(e, out, name, f->name.len, f->value.p != NULL ? f->value.p : "", f->value.len);
		if (name != small)
			free(name);
		if (rc != 0)
			return -1;
	}
	return 0;
}
