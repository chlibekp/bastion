/* See ram.h. */
#include "cache/ram.h"

#include <stdlib.h>
#include <string.h>

typedef struct fifo {
	bst_robj *head, *tail; /* new at head, old at tail */
	size_t bytes;
} fifo;

struct bst_ram {
	size_t max, max_object, small_max, bytes, count;
	bst_robj **tab;
	size_t nbuckets; /* a power of two */
	fifo small, main;
	uint64_t *ghost; /* a direct-mapped set of key hashes evicted from small */
	size_t nghost;
};

static size_t pow2_at_least(size_t n)
{
	size_t p = 64;
	while (p < n && p < (1u << 20))
		p <<= 1;
	return p;
}

bst_ram *bst_ram_new(size_t max_bytes, size_t max_object)
{
	bst_ram *r = calloc(1, sizeof *r);
	if (r == NULL)
		return NULL;
	r->max = max_bytes;
	r->max_object = max_object;
	r->small_max = max_bytes / 10;
	r->nbuckets = pow2_at_least(max_bytes / 4096);
	r->nghost = r->nbuckets;
	r->tab = calloc(r->nbuckets, sizeof *r->tab);
	r->ghost = calloc(r->nghost, sizeof *r->ghost);
	if (r->tab == NULL || r->ghost == NULL) {
		free(r->tab);
		free(r->ghost);
		free(r);
		return NULL;
	}
	return r;
}

void bst_robj_unref(bst_robj *o)
{
	if (o != NULL && --o->refs == 0)
		free(o);
}

static bst_robj **slot_of(bst_ram *r, const bst_key *k)
{
	bst_robj **pp = &r->tab[bst_key_u64(k) & (r->nbuckets - 1)];
	while (*pp != NULL && memcmp((*pp)->key.b, k->b, 32) != 0)
		pp = &(*pp)->hnext;
	return pp;
}

static void q_push(fifo *q, bst_robj *o)
{
	o->qprev = NULL;
	o->qnext = q->head;
	if (q->head != NULL)
		q->head->qprev = o;
	q->head = o;
	if (q->tail == NULL)
		q->tail = o;
	q->bytes += o->charge;
}

static void q_unlink(fifo *q, bst_robj *o)
{
	if (o->qprev != NULL)
		o->qprev->qnext = o->qnext;
	else
		q->head = o->qnext;
	if (o->qnext != NULL)
		o->qnext->qprev = o->qprev;
	else
		q->tail = o->qprev;
	o->qprev = o->qnext = NULL;
	q->bytes -= o->charge;
}

static fifo *q_of(bst_ram *r, const bst_robj *o)
{
	return o->queue == 1 ? &r->small : &r->main;
}

/* Out of the table and queues, and the tier's reference dropped. */
static void drop(bst_ram *r, bst_robj *o)
{
	bst_robj **pp = slot_of(r, &o->key);
	if (*pp == o)
		*pp = o->hnext;
	q_unlink(q_of(r, o), o);
	o->queue = 0;
	r->bytes -= o->charge;
	r->count--;
	bst_robj_unref(o);
}

static void ghost_add(bst_ram *r, const bst_key *k)
{
	uint64_t h = bst_key_u64(k) | 1; /* 0 means an empty slot */
	r->ghost[h % r->nghost] = h;
}

static bool ghost_has(bst_ram *r, const bst_key *k)
{
	uint64_t h = bst_key_u64(k) | 1;
	return r->ghost[h % r->nghost] == h;
}

static void evict_one(bst_ram *r)
{
	if (r->small.tail != NULL && (r->small.bytes > r->small_max || r->main.tail == NULL)) {
		bst_robj *o = r->small.tail;
		q_unlink(&r->small, o);
		if (o->freq > 0) { /* used again while new: it earned the main queue */
			o->freq = 0;
			o->queue = 2;
			q_push(&r->main, o);
		} else {
			o->queue = 1; /* drop expects it in a queue */
			q_push(&r->small, o);
			ghost_add(r, &o->key);
			drop(r, o);
		}
		return;
	}
	bst_robj *o = r->main.tail;
	if (o == NULL)
		return;
	q_unlink(&r->main, o);
	if (o->freq > 0) { /* another round */
		o->freq--;
		q_push(&r->main, o);
		return;
	}
	q_push(&r->main, o);
	drop(r, o);
}

bst_robj *bst_ram_get(bst_ram *r, const bst_key *k)
{
	bst_robj *o = *slot_of(r, k);
	if (o == NULL)
		return NULL;
	if (o->freq < 3)
		o->freq++;
	o->refs++;
	return o;
}

bool bst_ram_put(bst_ram *r, const bst_key *k, const bst_sobj_meta *m, const void *body, size_t len)
{
	size_t blob = (size_t)m->head.len + m->vary.len;
	size_t charge = sizeof(bst_robj) + blob + len;
	if (len > r->max_object || charge > r->max || m->ntags > BST_STORE_MAX_TAGS)
		return false;
	bst_robj *o = malloc(sizeof *o + blob + len + 1);
	if (o == NULL)
		return false;
	memset(o, 0, sizeof *o);
	char *p = (char *)(o + 1);
	if (m->head.len > 0)
		memcpy(p, m->head.p, m->head.len);
	if (m->vary.len > 0)
		memcpy(p + m->head.len, m->vary.p, m->vary.len);
	if (len > 0)
		memcpy(p + blob, body, len);
	o->refs = 1;
	o->key = *k;
	o->m = *m;
	o->m.head = (bst_str){ p, m->head.len };
	o->m.vary = (bst_str){ p + m->head.len, m->vary.len };
	if (m->ntags > 0)
		memcpy(o->tagbuf, m->tags, (size_t)m->ntags * 8);
	o->m.tags = o->tagbuf;
	o->m.body_len = len;
	o->body = (const unsigned char *)p + blob;
	o->charge = charge;
	bst_robj *old = *slot_of(r, k);
	if (old != NULL)
		drop(r, old);
	while (r->bytes + charge > r->max && r->count > 0)
		evict_one(r);
	bool returning = ghost_has(r, k);
	o->queue = returning ? 2 : 1;
	q_push(returning ? &r->main : &r->small, o);
	bst_robj **pp = slot_of(r, k);
	o->hnext = NULL;
	*pp = o;
	r->bytes += charge;
	r->count++;
	return true;
}

void bst_ram_remove(bst_ram *r, const bst_key *k)
{
	bst_robj *o = *slot_of(r, k);
	if (o != NULL)
		drop(r, o);
}

void bst_ram_free(bst_ram *r)
{
	if (r == NULL)
		return;
	while (r->small.tail != NULL)
		drop(r, r->small.tail);
	while (r->main.tail != NULL)
		drop(r, r->main.tail);
	free(r->tab);
	free(r->ghost);
	free(r);
}

size_t bst_ram_bytes(const bst_ram *r)
{
	return r->bytes;
}

size_t bst_ram_count(const bst_ram *r)
{
	return r->count;
}

size_t bst_ram_max_object(const bst_ram *r)
{
	return r->max_object;
}
