#include "handlers/ofcache.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

bst_file *bst_file_new(int fd, off_t size, int64_t mtime_ns, uint64_t ino, mode_t mode, uid_t uid)
{
	bst_file *f = malloc(sizeof *f);
	if (f == NULL)
		return NULL;
	*f = (bst_file){ fd, 1, size, mtime_ns, ino, mode, uid };
	return f;
}

bst_file *bst_file_ref(bst_file *f)
{
	f->refs++;
	return f;
}

void bst_file_unref(bst_file *f)
{
	if (f == NULL || --f->refs > 0)
		return;
	if (f->fd >= 0)
		close(f->fd);
	free(f);
}

typedef struct ent {
	struct ent *hnext;       /* bucket chain */
	struct ent *prev, *next; /* LRU: head is the most recent */
	uint64_t hash;
	uint64_t expires;
	bst_file *file; /* NULL: a remembered failure */
	int err;
	size_t klen;
	char key[];
} ent;

struct bst_ofcache {
	size_t max, count, nbuckets;
	uint64_t ttl_ms;
	bool errors;
	ent **buckets;
	ent *head, *tail;
};

static uint64_t fnv(const char *p, size_t n)
{
	uint64_t h = 1469598103934665603ull;
	for (size_t i = 0; i < n; i++)
		h = (h ^ (unsigned char)p[i]) * 1099511628211ull;
	return h;
}

bst_ofcache *bst_ofcache_new(size_t max, uint64_t ttl_ms, bool errors)
{
	if (max == 0)
		max = 1;
	bst_ofcache *c = calloc(1, sizeof *c);
	if (c == NULL)
		return NULL;
	c->nbuckets = 16;
	while (c->nbuckets < max * 2)
		c->nbuckets <<= 1;
	c->buckets = calloc(c->nbuckets, sizeof *c->buckets);
	if (c->buckets == NULL) {
		free(c);
		return NULL;
	}
	c->max = max;
	c->ttl_ms = ttl_ms;
	c->errors = errors;
	return c;
}

static void lru_unlink(bst_ofcache *c, ent *e)
{
	if (e->prev != NULL)
		e->prev->next = e->next;
	else
		c->head = e->next;
	if (e->next != NULL)
		e->next->prev = e->prev;
	else
		c->tail = e->prev;
	e->prev = e->next = NULL;
}

static void lru_push(bst_ofcache *c, ent *e)
{
	e->prev = NULL;
	e->next = c->head;
	if (c->head != NULL)
		c->head->prev = e;
	c->head = e;
	if (c->tail == NULL)
		c->tail = e;
}

static void drop(bst_ofcache *c, ent *e)
{
	ent **pp = &c->buckets[e->hash & (c->nbuckets - 1)];
	while (*pp != e)
		pp = &(*pp)->hnext;
	*pp = e->hnext;
	lru_unlink(c, e);
	bst_file_unref(e->file);
	free(e);
	c->count--;
}

void bst_ofcache_free(bst_ofcache *c)
{
	if (c == NULL)
		return;
	while (c->head != NULL)
		drop(c, c->head);
	free(c->buckets);
	free(c);
}

static ent *find(bst_ofcache *c, const char *key, size_t len, uint64_t h)
{
	for (ent *e = c->buckets[h & (c->nbuckets - 1)]; e != NULL; e = e->hnext)
		if (e->hash == h && e->klen == len && memcmp(e->key, key, len) == 0)
			return e;
	return NULL;
}

bst_file *bst_ofcache_get(bst_ofcache *c, const char *key, size_t len, uint64_t now_ms, int *err)
{
	*err = 0;
	uint64_t h = fnv(key, len);
	ent *e = find(c, key, len, h);
	if (e == NULL)
		return NULL;
	if (now_ms >= e->expires) {
		drop(c, e);
		return NULL;
	}
	lru_unlink(c, e);
	lru_push(c, e);
	if (e->file == NULL) {
		*err = e->err;
		return NULL;
	}
	return bst_file_ref(e->file);
}

static void put(bst_ofcache *c, const char *key, size_t len, bst_file *f, int err, uint64_t now)
{
	uint64_t h = fnv(key, len);
	ent *old = find(c, key, len, h);
	if (old != NULL)
		drop(c, old);
	while (c->count >= c->max && c->tail != NULL)
		drop(c, c->tail);
	ent *e = malloc(sizeof *e + len);
	if (e == NULL)
		return; /* a cache that cannot grow just does not remember */
	e->hash = h;
	e->expires = now + c->ttl_ms;
	e->file = f != NULL ? bst_file_ref(f) : NULL;
	e->err = err;
	e->klen = len;
	memcpy(e->key, key, len);
	ent **b = &c->buckets[h & (c->nbuckets - 1)];
	e->hnext = *b;
	*b = e;
	lru_push(c, e);
	c->count++;
}

void bst_ofcache_put(bst_ofcache *c, const char *key, size_t len, bst_file *f, uint64_t now_ms)
{
	put(c, key, len, f, 0, now_ms);
}

void bst_ofcache_put_err(bst_ofcache *c, const char *key, size_t len, int err, uint64_t now_ms)
{
	if (c->errors && err != 0)
		put(c, key, len, NULL, err, now_ms);
}

size_t bst_ofcache_count(const bst_ofcache *c)
{
	return c->count;
}
