/* See block.h. */
#include "sec/block.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

/* ---- the shared table ----
 *
 * A slot is four 64-bit words: the address (16 bytes), meta (LIVE | v6 << 16 | flags << 8 |
 * prefix) and the expiry. Open addressing with linear probing, at most half full. */

#define LIVE (1ull << 63)
#define V6 (1ull << 16)

typedef struct blk_slot {
	_Atomic uint64_t w[4];
} blk_slot;

typedef struct blk_half {
	_Atomic uint64_t count;
	_Atomic uint64_t v6lens[3]; /* bit p: some IPv6 block of prefix p */
} blk_half;

/* The shared bytes. Everything that sizes or indexes them (nslots, which half master writes)
 * lives in the private handle below: a worker that scribbled on the region (if it could) would
 * change what a lookup answers, never where master writes. The layout is the one earlier
 * releases used (the third word was nslots), so a reload or upgrade keeps the blocks. */
typedef struct blk_shared {
	_Atomic uint64_t seq;
	_Atomic uint32_t active;
	uint32_t unused; /* zero */
	blk_half half[2];
	blk_slot slots[]; /* half 0, then half 1 */
} blk_shared;

struct bst_block_table {
	blk_shared *rw;	      /* master's mapping; NULL in a child */
	const blk_shared *ro; /* what lookups read: a read-only view in workers */
	uint32_t nslots;      /* per half, a power of two: never read from the region */
	unsigned active;      /* the half master published last */
};

static uint32_t nslots_for(unsigned ceiling)
{
	uint32_t n = 64;
	while (n < 2u * ceiling && n < (1u << 30))
		n *= 2;
	return n;
}

size_t bst_block_table_bytes(unsigned ceiling)
{
	return sizeof(blk_shared) + 2u * (size_t)nslots_for(ceiling) * sizeof(blk_slot);
}

bst_block_table *bst_block_table_attach(void *mem, unsigned ceiling)
{
	if (mem == NULL)
		return NULL;
	bst_block_table *t = calloc(1, sizeof *t);
	if (t == NULL)
		return NULL;
	t->rw = mem;
	t->ro = mem;
	t->nslots = nslots_for(ceiling);
	/* master, before any child: a kept table goes on from the half it last published */
	t->active = atomic_load_explicit(&t->rw->active, memory_order_relaxed) & 1u;
	t->rw->unused = 0;
	return t;
}

void bst_block_table_set_view(bst_block_table *t, const void *ro)
{
	if (t != NULL && ro != NULL)
		t->ro = ro;
}

void bst_block_table_child(bst_block_table *t)
{
	if (t != NULL)
		t->rw = NULL;
}

void bst_block_table_free(bst_block_table *t)
{
	free(t);
}

static void mask_ip(bst_ip *ip, unsigned prefix)
{
	unsigned n = ip->family == BST_IP_V4 ? 4 : 16;
	for (unsigned i = 0; i < 16; i++) {
		unsigned bits = i < n && prefix > i * 8 ? prefix - i * 8 : 0;
		ip->b[i] &= bits >= 8 ? 0xff : (uint8_t)(0xff00u >> bits);
	}
}

static void words(const bst_ip *ip, uint64_t *a, uint64_t *b)
{
	memcpy(a, ip->b, 8);
	memcpy(b, ip->b + 8, 8);
}

static uint64_t meta_of(const bst_ip *ip, unsigned prefix, unsigned flags)
{
	return LIVE | (ip->family == BST_IP_V6 ? V6 : 0) | (uint64_t)(flags & 0xff) << 8 | (prefix & 0xff);
}

static uint64_t hash3(uint64_t a, uint64_t b, uint64_t m)
{
	uint64_t h = a * 0x9e3779b97f4a7c15ull ^ (b + 0x632be59bd9b4e019ull) * 0xbf58476d1ce4e5b9ull ^ m;
	h ^= h >> 31;
	h *= 0x94d049bb133111ebull;
	return h ^ (h >> 29);
}

/* Half h (0 or 1) of the read view; the bound is the private nslots. */
static const blk_slot *half_slots(const bst_block_table *t, unsigned h)
{
	return &t->ro->slots[(size_t)(h & 1u) * t->nslots];
}

/* The expiry of (a, b, meta's key) in half h, 0 when absent. */
static uint64_t probe(const bst_block_table *t, unsigned h, uint64_t a, uint64_t b, uint64_t meta)
{
	const blk_slot *s = half_slots(t, h);
	uint32_t mask = t->nslots - 1;
	uint64_t key = meta & (V6 | 0xff);
	for (uint32_t i = 0, at = (uint32_t)hash3(a, b, key) & mask; i <= mask; i++, at = (at + 1) & mask) {
		uint64_t m = atomic_load_explicit(&s[at].w[2], memory_order_relaxed);
		if (m == 0)
			return 0;
		if ((m & (V6 | 0xff)) == key && atomic_load_explicit(&s[at].w[0], memory_order_relaxed) == a &&
		    atomic_load_explicit(&s[at].w[1], memory_order_relaxed) == b)
			return atomic_load_explicit(&s[at].w[3], memory_order_relaxed);
	}
	return 0;
}

static bool lookup_half(const bst_block_table *t, unsigned h, const bst_ip *ip, uint64_t now_us)
{
	const blk_half *hf = &t->ro->half[h & 1u];
	if (atomic_load_explicit(&hf->count, memory_order_relaxed) == 0)
		return false;
	if (ip->family == BST_IP_V4) {
		uint64_t a, b;
		words(ip, &a, &b);
		return probe(t, h, a, b, meta_of(ip, 32, 0)) > now_us;
	}
	for (unsigned p = 0; p <= 128; p++) {
		if ((atomic_load_explicit(&hf->v6lens[p / 64], memory_order_relaxed) & (1ull << (p % 64))) == 0)
			continue;
		bst_ip m = *ip;
		mask_ip(&m, p);
		uint64_t a, b;
		words(&m, &a, &b);
		if (probe(t, h, a, b, meta_of(&m, p, 0)) > now_us)
			return true;
	}
	return false;
}

bool bst_block_any(const bst_block_table *t)
{
	if (t == NULL)
		return false;
	unsigned h = atomic_load_explicit(&t->ro->active, memory_order_acquire) & 1u;
	return atomic_load_explicit(&t->ro->half[h].count, memory_order_relaxed) > 0;
}

bool bst_block_lookup(const bst_block_table *t, const bst_ip *ip, uint64_t now_us)
{
	if (t == NULL || ip == NULL)
		return false;
	bst_ip c = bst_ip_canon(ip);
	bool found = false;
	for (int tries = 0; tries < 4; tries++) {
		uint64_t s1 = atomic_load_explicit(&t->ro->seq, memory_order_acquire);
		unsigned h = atomic_load_explicit(&t->ro->active, memory_order_acquire) & 1u;
		found = lookup_half(t, h, &c, now_us);
		atomic_thread_fence(memory_order_acquire);
		if (atomic_load_explicit(&t->ro->seq, memory_order_relaxed) == s1)
			break; /* master did not rewrite a half meanwhile */
	}
	return found;
}

size_t bst_block_table_snapshot(const bst_block_table *t, bst_block_entry *out, size_t cap)
{
	if (t == NULL || out == NULL)
		return 0;
	/* master's own record of the half it published, not the region's (which a reload's old
	 * workers could have written: what comes back is revalidated by bst_block_apply) */
	const blk_slot *s = half_slots(t, t->active);
	size_t n = 0;
	for (uint32_t i = 0; i < t->nslots && n < cap; i++) {
		uint64_t m = atomic_load_explicit(&s[i].w[2], memory_order_relaxed);
		if ((m & LIVE) == 0)
			continue;
		bst_block_entry *e = &out[n++];
		memset(e, 0, sizeof *e);
		e->ip.family = (m & V6) ? BST_IP_V6 : BST_IP_V4;
		uint64_t a = atomic_load_explicit(&s[i].w[0], memory_order_relaxed);
		uint64_t b = atomic_load_explicit(&s[i].w[1], memory_order_relaxed);
		memcpy(e->ip.b, &a, 8);
		memcpy(e->ip.b + 8, &b, 8);
		e->prefix = (uint8_t)(m & 0xff);
		e->flags = (uint8_t)((m >> 8) & 0xff);
		e->expires_us = atomic_load_explicit(&s[i].w[3], memory_order_relaxed);
	}
	return n;
}

/* ---- the user-space backend ---- */

typedef struct shm_backend {
	bst_block_table *t;
	bst_block_entry *e;
	size_t n, cap;
} shm_backend;

static bool same_key(const bst_block_entry *a, const bst_block_entry *b)
{
	return a->prefix == b->prefix && bst_ip_eq(&a->ip, &b->ip);
}

static int shm_add(void *ctx, const bst_block_entry *e)
{
	shm_backend *sb = ctx;
	for (size_t i = 0; i < sb->n; i++)
		if (same_key(&sb->e[i], e)) {
			sb->e[i] = *e;
			return 0;
		}
	if (sb->n == sb->cap)
		return -1;
	sb->e[sb->n++] = *e;
	return 0;
}

static int shm_remove(void *ctx, const bst_block_entry *e)
{
	shm_backend *sb = ctx;
	for (size_t i = 0; i < sb->n; i++)
		if (same_key(&sb->e[i], e)) {
			sb->e[i] = sb->e[--sb->n];
			return 0;
		}
	return -1;
}

static size_t shm_list(void *ctx, bst_block_entry *out, size_t cap)
{
	shm_backend *sb = ctx;
	size_t n = sb->n < cap ? sb->n : cap;
	if (out != NULL && n > 0)
		memcpy(out, sb->e, n * sizeof *out);
	return sb->n;
}

/* Rebuilds the inactive half from the list, then flips to it. */
static void shm_commit(void *ctx)
{
	shm_backend *sb = ctx;
	bst_block_table *t = sb->t;
	blk_shared *sh = t->rw;
	if (sh == NULL)
		return; /* only master publishes */
	unsigned h = (t->active & 1u) ^ 1u;
	atomic_fetch_add_explicit(&sh->seq, 1, memory_order_relaxed);
	atomic_thread_fence(memory_order_release);
	blk_slot *s = &sh->slots[(size_t)h * t->nslots];
	uint32_t mask = t->nslots - 1;
	for (uint32_t i = 0; i <= mask; i++)
		for (int k = 0; k < 4; k++)
			atomic_store_explicit(&s[i].w[k], 0, memory_order_relaxed);
	uint64_t lens[3] = { 0, 0, 0 };
	/* sb->n <= ceiling <= nslots / 2, so a free slot exists; the probe is bounded anyway */
	for (size_t i = 0; i < sb->n && i < mask; i++) {
		const bst_block_entry *e = &sb->e[i];
		uint64_t a, b, m = meta_of(&e->ip, e->prefix, e->flags);
		words(&e->ip, &a, &b);
		uint32_t at = (uint32_t)hash3(a, b, m & (V6 | 0xff)) & mask;
		for (uint32_t k = 0; k <= mask && atomic_load_explicit(&s[at].w[2], memory_order_relaxed) != 0; k++)
			at = (at + 1) & mask;
		atomic_store_explicit(&s[at].w[0], a, memory_order_relaxed);
		atomic_store_explicit(&s[at].w[1], b, memory_order_relaxed);
		atomic_store_explicit(&s[at].w[3], e->expires_us, memory_order_relaxed);
		atomic_store_explicit(&s[at].w[2], m, memory_order_relaxed);
		if (e->ip.family == BST_IP_V6)
			lens[e->prefix / 64] |= 1ull << (e->prefix % 64);
	}
	for (int k = 0; k < 3; k++)
		atomic_store_explicit(&sh->half[h].v6lens[k], lens[k], memory_order_relaxed);
	atomic_store_explicit(&sh->half[h].count, sb->n, memory_order_relaxed);
	atomic_store_explicit(&sh->active, h, memory_order_release);
	t->active = h;
	atomic_fetch_add_explicit(&sh->seq, 1, memory_order_release);
}

int bst_block_shm_backend(bst_block_backend *b, bst_block_table *t, unsigned ceiling)
{
	shm_backend *sb = calloc(1, sizeof *sb);
	if (sb == NULL)
		return -1;
	sb->cap = ceiling > 0 ? ceiling : 1;
	sb->e = calloc(sb->cap, sizeof *sb->e);
	if (sb->e == NULL) {
		free(sb);
		return -1;
	}
	sb->t = t;
	*b = (bst_block_backend){ .name = "shm", .ctx = sb, .add = shm_add, .remove = shm_remove,
				  .list = shm_list, .commit = shm_commit };
	return 0;
}

void bst_block_shm_backend_free(bst_block_backend *b)
{
	shm_backend *sb = b->ctx;
	if (sb != NULL) {
		free(sb->e);
		free(sb);
	}
	b->ctx = NULL;
}

/* ---- master ---- */

struct bst_block_master {
	unsigned ceiling;
	bst_cidr *exempt;
	size_t nexempt;
	bst_block_backend *be;
	bst_block_entry *e;
	size_t n;
	bool dirty;
};

bst_block_master *bst_block_master_new(unsigned ceiling, const bst_cidr *exempt, size_t nexempt,
					bst_block_backend *backend)
{
	bst_block_master *m = calloc(1, sizeof *m);
	if (m == NULL)
		return NULL;
	m->ceiling = ceiling > 0 ? ceiling : BST_BLOCK_CEILING_DEFAULT;
	m->e = calloc(m->ceiling, sizeof *m->e);
	m->exempt = nexempt > 0 ? calloc(nexempt, sizeof *m->exempt) : NULL;
	if (m->e == NULL || (nexempt > 0 && m->exempt == NULL)) {
		bst_block_master_free(m);
		return NULL;
	}
	if (nexempt > 0)
		memcpy(m->exempt, exempt, nexempt * sizeof *exempt);
	m->nexempt = nexempt;
	m->be = backend;
	return m;
}

void bst_block_master_free(bst_block_master *m)
{
	if (m != NULL) {
		free(m->e);
		free(m->exempt);
	}
	free(m);
}

bool bst_block_req_valid(const bst_block_req *r, bst_block_entry *e)
{
	if (r->pad != 0 || (r->flags & ~BST_BLOCK_FLAGS) != 0 || r->kind >= BST_BLOCK_KINDS)
		return false;
	if (r->ttl_us < BST_BLOCK_TTL_MIN_US || r->ttl_us > BST_BLOCK_TTL_MAX_US)
		return false;
	memset(e, 0, sizeof *e);
	if (r->family == 4) {
		if (r->prefix != 32)
			return false;
		for (int i = 4; i < 16; i++)
			if (r->addr[i] != 0)
				return false;
		e->ip.family = BST_IP_V4;
	} else if (r->family == 6) {
		if (r->prefix < 48 || r->prefix > 128)
			return false;
		e->ip.family = BST_IP_V6;
	} else {
		return false;
	}
	memcpy(e->ip.b, r->addr, 16);
	bst_ip masked = e->ip;
	mask_ip(&masked, r->prefix);
	if (!bst_ip_eq(&masked, &e->ip)) /* host bits set below the prefix */
		return false;
	if (e->ip.family == BST_IP_V6 && bst_ip_canon(&e->ip).family == BST_IP_V4)
		return false; /* ::ffff: forms come as IPv4 */
	e->prefix = r->prefix;
	e->flags = r->flags;
	return true;
}

/* Does the block overlap any exempt CIDR (either one inside the other)? Two prefixes overlap
 * when they agree on the shorter one's bits. */
static bool exempt(const bst_block_master *m, const bst_block_entry *e)
{
	for (size_t i = 0; i < m->nexempt; i++) {
		bst_cidr x = m->exempt[i];
		x.ip = bst_ip_canon(&x.ip);
		if (x.ip.family != e->ip.family)
			continue;
		if (x.ip.family == BST_IP_V4 && m->exempt[i].ip.family == BST_IP_V6)
			x.prefix = x.prefix >= 96 ? (uint8_t)(x.prefix - 96) : 0; /* ::ffff:a.b.c.d/p */
		unsigned p = x.prefix < e->prefix ? x.prefix : e->prefix;
		bst_ip a = x.ip, b = e->ip;
		mask_ip(&a, p);
		mask_ip(&b, p);
		if (bst_ip_eq(&a, &b))
			return true;
	}
	return false;
}

bst_block_rc bst_block_apply(bst_block_master *m, const bst_block_req *r, uint64_t now_us)
{
	bst_block_entry e;
	if (!bst_block_req_valid(r, &e))
		return BST_BLOCK_MALFORMED;
	if (exempt(m, &e))
		return BST_BLOCK_EXEMPT;
	e.expires_us = now_us + r->ttl_us;
	for (size_t i = 0; i < m->n; i++)
		if (same_key(&m->e[i], &e)) {
			if (e.expires_us > m->e[i].expires_us) {
				/* an L7-only block stays L7-only unless the source itself is seen */
				e.flags &= m->e[i].flags;
				m->e[i] = e;
				if (m->be != NULL && m->be->add(m->be->ctx, &e) != 0)
					return BST_BLOCK_FAILED;
				m->dirty = true;
			}
			return BST_BLOCK_EXTENDED;
		}
	if (m->n >= m->ceiling)
		return BST_BLOCK_CEILING;
	if (m->be != NULL && m->be->add(m->be->ctx, &e) != 0)
		return BST_BLOCK_FAILED;
	m->e[m->n++] = e;
	m->dirty = true;
	return BST_BLOCK_ADDED;
}

size_t bst_block_expire(bst_block_master *m, uint64_t now_us)
{
	size_t gone = 0;
	for (size_t i = 0; i < m->n;) {
		if (m->e[i].expires_us > now_us) {
			i++;
			continue;
		}
		if (m->be != NULL)
			(void)m->be->remove(m->be->ctx, &m->e[i]);
		m->e[i] = m->e[--m->n];
		m->dirty = true;
		gone++;
	}
	return gone;
}

void bst_block_commit(bst_block_master *m)
{
	if (!m->dirty)
		return;
	m->dirty = false;
	if (m->be != NULL && m->be->commit != NULL)
		m->be->commit(m->be->ctx);
}

void bst_block_commit_force(bst_block_master *m)
{
	m->dirty = true;
	bst_block_commit(m);
}

size_t bst_block_active(const bst_block_master *m)
{
	return m->n;
}

bool bst_block_remove(bst_block_master *m, const bst_block_entry *key)
{
	for (size_t i = 0; i < m->n; i++) {
		if (!same_key(&m->e[i], key))
			continue;
		if (m->be != NULL)
			(void)m->be->remove(m->be->ctx, &m->e[i]);
		m->e[i] = m->e[--m->n];
		m->dirty = true;
		return true;
	}
	return false;
}

const bst_block_entry *bst_block_at(const bst_block_master *m, size_t i)
{
	return i < m->n ? &m->e[i] : NULL;
}
