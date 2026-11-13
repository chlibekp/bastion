/* See filter.h. */
#include "cache/filter.h"

#include "cache/cache.h"
#include "cache/lock.h"
#include "cache/policy.h"
#include "proxy/upstream.h"
#include "cache/ram.h"
#include "core/log.h"
#include "handlers/range.h"
#include "http/conditional.h"
#include "proc/worker.h"
#include "proxy/handler.h"
#include "route/vars.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define VALID_MAX 32
#define MARKER_STATUS 0 /* the status of a Vary marker object */

static const bst_stream_ops sink_ops; /* detached internal requests, at the end of this file */
static void bg_fill(const bst_stream *orig);
static bool stale_on_error(bst_cfill *cf, int status);

typedef enum mode {
	M_LOOKUP = 0, /* looking for a stored response */
	M_FILL,	      /* forwarded: the response may be stored */
	M_REVALIDATE, /* forwarded with the stored validators */
	M_PASS,	      /* forwarded: nothing is stored (Range, HEAD miss, bypass of storing) */
	M_INVALIDATE, /* an unsafe method: a success removes the stored response */
} mode;

struct bst_cfill {
	bst_stream *s; /* NULL once the stream ended */
	bst_cache_rt *rt;
	const bst_cfg_cache *cc;
	bst_cache_forward_fn forward;
	bst_cfill **slot; /* the caller's pointer to us while we have the stream (filter.h) */
	mode mode;
	bst_key key;	  /* the object looked up or filled */
	bst_key base;	  /* the cache key itself (a Vary marker sits here) */
	bool variant;	  /* key is a variant of base */
	int64_t t0_ms;	  /* wall clock when the request began: the fill's stored_at */
	int64_t t0_s;
	bool aio;	  /* a disk read is in flight */
	bool dead;	  /* freed when the read comes back */
	const char *fwd;  /* Cache-Status fwd= reason */
	const char *detail;
	/* the stored response found */
	bst_sobj *so;
	bst_robj *ro;
	const bst_sobj_meta *m;
	bst_centry ie;	  /* its index entry */
	bst_headers sh;	  /* its fields (stream arena) */
	bool have;
	/* the fill */
	bst_swriter *w;
	bool storing, ram_ok;
	unsigned char *rbuf; /* the body for the RAM tier, up to ram_max_object */
	size_t rlen, rcap;
	uint64_t max_object;
	bst_sobj_meta fm;    /* what is written: head and vary point into fblob */
	char *fblob;
	bool vary_marker;    /* a marker goes under base on commit */
	char *marker_blob;
	size_t marker_len;
	/* the stampede lock (cache/lock.h) */
	bool locked;	     /* this request fetches for the others */
	bst_key lock_key;
	unsigned lock_slot;
	uint64_t lock_dl;
	bool waiting;	     /* waits for another request's fill */
	bst_timer wait_t;
	uint64_t wait_start, wait_ms;
	/* the found response's freshness, for stale serving */
	int64_t life, age, sie;
	bool must_reval;
};

static unsigned g_waiters; /* this worker's requests waiting on a lock */

/* ---- small helpers ---- */

static int64_t wall_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static bool truthy(bst_stream *s, const bst_cfg_list *l)
{
	for (size_t i = 0; i < l->n; i++) {
		bst_var_ctx vc;
		bst_var_ctx_init(&vc, s);
		bst_str v = bst_tpl_eval(l->items[i], &vc, s->arena);
		if (v.len > 0 && !(v.len == 1 && v.p[0] == '0'))
			return true;
	}
	return false;
}

static size_t policy_of(const bst_cfg_cache *cc, bst_cache_policy_cfg *pc, bst_cache_valid *v)
{
	size_t n = cc->valid.n < VALID_MAX ? cc->valid.n : VALID_MAX;
	for (size_t i = 0; i < n; i++)
		v[i] = *(const bst_cache_valid *)cc->valid.items[i];
	memset(pc, 0, sizeof *pc);
	pc->valid = v;
	pc->nvalid = n;
	pc->honor_request_cc = cc->honor_req_cc;
	pc->cookies = (bst_cache_cookies)cc->cookies;
	pc->ignore = cc->ignore;
	pc->vary_limit = cc->vary_limit;
	pc->heuristic_max = 86400;
	return n;
}

static bool copy_str(bst_arena *a, bst_str in, bst_str *out)
{
	char *b = bst_arena_alloc(a, (size_t)in.len + 1);
	if (b == NULL)
		return false;
	if (in.len > 0)
		memcpy(b, in.p, in.len);
	b[in.len] = 0;
	*out = (bst_str){ b, in.len };
	return true;
}

/* "name\0value\0" pairs of h into a malloc'd blob. */
static char *serialize(const bst_headers *h, const bst_cfg_cache *cc, size_t *len)
{
	size_t n = 0;
	for (uint32_t i = 0; i < h->n; i++)
		n += (size_t)h->v[i].name.len + h->v[i].value.len + 2;
	char *b = malloc(n + 1);
	if (b == NULL)
		return NULL;
	size_t k = 0;
	for (uint32_t i = 0; i < h->n; i++) {
		const bst_header *f = &h->v[i];
		if (f->id == BST_H_SET_COOKIE && cc->cookies == BST_CACHE_COOKIES_STRIP)
			continue; /* stored without the cookie that was for one client */
		if (bst_str_ieq(f->name, BST_S("cache-status")))
			continue;
		memcpy(b + k, f->name.p, f->name.len);
		k += f->name.len;
		b[k++] = 0;
		memcpy(b + k, f->value.p, f->value.len);
		k += f->value.len;
		b[k++] = 0;
	}
	*len = k;
	return b;
}

/* Cache-Status (RFC 9211), appended to h. */
static void add_status(bst_cfill *cf, bst_headers *h, bool hit, int64_t ttl)
{
	if (cf->cc->status_header == NULL)
		return;
	char *v = bst_arena_alloc(cf->s->arena, 160);
	if (v == NULL)
		return;
	int n;
	if (hit)
		n = snprintf(v, 160, "bastion; hit; ttl=%" PRId64, ttl);
	else
		n = snprintf(v, 160, "bastion; fwd=%s%s%s%s", cf->fwd ? cf->fwd : "miss",
			     cf->storing ? "; stored" : "", cf->detail ? "; detail=" : "",
			     cf->detail ? cf->detail : "");
	if (n > 0)
		(void)bst_headers_add(h, (bst_str){ cf->cc->status_header,
						    (uint32_t)strlen(cf->cc->status_header) },
				      (bst_str){ v, (uint32_t)(n < 160 ? n : 159) });
}

/* ---- min_uses: per worker, a direct-mapped table of recent misses ---- */

#define USES_SLOTS 4096
static struct {
	uint64_t key;
	uint32_t n;
} uses_tab[USES_SLOTS];

static unsigned note_use(const bst_key *k)
{
	uint64_t h = bst_key_u64(k);
	unsigned i = (unsigned)(h % USES_SLOTS);
	if (uses_tab[i].key != h) {
		uses_tab[i].key = h;
		uses_tab[i].n = 0;
	}
	return ++uses_tab[i].n;
}

/* ---- lifetime ---- */

static void drop_found(bst_cfill *cf)
{
	bst_sobj_free(cf->so);
	cf->so = NULL;
	bst_robj_unref(cf->ro);
	cf->ro = NULL;
	cf->m = NULL;
	cf->have = false;
}

static void unlock(bst_cfill *cf, bool pass)
{
	if (!cf->locked)
		return;
	cf->locked = false;
	uint64_t now = bst_mono_ms();
	bst_cachelock_release(cf->rt->locks, &cf->lock_key, cf->lock_slot, cf->lock_dl, pass,
			      now + cf->rt->cfg->lock_timeout_ms);
}

static void stop_waiting(bst_cfill *cf)
{
	if (!cf->waiting)
		return;
	cf->waiting = false;
	g_waiters--;
	bst_timer_cancel(&cf->wait_t);
}

static void cf_free(bst_cfill *cf)
{
	stop_waiting(cf);
	unlock(cf, false); /* a fill that ended unstored: the next request tries again */
	if (cf->aio) {
		cf->dead = true; /* freed when the read comes back */
		return;
	}
	drop_found(cf);
	bst_store_abort(cf->w);
	free(cf->rbuf);
	free(cf->fblob);
	free(cf->marker_blob);
	free(cf);
}

void bst_cache_reset(bst_cfill *cf)
{
	if (cf == NULL)
		return;
	cf->s = NULL;
	cf_free(cf);
}

static void let_go(bst_cfill *cf)
{
	if (cf->slot != NULL)
		*cf->slot = NULL;
	cf->slot = NULL;
}

static void forward(bst_cfill *cf, mode m, const char *why)
{
	let_go(cf);
	stop_waiting(cf);
	cf->mode = m;
	if (why != NULL)
		cf->fwd = why;
	cf->forward(cf->s, cf);
}

/* ---- serving a stored response ---- */

static void release_sobj(void *arg)
{
	bst_sobj_free(arg);
}

static void release_robj(bst_buf *b, void *ctx)
{
	(void)b;
	bst_robj_unref(ctx);
}

static int64_t age_of(const bst_cfill *cf, int64_t now)
{
	return bst_cache_age(BST_CC_NONE, BST_CC_NONE, cf->ie.req_time, cf->ie.resp_time, now);
}

/* The 304 of RFC 9110 section 15.4.5: the fields that describe the stored representation. */
static int not_modified(bst_cfill *cf, bst_stream *s, bst_resp_head *h)
{
	static const bst_hdr_id keep[] = { BST_H_ETAG, BST_H_CACHE_CONTROL, BST_H_EXPIRES, BST_H_VARY,
					   BST_H_CONTENT_LOCATION, BST_H_LAST_MODIFIED };
	bst_headers out;
	bst_headers_init(&out, s->arena);
	for (uint32_t i = 0; i < h->headers.n; i++) {
		const bst_header *f = &h->headers.v[i];
		bool k = bst_str_ieq(f->name, BST_S("age")) ||
			 (cf->cc->status_header && bst_str_ieq(f->name, (bst_str){ cf->cc->status_header,
				(uint32_t)strlen(cf->cc->status_header) }));
		for (size_t j = 0; j < sizeof keep / sizeof keep[0]; j++)
			k = k || f->id == keep[j];
		if (k && bst_headers_add(&out, f->name, f->value) != 0)
			return -1;
	}
	h->headers = out;
	h->status = 304;
	h->content_length = -1;
	return bst_stream_send_head(s, h, true);
}

/* Sends the stored response (cf->sh, status, body) to the client: conditionals, Range, HEAD.
 * hit: a fresh hit (Age and ttl); else a forwarded response served from storage. */
static void serve(bst_cfill *cf, bool hit, int64_t ttl)
{
	bst_stream *s = cf->s;
	const bst_sobj_meta *m = cf->m;
	int64_t now = (int64_t)time(NULL);
	let_go(cf);
	bst_resp_head h;
	memset(&h, 0, sizeof h);
	h.status = m->status;
	h.content_length = (int64_t)m->body_len;
	bst_headers_init(&h.headers, s->arena);
	bst_str tag = { cf->cc->tag_header, cf->cc->tag_header ? (uint32_t)strlen(cf->cc->tag_header) : 0 };
	for (uint32_t i = 0; i < cf->sh.n; i++) {
		const bst_header *f = &cf->sh.v[i];
		if (f->id == BST_H_DATE || f->id == BST_H_AGE)
			continue; /* the protocol writes Date; Age is ours */
		if (tag.len > 0 && !cf->cc->tag_header_pass && bst_str_ieq(f->name, tag))
			continue;
		if (bst_headers_add(&h.headers, f->name, f->value) != 0)
			goto oom;
	}
	char age[24];
	int an = snprintf(age, sizeof age, "%" PRId64, age_of(cf, now));
	if (bst_headers_add(&h.headers, BST_S("Age"), (bst_str){ age, (uint32_t)an }) != 0)
		goto oom;
	add_status(cf, &h.headers, hit, ttl);
	/* conditionals (RFC 9110 section 13.2.2) against the stored validators */
	bst_validators v;
	memset(&v, 0, sizeof v);
	const bst_header *et = bst_headers_get(&cf->sh, BST_H_ETAG);
	const bst_header *lm = bst_headers_get(&cf->sh, BST_H_LAST_MODIFIED);
	if (et != NULL) {
		v.has_etag = true;
		v.etag = et->value;
	}
	if (lm != NULL && bst_http_date_parse(lm->value, &v.mtime))
		v.has_mtime = true;
	if (m->status == 200) {
		bst_cond_result cr = bst_evaluate_preconditions(&s->req.head.headers, &v,
								s->req.head.method);
		if (cr == BST_COND_304) {
			cf->s = NULL;
			(void)not_modified(cf, s, &h);
			cf_free(cf);
			return;
		}
		if (cr == BST_COND_412) {
			cf->s = NULL;
			(void)bst_send_error(s, 412);
			cf_free(cf);
			return;
		}
	}
	off_t off = 0, len = (off_t)m->body_len;
	const bst_header *rg = bst_headers_get(&s->req.head.headers, BST_H_RANGE);
	const bst_header *ir = bst_headers_get(&s->req.head.headers, BST_H_IF_RANGE);
	if (rg != NULL && m->status == 200 && s->req.head.method == BST_M_GET &&
	    (ir == NULL || bst_if_range_ok(ir->value, et ? et->value : BST_S(""), v.has_mtime, v.mtime))) {
		bst_range r[1];
		int n = 0;
		int rs = bst_range_parse(rg->value, (off_t)m->body_len, r, 1, &n);
		char cr[80];
		if (rs == BST_RANGE_416) {
			int k = snprintf(cr, sizeof cr, "bytes */%" PRIu64, m->body_len);
			cf->s = NULL;
			(void)bst_send_error_hdr(s, 416, BST_S("Content-Range"),
						 (bst_str){ cr, (uint32_t)k });
			cf_free(cf);
			return;
		}
		if (rs == BST_RANGE_OK && n == 1) {
			off = r[0].start;
			len = r[0].end - r[0].start + 1;
			int k = snprintf(cr, sizeof cr, "bytes %lld-%lld/%" PRIu64, (long long)r[0].start,
					 (long long)r[0].end, m->body_len);
			char *c = bst_arena_alloc(s->arena, (size_t)k);
			if (c == NULL)
				goto oom;
			memcpy(c, cr, (size_t)k);
			if (bst_headers_add(&h.headers, BST_S("Content-Range"), (bst_str){ c, (uint32_t)k }) != 0)
				goto oom;
			h.status = 206;
			h.content_length = len;
		}
	}
	if (cf->ie.size > 0)
		(void)bst_cindex_touch(cf->rt->idx, &cf->key, (uint32_t)now);
	cf->s = NULL; /* the stream is the protocol's again once the response ends */
	if (s->req.head.method == BST_M_HEAD || len == 0) {
		(void)bst_stream_send_head(s, &h, true);
		cf_free(cf);
		return;
	}
	if (bst_stream_send_head(s, &h, false) != 0) {
		cf_free(cf);
		return;
	}
	bst_chain c;
	bst_chain_init(&c, s->chain_slab);
	int rc;
	if (cf->ro != NULL) {
		bst_buf *b = bst_buf_wrap((void *)cf->ro->body, (size_t)m->body_len, release_robj, cf->ro);
		if (b != NULL)
			b->len = (size_t)m->body_len;
		rc = b == NULL ? -1 : bst_chain_add_mem(&c, b, (size_t)off, (size_t)len);
		if (b != NULL) {
			cf->ro = NULL; /* the buffer holds the reference now */
			bst_buf_unref(b);
		}
	} else {
		/* a file segment: zero copy (sendfile, splice) where the connection allows it */
		rc = bst_chain_add_file_rel(&c, cf->so->fd, (off_t)cf->so->body_off + off, len,
					    release_sobj, cf->so);
		if (rc == 0)
			cf->so = NULL; /* closed by the segment's release */
	}
	if (rc != 0) {
		s->ops->reset(s, BST_STREAM_ERR_INTERNAL);
		cf_free(cf);
		return;
	}
	(void)bst_stream_send_body(s, &c, true, NULL, NULL);
	cf_free(cf);
	return;
oom:
	cf->s = NULL;
	(void)bst_send_error(s, 500);
	cf_free(cf);
}

/* ---- lookup ---- */

static void found(bst_cfill *cf);
static void lookup_key(bst_cfill *cf);

static void on_read(void *ud, bst_sobj *o, int err)
{
	bst_cfill *cf = ud;
	cf->aio = false;
	if (cf->dead || cf->s == NULL) {
		bst_sobj_free(o);
		cf->dead = false;
		cf->s = NULL;
		cf_free(cf);
		return;
	}
	if (o == NULL || o->m.stored_at_ms != cf->ie.stored_at_ms) {
		if (err == -EBADMSG)
			bst_log(BST_LOG_WARN, "cache_store %s: a broken object was removed",
				cf->rt->cfg->name);
		if (o == NULL && err != -ENOENT && err != -EBADMSG)
			bst_log(BST_LOG_WARN, "cache_store %s: reading an object failed: %s",
				cf->rt->cfg->name, strerror(-err));
		bst_sobj_free(o);
		if (err == -ENOENT || err == -EBADMSG)
			(void)bst_cindex_remove(cf->rt->idx, &cf->key); /* gone from disk */
		forward(cf, M_FILL, "miss");
		return;
	}
	stop_waiting(cf);
	cf->so = o;
	cf->m = &o->m;
	found(cf);
}

/* The index has key: the object comes from this worker's RAM tier when it holds the same fill,
 * else from disk. */
static void miss(bst_cfill *cf);
static void wait_more(bst_cfill *cf);

static void lookup_key(bst_cfill *cf)
{
	if (!bst_cindex_lookup(cf->rt->idx, &cf->key, &cf->ie)) {
		bst_ram *r = bst_cache_ram(cf->rt);
		if (r != NULL)
			bst_ram_remove(r, &cf->key); /* evicted or invalidated elsewhere */
		miss(cf);
		return;
	}
	bst_ram *r = bst_cache_ram(cf->rt);
	bst_robj *o = r != NULL ? bst_ram_get(r, &cf->key) : NULL;
	if (o != NULL && o->m.stored_at_ms == cf->ie.stored_at_ms) {
		stop_waiting(cf);
		cf->ro = o;
		cf->m = &o->m;
		found(cf);
		return;
	}
	if (o != NULL) {
		bst_robj_unref(o);
		bst_ram_remove(r, &cf->key);
	}
	cf->aio = true;
	int rc = bst_store_open_read(&cf->rt->store, bst_worker_loop(cf->s->worker), &cf->key, on_read, cf);
	if (rc == 0)
		return;
	cf->aio = false;
	uint64_t now = bst_mono_ms();
	if (rc == -EAGAIN && (!cf->waiting || now - cf->wait_start < cf->rt->cfg->lock_timeout_ms)) {
		/* the aio queue is full (a crowd of waiters woke at once): read a little later */
		if (!cf->waiting) {
			cf->waiting = true;
			g_waiters++;
			cf->wait_start = now;
			cf->wait_ms = 0;
			bst_timer_init(&cf->wait_t);
		}
		wait_more(cf);
		return;
	}
	forward(cf, M_FILL, "miss");
}

static void found(bst_cfill *cf)
{
	bst_stream *s = cf->s;
	const bst_sobj_meta *m = cf->m;
	bst_sobj view;
	view.m = *m;
	if (bst_sobj_headers(&view, &cf->sh, s->arena) != 0) {
		drop_found(cf);
		forward(cf, M_FILL, "miss");
		return;
	}
	if (m->status == MARKER_STATUS) {
		/* a Vary marker: the variant's key is the key plus this request's Vary data */
		char vd[BST_CACHE_VARY_MAX];
		int n = cf->variant ? -1 : bst_cache_vary_data(&cf->sh, &s->req.head.headers, 0, vd, sizeof vd);
		drop_found(cf);
		if (n < 0) {
			forward(cf, M_FILL, "miss");
			return;
		}
		char *k = bst_arena_alloc(s->arena, 32 + (size_t)n);
		if (k == NULL) {
			forward(cf, M_PASS, "miss");
			return;
		}
		memcpy(k, cf->base.b, 32);
		memcpy(k + 32, vd, (size_t)n);
		bst_key_make((bst_str){ k, (uint32_t)(32 + n) }, &cf->key);
		cf->variant = true;
		lookup_key(cf);
		return;
	}
	cf->have = true;
	bst_cache_valid v[VALID_MAX];
	bst_cache_policy_cfg pc;
	policy_of(cf->cc, &pc, v);
	int64_t now = (int64_t)time(NULL);
	bst_freshness fr;
	bst_cache_freshness(m->status, &cf->sh, &pc, now, &fr);
	int64_t age = age_of(cf, now);
	bool fresh = !fr.no_cache && age < fr.lifetime;
	cf->life = fr.lifetime;
	cf->age = age;
	cf->must_reval = fr.must_revalidate || fr.no_cache;
	int64_t swr = fr.swr > cf->cc->swr_s ? fr.swr : cf->cc->swr_s;
	cf->sie = fr.sie > cf->cc->sie_s ? fr.sie : cf->cc->sie_s;
	if (fresh && bst_cache_req_revalidate(&s->req.head.headers, &pc)) {
		forward(cf, M_REVALIDATE, "request");
		return;
	}
	if (fresh) {
		serve(cf, true, fr.lifetime - age);
		return;
	}
	if (!cf->must_reval && swr > 0 && age < fr.lifetime + swr && cf->rt->cfg->background_revalidate &&
	    s->req.head.method == BST_M_GET) {
		/* RFC 5861 section 3: the stale response now, and one revalidation in the background.
		 * The lock (left to expire) keeps it to one across every worker. */
		unsigned slot;
		uint64_t now_ms = bst_mono_ms();
		if (cf->rt->locks == NULL ||
		    bst_cachelock_try(cf->rt->locks, &cf->key, &slot, now_ms + cf->rt->cfg->lock_timeout_ms,
				      now_ms) == BST_LOCK_WON)
			bg_fill(s);
		cf->fwd = "stale";
		cf->detail = "stale-while-revalidate";
		serve(cf, false, 0);
		return;
	}
	forward(cf, M_REVALIDATE, "stale");
}

/* ---- the stampede lock: one fill per key, the others wait for it ---- */

static void wait_tick(void *ud);

static void wait_more(bst_cfill *cf)
{
	cf->wait_ms = cf->wait_ms < 5 ? 5 : cf->wait_ms * 2 > 50 ? 50 : cf->wait_ms * 2;
	bst_loop_timer_arm(bst_worker_loop(cf->s->worker), &cf->wait_t, cf->wait_ms, wait_tick, cf);
}

/* No stored response: fetch it, unless another request already is (then wait for its object). */
static void miss(bst_cfill *cf)
{
	const char *why = cf->variant ? "vary-miss" : "miss";
	bst_cfg_cache_store *st = cf->rt->cfg;
	if (!st->lock || cf->rt->locks == NULL || cf->s->req.head.method != BST_M_GET ||
	    bst_headers_get(&cf->s->req.head.headers, BST_H_RANGE) != NULL) {
		stop_waiting(cf);
		forward(cf, M_FILL, why);
		return;
	}
	uint64_t now = bst_mono_ms();
	unsigned slot;
	uint64_t dl = now + st->lock_timeout_ms;
	bst_lock_rc rc = bst_cachelock_try(cf->rt->locks, &cf->key, &slot, dl, now);
	if (rc == BST_LOCK_WON) {
		stop_waiting(cf);
		cf->locked = true;
		cf->lock_key = cf->key;
		cf->lock_slot = slot;
		cf->lock_dl = dl;
		forward(cf, M_FILL, why);
		return;
	}
	if (rc == BST_LOCK_HELD && !cf->waiting && g_waiters < st->lock_max_waiters) {
		cf->waiting = true;
		g_waiters++;
		cf->wait_start = now;
		cf->wait_ms = 0;
		bst_timer_init(&cf->wait_t);
		wait_more(cf);
		return;
	}
	if (rc == BST_LOCK_HELD && cf->waiting && now - cf->wait_start < st->lock_timeout_ms) {
		wait_more(cf);
		return;
	}
	/* PASS (not storable), FULL, too many waiters, or waited lock_timeout: fetch alone */
	stop_waiting(cf);
	forward(cf, M_FILL, rc == BST_LOCK_HELD ? "miss; detail=lock-timeout" : why);
}

static void wait_tick(void *ud)
{
	bst_cfill *cf = ud;
	if (cf->s == NULL)
		return;
	lookup_key(cf); /* the object, if the fill is done; else miss() waits on or fetches */
}

static bool method_cached(const bst_cfg_cache *cc, bst_method m)
{
	return m < 32 && (cc->methods & (1u << m)) != 0;
}

/* The request's cache key: cache_key, hashed. False on exhaustion. */
static bool make_key(bst_stream *s, const bst_cfg_cache *cc, bst_key *k)
{
	bst_var_ctx vc;
	bst_var_ctx_init(&vc, s);
	bst_str v = bst_tpl_eval(cc->key, &vc, s->arena);
	if (bst_str_failed(v))
		return false;
	bst_key_make(v, k);
	return true;
}

bool bst_cache_request(bst_stream *s, bst_cfill **slot, bst_cache_forward_fn fwd)
{
	const bst_cfg_cache *cc = &s->cfg->cache;
	bst_cache_rt *rt = cc->store != NULL ? cc->store->rt : NULL;
	*slot = NULL;
	if (rt == NULL || rt->broken || rt->idx == NULL)
		return false;
	bst_method me = s->req.head.method;
	bool cached = method_cached(cc, me);
	if (!cached && !bst_cache_invalidates(me, 200))
		return false;
	bst_cfill *cf = calloc(1, sizeof *cf);
	if (cf == NULL)
		return false;
	cf->s = s;
	cf->rt = rt;
	cf->cc = cc;
	cf->forward = fwd;
	cf->t0_ms = wall_ms();
	cf->t0_s = cf->t0_ms / 1000;
	cf->max_object = rt->cfg->max_object;
	if (!make_key(s, cc, &cf->base)) {
		free(cf);
		return false;
	}
	cf->key = cf->base;
	*slot = cf;
	cf->slot = slot;
	if (!cached) {
		forward(cf, M_INVALIDATE, NULL);
		return true;
	}
	if (s->ops == &sink_ops) { /* a background fill: straight to the upstream */
		forward(cf, M_FILL, "miss");
		return true;
	}
	if (truthy(s, &cc->bypass)) {
		forward(cf, M_FILL, "bypass");
		return true;
	}
	lookup_key(cf);
	return true;
}

/* ---- forwarding ---- */

int bst_cache_upstream_headers(bst_cfill *cf, bst_headers *hs)
{
	bst_stream *s = cf->s;
	if (cf->mode == M_INVALIDATE)
		return 0;
	if (s->req.head.method == BST_M_HEAD && cf->mode != M_REVALIDATE) {
		cf->mode = M_PASS; /* a HEAD miss is passed on, nothing to store */
		return 0;
	}
	if (cf->mode == M_REVALIDATE && s->req.head.method == BST_M_HEAD)
		cf->mode = M_PASS; /* a HEAD does not refresh a stored GET response */
	if (bst_headers_get(&s->req.head.headers, BST_H_RANGE) != NULL && cf->mode == M_FILL) {
		cf->mode = M_PASS; /* a partial response is not stored */
		return 0;
	}
	if (cf->mode == M_PASS)
		return 0;
	(void)bst_headers_remove(hs, BST_H_IF_NONE_MATCH); /* the full response comes back */
	(void)bst_headers_remove(hs, BST_H_IF_MODIFIED_SINCE);
	(void)bst_headers_remove(hs, BST_H_IF_MATCH);
	(void)bst_headers_remove(hs, BST_H_IF_UNMODIFIED_SINCE);
	(void)bst_headers_remove(hs, BST_H_IF_RANGE);
	(void)bst_headers_remove(hs, BST_H_RANGE);
	if (cf->mode == M_REVALIDATE && cf->have) {
		const bst_header *et = bst_headers_get(&cf->sh, BST_H_ETAG);
		const bst_header *lm = bst_headers_get(&cf->sh, BST_H_LAST_MODIFIED);
		if (et != NULL && bst_headers_add(hs, BST_S("If-None-Match"), et->value) != 0)
			return -1;
		if (lm != NULL && bst_headers_add(hs, BST_S("If-Modified-Since"), lm->value) != 0)
			return -1;
	}
	return 0;
}

/* Copies the 304's fields (as the client would get them) into the stored ones, refreshes the
 * entry's times, and serves the stored body. */
static void revalidated(bst_cfill *cf, const bst_headers *uh, const bst_resp_head *out)
{
	bst_stream *s = cf->s;
	(void)uh;
	if (bst_cache_merge_304(&cf->sh, &out->headers) != 0) {
		cf->s = NULL;
		(void)bst_send_error(s, 502);
		cf_free(cf);
		return;
	}
	int64_t date, agev, now = (int64_t)time(NULL);
	bst_cache_resp_times(uh, &date, &agev);
	int64_t initial = bst_cache_age(date, agev, cf->t0_s, now, now);
	cf->ie.req_time = now - initial;
	cf->ie.resp_time = now;
	(void)bst_cindex_refresh(cf->rt->idx, &cf->key, cf->ie.req_time, cf->ie.resp_time);
	cf->fwd = "stale; fwd-status=304"; /* served from storage after a 304 */
	cf->detail = NULL;
	cf->storing = false;
	serve(cf, false, 0);
}

/* The fields to store: the client's view of the response, plus the upstream's Date and Age
 * (the protocol replaces Date, and Age is computed per hit). */
static bool begin_store(bst_cfill *cf, int status, const bst_headers *uh, const bst_resp_head *out)
{
	bst_stream *s = cf->s;
	bst_headers st;
	bst_headers_init(&st, s->arena);
	for (uint32_t i = 0; i < out->headers.n; i++)
		if (bst_headers_add(&st, out->headers.v[i].name, out->headers.v[i].value) != 0)
			return false;
	const bst_header *d = bst_headers_get(uh, BST_H_DATE);
	if (d != NULL && bst_headers_add(&st, BST_S("date"), d->value) != 0)
		return false;
	size_t hl;
	cf->fblob = serialize(&st, cf->cc, &hl);
	if (cf->fblob == NULL)
		return false;
	int64_t date, agev, now = (int64_t)time(NULL);
	bst_cache_resp_times(uh, &date, &agev);
	int64_t initial = bst_cache_age(date, agev, cf->t0_s, now, now);
	bst_sobj_meta *m = &cf->fm;
	memset(m, 0, sizeof *m);
	m->stored_at_ms = cf->t0_ms;
	m->req_time = now - initial;
	m->resp_time = now;
	m->status = status;
	m->head = (bst_str){ cf->fblob, (uint32_t)hl };
	/* Vary: the object becomes a variant, with a marker under the key */
	char vd[BST_CACHE_VARY_MAX];
	int vn = (cf->cc->ignore & BST_CACHE_IGN_VARY) ? 0
		 : bst_cache_vary_data(&st, &s->req.head.headers, cf->cc->vary_limit, vd, sizeof vd);
	if (vn < 0)
		return false;
	if (vn > 0) {
		char *k = bst_arena_alloc(s->arena, 32 + (size_t)vn);
		if (k == NULL)
			return false;
		memcpy(k, cf->base.b, 32);
		memcpy(k + 32, vd, (size_t)vn);
		bst_key_make((bst_str){ k, (uint32_t)(32 + vn) }, &cf->key);
		cf->variant = true;
		/* the marker: the Vary fields only */
		bst_headers mk;
		bst_headers_init(&mk, s->arena);
		for (const bst_header *f = bst_headers_next(&st, NULL, BST_H_VARY); f != NULL;
		     f = bst_headers_next(&st, f, BST_H_VARY))
			if (bst_headers_add(&mk, f->name, f->value) != 0)
				return false;
		cf->marker_blob = serialize(&mk, cf->cc, &cf->marker_len);
		if (cf->marker_blob == NULL)
			return false;
		cf->vary_marker = true;
		char *vcopy = bst_arena_alloc(s->arena, (size_t)vn);
		if (vcopy == NULL)
			return false;
		memcpy(vcopy, vd, (size_t)vn);
		m->vary = (bst_str){ vcopy, (uint32_t)vn };
	} else {
		cf->key = cf->base;
	}
	cf->w = bst_store_begin_write(&cf->rt->store, &cf->key, m);
	if (cf->w == NULL) {
		static int64_t warned;
		if (now - warned >= 10) { /* once in a while: a broken disk must not flood the log */
			warned = now;
			bst_log(BST_LOG_WARN, "cache_store %s: can not store (%s): serving uncached",
				cf->rt->cfg->name, strerror(errno));
		}
		return false;
	}
	bst_ram *r = bst_cache_ram(cf->rt);
	cf->ram_ok = r != NULL && (out->content_length < 0 ||
				   (uint64_t)out->content_length <= bst_ram_max_object(r));
	return true;
}

bst_cache_head_rc bst_cache_on_head(bst_cfill *cf, int status, const bst_headers *uh,
				    bst_resp_head *out, bool end)
{
	bst_stream *s = cf->s;
	(void)end;
	if (cf->mode == M_INVALIDATE) {
		if (bst_cache_invalidates(s->req.head.method, status)) {
			(void)bst_cindex_remove(cf->rt->idx, &cf->base);
			(void)bst_store_delete(&cf->rt->store, &cf->base);
			bst_ram *r = bst_cache_ram(cf->rt);
			if (r != NULL)
				bst_ram_remove(r, &cf->base);
		}
		return BST_CACHE_HEAD_SEND;
	}
	if (cf->mode == M_REVALIDATE && status == 304 && cf->have) {
		revalidated(cf, uh, out);
		return BST_CACHE_HEAD_DONE;
	}
	if (status >= 500 && stale_on_error(cf, status))
		return BST_CACHE_HEAD_DONE;
	drop_found(cf);
	bst_str tag = { cf->cc->tag_header, cf->cc->tag_header ? (uint32_t)strlen(cf->cc->tag_header) : 0 };
	if (cf->mode == M_REVALIDATE)
		cf->mode = M_FILL; /* a new response replaces the stored one */
	if (cf->mode == M_FILL && s->req.head.method == BST_M_GET) {
		bst_cache_valid v[VALID_MAX];
		bst_cache_policy_cfg pc;
		policy_of(cf->cc, &pc, v);
		const char *why = NULL;
		bool ok = bst_cache_storable(&s->req.head, status, uh, &pc, &why);
		if (ok && truthy(s, &cf->cc->no_store_if))
			ok = false, why = "no_store_if";
		if (ok && out->content_length >= 0 && (uint64_t)out->content_length > cf->max_object)
			ok = false, why = "too-large";
		if (ok && cf->rt->cfg->min_uses > 1 && note_use(&cf->base) < cf->rt->cfg->min_uses)
			ok = false, why = "min-uses";
		if (ok && !begin_store(cf, status, uh, out)) {
			ok = false;
			why = "store-error";
			bst_store_abort(cf->w);
			cf->w = NULL;
		}
		cf->storing = ok;
		if (!ok)
			cf->detail = why;
	}
	if (!cf->storing) /* waiters need not wait: a private response is fetched by each */
		unlock(cf, status < 500);
	if (tag.len > 0 && !cf->cc->tag_header_pass)
		(void)bst_headers_remove_name(&out->headers, tag);
	add_status(cf, &out->headers, false, 0);
	return BST_CACHE_HEAD_SEND;
}

void bst_cache_on_body(bst_cfill *cf, const bst_chain *c)
{
	if (cf == NULL || !cf->storing || cf->w == NULL)
		return;
	struct iovec iov[64];
	int n = bst_chain_to_iov(c, iov, 64);
	uint64_t total = 0;
	for (int i = 0; i < n; i++)
		total += iov[i].iov_len;
	if (total != bst_chain_len(c) || bst_swriter_size(cf->w) + total > cf->max_object) {
		cf->storing = false; /* a file segment, more than 64 pieces, or too large */
		bst_store_abort(cf->w);
		cf->w = NULL;
		return;
	}
	for (int i = 0; i < n; i++) {
		int rc = bst_store_write(cf->w, iov[i].iov_base, iov[i].iov_len);
		if (rc != 0) {
			bst_log(BST_LOG_WARN, "cache_store %s: writing an object failed: %s: not stored",
				cf->rt->cfg->name, strerror(-rc));
			cf->storing = false;
			bst_store_abort(cf->w);
			cf->w = NULL;
			return;
		}
		if (cf->ram_ok) {
			if (cf->rlen + iov[i].iov_len > bst_ram_max_object(bst_cache_ram(cf->rt))) {
				cf->ram_ok = false;
				continue;
			}
			if (cf->rlen + iov[i].iov_len > cf->rcap) {
				size_t nc = (cf->rcap ? cf->rcap * 2 : 16384);
				while (nc < cf->rlen + iov[i].iov_len)
					nc *= 2;
				unsigned char *nb = realloc(cf->rbuf, nc);
				if (nb == NULL) {
					cf->ram_ok = false;
					continue;
				}
				cf->rbuf = nb;
				cf->rcap = nc;
			}
			memcpy(cf->rbuf + cf->rlen, iov[i].iov_base, iov[i].iov_len);
			cf->rlen += iov[i].iov_len;
		}
	}
}

/* RFC 5861 section 4: a stale response instead of an error, while stale-if-error allows. */
static bool stale_on_error(bst_cfill *cf, int status)
{
	if (cf->mode != M_REVALIDATE || !cf->have || cf->must_reval || cf->sie <= 0 ||
	    cf->age >= cf->life + cf->sie)
		return false;
	static char fwd[48];
	snprintf(fwd, sizeof fwd, "stale; fwd-status=%d", status);
	cf->fwd = fwd;
	cf->detail = "stale-if-error";
	cf->storing = false;
	serve(cf, false, 0);
	return true;
}

bool bst_cache_on_error(bst_cfill *cf, int status)
{
	return cf != NULL && cf->s != NULL && stale_on_error(cf, status);
}

static void put_marker(bst_cfill *cf)
{
	bst_sobj_meta mm;
	memset(&mm, 0, sizeof mm);
	mm.stored_at_ms = cf->t0_ms;
	mm.req_time = cf->fm.req_time;
	mm.resp_time = cf->fm.resp_time;
	mm.status = MARKER_STATUS;
	mm.head = (bst_str){ cf->marker_blob, (uint32_t)cf->marker_len };
	bst_swriter *w = bst_store_begin_write(&cf->rt->store, &cf->base, &mm);
	if (w == NULL || bst_store_commit(w) != 0)
		return;
	bst_centry e;
	memset(&e, 0, sizeof e);
	e.key = cf->base;
	e.size = BST_STORE_PAGE;
	e.stored_at_ms = mm.stored_at_ms;
	e.req_time = mm.req_time;
	e.resp_time = mm.resp_time;
	e.last_access = (uint32_t)time(NULL);
	(void)bst_cindex_insert(cf->rt->idx, &e);
}

static void commit(bst_cfill *cf)
{
	uint64_t body = bst_swriter_size(cf->w);
	int rc = bst_store_commit(cf->w);
	cf->w = NULL;
	if (rc != 0) {
		bst_log(BST_LOG_WARN, "cache_store %s: storing an object failed: %s", cf->rt->cfg->name,
			strerror(-rc));
		return;
	}
	if (cf->vary_marker)
		put_marker(cf);
	bst_centry e;
	memset(&e, 0, sizeof e);
	e.key = cf->key;
	e.size = body + BST_STORE_PAGE; /* the header's page too */
	e.stored_at_ms = cf->fm.stored_at_ms;
	e.req_time = cf->fm.req_time;
	e.resp_time = cf->fm.resp_time;
	e.last_access = (uint32_t)time(NULL);
	if (!bst_cindex_insert(cf->rt->idx, &e)) {
		bst_log(BST_LOG_WARN, "cache_store %s: the index is full (max_entries): not cached",
			cf->rt->cfg->name);
		(void)bst_store_delete(&cf->rt->store, &cf->key);
		return;
	}
	bst_ram *r = bst_cache_ram(cf->rt);
	if (r != NULL && cf->ram_ok && cf->rlen == body) {
		cf->fm.body_len = body;
		(void)bst_ram_put(r, &cf->key, &cf->fm, cf->rbuf, cf->rlen);
	}
	unlock(cf, false); /* indexed: the waiters find it now */
}

void bst_cache_finish(bst_cfill *cf, bool complete, bool client_gone)
{
	if (cf == NULL)
		return;
	bool refill = client_gone && cf->storing && !complete && cf->cc->background_fill &&
		      cf->s != NULL;
	if (cf->storing && cf->w != NULL && complete)
		commit(cf);
	if (refill)
		bg_fill(cf->s); /* the client left: the response is fetched again, for the cache */
	cf->s = NULL;
	cf_free(cf);
}

/* ---- detached internal requests ----
 *
 * A request with no client: the response goes nowhere, but the cache tee stores it. Used to
 * finish a fill whose client left (`cache_background_fill on`) and, later, for background
 * revalidation. It has its own arena and chain slab and a copy of the request; it is freed a
 * loop turn after its response ended, when no callback of the handler can run any more. */

typedef struct sink {
	bst_stream s;
	bst_timer t;
	bst_loop *loop;
	bool ended;
} sink;

static void sink_free(void *ud)
{
	sink *k = ud;
	bst_slab_free(k->s.chain_slab);
	bst_arena_free(k->s.arena);
	free(k);
}

static void sink_end(sink *k)
{
	if (k->ended)
		return;
	k->ended = true;
	bst_loop_timer_arm(k->loop, &k->t, 0, sink_free, k);
}

typedef struct sink_cb {
	bst_timer t;
	bst_done_cb cb;
	void *ud;
	size_t n;
} sink_cb;

static void sink_cb_fire(void *ud)
{
	sink_cb *c = ud;
	c->cb(c->ud, c->n, 0);
	free(c);
}

static int sink_head(bst_stream *s, const bst_resp_head *h, bool end)
{
	(void)h;
	if (end)
		sink_end((sink *)s);
	return 0;
}

static int sink_interim(bst_stream *s, int st, const bst_headers *h)
{
	(void)s, (void)st, (void)h;
	return 0;
}

static int sink_body(bst_stream *s, bst_chain *c, bool end, bst_done_cb cb, void *ud)
{
	sink *k = (sink *)s;
	size_t n = (size_t)bst_chain_len(c);
	bst_chain_clear(c);
	if (end) {
		sink_end(k);
		return 0;
	}
	if (cb != NULL) { /* never before send_body returns */
		sink_cb *x = calloc(1, sizeof *x);
		if (x == NULL)
			return -1;
		x->cb = cb;
		x->ud = ud;
		x->n = n;
		bst_timer_init(&x->t);
		bst_loop_timer_arm(k->loop, &x->t, 0, sink_cb_fire, x);
	}
	return 0;
}

static int sink_trailers(bst_stream *s, const bst_headers *h)
{
	(void)h;
	sink_end((sink *)s);
	return 0;
}

static void sink_read(bst_stream *s, size_t credit)
{
	(void)s, (void)credit;
}

static void sink_reset(bst_stream *s, bst_stream_err why)
{
	(void)why;
	sink_end((sink *)s);
}

static const bst_stream_ops sink_ops = {
	.send_head = sink_head,
	.send_interim = sink_interim,
	.send_body = sink_body,
	.send_trailers = sink_trailers,
	.read_body = sink_read,
	.reset = sink_reset,
};

/* A GET for the same target as orig, through the proxy handler. */
static void bg_fill(const bst_stream *orig)
{
	sink *k = calloc(1, sizeof *k);
	if (k == NULL)
		return;
	bst_stream *s = &k->s;
	s->arena = bst_arena_new(16384);
	s->chain_slab = bst_chain_slab_new(256);
	if (s->arena == NULL || s->chain_slab == NULL) {
		if (s->chain_slab != NULL)
			bst_slab_free(s->chain_slab);
		bst_arena_free(s->arena);
		free(k);
		return;
	}
	k->loop = bst_worker_loop(orig->worker);
	bst_timer_init(&k->t);
	s->ops = &sink_ops;
	s->worker = orig->worker;
	s->server = orig->server;
	s->cfg = orig->cfg;
	s->loc = orig->loc;
	s->peer = orig->peer;
	s->has_peer = orig->has_peer;
	s->uri_changed = orig->uri_changed;
	s->req = orig->req;
	bst_req_head *h = &s->req.head;
	const bst_req_head *o = &orig->req.head;
	h->method = BST_M_GET;
	h->method_str = BST_S("GET");
	s->req.framing.kind = BST_FRAMING_NONE;
	s->req.keepalive = false;
	s->req.expect_continue = false;
	bool ok = copy_str(s->arena, o->target, &h->target) && copy_str(s->arena, o->scheme, &h->scheme) &&
		  copy_str(s->arena, o->authority, &h->authority) && copy_str(s->arena, o->path, &h->path) &&
		  copy_str(s->arena, o->query, &h->query) && copy_str(s->arena, orig->req.host, &s->req.host) &&
		  copy_str(s->arena, orig->uri, &s->uri);
	h->protocol = (bst_str){ "", 0 };
	bst_headers_init(&h->headers, s->arena);
	for (uint32_t i = 0; ok && i < o->headers.n; i++) {
		const bst_header *f = &o->headers.v[i];
		if (f->id == BST_H_RANGE || f->id == BST_H_IF_NONE_MATCH || f->id == BST_H_IF_MODIFIED_SINCE ||
		    f->id == BST_H_CONTENT_LENGTH || f->id == BST_H_TRANSFER_ENCODING || f->id == BST_H_EXPECT)
			continue;
		bst_str n, v;
		ok = copy_str(s->arena, f->name, &n) && copy_str(s->arena, f->value, &v) &&
		     bst_headers_add(&h->headers, n, v) == 0;
	}
	if (!ok) {
		k->ended = true;
		sink_free(k);
		return;
	}
	bst_stream_set_handler(s, &bst_proxy_handler, NULL);
}
