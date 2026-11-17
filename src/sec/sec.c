/* See sec.h. */
#include "sec/sec.h"

#include "core/addr.h"
#include "core/counters.h"
#include "core/log.h"
#include "core/shm.h"
#include "core/wheel.h"
#include "io/loop.h"
#include "http/transport.h"
#include "proc/worker.h"
#include "proxy/handler.h"
#include "route/vars.h"
#include "sec/limit.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

static bst_counter_id c_rejected = BST_COUNTER_INVALID, c_delayed = BST_COUNTER_INVALID,
		      c_dry_run = BST_COUNTER_INVALID;

static void count(bst_counter_id id)
{
	if (id != BST_COUNTER_INVALID)
		bst_counter_add(id, 1);
}

int bst_sec_setup(bst_config *cfg, int nworkers, bst_err *e)
{
	(void)nworkers;
	bst_cfg_global *g = &cfg->global;
	for (size_t i = 0; i < g->nlimit_zones; i++) {
		bst_limit_zone *z = g->limit_zones[i];
		if (z->size == 0)
			z->size = 65536;
		void *mem = bst_shm_create("bastion-limit", bst_limit_zone_bytes(z), NULL);
		if (mem == NULL) {
			bst_err_set(e, "limit_zone %s: shared memory: %s", z->name, strerror(errno));
			return -1;
		}
		if (bst_limit_zone_attach(z, mem) != 0) {
			bst_err_set(e, "limit_zone %s: no randomness for the hash key", z->name);
			return -1;
		}
	}
	if (g->nlimit_zones > 0) {
		c_rejected = bst_counter_register("bastion_limit_rejected_total",
						  "requests refused by a limit_zone", NULL);
		c_delayed = bst_counter_register("bastion_limit_delayed_total",
						 "requests held by a limit_zone in mode delay", NULL);
		c_dry_run = bst_counter_register("bastion_limit_dry_run_total",
						 "requests a dry_run limit_zone would have refused", NULL);
	}
	return 0;
}

bool bst_sec_required(const bst_stream *s)
{
	return s->cfg->sec.limits.n > 0;
}

/* ---- RateLimit fields ---- */

typedef struct rl_filter {
	bst_filter f;
	const bst_limit_zone *z;
	uint64_t remaining;
} rl_filter;

static int rl_on_head(bst_filter *f, bst_resp_head *h, bool end)
{
	(void)end;
	rl_filter *r = (rl_filter *)f;
	uint64_t burst = r->z->burst > 0 ? r->z->burst : 1;
	uint64_t window = (r->z->l_ns + 999999999u) / 1000000000u;
	uint64_t reset = ((burst - r->remaining) * r->z->t_ns + 999999999u) / 1000000000u;
	char v[96], p[64];
	int n = snprintf(v, sizeof v, "limit=%llu, remaining=%llu, reset=%llu", (unsigned long long)burst,
			 (unsigned long long)r->remaining, (unsigned long long)reset);
	int m = snprintf(p, sizeof p, "%llu;w=%llu", (unsigned long long)burst,
			 (unsigned long long)(window > 0 ? window : 1));
	char *vv = bst_arena_alloc(f->s->arena, (size_t)n), *pp = bst_arena_alloc(f->s->arena, (size_t)m);
	if (vv == NULL || pp == NULL)
		return -1;
	memcpy(vv, v, (size_t)n);
	memcpy(pp, p, (size_t)m);
	if (bst_headers_add(&h->headers, BST_S("RateLimit"), (bst_str){ vv, (uint32_t)n }) != 0 ||
	    bst_headers_add(&h->headers, BST_S("RateLimit-Policy"), (bst_str){ pp, (uint32_t)m }) != 0)
		return -1;
	return 0;
}

static int rl_on_body(bst_filter *f, bst_chain *c, bool end)
{
	(void)f, (void)c, (void)end;
	return 0;
}

static void rl_release(bst_filter *f)
{
	(void)f;
}

static const bst_filter_ops rl_ops = { rl_on_head, rl_on_body, rl_release };

/* ---- mode delay: a placeholder handler holds the request until its timer ---- */

typedef struct delay_ctx {
	bst_timer t;
	bst_stream *s;
	bst_sec_cont cont;
} delay_ctx;

static void delay_request(bst_stream *s)
{
	(void)s;
}

static void delay_body(bst_stream *s, bst_chain *c, bool end)
{
	(void)s, (void)end;
	bst_chain_clear(c);
}

static void delay_reset(bst_stream *s, bst_stream_err why)
{
	(void)why;
	delay_ctx *d = s->hctx;
	bst_timer_cancel(&d->t);
}

static const bst_handler_ops delay_ops = { .on_request = delay_request, .on_body = delay_body,
					   .on_reset = delay_reset };

static void delay_fire(void *ud)
{
	delay_ctx *d = ud;
	d->cont(d->s);
}

/* ---- the check ---- */

static bst_str retry_after(bst_stream *s, uint64_t us)
{
	uint64_t sec = (us + 999999u) / 1000000u;
	if (sec == 0)
		sec = 1;
	char b[24];
	int n = snprintf(b, sizeof b, "%llu", (unsigned long long)sec);
	char *v = bst_arena_alloc(s->arena, (size_t)n);
	if (v == NULL)
		return (bst_str){ NULL, 0 };
	memcpy(v, b, (size_t)n);
	return (bst_str){ v, (uint32_t)n };
}

static void log_client(const bst_stream *s, const char *what, const bst_limit_zone *z)
{
	char a[BST_ADDR_STRLEN] = "-";
	if (s->sec_ip_set)
		(void)bst_addr_format(&s->sec_ip, a, sizeof a);
	bst_log(BST_LOG_INFO, "limit: zone %s %s %s", z->name, what, a);
}

/* The address the checks key on: the peer, or the client a trusted real_ip_header names. The
 * stream's peer itself is left alone (the proxy names the connection's peer upstream). */
static void set_client(bst_stream *s)
{
	s->sec_ip_set = s->has_peer;
	s->sec_ip_from_header = s->transport != NULL && s->transport->client_addr_from_header;
	if (!s->has_peer)
		return;
	bst_sockaddr saved = s->peer;
	bst_proxy_real_ip(s);
	if (!bst_ip_eq(&saved.ip, &s->peer.ip))
		s->sec_ip_from_header = true;
	s->sec_ip = bst_ip_canon(&s->peer.ip);
	s->peer = saved;
}

bool bst_sec_check(bst_stream *s, bst_sec_cont cont)
{
	const bst_cfg_sec *sc = &s->cfg->sec;
	uint64_t now = bst_limit_now_us(), delay = 0;
	set_client(s);
	for (size_t i = 0; i < sc->limits.n; i++) {
		const bst_limit_ref *ref = sc->limits.items[i];
		bst_limit_zone *z = ref->zone;
		uint64_t key;
		if (z->key_is_addr) {
			if (!s->sec_ip_set)
				continue;
			key = bst_limit_key_ip(z, &s->sec_ip);
		} else {
			bst_var_ctx vc;
			bst_var_ctx_init(&vc, s);
			bst_str k = bst_tpl_eval(z->key, &vc, s->arena);
			if (bst_str_failed(k)) {
				s->ops->reset(s, BST_STREAM_ERR_INTERNAL);
				return true;
			}
			key = bst_limit_key_str(z, k);
		}
		bst_limit_result r = bst_limit_check_hash(z, key, now);
		if (i == 0 && sc->limit_headers) {
			rl_filter *f = bst_arena_alloc(s->arena, sizeof *f);
			if (f != NULL) {
				memset(f, 0, sizeof *f);
				f->f.ops = &rl_ops;
				f->z = z;
				f->remaining = r.remaining;
				bst_stream_add_filter(s, &f->f);
			}
		}
		if (r.verdict == BST_LIMIT_ALLOW)
			continue;
		if (z->dry_run) {
			count(c_dry_run);
			log_client(s, r.verdict == BST_LIMIT_REJECT ? "would reject (dry_run)"
								     : "would delay (dry_run)", z);
			continue;
		}
		if (r.verdict == BST_LIMIT_DELAY) {
			if (r.delay_us > delay)
				delay = r.delay_us;
			continue;
		}
		count(c_rejected);
		log_client(s, "rejected", z);
		bst_str ra = retry_after(s, r.retry_after_us);
		if (ra.p == NULL)
			s->ops->reset(s, BST_STREAM_ERR_INTERNAL);
		else
			(void)bst_send_error_hdr(s, (int)z->status, BST_S("Retry-After"), ra);
		return true;
	}
	if (delay == 0)
		return false;
	count(c_delayed);
	delay_ctx *d = bst_arena_alloc(s->arena, sizeof *d);
	if (d == NULL) {
		s->ops->reset(s, BST_STREAM_ERR_INTERNAL);
		return true;
	}
	memset(d, 0, sizeof *d);
	bst_timer_init(&d->t);
	d->s = s;
	d->cont = cont;
	bst_stream_set_handler(s, &delay_ops, d);
	bst_loop_timer_arm(bst_worker_loop(s->worker), &d->t, (delay + 999) / 1000, delay_fire, d);
	return true;
}
