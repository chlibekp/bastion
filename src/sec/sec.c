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
#include "io/sock.h"
#include "sec/acl.h"
#include "sec/attack.h"
#include "sec/block.h"
#include "sec/challenge.h"
#include "sec/connlimit.h"
#include "sec/escalate.h"
#include "sec/limit.h"
#include "sec/waf.h"
#include "proxy/upstream.h"
#include "xdp/block.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bst_counter_id c_rejected = BST_COUNTER_INVALID, c_delayed = BST_COUNTER_INVALID,
		      c_dry_run = BST_COUNTER_INVALID, c_conn_refused = BST_COUNTER_INVALID,
		      c_acl_denied = BST_COUNTER_INVALID, c_blocked = BST_COUNTER_INVALID,
		      c_esc_sent = BST_COUNTER_INVALID, c_esc_dropped = BST_COUNTER_INVALID,
		      c_esc_ignored = BST_COUNTER_INVALID, c_blocks = BST_COUNTER_INVALID,
		      c_waf_matched = BST_COUNTER_INVALID, c_waf_denied = BST_COUNTER_INVALID,
		      c_refused[4] = { BST_COUNTER_INVALID, BST_COUNTER_INVALID, BST_COUNTER_INVALID,
				       BST_COUNTER_INVALID };

static void count(bst_counter_id id)
{
	if (id != BST_COUNTER_INVALID)
		bst_counter_add(id, 1);
}

static bool conn_limits_used(const bst_config *cfg);

/* ---- escalation: shared state, and master's side ---- */

static bst_block_table *g_blocks; /* every process: what workers enforce */
static bst_block_master *g_bm;	  /* master only */
static bst_block_backend g_be;
static int g_nworkers;

static bool escalation_used(const bst_config *cfg)
{
	const bst_cfg_global *g = &cfg->global;
	for (size_t i = 0; i < g->nlimit_zones; i++)
		if (g->limit_zones[i]->esc.after > 0)
			return true;
	if (g->common.http.h2.abuse.esc.after > 0)
		return true;
	for (size_t i = 0; i < g->nservers; i++)
		if (g->servers[i]->common.http.h2.abuse.esc.after > 0)
			return true;
	for (size_t i = 0; i < g->nwaf_rules; i++)
		if (g->waf_rules[i]->esc.after > 0)
			return true;
	if (g->common.sec.challenge.esc.after > 0)
		return true;
	for (size_t i = 0; i < g->nservers; i++) {
		const bst_cfg_server *s = g->servers[i];
		if (s->common.sec.challenge.esc.after > 0)
			return true;
		for (size_t j = 0; j < s->nlocations; j++)
			if (s->locations[j]->common.sec.challenge.esc.after > 0)
				return true;
	}
	return false;
}

/* escalation_allow and every real_ip_from CIDR: never blocked. */
static int add_exempt(bst_cidr **v, size_t *n, size_t *cap, const bst_cidr *x)
{
	if (*n == *cap) {
		size_t nc = *cap ? *cap * 2 : 16;
		bst_cidr *nv = realloc(*v, nc * sizeof *nv);
		if (nv == NULL)
			return -1;
		*v = nv;
		*cap = nc;
	}
	(*v)[(*n)++] = *x;
	return 0;
}

static int add_exempt_list(bst_cidr **v, size_t *n, size_t *cap, const bst_cfg_list *l)
{
	for (size_t i = 0; i < l->n; i++)
		if (add_exempt(v, n, cap, l->items[i]) != 0)
			return -1;
	return 0;
}

static int setup_escalation(bst_config *cfg, int nworkers, bst_err *e)
{
	const bst_cfg_global *g = &cfg->global;
	unsigned ceiling = g->escalation_ceiling > 0 ? g->escalation_ceiling : BST_BLOCK_CEILING_DEFAULT;
	void *em = bst_shm_create("bastion-escalate", bst_escalate_bytes(nworkers), NULL);
	void *bm = bst_shm_create("bastion-blocks", bst_block_table_bytes(ceiling), NULL);
	if (em == NULL || bm == NULL) {
		bst_err_set(e, "escalation: shared memory: %s", strerror(errno));
		return -1;
	}
	if (bst_escalate_attach(em, nworkers) != 0) {
		bst_err_set(e, "escalation: no randomness for the hash key");
		return -1;
	}
	g_blocks = bst_block_table_attach(bm, ceiling);
	bst_cidr *ex = NULL;
	size_t nex = 0, cap = 0;
	int rc = 0;
	for (size_t i = 0; rc == 0 && i < g->nescalation_allow; i++)
		rc = add_exempt(&ex, &nex, &cap, &g->escalation_allow[i]);
	if (rc == 0)
		rc = add_exempt_list(&ex, &nex, &cap, &g->common.proxy.real_ip_from);
	if (rc == 0)
		rc = add_exempt_list(&ex, &nex, &cap, &g->common.proxy.pp_from);
	for (size_t i = 0; rc == 0 && i < g->nservers; i++) {
		const bst_cfg_server *s = g->servers[i];
		rc = add_exempt_list(&ex, &nex, &cap, &s->common.proxy.real_ip_from);
		if (rc == 0) /* the balancers that send PROXY headers: trusted proxies too */
			rc = add_exempt_list(&ex, &nex, &cap, &s->common.proxy.pp_from);
		for (size_t j = 0; rc == 0 && j < s->nlocations; j++)
			rc = add_exempt_list(&ex, &nex, &cap, &s->locations[j]->common.proxy.real_ip_from);
	}
	if (rc == 0 && bst_block_shm_backend(&g_be, g_blocks, ceiling) == 0)
		g_bm = bst_block_master_new(ceiling, ex, nex, &g_be);
	free(ex);
	if (g_bm == NULL) {
		bst_err_set(e, "escalation: out of memory");
		return -1;
	}
	g_nworkers = nworkers;
	c_esc_sent = bst_counter_register("bastion_escalate_requests_total",
					  "block requests workers sent to master", NULL);
	c_esc_dropped = bst_counter_register("bastion_escalate_ring_dropped_total",
					     "block requests dropped on a full ring", NULL);
	c_esc_ignored = bst_counter_register("bastion_escalate_ignored_total",
					     "strikes of unvalidated peers, never escalated", NULL);
	c_blocks = bst_counter_register("bastion_escalate_blocks_total", "blocks master added", NULL);
	static const char *const why[4] = { "reason=malformed", "reason=exempt", "reason=ceiling",
					    "reason=backend" };
	for (int i = 0; i < 4; i++)
		c_refused[i] = bst_counter_register("bastion_escalate_refused_total",
						    "block requests master refused", why[i]);
	return 0;
}

static bst_block_backend g_inner; /* the user-space backend, under the XDP one */

int bst_sec_use_xdp(struct bst_xdp *x, const bst_config *cfg)
{
	if (g_bm == NULL || x == NULL)
		return 0;
	const bst_cfg_global *g = &cfg->global;
	bst_cidr *ex = NULL;
	size_t nex = 0, cap = 0;
	bst_cidr lo4, lo6;
	memset(&lo4, 0, sizeof lo4);
	memset(&lo6, 0, sizeof lo6);
	(void)bst_cidr_parse(BST_S("127.0.0.0/8"), &lo4);
	(void)bst_cidr_parse(BST_S("::1/128"), &lo6);
	int rc = add_exempt(&ex, &nex, &cap, &lo4) | add_exempt(&ex, &nex, &cap, &lo6);
	for (size_t i = 0; rc == 0 && g->xdp != NULL && i < g->xdp->nallow; i++)
		rc = add_exempt(&ex, &nex, &cap, &g->xdp->allow[i]);
	for (size_t i = 0; rc == 0 && i < g->nupstreams; i++) {
		const bst_cfg_upstream *u = g->upstreams[i];
		for (size_t j = 0; rc == 0 && j < u->nservers; j++) {
			bst_ip ip;
			const char *h = u->servers[j].host;
			if (h == NULL || !bst_addr_parse((bst_str){ h, (uint32_t)strlen(h) }, &ip))
				continue; /* a host name: its addresses change; escalation_allow covers it */
			bst_cidr c = { .ip = ip, .prefix = (uint8_t)(ip.family == BST_IP_V4 ? 32 : 128) };
			rc = add_exempt(&ex, &nex, &cap, &c);
		}
	}
	if (rc == 0) {
		g_inner = g_be;
		rc = bst_block_backend_xdp(&g_be, &g_inner, x, ex, nex);
		if (rc != 0)
			g_be = g_inner;
	}
	free(ex);
	return rc;
}

static const char *const strike_names[BST_STRIKE_KINDS] = { "limit", "waf", "http2_abuse", "challenge" };

uint64_t bst_sec_master_tick(uint64_t now_ms)
{
	if (g_bm == NULL)
		return 0;
	uint64_t now_us = bst_limit_now_us();
	bst_block_req req[64];
	for (int w = 0; w < g_nworkers; w++) {
		size_t n;
		/* at most a ring per worker per tick: a flood can not hold master here */
		for (size_t got = 0; got < BST_ESC_RING && (n = bst_escalate_drain(w, req, 64)) > 0; got += n)
			for (size_t i = 0; i < n; i++) {
				bst_block_rc rc = bst_block_apply(g_bm, &req[i], now_us);
				char a[BST_ADDR_STRLEN] = "?";
				bst_ip ip = { .family = req[i].family == 4 ? BST_IP_V4 : BST_IP_V6 };
				memcpy(ip.b, req[i].addr, 16);
				if (rc != BST_BLOCK_MALFORMED)
					(void)bst_addr_format(&ip, a, sizeof a);
				switch (rc) {
				case BST_BLOCK_ADDED:
					count(c_blocks);
					bst_log(BST_LOG_WARN, "escalate: blocked %s/%u for %llus (%s)%s", a,
						req[i].prefix, (unsigned long long)(req[i].ttl_us / 1000000u),
						strike_names[req[i].kind],
						(req[i].flags & BST_BLOCK_L7) ? " l7 only" : "");
					break;
				case BST_BLOCK_EXTENDED:
					break;
				case BST_BLOCK_MALFORMED:
					count(c_refused[0]);
					bst_log(BST_LOG_WARN, "escalate: worker %d sent a malformed block request", w);
					break;
				case BST_BLOCK_EXEMPT:
					count(c_refused[1]);
					bst_log(BST_LOG_INFO, "escalate: %s is exempt (escalation_allow, real_ip_from)", a);
					break;
				case BST_BLOCK_CEILING:
					count(c_refused[2]);
					bst_log(BST_LOG_WARN, "escalate: escalation_ceiling reached, not blocking %s", a);
					break;
				case BST_BLOCK_FAILED:
					count(c_refused[3]);
					break;
				}
			}
	}
	size_t gone = bst_block_expire(g_bm, now_us);
	if (gone > 0)
		bst_log(BST_LOG_INFO, "escalate: %zu blocks expired", gone);
	bst_block_commit(g_bm);
	return now_ms + 50; /* blocks apply within a tick of the request */
}

/* A strike from the worker's own code. */
static void strike(const bst_escalate_cfg *cfg, const bst_ip *ip, bst_strike_kind kind, bool validated,
		   bool l7_only, unsigned v6p)
{
	if (cfg == NULL || cfg->after == 0 || ip == NULL)
		return;
	bst_strike_src src = { .validated = validated, .l7_only = l7_only };
	switch (bst_escalate_strike(cfg, ip, kind, &src, v6p, bst_limit_now_us())) {
	case BST_STRIKE_SENT:
		count(c_esc_sent);
		break;
	case BST_STRIKE_DROPPED:
		count(c_esc_dropped);
		break;
	case BST_STRIKE_IGNORED:
		count(c_esc_ignored);
		break;
	default:
		break;
	}
}

void bst_sec_strike(const bst_escalate_cfg *cfg, const bst_ip *ip, unsigned kind, bool validated, bool l7_only)
{
	strike(cfg, ip, (bst_strike_kind)kind, validated, l7_only, 64);
}

void bst_sec_strike_stream(const bst_escalate_cfg *cfg, const bst_stream *s, unsigned kind, unsigned v6p)
{
	if (s->sec_ip_set)
		strike(cfg, &s->sec_ip, (bst_strike_kind)kind, true, s->sec_ip_from_header, v6p);
}

bool bst_sec_blocked(const bst_ip *ip)
{
	return g_blocks != NULL && bst_block_any(g_blocks) && bst_block_lookup(g_blocks, ip, bst_limit_now_us());
}

/* ---- `challenge auto`: the helper's 1 Hz sample (sec/attack.h) ---- */

static bool g_attack_used;
static bst_attack_cfg g_attack;
static bst_attack_state g_attack_st;
static bst_loop *g_hloop;
static bst_timer g_attack_t;
static bst_counter_id c_attack_on = BST_COUNTER_INVALID;

static bool auto_used(const bst_config *cfg)
{
	const bst_cfg_global *g = &cfg->global;
	if (g->common.sec.challenge.mode == BST_CHAL_AUTO)
		return true;
	for (size_t i = 0; i < g->nservers; i++) {
		const bst_cfg_server *s = g->servers[i];
		if (s->common.sec.challenge.mode == BST_CHAL_AUTO)
			return true;
		for (size_t j = 0; j < s->nlocations; j++)
			if (s->locations[j]->common.sec.challenge.mode == BST_CHAL_AUTO)
				return true;
	}
	return false;
}

static void attack_tick(void *ud)
{
	(void)ud;
	int r = bst_attack_sample(&g_attack, &g_attack_st, bst_limit_now_us());
	if (r > 0) {
		count(c_attack_on);
		bst_log(BST_LOG_WARN, "challenge auto: under attack (%llu requests/s, %llu refusals/s): challenging",
			(unsigned long long)g_attack_st.rps, (unsigned long long)g_attack_st.refusals_ps);
	} else if (r < 0) {
		bst_log(BST_LOG_WARN, "challenge auto: below the thresholds for %llus: challenge off",
			(unsigned long long)g_attack.hold_s);
	}
	bst_loop_timer_arm(g_hloop, &g_attack_t, 1000, attack_tick, NULL);
}

void bst_sec_helper_start(bst_loop *l)
{
	if (!g_attack_used)
		return;
	g_hloop = l;
	bst_timer_init(&g_attack_t);
	attack_tick(NULL); /* the first sample is the baseline */
}

int bst_sec_setup(bst_config *cfg, int nworkers, bst_err *e)
{
	if (auto_used(cfg)) {
		void *am = bst_shm_create("bastion-attack", bst_attack_bytes(nworkers), NULL);
		if (am == NULL) {
			bst_err_set(e, "challenge auto: shared memory: %s", strerror(errno));
			return -1;
		}
		bst_attack_attach(am, nworkers);
		g_attack = (bst_attack_cfg){ .rps = cfg->global.challenge_auto_rps,
					     .block_rate = cfg->global.challenge_auto_block_rate,
					     .hold_s = cfg->global.challenge_auto_hold_s };
		g_attack_used = true;
		c_attack_on = bst_counter_register("bastion_under_attack_total",
						   "times challenge auto turned on (the helper's 1 Hz decision)", NULL);
	}
	bst_cfg_global *g = &cfg->global;
	if (escalation_used(cfg) && setup_escalation(cfg, nworkers, e) != 0)
		return -1;
	/* the challenge key: 32 random bytes every worker shares (sec/challenge.h) */
	void *ck = bst_shm_create("bastion-challenge", BST_CHALLENGE_KEY_LEN, NULL);
	if (ck == NULL || bst_challenge_setup(ck) != 0) {
		bst_err_set(e, "challenge: shared key: %s", ck == NULL ? strerror(errno) : "no randomness");
		return -1;
	}
	c_blocked = bst_counter_register("bastion_blocked_total",
					 "connections and requests refused for an escalation block", NULL);
	if (g->nwaf_rules > 0) {
		c_waf_matched = bst_counter_register("bastion_waf_matches_total", "waf rules that matched", NULL);
		c_waf_denied = bst_counter_register("bastion_waf_denied_total", "requests a waf rule denied", NULL);
	}
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
	if (conn_limits_used(cfg)) {
		void *mem = bst_shm_create("bastion-connlimit", bst_connlimit_bytes(nworkers), NULL);
		if (mem == NULL || bst_connlimit_attach(mem, nworkers) != 0) {
			bst_err_set(e, "limit_conn: shared memory: %s", strerror(errno));
			return -1;
		}
	}
	c_conn_refused = bst_counter_register("bastion_conn_limit_refused_total",
					      "connections closed at accept by limit_conn", NULL);
	c_acl_denied = bst_counter_register("bastion_acl_denied_total",
					    "connections and requests an ACL refused", NULL);
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

void bst_sec_request(void)
{
	bst_attack_request(); /* the requests `challenge auto` measures (a no-op when unused) */
}

/* A refusal: counted under id and toward challenge_auto_block_rate. */
static void refused(bst_counter_id id)
{
	count(id);
	bst_attack_refusal();
}

bool bst_sec_required(const bst_stream *s)
{
	return s->cfg->sec.limits.n > 0 || s->cfg->sec.acl.n > 0 || s->cfg->sec.acl_default_deny || s->cfg->sec.waf.n > 0 ||
	       s->cfg->sec.challenge.mode != BST_CHAL_OFF ||
	       bst_block_any(g_blocks);
}

/* ---- connection level ---- */

static bool conn_limits_used(const bst_config *cfg)
{
	if (cfg->global.common.sec.conn.set)
		return true;
	for (size_t i = 0; i < cfg->global.nservers; i++)
		if (cfg->global.servers[i]->common.sec.conn.set)
			return true;
	return false;
}

static bst_loop *g_loop;
static bst_timer g_sweep;

static void sweep(void *ud)
{
	(void)ud;
	bst_connlimit_sweep();
	bst_loop_timer_arm(g_loop, &g_sweep, 2000, sweep, NULL);
}

void bst_sec_worker_start(int slot, bst_loop *l)
{
	g_loop = l;
	bst_attack_worker(slot);
	bst_escalate_worker(slot);
	bst_connlimit_worker(slot);
	bst_sock_close_hook = bst_connlimit_release;
	bst_timer_init(&g_sweep);
	bst_loop_timer_arm(l, &g_sweep, 2000, sweep, NULL);
}

bool bst_sec_accept(const bst_cfg_common *srv, const bst_ip *peer, int fd)
{
	const bst_cfg_sec *sc = &srv->sec;
	/* a trusted front proxy carries many clients: its own address is not the client's */
	if (bst_proxy_cidr_match(&srv->proxy.real_ip_from, peer))
		return true;
	if (bst_sec_blocked(peer)) { /* an escalation block, in every worker */
		refused(c_blocked);
		return false;
	}
	if ((sc->acl.n > 0 || sc->acl_default_deny) && !bst_acl_check(&sc->acl, sc->acl_default_deny, peer)) {
		count(c_acl_denied);
		return false;
	}
	if (sc->conn.set && !bst_connlimit_acquire(&sc->conn, peer, fd)) {
		count(c_conn_refused);
		return false;
	}
	return true;
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

/* One request against zone z. True: it was answered (refused, or reset); *delay grows for a
 * `mode delay` hold. */
static bool check_zone(bst_stream *s, bst_limit_zone *z, uint64_t now, bool headers, uint64_t *delay)
{
	uint64_t key;
	if (z->key_is_addr) {
		if (!s->sec_ip_set)
			return false;
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
	if (headers) {
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
		return false;
	if (z->dry_run) {
		count(c_dry_run);
		log_client(s, r.verdict == BST_LIMIT_REJECT ? "would reject (dry_run)" : "would delay (dry_run)", z);
		return false;
	}
	if (r.verdict == BST_LIMIT_DELAY) {
		if (r.delay_us > *delay)
			*delay = r.delay_us;
		return false;
	}
	refused(c_rejected);
	log_client(s, "rejected", z);
	bst_sec_strike_stream(&z->esc, s, BST_STRIKE_LIMIT, z->ipv6_prefix);
	bst_str ra = retry_after(s, r.retry_after_us);
	if (ra.p == NULL)
		s->ops->reset(s, BST_STREAM_ERR_INTERNAL);
	else
		(void)bst_send_error_hdr(s, (int)z->status, BST_S("Retry-After"), ra);
	return true;
}

/* ---- WAF-lite ---- */

static bool waf_challenges(const bst_cfg_sec *sc)
{
	for (size_t i = 0; i < sc->waf.n; i++) {
		const bst_waf_ref *r = sc->waf.items[i];
		if (r->rule != NULL && r->rule->action == BST_WAF_CHALLENGE)
			return true;
	}
	return false;
}

static const char *const waf_verbs[] = { "log", "allow", "deny", "challenge", "limit" };

static void waf_matched(const bst_waf_rule *r, const bst_stream *s, void *ud)
{
	(void)ud;
	count(c_waf_matched);
	char a[BST_ADDR_STRLEN] = "-";
	if (s->sec_ip_set)
		(void)bst_addr_format(&s->sec_ip, a, sizeof a);
	bst_log(BST_LOG_INFO, "waf: rule %s %s%s %s", r->name, s->cfg->sec.waf_log ? "would " : "",
		waf_verbs[r->action], a);
}

/* The scope's waf rules. True: the request was answered (or handed to the challenge). */
static bool check_waf(bst_stream *s, uint64_t now, uint64_t *delay)
{
	const bst_cfg_sec *sc = &s->cfg->sec;
	bst_waf_action a = bst_waf_eval(&sc->waf, s, waf_matched, NULL);
	if (a.regex_limit)
		bst_log(BST_LOG_WARN, "waf: a regex hit regex_match_limit (fail closed for deny and challenge)");
	if (a.verdict == BST_WAF_NONE || a.verdict == BST_WAF_ALLOW || sc->waf_log)
		return false;
	switch (a.verdict) {
	case BST_WAF_DENY:
		refused(c_waf_denied);
		bst_sec_strike_stream(&a.rule->esc, s, BST_STRIKE_WAF, 64);
		(void)bst_send_error(s, (int)a.status);
		return true;
	case BST_WAF_CHALLENGE:
		/* a client holding a valid pass goes on; the others get the challenge */
		return bst_challenge_check(s, true);
	case BST_WAF_LIMIT:
		return check_zone(s, a.rule->zone, now, false, delay);
	default:
		return false;
	}
}

bool bst_sec_check(bst_stream *s, bst_sec_cont cont)
{
	const bst_cfg_sec *sc = &s->cfg->sec;
	uint64_t now = bst_limit_now_us(), delay = 0;
	set_client(s);
	if (s->sec_ip_set && bst_sec_blocked(&s->sec_ip)) { /* also the L7-only blocks */
		refused(c_blocked);
		(void)bst_send_error(s, 403);
		return true;
	}
	if (s->sec_ip_set && (sc->acl.n > 0 || sc->acl_default_deny) &&
	    !bst_acl_check(&sc->acl, sc->acl_default_deny, &s->sec_ip)) {
		count(c_acl_denied);
		(void)bst_send_error(s, 403);
		return true;
	}
	/* the challenge: its verify endpoint, then the gate (a valid pass or allowlisted goes on) */
	bool chal = sc->challenge.mode != BST_CHAL_OFF;
	if ((chal || waf_challenges(sc)) && bst_challenge_is_verify(s))
		return bst_challenge_check(s, true);
	if (chal && bst_challenge_check(s, false))
		return true;
	if (sc->waf.n > 0 && check_waf(s, now, &delay))
		return true;
	for (size_t i = 0; i < sc->limits.n; i++) {
		const bst_limit_ref *ref = sc->limits.items[i];
		if (check_zone(s, ref->zone, now, i == 0 && sc->limit_headers, &delay))
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
