/* The reverse proxy's directives: `upstream` blocks with their `server` lines and pool settings,
 * and the `resolver` the helper uses for `resolve` servers. Peers are built by a post hook, once
 * every block is known (proxy/upstream.h says how a server becomes peers). */
#include "config/compile.h"
#include "config/values.h"
#include "core/cidr.h"
#include "core/str.h"
#include "http/token.h"
#include "proxy/health.h"
#include "proxy/up_tls.h"
#include "proxy/upstream.h"

#include <netdb.h>
#include <openssl/ssl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#define MS 1000 /* microseconds per millisecond */
#define SEC 1000000

static bst_str as_str(const bst_ast_arg *a)
{
	return (bst_str){ a->text, (uint32_t)a->len };
}

static bst_str cstr(const char *s)
{
	return (bst_str){ s, (uint32_t)strlen(s) };
}
#define BST_S_C(s) cstr(s)

static int oom(bst_err *e)
{
	bst_err_set(e, "out of memory");
	return -1;
}

static int bad_at(bst_cfg_ctx *c, const bst_ast_arg *a, bst_err *e)
{
	(void)c;
	bst_cfg_err_at(e, &a->loc);
	return -1;
}

/* host[:port], [v6][:port]: splits into host (copied, brackets removed) and port (default dflt).
 * false with err set on a malformed value. */
static bool split_hostport(bst_cfg_ctx *c, bst_str s, uint16_t dflt, const char **host,
			   uint16_t *port, bst_err *e)
{
	bst_str h = s, p = { NULL, 0 };
	if (s.len > 0 && s.p[0] == '[') {
		const char *rb = memchr(s.p, ']', s.len);
		if (rb == NULL) {
			bst_err_set(e, "\"%.*s\": an IPv6 address needs its closing ']'", (int)s.len, s.p);
			return false;
		}
		h = (bst_str){ s.p + 1, (uint32_t)(rb - s.p - 1) };
		size_t rest = s.len - (size_t)(rb - s.p) - 1;
		if (rest > 0) {
			if (rb[1] != ':') {
				bst_err_set(e, "\"%.*s\": expected ':' after ']'", (int)s.len, s.p);
				return false;
			}
			p = (bst_str){ rb + 2, (uint32_t)(rest - 1) };
		}
	} else {
		const char *colon = memchr(s.p, ':', s.len);
		if (colon != NULL) {
			if (memchr(colon + 1, ':', s.len - (size_t)(colon - s.p) - 1) != NULL) {
				bst_err_set(e, "\"%.*s\": write an IPv6 address as [addr]:port", (int)s.len,
					    s.p);
				return false;
			}
			h = (bst_str){ s.p, (uint32_t)(colon - s.p) };
			p = (bst_str){ colon + 1, (uint32_t)(s.len - (size_t)(colon - s.p) - 1) };
		}
	}
	if (h.len == 0) {
		bst_err_set(e, "\"%.*s\": no host", (int)s.len, s.p);
		return false;
	}
	*port = dflt;
	if (p.p != NULL) {
		int64_t v;
		if (!bst_parse_int(p, 1, 65535, &v)) {
			bst_err_set(e, "\"%.*s\": the port must be 1 to 65535", (int)s.len, s.p);
			return false;
		}
		*port = (uint16_t)v;
	}
	*host = bst_cfg_strdup(c, h.p, h.len, e);
	return *host != NULL;
}

bool bst_proxy_split_hostport(bst_cfg_ctx *c, bst_str s, uint16_t dflt, const char **host,
			      uint16_t *port, bst_err *e);
bool bst_proxy_split_hostport(bst_cfg_ctx *c, bst_str s, uint16_t dflt, const char **host,
			      uint16_t *port, bst_err *e)
{
	return split_hostport(c, s, dflt, host, port, e);
}

/* ---- upstream { } ---- */

static int ap_upstream(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	bst_cfg_upstream *u = bst_arena_alloc(c->arena, sizeof *u);
	if (u == NULL)
		return oom(e);
	memset(u, 0, sizeof *u); /* the block's defaults apply as directives */
	u->name = bst_cfg_strdup(c, a->text, a->len, e);
	if (u->name == NULL || bst_cfg_loc_at(c, &a->loc, &u->loc, e) != 0)
		return -1;
	bst_cfg_global *g = c->global;
	u->index = g->nupstreams;
	if (bst_cfg_push_owned(c, &g->upstreams, &g->nupstreams, &g->upstreams_cap_, sizeof u, &u,
			       e) != 0)
		return -1;
	c->upstream = u;
	return 0;
}

static int ap_server(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	bst_cfg_upstream *u = c->upstream;
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	bst_up_server s;
	memset(&s, 0, sizeof s);
	s.weight = 1;
	if (!split_hostport(c, as_str(a), 80, &s.host, &s.port, e))
		return bad_at(c, a, e);
	for (size_t i = 1; i < bst_dir_npos(d, n); i++) {
		const bst_ast_arg *f = bst_dir_pos(d, n, i);
		if (bst_str_eq(as_str(f), BST_S("backup")))
			s.backup = true;
		else
			s.resolve = true; /* the enum allows nothing else */
	}
	bst_ast_arg v;
	uint64_t x;
	if (bst_dir_opt(d, n, "weight=", &v) && bst_str_to_u64(as_str(&v), &x))
		s.weight = (unsigned)x;
	if (bst_dir_opt(d, n, "max_conns=", &v) && bst_str_to_u64(as_str(&v), &x))
		s.max_conns = (unsigned)x;
	if (bst_dir_opt(d, n, "slow_start=", &v) && bst_parse_duration_us(as_str(&v), &x))
		s.slow_start_ms = (x + MS - 1) / MS;
	bst_ip ip;
	if (s.resolve && bst_addr_parse(BST_S_C(s.host), &ip)) {
		bst_err_set(e, "server %s: `resolve` needs a host name, not an address", s.host);
		return bad_at(c, a, e);
	}
	if (bst_cfg_loc_of(c, n, &s.loc, e) != 0)
		return -1;
	return bst_cfg_push_owned(c, &u->servers, &u->nservers, &u->servers_cap_, sizeof s, &s, e);
}

static int set_ms(const bst_directive *d, const bst_ast_node *n, uint64_t *out)
{
	uint64_t us;
	if (bst_parse_duration_us(as_str(bst_dir_pos(d, n, 0)), &us)) /* validated */
		*out = (us + MS - 1) / MS;
	return 0;
}

static int ap_keepalive(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	uint64_t v;
	(void)e;
	if (bst_str_to_u64(as_str(bst_dir_pos(d, n, 0)), &v))
		c->upstream->keepalive = (unsigned)v;
	return 0;
}

static int ap_keepalive_requests(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
				 bst_err *e)
{
	uint64_t v;
	(void)e;
	if (bst_str_to_u64(as_str(bst_dir_pos(d, n, 0)), &v))
		c->upstream->keepalive_requests = (unsigned)v;
	return 0;
}

#define AP_MS(fn, field)                                                                       \
	static int fn(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e) \
	{                                                                                      \
		(void)e;                                                                       \
		return set_ms(d, n, &c->upstream->field);                                      \
	}
AP_MS(ap_keepalive_timeout, keepalive_timeout_ms)
AP_MS(ap_connect_timeout, connect_timeout_ms)
AP_MS(ap_send_timeout, send_timeout_ms)
AP_MS(ap_read_timeout, read_timeout_ms)

/* ---- balance ---- */

static int ap_balance(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	bst_cfg_upstream *u = c->upstream;
	if (strcmp(d->subname, "least_conn") == 0) {
		u->balance = BST_BAL_LEAST_CONN;
	} else if (strcmp(d->subname, "peak_ewma") == 0) {
		u->balance = BST_BAL_PEAK_EWMA;
	} else if (strcmp(d->subname, "hash") == 0) {
		u->balance = BST_BAL_HASH;
		u->hash_key = bst_tpl_compile_arg(bst_dir_pos(d, n, 0), c->arena, e);
		if (u->hash_key == NULL)
			return -1;
		u->hash_consistent = bst_dir_npos(d, n) > 1;
	} else {
		u->balance = BST_BAL_ROUND_ROBIN;
	}
	return 0;
}

/* ---- resilience (Task 5) ---- */

static bool opt_ms(const bst_directive *d, const bst_ast_node *n, const char *k, uint64_t *out)
{
	bst_ast_arg v;
	uint64_t us;
	if (!bst_dir_opt(d, n, k, &v) || !bst_parse_duration_us(as_str(&v), &us))
		return false;
	*out = (us + MS - 1) / MS;
	return true;
}

static bool opt_uint(const bst_directive *d, const bst_ast_node *n, const char *k, unsigned *out)
{
	bst_ast_arg v;
	uint64_t x;
	if (!bst_dir_opt(d, n, k, &v) || !bst_str_to_u64(as_str(&v), &x))
		return false;
	*out = (unsigned)x;
	return true;
}

static int ap_health_check(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			   bst_err *e)
{
	bst_up_health *h = &c->upstream->health;
	*h = (bst_up_health){ .on = true, .path = "/", .interval_ms = 5000, .timeout_ms = 2000,
			      .fails = 3, .passes = 2, .expect_lo = 200, .expect_hi = 399 };
	bst_ast_arg v;
	if (bst_dir_opt(d, n, "path=", &v)) {
		if (v.len == 0 || v.text[0] != '/' || memchr(v.text, ' ', v.len) != NULL) {
			bst_err_set(e, "health_check: path= must start with '/' and hold no space");
			return bad_at(c, &v, e);
		}
		h->path = bst_cfg_strdup(c, v.text, v.len, e);
		if (h->path == NULL)
			return -1;
	}
	if (bst_dir_opt(d, n, "expect=", &v) &&
	    !bst_health_parse_expect(v.text, v.len, &h->expect_lo, &h->expect_hi)) {
		bst_err_set(e, "health_check: expect= is a status (200) or a range (200-399)");
		return bad_at(c, &v, e);
	}
	(void)opt_ms(d, n, "interval=", &h->interval_ms);
	(void)opt_ms(d, n, "timeout=", &h->timeout_ms);
	(void)opt_uint(d, n, "fails=", &h->fails);
	(void)opt_uint(d, n, "passes=", &h->passes);
	return 0;
}

static int ap_passive_eject(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			    bst_err *e)
{
	(void)e;
	bst_up_passive *p = &c->upstream->passive;
	*p = (bst_up_passive){ .fails = 5, .window_ms = 10000, .for_ms = 30000 };
	(void)opt_uint(d, n, "fails=", &p->fails);
	(void)opt_ms(d, n, "window=", &p->window_ms);
	(void)opt_ms(d, n, "for=", &p->for_ms);
	return 0;
}

static int ap_retry(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	bst_up_retry *r = &c->upstream->retry;
	*r = (bst_up_retry){ .set = true, .attempts = 1, .budget_pct = 20, .on = BST_RETRY_ON_ERROR };
	(void)opt_uint(d, n, "attempts=", &r->attempts);
	(void)opt_ms(d, n, "timeout=", &r->timeout_ms);
	bst_ast_arg v;
	uint8_t pct;
	if (bst_dir_opt(d, n, "budget=", &v) && bst_parse_percent(as_str(&v), &pct))
		r->budget_pct = pct;
	if (bst_dir_opt(d, n, "on=", &v)) {
		r->on = 0;
		const char *p = v.text, *end = v.text + v.len;
		while (p < end) {
			const char *q = memchr(p, ',', (size_t)(end - p));
			size_t l = q ? (size_t)(q - p) : (size_t)(end - p);
			bst_str w = { p, (uint32_t)l };
			if (bst_str_eq(w, BST_S("error")))
				r->on |= BST_RETRY_ON_ERROR;
			else if (bst_str_eq(w, BST_S("timeout")))
				r->on |= BST_RETRY_ON_TIMEOUT;
			else if (bst_str_eq(w, BST_S("5xx")))
				r->on |= BST_RETRY_ON_5XX;
			else if (!bst_str_eq(w, BST_S("off"))) {
				bst_err_set(e, "retry: on= is a comma list of error, timeout, 5xx (or off)");
				return bad_at(c, &v, e);
			}
			p += l + 1;
		}
	}
	return 0;
}

static int ap_breaker(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	bst_up_breaker *b = &c->upstream->breaker;
	*b = (bst_up_breaker){ .for_ms = 10000 };
	(void)opt_uint(d, n, "max_pending=", &b->max_pending);
	(void)opt_uint(d, n, "max_active=", &b->max_active);
	(void)opt_uint(d, n, "max_retries=", &b->max_retries);
	(void)opt_uint(d, n, "fails=", &b->fails);
	(void)opt_ms(d, n, "for=", &b->for_ms);
	return 0;
}

static int ap_panic(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	uint8_t pct;
	if (bst_parse_percent(as_str(bst_dir_pos(d, n, 0)), &pct))
		c->upstream->panic_pct = pct;
	return 0;
}

/* ---- HTTP/2 upstreams (Task 8) ---- */

static int ap_protocol(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	c->upstream->h2 = bst_str_eq(as_str(bst_dir_pos(d, n, 0)), BST_S("http2"));
	return 0;
}

static const char *const pp_versions[] = { "v1", "v2", NULL };

static int ap_send_pp(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	c->upstream->send_pp = bst_str_eq(as_str(bst_dir_pos(d, n, 0)), BST_S("v2")) ? 2 : 1;
	return bst_cfg_loc_of(c, n, &c->upstream->send_pp_loc, e);
}

static int ap_h2_streams(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	uint64_t v;
	if (bst_str_to_u64(as_str(bst_dir_pos(d, n, 0)), &v))
		c->upstream->h2_max_streams = (unsigned)v;
	return 0;
}

/* ---- tls (Task 6) ---- */

static int tls_line(bst_cfg_ctx *c, const bst_ast_node *n, bst_err *e)
{
	bst_cfg_upstream *u = c->upstream;
	if (!u->tls) {
		u->tls = true;
		return bst_cfg_loc_of(c, n, &u->tlsc.loc, e);
	}
	return 0;
}

static int ap_tls_up(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	bst_cfg_upstream *u = c->upstream;
	if (tls_line(c, n, e) != 0)
		return -1;
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	if (strcmp(d->subname, "verify") == 0) {
		bool v = true;
		(void)bst_parse_bool(as_str(a), &v);
		u->tlsc.no_verify = !v;
		return 0;
	}
	if (strcmp(d->subname, "versions") == 0) {
		int lo = TLS1_3_VERSION, hi = TLS1_2_VERSION;
		for (size_t i = 0; i < bst_dir_npos(d, n); i++) {
			int v = strcmp(bst_dir_pos(d, n, i)->text, "1.3") == 0 ? TLS1_3_VERSION
									  : TLS1_2_VERSION;
			lo = v < lo ? v : lo;
			hi = v > hi ? v : hi;
		}
		u->tlsc.min_ver = lo;
		u->tlsc.max_ver = hi;
		return 0;
	}
	const char *s = bst_cfg_strdup(c, a->text, a->len, e);
	if (s == NULL)
		return -1;
	if (strcmp(d->subname, "ca") == 0)
		u->tlsc.ca = s;
	else if (strcmp(d->subname, "sni") == 0)
		u->tlsc.sni = s;
	else if (strcmp(d->subname, "cert") == 0)
		u->tlsc.cert = s;
	else
		u->tlsc.key = s;
	return 0;
}

static int post_upstream_tls(bst_config *cfg, bst_cfg_ctx *c, bst_err *e)
{
	return bst_uptls_setup(cfg, c, e);
}
BST_CFG_POST(post_upstream_tls);

/* ---- resolver ---- */

static int ap_resolver(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	bst_cfg_resolver *r = &c->global->resolver;
	size_t np = bst_dir_npos(d, n);
	for (size_t i = 0; i < np; i++) {
		const bst_ast_arg *a = bst_dir_pos(d, n, i);
		const char *host;
		uint16_t port;
		bst_ip ip;
		if (!split_hostport(c, as_str(a), 53, &host, &port, e))
			return bad_at(c, a, e);
		if (!bst_addr_parse(BST_S_C(host), &ip)) {
			bst_err_set(e, "resolver %s: an IP address is needed (the resolver is not "
				       "itself resolved)", host);
			return bad_at(c, a, e);
		}
		r->addrs[r->naddrs++] = (bst_sockaddr){ .ip = ip, .port = port };
	}
	return 0;
}

#define AP_RMS(fn, field)                                                                      \
	static int fn(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e) \
	{                                                                                      \
		(void)e;                                                                       \
		return set_ms(d, n, &c->global->resolver.field);                               \
	}
AP_RMS(ap_resolver_ttl_min, ttl_min_ms)
AP_RMS(ap_resolver_ttl_max, ttl_max_ms)
AP_RMS(ap_resolver_timeout, timeout_ms)

/* ---- peers ---- */

/* One peer per address of a host name, resolved now (master, or `bastion -t`). */
static int resolve_static(bst_cfg_ctx *c, bst_cfg_upstream *u, bst_up_server *s, bst_ip *ips,
			  size_t cap, size_t *n, bst_err *e)
{
	struct addrinfo hints, *res = NULL;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	int rc = getaddrinfo(s->host, NULL, &hints, &res);
	if (rc != 0) {
		bst_err_set(e, "upstream %s: server %s does not resolve (%s); add `resolve` to keep "
			       "trying at run time", u->name, s->host, gai_strerror(rc));
		bst_cfg_err_at(e, bst_cfg_src(c, &s->loc));
		return -1;
	}
	*n = 0;
	for (struct addrinfo *ai = res; ai != NULL && *n < cap; ai = ai->ai_next) {
		bst_ip ip;
		memset(&ip, 0, sizeof ip);
		if (ai->ai_family == AF_INET) {
			ip.family = BST_IP_V4;
			memcpy(ip.b, &((struct sockaddr_in *)ai->ai_addr)->sin_addr, 4);
		} else if (ai->ai_family == AF_INET6) {
			ip.family = BST_IP_V6;
			memcpy(ip.b, &((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr, 16);
		} else {
			continue;
		}
		bool dup = false;
		for (size_t k = 0; k < *n; k++)
			dup = dup || bst_ip_eq(&ips[k], &ip);
		if (!dup)
			ips[(*n)++] = ip;
	}
	freeaddrinfo(res);
	return 0;
}

static int build_peers(bst_cfg_ctx *c, bst_cfg_upstream *u, size_t *state, bst_err *e)
{
	enum { CAP = 16 };
	size_t total = 0;
	bst_ip (*ips)[CAP] = calloc(u->nservers ? u->nservers : 1, sizeof *ips);
	size_t *nips = calloc(u->nservers ? u->nservers : 1, sizeof *nips);
	int rc = -1;
	if (ips == NULL || nips == NULL) {
		oom(e);
		goto out;
	}
	for (size_t i = 0; i < u->nservers; i++) {
		bst_up_server *s = &u->servers[i];
		if (s->resolve) {
			nips[i] = BST_UP_RESOLVE_SLOTS;
		} else if (bst_addr_parse(BST_S_C(s->host), &ips[i][0])) {
			nips[i] = 1;
		} else if (resolve_static(c, u, s, ips[i], CAP, &nips[i], e) != 0) {
			goto out;
		}
		total += nips[i];
	}
	u->peers = bst_arena_alloc(c->arena, (total ? total : 1) * sizeof *u->peers);
	if (u->peers == NULL) {
		oom(e);
		goto out;
	}
	memset(u->peers, 0, (total ? total : 1) * sizeof *u->peers);
	for (size_t i = 0; i < u->nservers; i++) {
		bst_up_server *s = &u->servers[i];
		s->first_peer = u->npeers;
		s->npeers = nips[i];
		for (size_t k = 0; k < nips[i]; k++) {
			bst_peer *p = &u->peers[u->npeers++];
			p->dynamic = s->resolve;
			if (!s->resolve)
				p->addr = (bst_sockaddr){ .ip = ips[i][k], .port = s->port };
			p->weight = s->weight;
			p->max_conns = s->max_conns;
			p->slow_start_ms = s->slow_start_ms;
			p->backup = s->backup;
			p->server = i;
			p->state = (*state)++;
		}
	}
	rc = 0;
out:
	free(ips);
	free(nips);
	return rc;
}

static int post_upstream_peers(bst_config *cfg, bst_cfg_ctx *c, bst_err *e)
{
	bst_cfg_global *g = &cfg->global;
	size_t state = 0;
	for (size_t i = 0; i < g->nupstreams; i++) {
		bst_cfg_upstream *u = g->upstreams[i];
		for (size_t k = 0; k < i; k++) {
			if (!u->implicit && !g->upstreams[k]->implicit &&
			    strcmp(u->name, g->upstreams[k]->name) == 0) {
				bst_err_set(e, "upstream \"%s\" is defined twice", u->name);
				bst_cfg_err_at(e, bst_cfg_src(c, &u->loc));
				return -1;
			}
		}
		if (u->nservers == 0) {
			bst_err_set(e, "upstream \"%s\" has no server", u->name);
			bst_cfg_err_at(e, bst_cfg_src(c, &u->loc));
			return -1;
		}
		for (size_t k = 0; k < u->nservers; k++) {
			if (u->servers[k].resolve && g->resolver.naddrs == 0) {
				bst_err_set(e, "server %s: `resolve` needs a `resolver`",
					    u->servers[k].host);
				bst_cfg_err_at(e, bst_cfg_src(c, &u->servers[k].loc));
				return -1;
			}
		}
		if (!u->retry.set)
			u->retry = (bst_up_retry){ .set = true, .attempts = 1, .budget_pct = 20,
						   .on = BST_RETRY_ON_ERROR };
		if (u->breaker.for_ms == 0)
			u->breaker.for_ms = 10000;
		if (build_peers(c, u, &state, e) != 0)
			return -1;
	}
	return 0;
}
BST_CFG_POST(post_upstream_peers);

/* ---- the tables ---- */

static const char *const server_flags[] = { "backup", "resolve", NULL };
static const char *const hash_flags[] = { "consistent", NULL };
static const bst_optspec server_opts[] = {
	{ .key = "weight=", .type = { .kind = BST_T_INT, .min = 1, .max = 1000 } },
	{ .key = "max_conns=", .type = { .kind = BST_T_INT, .min = 1, .max = 1048576 } },
	{ .key = "slow_start=", .type = { .kind = BST_T_DURATION, .min = 1000000, .max = 3600000000LL } },
};

static const char *const tls_versions[] = { "1.2", "1.3", NULL };
static const char *const up_protocols[] = { "http1", "http2", NULL };
#define DOPT(k, lo, hi) { .key = k, .type = { .kind = BST_T_DURATION, .min = (lo), .max = (hi) } }
#define IOPT(k, lo, hi) { .key = k, .type = { .kind = BST_T_INT, .min = (lo), .max = (hi) } }
static const bst_optspec health_opts[] = {
	{ .key = "path=", .type = { .kind = BST_T_STRING } },
	{ .key = "expect=", .type = { .kind = BST_T_STRING } },
	DOPT("interval=", 10000, 3600000000LL),
	DOPT("timeout=", 1000, 600000000LL),
	IOPT("fails=", 1, 1000),
	IOPT("passes=", 1, 1000),
};
static const bst_optspec passive_opts[] = {
	IOPT("fails=", 1, 1000000),
	DOPT("window=", 1000, 3600000000LL),
	DOPT("for=", 1000, 3600000000LL),
};
static const bst_optspec retry_opts[] = {
	IOPT("attempts=", 0, 16),
	{ .key = "budget=", .type = { .kind = BST_T_PERCENT } },
	{ .key = "on=", .type = { .kind = BST_T_STRING } },
	DOPT("timeout=", 1000, 3600000000LL),
};
static const bst_optspec breaker_opts[] = {
	IOPT("max_pending=", 1, 1048576),
	IOPT("max_active=", 1, 1048576),
	IOPT("max_retries=", 1, 1048576),
	IOPT("fails=", 1, 1000000),
	DOPT("for=", 1000, 3600000000LL),
};

#define UP1(...) .args = { .min_args = 1, .max_args = 1, .pos = { __VA_ARGS__ } }
#define DUR(lo, hi) { .kind = BST_T_DURATION, .min = (lo), .max = (hi) }

static const bst_directive upstream_dirs[] = {
	{ .name = "upstream", .contexts = BST_CTX_GLOBAL, .apply = ap_upstream, .repeatable = true,
	  .child_ctx = BST_CTX_UPSTREAM,
	  .doc = "A named group of servers a `proxy` sends requests to (`proxy name`). Names are "
		 "unique. `proxy http://host:port` makes an unnamed one with that single server and "
		 "the defaults of this block.",
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_STRING } },
		    .block = BST_BLOCK_REQUIRED } },
	{ .name = "server", .contexts = BST_CTX_UPSTREAM, .apply = ap_server, .repeatable = true,
	  .doc = "An upstream server: `host:port` (port 80 when omitted; `[v6]:port` for IPv6), "
		 "with `weight=` (1 to 1000, default 1), `max_conns=` (per worker), `slow_start=` (after it recovers from being down, its share of traffic ramps up over this time), `backup` (used "
		 "only when no other server can take the request) and `resolve`. A host name without "
		 "`resolve` is looked up once when the configuration loads and must resolve; with "
		 "`resolve` the helper looks it up through `resolver` and keeps the addresses fresh "
		 "within their TTL, with no reload, and the server starts even while DNS fails (its "
		 "requests are answered 502 until it resolves).",
	  .args = { .min_args = 1, .max_args = 3,
		    .pos = { { .kind = BST_T_STRING },
			     { .kind = BST_T_ENUM, .enum_values = server_flags } },
		    .opts = server_opts, .nopts = sizeof server_opts / sizeof server_opts[0] } },
	{ .name = "balance", .subname = "round_robin", .contexts = BST_CTX_UPSTREAM,
	  .apply = ap_balance, .subname_exclusive = true,
	  .doc = "Smooth weighted round robin, the default: over any window each server gets its "
		 "weight's share, interleaved rather than in bursts." },
	{ .name = "balance", .subname = "least_conn", .contexts = BST_CTX_UPSTREAM,
	  .apply = ap_balance, .subname_exclusive = true,
	  .doc = "The server with the fewest open requests from this worker relative to its weight; "
		 "ties go round robin." },
	{ .name = "balance", .subname = "hash", .contexts = BST_CTX_UPSTREAM, .apply = ap_balance,
	  .subname_exclusive = true,
	  .doc = "The same key (`balance hash $remote_addr;`, any template) goes to the same server. "
		 "With `consistent`, servers sit on a hash ring, so removing one of n moves only "
		 "about 1/n of the keys, and a server already carrying 25% more than its share passes "
		 "its keys on to the next (bounded load).",
	  .args = { .min_args = 1, .max_args = 2,
		    .pos = { { .kind = BST_T_TEMPLATE },
			     { .kind = BST_T_ENUM, .enum_values = hash_flags } } } },
	{ .name = "balance", .subname = "peak_ewma", .contexts = BST_CTX_UPSTREAM,
	  .apply = ap_balance, .subname_exclusive = true,
	  .doc = "Two servers drawn at random, the one with the lower moving average of response "
		 "latency (peaks count at once, recovery decays over 10 s) times its open requests "
		 "wins: slow servers get less traffic." },
	{ .name = "keepalive", .contexts = BST_CTX_UPSTREAM, .apply = ap_keepalive,
	  .default_value = "32",
	  .doc = "Idle connections to this upstream each worker keeps open for reuse; 0 closes "
		 "every connection after its response.",
	  UP1({ .kind = BST_T_INT, .min = 0, .max = 65536 }) },
	{ .name = "keepalive_timeout", .contexts = BST_CTX_UPSTREAM, .apply = ap_keepalive_timeout,
	  .default_value = "60s",
	  .doc = "How long an idle upstream connection is kept. Keep it below the upstream's own "
		 "idle timeout, so the upstream does not close a connection just as a request goes "
		 "out on it.",
	  UP1(DUR(1 * MS, 3600LL * SEC)) },
	{ .name = "keepalive_requests", .contexts = BST_CTX_UPSTREAM, .apply = ap_keepalive_requests,
	  .default_value = "1000",
	  .doc = "Requests one upstream connection carries before it is closed.",
	  UP1({ .kind = BST_T_INT, .min = 1, .max = 1000000000 }) },
	{ .name = "connect_timeout", .contexts = BST_CTX_UPSTREAM, .apply = ap_connect_timeout,
	  .default_value = "5s",
	  .doc = "How long a connection to an upstream server may take; past it the request gets "
		 "504 Gateway Timeout (a refused connection gets 502).",
	  UP1(DUR(1 * MS, 600LL * SEC)) },
	{ .name = "send_timeout", .contexts = BST_CTX_UPSTREAM, .apply = ap_send_timeout,
	  .default_value = "60s",
	  .doc = "How long a write of the request to the upstream may make no progress.",
	  UP1(DUR(1 * MS, 3600LL * SEC)) },
	{ .name = "read_timeout", .contexts = BST_CTX_UPSTREAM, .apply = ap_read_timeout,
	  .default_value = "60s",
	  .doc = "How long the upstream may stay silent: before the first byte of the response it "
		 "is a 504, later the client's response is aborted.",
	  UP1(DUR(1 * MS, 3600LL * SEC)) },
	{ .name = "health_check", .contexts = BST_CTX_UPSTREAM, .apply = ap_health_check,
	  .doc = "Active health checks, sent by the helper process (one probe per server per "
		 "interval, however many workers): `path=` (default /), `interval=` (5s), "
		 "`timeout=` (2s), `fails=` (3 consecutive failures mark the server down), "
		 "`passes=` (2 consecutive passes bring it back) and `expect=` (a status or range, "
		 "default 200-399). For a TLS upstream the TCP connect alone is checked.",
	  .args = { .min_args = 0, .max_args = 0, .opts = health_opts,
		    .nopts = sizeof health_opts / sizeof health_opts[0] } },
	{ .name = "passive_eject", .contexts = BST_CTX_UPSTREAM, .apply = ap_passive_eject,
	  .doc = "Ejects a server after `fails=` (default 5) failures of real requests (connect "
		 "errors, timeouts, resets and 5xx responses) within `window=` (10s), for `for=` "
		 "(30s). Every worker counts into the same shared state, so an ejection applies to "
		 "all of them at once.",
	  .args = { .min_args = 0, .max_args = 0, .opts = passive_opts,
		    .nopts = sizeof passive_opts / sizeof passive_opts[0] } },
	{ .name = "retry", .contexts = BST_CTX_UPSTREAM, .apply = ap_retry,
	  .doc = "Retries a failed request on another server: `attempts=` extra tries (default 1, 0 "
		 "turns retries off), `on=` a comma list of error, timeout and 5xx (default error), "
		 "`budget=` the share of requests retries may add (default 20%, so an outage is never "
		 "amplified) and `timeout=` (no new try once the request is that old). A request is "
		 "never retried once any response byte reached the client, and a request that is "
		 "not idempotent or has a body only when the connection itself failed (nothing reached "
		 "the upstream).",
	  .args = { .min_args = 0, .max_args = 0, .opts = retry_opts,
		    .nopts = sizeof retry_opts / sizeof retry_opts[0] } },
	{ .name = "circuit_breaker", .contexts = BST_CTX_UPSTREAM, .apply = ap_breaker,
	  .doc = "Per-worker limits: `max_pending=` requests waiting for a response head, "
		 "`max_active=` requests in flight, `max_retries=` retries in flight; a request over "
		 "a limit gets 503 with Retry-After at once, nothing queues. With `fails=`, that many "
		 "consecutive failures open the breaker for `for=` (default 10s): requests get 503, "
		 "then one probe request decides whether it closes or opens again.",
	  .args = { .min_args = 0, .max_args = 0, .opts = breaker_opts,
		    .nopts = sizeof breaker_opts / sizeof breaker_opts[0] } },
	{ .name = "panic_threshold", .contexts = BST_CTX_UPSTREAM, .apply = ap_panic,
	  .default_value = "0%",
	  .doc = "When fewer than this share of the primary servers are healthy, health is ignored "
		 "and requests go to every server with an address (better some errors than a "
		 "stampede on the survivors). 0% (the default): an upstream with no healthy server "
		 "answers 503 with Retry-After at once.",
	  UP1({ .kind = BST_T_PERCENT }) },
	{ .name = "protocol", .contexts = BST_CTX_UPSTREAM, .apply = ap_protocol,
	  .default_value = "http1",
	  .doc = "The protocol requests reach the servers in. `http1` (the default): one HTTP/1.1 "
		 "exchange per connection at a time. `http2`: requests are streams multiplexed over "
		 "few HTTP/2 connections per worker (cleartext with prior knowledge, or `h2` by ALPN "
		 "with `tls`), as gRPC needs; response trailers are passed on. A request whose "
		 "Content-Type is application/grpc gets upstream failures as a gRPC status "
		 "(`grpc-status` 14 UNAVAILABLE, 4 DEADLINE_EXCEEDED for a timeout) rather than an "
		 "error page. WebSocket upgrades are not passed to an `http2` upstream.",
	  UP1({ .kind = BST_T_ENUM, .enum_values = up_protocols }) },
	{ .name = "send_proxy_protocol", .contexts = BST_CTX_UPSTREAM, .apply = ap_send_pp,
	  .doc = "Every connection to the servers starts with a PROXY protocol header of this "
		 "version (`v1` text, `v2` binary) naming the client ($remote_addr) and the address "
		 "it connected to, before TLS. Each request then gets a connection of its own (never "
		 "pooled: the header names one client). Not with `protocol http2`.",
	  UP1({ .kind = BST_T_ENUM, .enum_values = pp_versions }) },
	{ .name = "max_upstream_h2_streams", .contexts = BST_CTX_UPSTREAM, .apply = ap_h2_streams,
	  .default_value = "100",
	  .doc = "Streams one HTTP/2 upstream connection carries at once (the server's own "
		 "SETTINGS_MAX_CONCURRENT_STREAMS also applies, the smaller wins); a new connection "
		 "is opened only when every one is full.",
	  UP1({ .kind = BST_T_INT, .min = 1, .max = 65536 }) },
	{ .name = "tls", .subname = "verify", .contexts = BST_CTX_UPSTREAM, .apply = ap_tls_up,
	  .doc = "TLS to the servers of this upstream (any `tls` line turns it on; `proxy https://` "
		 "does too). `on` (the default) checks the certificate chain against `tls ca` (else "
		 "the system's CA bundle) and that it names the server (`tls sni`, else the server's "
		 "host). `off` checks nothing: `bastion -t` warns.",
	  UP1({ .kind = BST_T_BOOL }) },
	{ .name = "tls", .subname = "ca", .contexts = BST_CTX_UPSTREAM, .apply = ap_tls_up,
	  .doc = "PEM file of the CAs the upstream's certificate must lead to, read when the "
		 "configuration loads (before the sandbox), instead of the system bundle.",
	  UP1({ .kind = BST_T_PATH }) },
	{ .name = "tls", .subname = "sni", .contexts = BST_CTX_UPSTREAM, .apply = ap_tls_up,
	  .doc = "The name sent as SNI and checked against the upstream's certificate. Default: the "
		 "server's host as written (an IP address is checked against the certificate's IP "
		 "entries and not sent as SNI).",
	  UP1({ .kind = BST_T_STRING }) },
	{ .name = "tls", .subname = "cert", .contexts = BST_CTX_UPSTREAM, .apply = ap_tls_up,
	  .doc = "Client certificate (PEM chain) presented to the upstream (mTLS); needs `tls key`.",
	  UP1({ .kind = BST_T_PATH }) },
	{ .name = "tls", .subname = "key", .contexts = BST_CTX_UPSTREAM, .apply = ap_tls_up,
	  .doc = "Private key of `tls cert`.",
	  UP1({ .kind = BST_T_PATH }) },
	{ .name = "tls", .subname = "versions", .contexts = BST_CTX_UPSTREAM, .apply = ap_tls_up,
	  .doc = "TLS versions offered to the upstream: 1.2, 1.3 or both (the default).",
	  .args = { .min_args = 1, .max_args = 2,
		    .pos = { { .kind = BST_T_ENUM, .enum_values = tls_versions } } } },
	{ .name = "resolver", .contexts = BST_CTX_GLOBAL, .apply = ap_resolver,
	  .doc = "DNS servers (IP addresses, port 53 when omitted; at most 4) the helper asks for "
		 "`server ... resolve` upstreams, in turn. Only the helper process sends queries: "
		 "workers never resolve. Query IDs come from the system's CSPRNG and each query "
		 "uses a fresh socket, so a new random source port.",
	  .args = { .min_args = 1, .max_args = BST_RESOLVER_MAX, .pos = { { .kind = BST_T_STRING } } } },
	{ .name = "resolver_ttl_min", .contexts = BST_CTX_GLOBAL, .apply = ap_resolver_ttl_min,
	  .default_value = "5s",
	  .doc = "Shortest time a resolved address is kept before asking again, whatever the "
		 "record's TTL; also the retry interval after a failed lookup.",
	  UP1(DUR(1 * SEC, 3600LL * SEC)) },
	{ .name = "resolver_ttl_max", .contexts = BST_CTX_GLOBAL, .apply = ap_resolver_ttl_max,
	  .default_value = "1h",
	  .doc = "Longest time a resolved address is kept before asking again.",
	  UP1(DUR(1 * SEC, 86400LL * SEC)) },
	{ .name = "resolver_timeout", .contexts = BST_CTX_GLOBAL, .apply = ap_resolver_timeout,
	  .default_value = "5s",
	  .doc = "How long the helper waits for one DNS answer. When the resolver does not answer, "
		 "the addresses in use stay in use (past their TTL) and a warning is logged.",
	  UP1(DUR(10 * MS, 60LL * SEC)) },
};
BST_DIRECTIVES(upstream_dirs);

/* ---- proxy and its companions (server and location) ---- */

static int ap_proxy(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	bst_cfg_proxy *p = &c->common->proxy;
	p->set = true;
	p->up = NULL;
	p->target = bst_cfg_strdup(c, a->text, a->len, e);
	if (p->target == NULL || bst_cfg_loc_at(c, &a->loc, &p->loc, e) != 0)
		return -1;
	return 0;
}

static int ap_proxy_uri(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	c->common->proxy.uri = bst_str_eq(as_str(bst_dir_pos(d, n, 0)), BST_S("strip_prefix"))
				       ? BST_PROXY_URI_STRIP_PREFIX
				       : BST_PROXY_URI_PASS;
	return 0;
}

static int ap_proxy_host(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	bst_cfg_proxy *p = &c->common->proxy;
	bst_str v = as_str(a);
	if (bst_str_eq(v, BST_S("$host"))) {
		p->host_mode = BST_PROXY_HOST_CLIENT;
	} else if (bst_str_eq(v, BST_S("upstream"))) {
		p->host_mode = BST_PROXY_HOST_UPSTREAM;
	} else {
		if (memchr(a->text, '$', a->len) != NULL) {
			bst_err_set(e, "proxy_host: $host, upstream or a fixed value (no other variable)");
			return bad_at(c, a, e);
		}
		p->host_mode = BST_PROXY_HOST_VALUE;
		p->host_value = bst_cfg_strdup(c, a->text, a->len, e);
		if (p->host_value == NULL)
			return -1;
	}
	return 0;
}

static int ap_forwarded(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	bst_str v = as_str(bst_dir_pos(d, n, 0));
	c->common->proxy.fwd = bst_str_eq(v, BST_S("forwarded")) ? BST_FWD_FORWARDED
			       : bst_str_eq(v, BST_S("off"))	   ? BST_FWD_OFF
								   : BST_FWD_XFF;
	return 0;
}

static int cidr_list(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
		     bst_cfg_list *list, bst_err *e)
{
	for (size_t i = 0; i < bst_dir_npos(d, n); i++) {
		bst_cidr *x = bst_arena_alloc(c->arena, sizeof *x);
		if (x == NULL)
			return oom(e);
		if (!bst_cidr_parse(as_str(bst_dir_pos(d, n, i)), x))
			return 0; /* validated by the argspec */
		if (bst_cfg_list_append(c, list, x, e) != 0)
			return -1;
	}
	return 0;
}

static int ap_trusted(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	return cidr_list(c, d, n, &c->common->proxy.trusted, e);
}

static int ap_real_ip_from(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			   bst_err *e)
{
	return cidr_list(c, d, n, &c->common->proxy.real_ip_from, e);
}

static int ap_real_ip_header(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			     bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	if (!bst_is_token(as_str(a))) {
		bst_err_set(e, "real_ip_header: not a header name");
		return bad_at(c, a, e);
	}
	c->common->proxy.real_ip_header = bst_cfg_strdup(c, a->text, a->len, e);
	return c->common->proxy.real_ip_header == NULL ? -1 : 0;
}

static int name_list(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
		     bst_cfg_list *list, bst_err *e)
{
	for (size_t i = 0; i < bst_dir_npos(d, n); i++) {
		const bst_ast_arg *a = bst_dir_pos(d, n, i);
		if (!bst_is_token(as_str(a))) {
			bst_err_set(e, "%s: not a header name", d->name);
			return bad_at(c, a, e);
		}
		char *s = bst_cfg_strdup(c, a->text, a->len, e);
		if (s == NULL)
			return -1;
		for (char *q = s; *q; q++)
			if (*q >= 'A' && *q <= 'Z')
				*q = (char)(*q + 32);
		if (bst_cfg_list_extend(c, list, s, e) != 0)
			return -1;
	}
	return 0;
}

static int ap_pass_header(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	return name_list(c, d, n, &c->common->proxy.pass_headers, e);
}

static int ap_hide_header(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	return name_list(c, d, n, &c->common->proxy.hide_headers, e);
}

static int ap_intercept(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	bool v = false;
	(void)bst_parse_bool(as_str(bst_dir_pos(d, n, 0)), &v);
	c->common->proxy.intercept_errors = v;
	return 0;
}

static int ap_max_header(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	uint64_t v;
	(void)e;
	if (bst_parse_size(as_str(bst_dir_pos(d, n, 0)), &v))
		c->common->proxy.max_header = (uint32_t)v;
	return 0;
}

static int ap_buffer_size(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	uint64_t v;
	(void)e;
	if (bst_parse_size(as_str(bst_dir_pos(d, n, 0)), &v))
		c->common->proxy.buffer_size = (uint32_t)v;
	return 0;
}

static int ap_websocket(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	bool v = true;
	(void)bst_parse_bool(as_str(bst_dir_pos(d, n, 0)), &v);
	c->common->proxy.websocket = v;
	return 0;
}

#define AP_PMS(fn, field)                                                                      \
	static int fn(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e) \
	{                                                                                      \
		(void)e;                                                                       \
		return set_ms(d, n, &c->common->proxy.field);                                  \
	}
AP_PMS(ap_tunnel_idle, tunnel_idle_ms)
AP_PMS(ap_tunnel_max, tunnel_max_ms)
AP_PMS(ap_tunnel_drain, tunnel_drain_ms)

static int ap_max_tunnels(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	uint64_t v;
	if (bst_str_to_u64(as_str(bst_dir_pos(d, n, 0)), &v))
		c->common->proxy.max_tunnels = (unsigned)v;
	return 0;
}

/* `proxy http://host[:port][/path]`: the implicit upstream for host:port (one per distinct
 * address, shared by every scope that names it). */
static bst_cfg_upstream *implicit_upstream(bst_config *cfg, bst_cfg_ctx *c, bst_cfg_proxy *p,
					   bst_err *e)
{
	bool https = strncmp(p->target, "https://", 8) == 0;
	const char *rest = p->target + (https ? 8 : 7);
	const char *slash = strchr(rest, '/');
	size_t hl = slash ? (size_t)(slash - rest) : strlen(rest);
	if (memchr(rest, '?', strlen(rest)) != NULL || memchr(rest, '#', strlen(rest)) != NULL ||
	    memchr(rest, '@', hl) != NULL) {
		bst_err_set(e, "proxy %s: a URL with userinfo, a query or a fragment is not allowed",
			    p->target);
		bst_cfg_err_at(e, bst_cfg_src(c, &p->loc));
		return NULL;
	}
	const char *host;
	uint16_t port;
	if (!split_hostport(c, (bst_str){ rest, (uint32_t)hl }, https ? 443 : 80, &host, &port, e)) {
		bst_cfg_err_at(e, bst_cfg_src(c, &p->loc));
		return NULL;
	}
	size_t pl = slash ? strlen(slash) : 0;
	while (pl > 0 && slash[pl - 1] == '/')
		pl--;
	p->url_path = slash ? bst_cfg_strdup(c, slash, pl, e) : "";
	p->up_host = bst_cfg_strdup(c, rest, hl, e);
	if (p->url_path == NULL || p->up_host == NULL)
		return NULL;
	bst_cfg_global *g = &cfg->global;
	for (size_t i = 0; i < g->nupstreams; i++) {
		bst_cfg_upstream *u = g->upstreams[i];
		if (u->implicit && u->tls == https && u->servers[0].port == port &&
		    strcmp(u->servers[0].host, host) == 0)
			return u;
	}
	bst_cfg_upstream *u = bst_arena_alloc(c->arena, sizeof *u);
	if (u == NULL) {
		oom(e);
		return NULL;
	}
	memset(u, 0, sizeof *u);
	bst_upstream_defaults(u);
	u->implicit = true;
	u->tls = https;
	u->tlsc.loc = p->loc;
	u->name = p->up_host;
	u->loc = p->loc;
	u->index = g->nupstreams;
	bst_up_server s = { .host = host, .port = port, .weight = 1, .loc = p->loc };
	if (bst_cfg_push_owned(c, &u->servers, &u->nservers, &u->servers_cap_, sizeof s, &s, e) != 0 ||
	    bst_cfg_push_owned(c, &g->upstreams, &g->nupstreams, &g->upstreams_cap_, sizeof u, &u,
			       e) != 0)
		return NULL;
	return u;
}

static int resolve_proxy(bst_config *cfg, bst_cfg_ctx *c, bst_cfg_common *cm, bst_err *e)
{
	bst_cfg_proxy *p = &cm->proxy;
	if (!p->set || p->up != NULL)
		return 0;
	if (strncmp(p->target, "http://", 7) == 0 || strncmp(p->target, "https://", 8) == 0) {
		p->up = implicit_upstream(cfg, c, p, e);
		return p->up == NULL ? -1 : 0;
	}
	if (strchr(p->target, ':') != NULL || strchr(p->target, '/') != NULL) {
		bst_err_set(e, "proxy %s: a URL starts with http://; anything else names an upstream",
			    p->target);
		bst_cfg_err_at(e, bst_cfg_src(c, &p->loc));
		return -1;
	}
	p->up = bst_upstream_find(&cfg->global, p->target, strlen(p->target));
	if (p->up == NULL) {
		bst_err_set(e, "proxy %s: no upstream with that name", p->target);
		bst_cfg_err_at(e, bst_cfg_src(c, &p->loc));
		return -1;
	}
	p->url_path = "";
	p->up_host = p->up->name;
	return 0;
}

static int resolve_locations(bst_config *cfg, bst_cfg_ctx *c, bst_cfg_location **ls, size_t n,
			     bst_err *e)
{
	for (size_t i = 0; i < n; i++) {
		if (resolve_proxy(cfg, c, &ls[i]->common, e) != 0 ||
		    resolve_locations(cfg, c, ls[i]->children, ls[i]->nchildren, e) != 0)
			return -1;
	}
	return 0;
}

/* Runs before post_upstream_peers (hooks run in name order): implicit upstreams need peers too. */
static int post_proxy_refs(bst_config *cfg, bst_cfg_ctx *c, bst_err *e)
{
	for (size_t i = 0; i < cfg->global.nservers; i++) {
		bst_cfg_server *s = cfg->global.servers[i];
		if (resolve_proxy(cfg, c, &s->common, e) != 0 ||
		    resolve_locations(cfg, c, s->locations, s->nlocations, e) != 0)
			return -1;
	}
	return 0;
}
BST_CFG_POST(post_proxy_refs);

/* ---- PROXY protocol (Task 9) ---- */

static int ap_pp_from(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	return cidr_list(c, d, n, &c->common->proxy.pp_from, e);
}

AP_PMS(ap_pp_timeout, pp_timeout_ms)

static int post_proxy_protocol(bst_config *cfg, bst_cfg_ctx *c, bst_err *e)
{
	for (size_t i = 0; i < cfg->global.nservers; i++) {
		const bst_cfg_server *s = cfg->global.servers[i];
		for (size_t j = 0; j < s->nlistens; j++)
			if (s->listens[j].proxy_protocol && s->common.proxy.pp_from.n == 0) {
				bst_err_set(e, "listen: `proxy_protocol` needs `proxy_protocol_from` (the "
					       "balancers allowed to name the client) in this server or "
					       "globally");
				bst_cfg_err_at(e, bst_cfg_src(c, &s->listens[j].loc));
				return -1;
			}
	}
	for (size_t i = 0; i < cfg->global.nupstreams; i++) {
		const bst_cfg_upstream *u = cfg->global.upstreams[i];
		if (u->send_pp != 0 && u->h2) {
			bst_err_set(e, "send_proxy_protocol: not with `protocol http2` (an HTTP/2 "
				       "connection carries many clients; a PROXY header names one)");
			bst_cfg_err_at(e, bst_cfg_src(c, &u->send_pp_loc));
			return -1;
		}
	}
	return 0;
}
BST_CFG_POST(post_proxy_protocol);

/* ---- buffering (Task 10) ---- */

static int ap_req_buffering(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	bool v = false;
	(void)bst_parse_bool(as_str(bst_dir_pos(d, n, 0)), &v);
	c->common->proxy.req_buffering = v;
	c->global->spool_used |= v;
	return 0;
}

static int ap_resp_buffering(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	bool v = false;
	(void)bst_parse_bool(as_str(bst_dir_pos(d, n, 0)), &v);
	c->common->proxy.resp_buffering = v;
	c->global->spool_used |= v;
	return 0;
}

static int ap_retry_buffered(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	bool v = false;
	(void)bst_parse_bool(as_str(bst_dir_pos(d, n, 0)), &v);
	c->common->proxy.retry_buffered = v;
	return 0;
}

static int ap_spool_mem(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	uint64_t v;
	if (bst_parse_size(as_str(bst_dir_pos(d, n, 0)), &v))
		c->common->proxy.spool_mem = v;
	return 0;
}

static int ap_temp_path(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	if (a->text[0] != '/') {
		bst_err_set(e, "temp_path: needs an absolute path");
		return bad_at(c, a, e);
	}
	c->global->temp_path = bst_cfg_strdup(c, a->text, a->len, e);
	return c->global->temp_path == NULL ? -1 : 0;
}

static int post_spool(bst_config *cfg, bst_cfg_ctx *c, bst_err *e)
{
	(void)c;
	(void)e;
	cfg->global.temp_fd = -1; /* opened by bst_roots_open */
	return 0;
}
BST_CFG_POST(post_spool);

static const char *const uri_modes[] = { "pass", "strip_prefix", NULL };
static const char *const fwd_modes[] = { "xff", "forwarded", "off", NULL };

#define SL (BST_CTX_SERVER | BST_CTX_LOCATION)
#define GSL (BST_CTX_GLOBAL | BST_CTX_SERVER | BST_CTX_LOCATION)

static const bst_directive proxy_dirs[] = {
	{ .name = "proxy", .contexts = SL, .apply = ap_proxy,
	  .doc = "Answers requests by forwarding them: `proxy http://host:port[/path]` to one server, "
		 "or `proxy name` to an `upstream` block. Every protocol a client speaks (HTTP/1.1, "
		 "HTTP/2, HTTP/3) reaches the upstream as HTTP/1.1 (HTTP/2 for an upstream with "
		 "`protocol http2`), with the request head written "
		 "anew from the parsed request: nothing of the client's bytes passes unparsed. "
		 "Bodies stream both ways; a response cut off after it started aborts the client's "
		 "stream, never ending it cleanly.",
	  UP1({ .kind = BST_T_STRING }) },
	{ .name = "proxy_uri", .contexts = GSL, .apply = ap_proxy_uri, .default_value = "pass",
	  .doc = "`pass` sends the request's path and query exactly as the client sent them (after "
		 "the URL's own path, when `proxy` has one; a `rewrite` sends the rewritten path). "
		 "`strip_prefix` removes the location's prefix first: `location /api/` sends /api/x "
		 "as /x.",
	  UP1({ .kind = BST_T_ENUM, .enum_values = uri_modes }) },
	{ .name = "proxy_host", .contexts = GSL, .apply = ap_proxy_host, .default_value = "$host",
	  .doc = "The Host the upstream sees: `$host` (the client's), `upstream` (the URL's host:port "
		 "or the upstream's name) or a fixed value.",
	  UP1({ .kind = BST_T_TEMPLATE }) },
	{ .name = "forwarded_headers", .contexts = GSL, .apply = ap_forwarded, .default_value = "xff",
	  .doc = "How the client is described to the upstream: `xff` sets X-Forwarded-For, "
		 "X-Forwarded-Proto and X-Forwarded-Host; `forwarded` sets RFC 7239 Forwarded; `off` "
		 "sends neither. Whatever a client sends in these fields is replaced, unless the "
		 "connection comes from `trusted_proxies`: then its values are kept and this hop is "
		 "appended. Connection cannot remove them.",
	  UP1({ .kind = BST_T_ENUM, .enum_values = fwd_modes }) },
	{ .name = "trusted_proxies", .contexts = GSL, .apply = ap_trusted,
	  .doc = "Address ranges of front proxies whose X-Forwarded-* or Forwarded values are kept "
		 "and appended to. Everyone else's are replaced.",
	  .args = { .min_args = 1, .max_args = BST_ARGS_ANY, .pos = { { .kind = BST_T_CIDR } } } },
	{ .name = "real_ip_header", .contexts = GSL, .apply = ap_real_ip_header,
	  .doc = "A header (X-Forwarded-For, X-Real-IP, ...) that names the client, believed only from "
		 "connections in `real_ip_from`: $remote_addr becomes the rightmost address in it that "
		 "is not itself in real_ip_from.",
	  UP1({ .kind = BST_T_STRING }) },
	{ .name = "real_ip_from", .contexts = GSL, .apply = ap_real_ip_from,
	  .doc = "Address ranges allowed to set the client address through `real_ip_header`.",
	  .args = { .min_args = 1, .max_args = BST_ARGS_ANY, .pos = { { .kind = BST_T_CIDR } } } },
	{ .name = "proxy_pass_header", .contexts = GSL, .apply = ap_pass_header, .repeatable = true,
	  .doc = "Passes response fields that are hidden by default (X-Accel-*). Adds to the parent's "
		 "list. Date and Server always come from bastion itself.",
	  .args = { .min_args = 1, .max_args = BST_ARGS_ANY, .pos = { { .kind = BST_T_STRING } } } },
	{ .name = "proxy_hide_header", .contexts = GSL, .apply = ap_hide_header, .repeatable = true,
	  .doc = "Response fields from the upstream that are not passed to the client. Adds to the "
		 "parent's list.",
	  .args = { .min_args = 1, .max_args = BST_ARGS_ANY, .pos = { { .kind = BST_T_STRING } } } },
	{ .name = "intercept_errors", .contexts = GSL, .apply = ap_intercept, .default_value = "off",
	  .doc = "on: an upstream response of 400 or above is replaced by bastion's own error page "
		 "(or the `error_page` for it), and its body is not read.",
	  UP1({ .kind = BST_T_BOOL }) },
	{ .name = "max_upstream_header_size", .contexts = GSL, .apply = ap_max_header,
	  .default_value = "16k",
	  .doc = "Largest response head an upstream may send; a longer one is a 502.",
	  UP1({ .kind = BST_T_SIZE, .min = 1024, .max = 1048576 }) },
	{ .name = "websocket", .contexts = GSL, .apply = ap_websocket, .default_value = "on",
	  .doc = "Where `proxy` is set: an HTTP/1.1 WebSocket upgrade (GET with Upgrade: websocket, "
		 "a valid Sec-WebSocket-Key and version 13) is passed on, and when the upstream "
		 "answers 101 the connection becomes a tunnel of opaque bytes both ways. An upstream "
		 "that answers anything else gets its response relayed as a normal one, never a "
		 "tunnel. An HTTP/2 client's extended CONNECT (RFC 8441, with "
		 "`http2_connect_protocol on`) reaches the upstream as that same HTTP/1.1 upgrade, "
		 "with a key the proxy makes and whose Sec-WebSocket-Accept it checks; the client "
		 "gets 200 and the stream carries the tunnel. Not for an `http2` upstream. `off` "
		 "sends upgrades as plain requests and refuses extended CONNECT with 501.",
	  UP1({ .kind = BST_T_BOOL }) },
	{ .name = "tunnel_idle_timeout", .contexts = GSL, .apply = ap_tunnel_idle,
	  .default_value = "1h",
	  .doc = "A tunnel with no byte in either direction for this long is closed.",
	  UP1(DUR(1 * MS, 86400LL * SEC)) },
	{ .name = "tunnel_max_duration", .contexts = GSL, .apply = ap_tunnel_max,
	  .default_value = "24h",
	  .doc = "A tunnel is closed after this long, however busy.",
	  UP1(DUR(1 * MS, 30LL * 86400 * SEC)) },
	{ .name = "tunnel_drain_timeout", .contexts = GSL, .apply = ap_tunnel_drain,
	  .default_value = "30s",
	  .doc = "After one side of a tunnel ended its direction (half-close), the other side has "
		 "this long to finish before the tunnel is closed.",
	  UP1(DUR(1 * MS, 3600LL * SEC)) },
	{ .name = "max_tunnels", .contexts = GSL, .apply = ap_max_tunnels, .default_value = "0",
	  .doc = "Tunnels each worker holds open at once; past it an upgrade gets 503. 0: no limit.",
	  UP1({ .kind = BST_T_INT, .min = 0, .max = 16777216 }) },
	{ .name = "proxy_buffer_size", .contexts = GSL, .apply = ap_buffer_size, .default_value = "64k",
	  .doc = "Request body bytes read from the client ahead of the upstream: the client is given "
		 "this much credit each time the previous round reached the upstream.",
	  UP1({ .kind = BST_T_SIZE, .min = 4096, .max = 16777216 }) },
	{ .name = "request_buffering", .contexts = GSL, .apply = ap_req_buffering,
	  .default_value = "off",
	  .doc = "on: the whole request body is read (in memory up to spool_memory_limit, then in an "
		 "unnamed file in temp_path) before the upstream sees a byte, and is sent with a "
		 "Content-Length. off (the default): the body streams through as it arrives. Applies "
		 "to `http1` upstreams. A full disk answers 507.",
	  UP1({ .kind = BST_T_BOOL }) },
	{ .name = "response_buffering", .contexts = GSL, .apply = ap_resp_buffering,
	  .default_value = "off",
	  .doc = "on: the upstream's response body is read as fast as the upstream sends it, kept in "
		 "memory up to spool_memory_limit and then in an unnamed file in temp_path, and "
		 "given to the client at the client's pace, so a slow client does not hold the "
		 "upstream connection. off (the default): the upstream is read only as fast as the "
		 "client takes it.",
	  UP1({ .kind = BST_T_BOOL }) },
	{ .name = "retry_buffered_body", .contexts = GSL, .apply = ap_retry_buffered,
	  .default_value = "off",
	  .doc = "on: a request whose body was buffered (request_buffering on) may be sent again to "
		 "another server by `retry` after a failure, even when it is not idempotent. off (the "
		 "default): once request bytes reached an upstream, a request with a body is never "
		 "replayed.",
	  UP1({ .kind = BST_T_BOOL }) },
	{ .name = "spool_memory_limit", .contexts = GSL, .apply = ap_spool_mem,
	  .default_value = "1m",
	  .doc = "Bytes of a buffered request or response body kept in memory; the rest goes to an "
		 "unnamed (O_TMPFILE) file in temp_path, which disappears with its last descriptor.",
	  UP1({ .kind = BST_T_SIZE, .min = 0, .max = 1073741824 }) },
	{ .name = "temp_path", .contexts = BST_CTX_GLOBAL, .apply = ap_temp_path,
	  .default_value = "/tmp",
	  .doc = "Directory for spooled bodies (request_buffering, response_buffering). Opened at "
		 "start and granted write access by the sandbox only when some scope turns buffering "
		 "on. Files are unnamed (O_TMPFILE): nothing is left behind, even after a crash.",
	  UP1({ .kind = BST_T_PATH }) },
	{ .name = "proxy_protocol_from", .contexts = BST_CTX_GLOBAL | BST_CTX_SERVER,
	  .apply = ap_pp_from,
	  .doc = "Address ranges of the balancers allowed to send a PROXY protocol header to a "
		 "`listen ... proxy_protocol` address (required there; read on the address's default "
		 "server). A connection from anywhere else is closed without a byte read.",
	  .args = { .min_args = 1, .max_args = BST_ARGS_ANY, .pos = { { .kind = BST_T_CIDR } } } },
	{ .name = "proxy_protocol_timeout", .contexts = BST_CTX_GLOBAL | BST_CTX_SERVER,
	  .apply = ap_pp_timeout, .default_value = "5s",
	  .doc = "How long a `proxy_protocol` connection may take to send its whole header; a "
		 "missing, malformed or late header closes the connection.",
	  UP1(DUR(1 * MS, 3600LL * SEC)) },
};
BST_DIRECTIVES(proxy_dirs);
