/* The reverse proxy's directives: `upstream` blocks with their `server` lines and pool settings,
 * and the `resolver` the helper uses for `resolve` servers. Peers are built by a post hook, once
 * every block is known (proxy/upstream.h says how a server becomes peers). */
#include "config/compile.h"
#include "config/values.h"
#include "core/str.h"
#include "proxy/upstream.h"

#include <netdb.h>
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
		if (build_peers(c, u, &state, e) != 0)
			return -1;
	}
	return 0;
}
BST_CFG_POST(post_upstream_peers);

/* ---- the tables ---- */

static const char *const server_flags[] = { "backup", "resolve", NULL };
static const bst_optspec server_opts[] = {
	{ .key = "weight=", .type = { .kind = BST_T_INT, .min = 1, .max = 1000 } },
	{ .key = "max_conns=", .type = { .kind = BST_T_INT, .min = 1, .max = 1048576 } },
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
		 "with `weight=` (1 to 1000, default 1), `max_conns=` (per worker), `backup` (used "
		 "only when no other server can take the request) and `resolve`. A host name without "
		 "`resolve` is looked up once when the configuration loads and must resolve; with "
		 "`resolve` the helper looks it up through `resolver` and keeps the addresses fresh "
		 "within their TTL, with no reload, and the server starts even while DNS fails (its "
		 "requests are answered 502 until it resolves).",
	  .args = { .min_args = 1, .max_args = 3,
		    .pos = { { .kind = BST_T_STRING },
			     { .kind = BST_T_ENUM, .enum_values = server_flags } },
		    .opts = server_opts, .nopts = sizeof server_opts / sizeof server_opts[0] } },
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
