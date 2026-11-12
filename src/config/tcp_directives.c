/* tcp_profile blocks (architecture section 4): named, repeatable, global-only sets of TCP
 * socket options. A listener picks one with `listen ... tcp_profile=name`, resolved by
 * post_tcp_resolve once every block is known. io/listener.c and io/sockopts.c apply the
 * result; this file only parses, validates and records.
 *
 * Every directive takes a trailing `require`: a kernel that refuses the option then fails
 * startup instead of logging a warning (no silent no-ops). */
#include "config/compile.h"
#include "config/errfmt.h"
#include "config/schema_priv.h"
#include "config/values.h"
#include "core/str.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bst_str as_str(const bst_ast_arg *a)
{
	return (bst_str){ a->text, (uint32_t)a->len };
}

static int fail_at(bst_err *e, const bst_ast_arg *a, const char *msg)
{
	bst_err_set(e, "%s", msg);
	bst_cfg_err_at(e, &a->loc);
	return -1;
}

/* Records that the profile asks for option o (and whether with `require`). */
static void want(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_tcp_opt o)
{
	c->tcp->set |= 1u << o;
	if (bst_dir_has_require(d, n))
		c->tcp->require |= 1u << o;
}

/* The argument as a number: the schema already checked the range, so this cannot fail. */
static uint64_t num(const bst_ast_arg *a)
{
	uint64_t v = 0;
	(void)bst_str_to_u64(as_str(a), &v);
	return v;
}

static uint64_t dur_us(const bst_ast_arg *a)
{
	uint64_t v = 0;
	(void)bst_parse_duration_us(as_str(a), &v);
	return v;
}

static uint64_t size_b(const bst_ast_arg *a)
{
	uint64_t v = 0;
	(void)bst_parse_size(as_str(a), &v);
	return v;
}

static bool flag(const bst_ast_arg *a)
{
	bool v = false;
	(void)bst_parse_bool(as_str(a), &v);
	return v;
}

/* ---- The block ---- */

static int ap_tcp_profile(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			  bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	bst_tcp_profile *p = bst_arena_alloc(c->arena, sizeof *p);
	bst_cfg_loc loc;
	if (p == NULL) {
		bst_err_set(e, "out of memory");
		return -1;
	}
	memset(p, 0, sizeof *p); /* the block's own defaults (nodelay, backlog) apply as directives */
	p->name = bst_cfg_strdup(c, a->text, a->len, e);
	if (p->name == NULL || bst_cfg_loc_at(c, &a->loc, &loc, e) != 0)
		return -1;
	bst_cfg_global *g = c->global;
	/* Duplicate names are found once, sorted, by post_tcp_resolve. */
	if (bst_cfg_push_owned(c, &g->tcp_profiles, &g->ntcp_profiles, &g->tcp_profiles_cap_,
			       sizeof p, &p, e) != 0)
		return -1;
	size_t ni = g->ntcp_profiles - 1; /* the locs array stays in step */
	if (bst_cfg_push_owned(c, &g->tcp_profile_locs, &ni, &g->tcp_profile_locs_cap_, sizeof loc,
			       &loc, e) != 0)
		return -1;
	c->tcp = p;
	return 0;
}

/* ---- Options ---- */

static int ap_fastopen(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	c->tcp->fastopen = (int)num(bst_dir_pos(d, n, 0));
	want(c, d, n, BST_TCP_FASTOPEN);
	return 0;
}

static int ap_fastopen_key(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			   bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	/* The key's text is a secret: it is never echoed in the message. */
	if (!bst_tcp_parse_key(a->text, a->len, c->tcp->fastopen_key))
		return fail_at(e, a, "fastopen_key must be 32 hex digits (16 bytes), or four groups of "
				     "8 hex digits separated by '-'");
	want(c, d, n, BST_TCP_FASTOPEN_KEY);
	return 0;
}

static int ap_defer_accept(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			   bst_err *e)
{
	(void)e;
	uint64_t us = dur_us(bst_dir_pos(d, n, 0));
	c->tcp->defer_accept_s = (unsigned)((us + 999999) / 1000000); /* whole seconds, up */
	want(c, d, n, BST_TCP_DEFER_ACCEPT);
	return 0;
}

static int ap_busy_poll(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	c->tcp->busy_poll_us = (unsigned)dur_us(bst_dir_pos(d, n, 0));
	want(c, d, n, BST_TCP_BUSY_POLL);
	return 0;
}

static int ap_prefer_busy_poll(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			       bst_err *e)
{
	(void)e;
	c->tcp->prefer_busy_poll = flag(bst_dir_pos(d, n, 0));
	want(c, d, n, BST_TCP_PREFER_BUSY_POLL);
	return 0;
}

static int ap_busy_poll_budget(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			       bst_err *e)
{
	(void)e;
	c->tcp->busy_poll_budget = (unsigned)num(bst_dir_pos(d, n, 0));
	want(c, d, n, BST_TCP_BUSY_POLL_BUDGET);
	return 0;
}

static int ap_nodelay(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	c->tcp->nodelay = flag(bst_dir_pos(d, n, 0));
	want(c, d, n, BST_TCP_NODELAY);
	return 0;
}

static int ap_quickack(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	c->tcp->quickack = flag(bst_dir_pos(d, n, 0));
	want(c, d, n, BST_TCP_QUICKACK);
	return 0;
}

/* The kernel's names are lower-case words, digits, '-' and '_' (bbr, cubic, reno, dctcp). */
static int ap_congestion(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			 bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	if (a->len >= BST_TCP_CA_NAME_MAX)
		return fail_at(e, a, "congestion: the name is too long (at most 15 characters)");
	for (size_t i = 0; i < a->len; i++) {
		char ch = a->text[i];
		if (!((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_'))
			return fail_at(e, a, "congestion: a name is lower-case letters, digits, '-' "
					     "and '_' (bbr, cubic, reno)");
	}
	memcpy(c->tcp->congestion, a->text, a->len);
	c->tcp->congestion[a->len] = 0;
	want(c, d, n, BST_TCP_CONGESTION);
	return 0;
}

static int ap_notsent_lowat(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			    bst_err *e)
{
	(void)e;
	c->tcp->notsent_lowat = (uint32_t)size_b(bst_dir_pos(d, n, 0));
	want(c, d, n, BST_TCP_NOTSENT_LOWAT);
	return 0;
}

static int ap_user_timeout(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			   bst_err *e)
{
	(void)e;
	c->tcp->user_timeout_ms = (unsigned)(dur_us(bst_dir_pos(d, n, 0)) / 1000);
	want(c, d, n, BST_TCP_USER_TIMEOUT);
	return 0;
}

static int ap_keepalive(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			bst_err *e)
{
	bst_ast_arg v;
	(void)e;
	if (bst_dir_opt(d, n, "idle=", &v))
		c->tcp->ka_idle_s = (unsigned)(dur_us(&v) / 1000000);
	if (bst_dir_opt(d, n, "interval=", &v))
		c->tcp->ka_interval_s = (unsigned)(dur_us(&v) / 1000000);
	if (bst_dir_opt(d, n, "count=", &v))
		c->tcp->ka_count = (unsigned)num(&v);
	want(c, d, n, BST_TCP_KEEPALIVE);
	return 0;
}

static int ap_rcvbuf(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	c->tcp->rcvbuf = (uint32_t)size_b(bst_dir_pos(d, n, 0));
	want(c, d, n, BST_TCP_RCVBUF);
	return 0;
}

static int ap_sndbuf(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	c->tcp->sndbuf = (uint32_t)size_b(bst_dir_pos(d, n, 0));
	want(c, d, n, BST_TCP_SNDBUF);
	return 0;
}

static int ap_pacing_rate(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			  bst_err *e)
{
	(void)e;
	c->tcp->pacing_rate = (uint32_t)size_b(bst_dir_pos(d, n, 0));
	want(c, d, n, BST_TCP_PACING_RATE);
	return 0;
}

static int ap_mark(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	c->tcp->mark = (uint32_t)num(bst_dir_pos(d, n, 0));
	want(c, d, n, BST_TCP_MARK);
	return 0;
}

static int ap_freebind(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	c->tcp->freebind = flag(bst_dir_pos(d, n, 0));
	want(c, d, n, BST_TCP_FREEBIND);
	return 0;
}

static int ap_backlog(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	c->tcp->backlog = (int)num(bst_dir_pos(d, n, 0));
	want(c, d, n, BST_TCP_BACKLOG);
	return 0;
}

static const char *const steer_values[] = { "none", "incoming_cpu", "ebpf", NULL };

static int ap_steering(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	size_t idx = 0;
	(void)bst_parse_enum(as_str(a), steer_values, &idx);
	/* No phase owns a steering BPF program yet, and a listener that quietly ignored the
	 * request would be a silent no-op: refuse it until one does. */
	if (idx == 2)
		return fail_at(e, a, "steering ebpf is not supported yet: use incoming_cpu or none");
	c->tcp->steering = idx == 1 ? BST_STEER_INCOMING_CPU : BST_STEER_NONE;
	want(c, d, n, BST_TCP_STEERING);
	return 0;
}

/* ---- Table ---- */

#define POS1(...) .args = { .min_args = 1, .max_args = 1, .pos = { __VA_ARGS__ } }
#define DIR(nm, fn, text, ...)                                                          \
	{ .name = nm, .contexts = BST_CTX_TCP_PROFILE, .apply = fn, .require = true,    \
	  .doc = text, __VA_ARGS__ }
#define SEC 1000000LL

static const bst_optspec keepalive_opts[] = {
	{ .key = "idle=", .required = true,
	  .type = { .kind = BST_T_DURATION, .min = 1 * SEC, .max = 32767 * SEC } },
	{ .key = "interval=", .required = true,
	  .type = { .kind = BST_T_DURATION, .min = 1 * SEC, .max = 32767 * SEC } },
	{ .key = "count=", .required = true, .type = { .kind = BST_T_INT, .min = 1, .max = 127 } },
};

static const bst_directive tcp_dirs[] = {
	{ .name = "tcp_profile", .contexts = BST_CTX_GLOBAL, .apply = ap_tcp_profile,
	  .repeatable = true, .child_ctx = BST_CTX_TCP_PROFILE,
	  .doc = "A named set of TCP socket options for listeners (`listen ... tcp_profile=name`). "
		 "Names are unique. A listener without one gets the default profile: nodelay on and "
		 "backlog 4096. An option the running kernel refuses logs a warning and the server "
		 "starts; add `require` to an option to make that a startup error.",
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_STRING } },
		    .block = BST_BLOCK_REQUIRED } },
	DIR("fastopen", ap_fastopen,
	    "TCP Fast Open on the listener: the queue length of connections that arrive with data "
	    "in the SYN. The data can be replayed by the network (a duplicated SYN delivers it "
	    "twice), so it is as dangerous as TLS 0-RTT early data and obeys the same policy: "
	    "only a safe method (GET, HEAD, OPTIONS) runs from it, anything else is answered "
	    "425 Too Early and `$ssl_early_data` is 1 for the request. Needs the server bit of net.ipv4.tcp_fastopen "
	    "(value 2 or 3); without it the kernel ignores Fast Open and bastion warns.",
	    POS1({ .kind = BST_T_INT, .min = 1, .max = 1048576 })),
	DIR("fastopen_key", ap_fastopen_key,
	    "The TCP Fast Open cookie key: 32 hex digits, or four groups of 8 separated by '-'. "
	    "Share one key across machines behind one address so a client's cookie works on all. "
	    "This is a secret: `bastion -T` prints it like any other directive, so keep the "
	    "config's permissions tight and review `-T` output before sharing it. Without it the "
	    "kernel picks a random key.",
	    POS1({ .kind = BST_T_STRING })),
	DIR("defer_accept", ap_defer_accept,
	    "TCP_DEFER_ACCEPT: the kernel completes the handshake but hands the connection to the "
	    "server only when data arrives, or when this time (rounded up to the kernel's "
	    "retransmit schedule) has passed. This delays connections that send nothing, such as "
	    "a client waiting for a server greeting, a health check that only connects, or "
	    "a port scan, and it hides them from the accept queue; it also saves a wakeup per "
	    "request.",
	    POS1({ .kind = BST_T_DURATION, .min = 1 * SEC, .max = 3600 * SEC })),
	DIR("busy_poll", ap_busy_poll,
	    "SO_BUSY_POLL: poll the network device for this long before sleeping on a socket. "
	    "Lower latency, paid for with CPU. Raising it above the net.core.busy_poll sysctl "
	    "needs CAP_NET_ADMIN, which master has before it drops privileges.",
	    POS1({ .kind = BST_T_DURATION, .min = 1, .max = 1 * SEC })),
	DIR("prefer_busy_poll", ap_prefer_busy_poll,
	    "SO_PREFER_BUSY_POLL (Linux 5.11): let busy polling defer the device's own interrupt "
	    "handling while the application polls. Only useful with busy_poll.",
	    POS1({ .kind = BST_T_BOOL })),
	DIR("busy_poll_budget", ap_busy_poll_budget,
	    "SO_BUSY_POLL_BUDGET (Linux 5.11): packets processed per busy poll. Values above the "
	    "kernel's default need CAP_NET_ADMIN.",
	    POS1({ .kind = BST_T_INT, .min = 1, .max = 65535 })),
	DIR("nodelay", ap_nodelay,
	    "TCP_NODELAY on accepted connections: send small writes at once instead of waiting "
	    "to coalesce them. On by default; HTTP responses are written whole, so Nagle only "
	    "adds latency.",
	    .default_value = "on", POS1({ .kind = BST_T_BOOL })),
	DIR("quickack", ap_quickack,
	    "TCP_QUICKACK on each accepted connection (set per connection: the kernel does not "
	    "keep it). `off` delays acknowledgements so they ride on data, saving packets; `on` "
	    "is how a new connection starts anyway.",
	    POS1({ .kind = BST_T_BOOL })),
	DIR("congestion", ap_congestion,
	    "TCP congestion control algorithm by kernel name (bbr, cubic, reno, ...). It must be "
	    "listed in net.ipv4.tcp_available_congestion_control; the kernel refuses a missing "
	    "one (bbr needs the tcp_bbr module), and bastion warns, or fails with `require`.",
	    POS1({ .kind = BST_T_STRING })),
	DIR("notsent_lowat", ap_notsent_lowat,
	    "TCP_NOTSENT_LOWAT: do not report the socket writable while this many bytes are "
	    "queued unsent. Bounds the memory a slow client pins and keeps responses fresh "
	    "for HTTP/2 prioritisation.",
	    POS1({ .kind = BST_T_SIZE, .min = 1, .max = 2147483647 })),
	DIR("user_timeout", ap_user_timeout,
	    "TCP_USER_TIMEOUT: drop a connection when sent data stays unacknowledged this long "
	    "(rounded down to milliseconds). Without it the kernel waits out its retransmit "
	    "schedule, about 15 minutes.",
	    POS1({ .kind = BST_T_DURATION, .min = 1000, .max = 86400 * SEC })),
	DIR("keepalive", ap_keepalive,
	    "TCP keepalive probes on accepted connections: first probe after idle, then one every "
	    "interval, and the connection is dropped after count unanswered probes. All three are "
	    "needed. Detects peers that vanished without closing.",
	    .args = { .min_args = 0, .max_args = 0, .opts = keepalive_opts,
		      .nopts = sizeof keepalive_opts / sizeof keepalive_opts[0] }),
	DIR("rcvbuf", ap_rcvbuf,
	    "SO_RCVBUF: receive buffer size, set before the handshake so it shapes the window "
	    "the connection starts with. Disables receive autotuning for the connection. The "
	    "kernel caps it at net.core.rmem_max; bastion warns when that happens.",
	    POS1({ .kind = BST_T_SIZE, .min = 4096, .max = 1073741824 })),
	DIR("sndbuf", ap_sndbuf,
	    "SO_SNDBUF: send buffer size. Disables send autotuning for the connection. The "
	    "kernel caps it at net.core.wmem_max; bastion warns when that happens.",
	    POS1({ .kind = BST_T_SIZE, .min = 4096, .max = 1073741824 })),
	DIR("pacing_rate", ap_pacing_rate,
	    "SO_MAX_PACING_RATE: the most bytes per second one connection may send (the size "
	    "suffixes mean bytes: 10m is 10 MiB per second). Enforced by the fq qdisc, or by "
	    "TCP's own pacing on Linux 4.13 and later.",
	    POS1({ .kind = BST_T_SIZE, .min = 1, .max = 4294967294LL })),
	DIR("mark", ap_mark,
	    "SO_MARK: the firewall mark on the connection's packets, for policy routing and "
	    "netfilter. Needs CAP_NET_ADMIN, which master has before it drops privileges.",
	    POS1({ .kind = BST_T_INT, .min = 1, .max = 4294967295LL })),
	DIR("freebind", ap_freebind,
	    "IP_FREEBIND: bind to an address the machine does not have yet (a floating IP "
	    "that moves to this host later).",
	    POS1({ .kind = BST_T_BOOL })),
	DIR("backlog", ap_backlog,
	    "The listen(2) backlog: connections the kernel queues before the server accepts. "
	    "The default is 4096. The kernel caps it at net.core.somaxconn without an error; "
	    "bastion warns when that happens.",
	    .default_value = "4096", POS1({ .kind = BST_T_INT, .min = 1, .max = 65535 })),
	DIR("steering", ap_steering,
	    "How connections reach a worker: none leaves it to the kernel's hash over the "
	    "worker sockets, incoming_cpu prefers the socket of the worker pinned to the CPU "
	    "that received the packet (SO_INCOMING_CPU: the slot-th socket prefers CPU "
	    "slot modulo the CPU count). ebpf is not supported yet and is a config error.",
	    POS1({ .kind = BST_T_ENUM, .enum_values = steer_values })),
};
BST_DIRECTIVES(tcp_dirs);

/* ---- Resolving profile names ---- */

typedef struct pkey {
	const char *name;
	size_t idx;
} pkey;

static int cmp_pkey(const void *x, const void *y)
{
	const pkey *a = x, *b = y;
	int c = strcmp(a->name, b->name);
	return c != 0 ? c : a->idx < b->idx ? -1 : a->idx > b->idx;
}

static int cmp_pkey_name(const void *k, const void *y)
{
	return strcmp((const char *)k, ((const pkey *)y)->name);
}

/* Duplicate profile names: sort, then adjacent equals. The error goes to the earliest second
 * occurrence in file order. */
static int check_dups(const bst_cfg_global *g, const pkey *sorted, bst_cfg_ctx *c, bst_err *e)
{
	size_t dup = SIZE_MAX;
	for (size_t i = 1; i < g->ntcp_profiles; i++)
		if (strcmp(sorted[i - 1].name, sorted[i].name) == 0 && sorted[i].idx < dup)
			dup = sorted[i].idx;
	if (dup == SIZE_MAX)
		return 0;
	char tok[BST_SCHEMA_MAX_TOKEN_SHOWN + 8];
	bst_cfg_shown(g->tcp_profiles[dup]->name, strlen(g->tcp_profiles[dup]->name), tok, sizeof tok);
	bst_err_set(e, "duplicate tcp_profile \"%s\"", tok);
	bst_cfg_err_at(e, bst_cfg_src(c, &g->tcp_profile_locs[dup]));
	return -1;
}

static int undefined(const bst_cfg_global *g, const bst_cfg_listen *l, bst_cfg_ctx *c, bst_err *e)
{
	char tok[BST_SCHEMA_MAX_TOKEN_SHOWN + 8], sug[BST_SCHEMA_MAX_TOKEN_SHOWN + 8];
	size_t nl = strlen(l->tcp_profile_name);
	bst_cfg_shown(l->tcp_profile_name, nl, tok, sizeof tok);
	const char *best = NULL;
	unsigned bd = BST_SUGGEST_MAX_DIST + 1;
	for (size_t i = 0; i < g->ntcp_profiles; i++) {
		unsigned d = bst_lev_bounded(l->tcp_profile_name, nl, g->tcp_profiles[i]->name,
					     strlen(g->tcp_profiles[i]->name), BST_SUGGEST_MAX_DIST);
		if (d < bd) {
			bd = d;
			best = g->tcp_profiles[i]->name;
		}
	}
	if (best != NULL) {
		bst_cfg_shown(best, strlen(best), sug, sizeof sug);
		bst_err_set(e, "undefined tcp_profile \"%s\", did you mean \"%s\"?", tok, sug);
	} else {
		bst_err_set(e, "undefined tcp_profile \"%s\" (define it with `tcp_profile %s { ... }`)",
			    tok, tok);
	}
	bst_cfg_err_at(e, bst_cfg_src(c, &l->tcp_loc));
	return -1;
}

typedef struct lkey {
	bst_cfg_listen *l;
	size_t idx;
} lkey;

static int cmp_lkey(const void *x, const void *y)
{
	const lkey *a = x, *b = y;
	int c = (int)a->l->http3 - (int)b->l->http3;
	if (c == 0)
		c = a->l->addr.ip.family - b->l->addr.ip.family;
	if (c == 0)
		c = memcmp(a->l->addr.ip.b, b->l->addr.ip.b, sizeof a->l->addr.ip.b);
	if (c == 0)
		c = (int)a->l->addr.port - (int)b->l->addr.port;
	if (c == 0)
		c = a->idx < b->idx ? -1 : a->idx > b->idx;
	return c;
}

/* One socket has one set of options, and servers that differ only by name share the socket of
 * an address. Per address: at most one distinct profile named; a listen that names none
 * takes the named one, else the default. */
static int unify_addresses(bst_config *cfg, bst_cfg_ctx *c, bst_err *e)
{
	bst_cfg_global *g = &cfg->global;
	size_t total = 0;
	for (size_t i = 0; i < g->nservers; i++)
		total += g->servers[i]->nlistens;
	lkey *keys = malloc((total ? total : 1) * sizeof *keys);
	if (keys == NULL) {
		bst_err_set(e, "out of memory");
		return -1;
	}
	size_t k = 0;
	for (size_t i = 0; i < g->nservers; i++)
		for (size_t j = 0; j < g->servers[i]->nlistens; j++, k++)
			keys[k] = (lkey){ &g->servers[i]->listens[j], k };
	qsort(keys, k, sizeof *keys, cmp_lkey);
	int rc = 0;
	for (size_t i = 0; i < k && rc == 0;) {
		size_t end = i + 1;
		while (end < k && bst_listen_same_socket(keys[end].l, keys[i].l))
			end++;
		const bst_cfg_listen *named = NULL; /* the first listen here that names a profile */
		for (size_t m = i; m < end && rc == 0; m++) {
			bst_cfg_listen *l = keys[m].l;
			if (l->tcp_profile_name == NULL)
				continue;
			if (named == NULL) {
				named = l;
			} else if (l->tcp != named->tcp) {
				char ip[BST_ADDR_STRLEN], addr[BST_ADDR_STRLEN + 8], first[BST_CFG_SHOWN_FILE + 24];
				char f[BST_CFG_SHOWN_FILE + 8], n1[BST_SCHEMA_MAX_TOKEN_SHOWN + 8];
				char n2[BST_SCHEMA_MAX_TOKEN_SHOWN + 8];
				const bst_loc *fl = bst_cfg_src(c, &named->loc);
				bst_addr_format(&l->addr.ip, ip, sizeof ip);
				snprintf(addr, sizeof addr, l->addr.ip.family == BST_IP_V6 ? "[%s]" : "%s", ip);
				bst_cfg_shown_file(fl->file, f, sizeof f);
				snprintf(first, sizeof first, "%s:%d:%d", f, fl->line, fl->col);
				bst_cfg_shown(l->tcp->name, strlen(l->tcp->name), n1, sizeof n1);
				bst_cfg_shown(named->tcp->name, strlen(named->tcp->name), n2, sizeof n2);
				bst_err_set(e, "listen %s:%u names tcp_profile \"%s\" but the first listen on "
					       "that address (%s) names \"%s\": one socket has one set of "
					       "options", addr, (unsigned)l->addr.port, n1, first, n2);
				bst_cfg_err_at(e, bst_cfg_src(c, &l->tcp_loc));
				rc = -1;
			}
		}
		for (size_t m = i; m < end && rc == 0; m++)
			if (keys[m].l->tcp_profile_name == NULL)
				keys[m].l->tcp = named != NULL ? named->tcp : &g->tcp_default;
		i = end;
	}
	free(keys);
	return rc;
}

static int post_tcp_resolve(bst_config *cfg, bst_cfg_ctx *c, bst_err *e)
{
	bst_cfg_global *g = &cfg->global;
	bst_tcp_profile_defaults(&g->tcp_default, "default");
	pkey *sorted = malloc((g->ntcp_profiles ? g->ntcp_profiles : 1) * sizeof *sorted);
	if (sorted == NULL) {
		bst_err_set(e, "out of memory");
		return -1;
	}
	for (size_t i = 0; i < g->ntcp_profiles; i++)
		sorted[i] = (pkey){ g->tcp_profiles[i]->name, i };
	qsort(sorted, g->ntcp_profiles, sizeof *sorted, cmp_pkey);
	int rc = check_dups(g, sorted, c, e);
	for (size_t i = 0; i < g->nservers && rc == 0; i++) {
		bst_cfg_server *s = g->servers[i];
		for (size_t j = 0; j < s->nlistens && rc == 0; j++) {
			bst_cfg_listen *l = &s->listens[j];
			if (l->tcp_profile_name == NULL)
				continue;
			const pkey *hit = bsearch(l->tcp_profile_name, sorted, g->ntcp_profiles,
						  sizeof *sorted, cmp_pkey_name);
			if (hit == NULL)
				rc = undefined(g, l, c, e);
			else
				l->tcp = g->tcp_profiles[hit->idx];
		}
	}
	free(sorted);
	return rc == 0 ? unify_addresses(cfg, c, e) : rc;
}
BST_CFG_POST(post_tcp_resolve);
