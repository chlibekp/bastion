/* Core directives: global (user group workers worker_rlimit_nofile shutdown_timeout pid
 * error_log server include), server (listen name location) and client_max_body_size. Phase 4
 * consumes client_max_body_size and must not register it again. Cross-block checks (no listen,
 * duplicate listener) are in bst_cfg_core_check, run after every block applied. */
#include "config/compile.h"
#include "config/errfmt.h"
#include "config/values.h"
#include "core/str.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BST_CFG_MAX_WORKERS 4096
#define BST_CFG_MAX_NOFILE 1073741816 /* the kernel ceiling of fs.nr_open */

/* ---- Argument helpers ---- */

static int fail_at(bst_err *e, const bst_ast_arg *a, const char *what, const char *tok)
{
	char t[BST_SCHEMA_MAX_TOKEN_SHOWN + 8];
	bst_cfg_shown(tok, strlen(tok), t, sizeof t);
	bst_err_set(e, "%s \"%s\"", what, t);
	bst_cfg_err_at(e, &a->loc);
	return -1;
}

static bst_str as_str(const bst_ast_arg *a)
{
	return (bst_str){ a->text, (uint32_t)a->len };
}

/* ---- Global ---- */

static int ap_user(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	c->global->user = bst_cfg_strdup(c, a->text, a->len, e);
	return c->global->user ? 0 : -1;
}

static int ap_group(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	c->global->group = bst_cfg_strdup(c, a->text, a->len, e);
	return c->global->group ? 0 : -1;
}

static int ap_shutdown_timeout(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			       bst_err *e)
{
	uint64_t us = 0;
	(void)e;
	if (bst_parse_duration_us(as_str(bst_dir_pos(d, n, 0)), &us)) /* validated */
		c->global->shutdown_timeout_ms = us / 1000;
	return 0;
}

static int ap_rlimit_nofile(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			    bst_err *e)
{
	uint64_t v;
	(void)e;
	if (bst_str_to_u64(as_str(bst_dir_pos(d, n, 0)), &v)) /* validated */
		c->global->worker_rlimit_nofile = (unsigned)v;
	return 0;
}

static int ap_workers(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	uint64_t v;
	(void)e;
	if (strcmp(a->text, "auto") == 0) {
		c->global->workers_auto = true;
		c->global->workers = 0;
	} else if (bst_str_to_u64(as_str(a), &v)) { /* validated 1..BST_CFG_MAX_WORKERS */
		c->global->workers_auto = false;
		c->global->workers = (int)v;
	}
	return 0;
}

static int ap_pid(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	c->global->pid = bst_cfg_strdup(c, a->text, a->len, e);
	return c->global->pid ? 0 : -1;
}

static int ap_error_log(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			bst_err *e)
{
	const bst_ast_arg *p = bst_dir_pos(d, n, 0), *l = bst_dir_pos(d, n, 1);
	c->global->error_log = bst_cfg_strdup(c, p->text, p->len, e);
	if (c->global->error_log == NULL)
		return -1;
	c->global->error_log_level = l ? bst_cfg_strdup(c, l->text, l->len, e) : "warn";
	return c->global->error_log_level ? 0 : -1;
}

static int ap_include(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)c, (void)d, (void)n, (void)e; /* the parser already expanded it */
	return 0;
}

static int ap_server(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)d;
	bst_cfg_server *s = bst_arena_alloc(c->arena, sizeof *s);
	if (s == NULL) {
		bst_err_set(e, "out of memory");
		return -1;
	}
	memset(s, 0, sizeof *s);
	s->common = *c->common; /* inherit: one assignment */
	if (bst_cfg_loc_of(c, n, &s->loc, e) != 0)
		return -1;
	if (bst_cfg_push_owned(c, &c->global->servers, &c->global->nservers, &c->global->servers_cap_,
			 sizeof s, &s, e) != 0)
		return -1;
	c->server = s;
	c->location = NULL;
	c->common = &s->common;
	return 0;
}

/* ---- Server ---- */

static bool all_digits(const char *s, size_t len)
{
	if (len == 0)
		return false;
	for (size_t i = 0; i < len; i++)
		if (s[i] < '0' || s[i] > '9')
			return false;
	return true;
}

static bool parse_port(const char *s, size_t len, uint16_t *out)
{
	uint64_t v;
	if (!all_digits(s, len) || (len > 1 && s[0] == '0') || !bst_str_to_u64((bst_str){ s, (uint32_t)len }, &v) ||
	    v < 1 || v > 65535)
		return false;
	*out = (uint16_t)v;
	return true;
}

/* `port`, `addr:port` or `[v6]:port`. */
static int parse_listen(const bst_ast_arg *a, bst_sockaddr *out, bst_err *e)
{
	const char *t = a->text;
	size_t len = a->len, colons = 0, alen = 0, plen;
	const char *addr = NULL, *port;
	bool v6 = false;
	for (size_t i = 0; i < len; i++)
		colons += t[i] == ':';
	if (len > 0 && t[0] == '[') {
		const char *rb = memchr(t, ']', len);
		if (rb == NULL || (size_t)(rb - t) + 1 >= len || rb[1] != ':')
			return fail_at(e, a, "listen: expected [address]:port, got", t);
		addr = t + 1;
		alen = (size_t)(rb - t) - 1;
		port = rb + 2;
		plen = len - (size_t)(rb - t) - 2;
		v6 = true;
	} else if (colons == 0) {
		if (!all_digits(t, len))
			return fail_at(e, a, "listen: expected port or addr:port, got", t);
		port = t;
		plen = len;
	} else if (colons == 1) {
		const char *cp = memchr(t, ':', len);
		addr = t;
		alen = (size_t)(cp - t);
		port = cp + 1;
		plen = len - alen - 1;
	} else {
		return fail_at(e, a, "listen: an IPv6 address needs brackets, [addr]:port, got", t);
	}
	if (!parse_port(port, plen, &out->port)) {
		char tok[BST_SCHEMA_MAX_TOKEN_SHOWN + 8];
		bst_cfg_shown(port, plen, tok, sizeof tok);
		bst_err_set(e, "listen: invalid port \"%s\" (want 1-65535)", tok);
		bst_cfg_err_at(e, &a->loc);
		return -1;
	}
	if (addr == NULL) {
		memset(&out->ip, 0, sizeof out->ip);
		out->ip.family = BST_IP_V4; /* port only: every IPv4 address */
		return 0;
	}
	if (alen > UINT32_MAX || !bst_addr_parse((bst_str){ addr, (uint32_t)alen }, &out->ip) ||
	    (out->ip.family == BST_IP_V6) != v6) {
		char tok[BST_SCHEMA_MAX_TOKEN_SHOWN + 8];
		bst_cfg_shown(addr, alen, tok, sizeof tok);
		bst_err_set(e, "listen: invalid %s address \"%s\"", v6 ? "IPv6" : "IPv4", tok);
		bst_cfg_err_at(e, &a->loc);
		return -1;
	}
	return 0;
}

static int ap_listen(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	bst_cfg_listen l;
	memset(&l, 0, sizeof l);
	if (parse_listen(bst_dir_pos(d, n, 0), &l.addr, e) != 0)
		return -1;
	/* tcp_profile=<name> is an option, not a positional, so max_args stays 1. tls, http2,
	 * http3 and redirect_https are added by later phases: the one that adds the first raises
	 * max_args in the table below, gives the second positional type BST_T_ENUM with
	 * enum_values for the flags (never .keywords: a typo like `tsl` would be accepted), and
	 * stores them on bst_cfg_listen here. */
	if (bst_cfg_loc_of(c, n, &l.loc, e) != 0)
		return -1;
	for (size_t i = 1; i < bst_dir_npos(d, n); i++) { /* flags: validated as an enum */
		const bst_ast_arg *fa = bst_dir_pos(d, n, i);
		bool *which = strcmp(fa->text, "tls") == 0 ? &l.tls : &l.default_server;
		if (*which)
			return fail_at(e, fa, "listen: flag given twice", fa->text);
		*which = true;
	}
	bst_ast_arg prof;
	if (bst_dir_opt(d, n, "tcp_profile=", &prof)) {
		l.tcp_profile_name = bst_cfg_strdup(c, prof.text, prof.len, e);
		/* resolved by post_tcp_resolve (tcp_directives.c): the profile may come later */
		/* bst_dir_opt returns a copy: the position to record is the AST argument's own. */
		const bst_loc *at = &n->loc;
		for (size_t i = 0; i < n->nargs; i++)
			if (prof.text >= n->args[i].text && prof.text <= n->args[i].text + n->args[i].len)
				at = &n->args[i].loc;
		if (l.tcp_profile_name == NULL || bst_cfg_loc_at(c, at, &l.tcp_loc, e) != 0)
			return -1;
	}
	bst_cfg_server *s = c->server;
	return bst_cfg_push_owned(c, &s->listens, &s->nlistens, &s->listens_cap_, sizeof l, &l, e);
}

/* A name is exact, `*.example.com` (leading wildcard), `example.*` (trailing wildcard) or
 * `~regex` (compiled and checked by the router's post hook). A `*` anywhere else would match
 * nothing and say nothing, so it is an error here. */
static int check_name_form(const bst_ast_arg *a, bst_err *e)
{
	const char *t = a->text;
	if (t[0] == '~')
		return a->len > 1 ? 0 : fail_at(e, a, "empty regular expression in name", t);
	size_t stars = 0;
	for (size_t i = 0; i < a->len; i++)
		stars += t[i] == '*';
	if (stars == 0)
		return 0;
	bool lead = stars == 1 && a->len > 2 && t[0] == '*' && t[1] == '.';
	bool trail = stars == 1 && a->len > 2 && t[a->len - 1] == '*' && t[a->len - 2] == '.';
	if (!lead && !trail)
		return fail_at(e, a, "a wildcard name is *.example.com or example.*, got", t);
	return 0;
}

static int ap_name(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	bst_cfg_server *s = c->server;
	for (size_t i = 0, np = bst_dir_npos(d, n); i < np; i++) {
		const bst_ast_arg *a = bst_dir_pos(d, n, i);
		if (a->len == 0) {
			bst_err_set(e, "name must not be empty");
			bst_cfg_err_at(e, &a->loc);
			return -1;
		}
		if (check_name_form(a, e) != 0)
			return -1;
		char *lc = bst_cfg_strdup(c, a->text, a->len, e);
		bst_cfg_loc at;
		if (lc == NULL || bst_cfg_loc_at(c, &a->loc, &at, e) != 0)
			return -1;
		for (size_t k = 0; k < a->len && lc[0] != '~'; k++) /* ~regex stays as written */
			lc[k] = (char)tolower((unsigned char)lc[k]);
		/* Duplicates are found once per server by bst_cfg_core_check (sorted, not a scan
		 * per name: one server can hold tens of thousands of names). */
		if (bst_cfg_push_owned(c, &s->names, &s->nnames, &s->names_cap_, sizeof lc, &lc, e) != 0)
			return -1;
		size_t nl = s->nnames - 1; /* name_locs stays in step with names */
		if (bst_cfg_push_owned(c, &s->name_locs, &nl, &s->name_locs_cap_, sizeof at, &at, e) != 0)
			return -1;
	}
	return 0;
}

static const struct { const char *text; bst_loc_mod mod; } loc_mods[] = {
	{ "=", BST_LOC_EXACT }, { "^~", BST_LOC_PREFIX_STOP }, { "~", BST_LOC_REGEX },
	{ "~*", BST_LOC_REGEX_I },
};

static bool find_mod(const bst_ast_arg *a, bst_loc_mod *mod)
{
	for (size_t i = 0; i < sizeof loc_mods / sizeof loc_mods[0]; i++)
		if (strcmp(a->text, loc_mods[i].text) == 0) {
			*mod = loc_mods[i].mod;
			return true;
		}
	return false;
}

static int ap_location(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
		       bst_err *e)
{
	size_t np = bst_dir_npos(d, n);
	const bst_ast_arg *first = bst_dir_pos(d, n, 0), *pat = first;
	bst_loc_mod mod = BST_LOC_PREFIX;
	if (np == 2) {
		if (!find_mod(first, &mod))
			return fail_at(e, first,
				       "invalid location modifier (use =, ^~, ~ or ~*)", first->text);
		pat = bst_dir_pos(d, n, 1);
	} else if (find_mod(first, &mod)) {
		return fail_at(e, first, "location modifier needs a pattern after", first->text);
	}
	if (pat->len == 0) {
		bst_err_set(e, "location pattern must not be empty");
		bst_cfg_err_at(e, &pat->loc);
		return -1;
	}
	bst_cfg_location *l = bst_arena_alloc(c->arena, sizeof *l);
	if (l == NULL) {
		bst_err_set(e, "out of memory");
		return -1;
	}
	memset(l, 0, sizeof *l);
	l->common = *c->common; /* inherit from the finished server or parent location */
	l->parent = c->location;
	l->mod = np == 2 ? mod : BST_LOC_PREFIX;
	l->pattern = bst_cfg_strdup(c, pat->text, pat->len, e);
	if (l->pattern == NULL)
		return -1;
	if (bst_cfg_loc_of(c, n, &l->loc, e) != 0)
		return -1;
	bst_cfg_server *s = c->server;
	bst_cfg_location *par = c->location;
	if (par ? bst_cfg_push_owned(c, &par->children, &par->nchildren, &par->children_cap_,
				     sizeof l, &l, e)
		: bst_cfg_push_owned(c, &s->locations, &s->nlocations, &s->locations_cap_,
				     sizeof l, &l, e))
		return -1;
	c->location = l;
	c->common = &l->common;
	return 0;
}

/* ---- Server and location ---- */

static int ap_cmbs(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	uint64_t v;
	(void)e;
	if (bst_parse_size(as_str(bst_dir_pos(d, n, 0)), &v)) /* validated */
		c->common->client_max_body_size = v;
	return 0;
}

/* ---- Table ---- */

#define POS1(...) .args = { .min_args = 1, .max_args = 1, .pos = { __VA_ARGS__ } }

static const char *const ev_level[] = { "debug", "info", "notice", "warn", "error", NULL };
static const char *const kw_auto[] = { "auto", NULL };

static const char *const listen_flags[] = { "default_server", "tls", NULL };

static const bst_optspec listen_opts[] = {
	{ .key = "tcp_profile=", .type = { .kind = BST_T_STRING } },
};

static const bst_directive core_dirs[] = {
	{ .name = "user", .contexts = BST_CTX_GLOBAL, .apply = ap_user,
	  .doc = "Workers and the helper drop to this user after binding sockets and creating their "
		 "event loops; master stays root. Without it, a server started as root runs its "
		 "workers as root, with a warning. Ignored, with a warning, when not started as "
		 "root.",
	  POS1({ .kind = BST_T_STRING }) },
	{ .name = "group", .contexts = BST_CTX_GLOBAL, .apply = ap_group,
	  .doc = "Group for workers and the helper. Default: the primary group of user.",
	  POS1({ .kind = BST_T_STRING }) },
	{ .name = "workers", .contexts = BST_CTX_GLOBAL, .apply = ap_workers,
	  .default_value = "auto",
	  .doc = "Worker process count, or auto for one per CPU this process may run on.",
	  POS1({ .kind = BST_T_INT, .min = 1, .max = BST_CFG_MAX_WORKERS, .keywords = kw_auto }) },
	{ .name = "worker_rlimit_nofile", .contexts = BST_CTX_GLOBAL, .apply = ap_rlimit_nofile,
	  .doc = "Open file limit (soft and hard) each worker sets for itself, before dropping "
		 "privileges. Default: the limit the server was started with.",
	  POS1({ .kind = BST_T_INT, .min = 1, .max = BST_CFG_MAX_NOFILE }) },
	{ .name = "shutdown_timeout", .contexts = BST_CTX_GLOBAL, .apply = ap_shutdown_timeout,
	  .default_value = "30s",
	  .doc = "How long a graceful stop (SIGQUIT) waits for connections in progress. Workers "
		 "still busy after it are killed.",
	  POS1({ .kind = BST_T_DURATION, .min = 1000, .max = (uint64_t)86400 * 1000000 }) },
	{ .name = "pid", .contexts = BST_CTX_GLOBAL, .apply = ap_pid,
	  .doc = "Path of the pid file. Master writes and locks it at start and removes it at exit; "
		 "a second server with the same file refuses to start.",
	  POS1({ .kind = BST_T_PATH }) },
	{ .name = "error_log", .contexts = BST_CTX_GLOBAL, .apply = ap_error_log,
	  .doc = "Error log path and optional minimum level (default warn).",
	  .args = { .min_args = 1, .max_args = 2,
		    .pos = { { .kind = BST_T_PATH }, { .kind = BST_T_ENUM, .enum_values = ev_level } } } },
	{ .name = "include", .contexts = BST_CTX_ALL, .apply = ap_include, .repeatable = true,
	  .doc = "Include another file or glob here (expanded by the parser).",
	  POS1({ .kind = BST_T_PATH }) },
	{ .name = "server", .contexts = BST_CTX_GLOBAL, .apply = ap_server, .repeatable = true,
	  .child_ctx = BST_CTX_SERVER, .doc = "A virtual server: listeners, names and locations.",
	  .args = { .block = BST_BLOCK_REQUIRED } },
	{ .name = "listen", .contexts = BST_CTX_SERVER, .apply = ap_listen, .repeatable = true,
	  .doc = "Listen on port, addr:port or [v6]:port. tcp_profile=name picks the socket tuning "
		 "from a tcp_profile block (default: nodelay on, backlog 4096, the kernel's defaults "
		 "otherwise). A socket has one set of options, so two listens on one address may name "
		 "at most one profile between them. The flag default_server makes this server "
		 "answer a request whose Host matches no name on the address (otherwise the server "
		 "with no name, else the first one). The flag tls makes every connection on the address "
		 "start with a TLS handshake (see tls_cert and tls_profile); all servers on one address "
		 "must agree on it.",
	  .args = { .min_args = 1, .max_args = 3,
		    .pos = { { .kind = BST_T_STRING },
			     { .kind = BST_T_ENUM, .enum_values = listen_flags } },
		    .opts = listen_opts, .nopts = sizeof listen_opts / sizeof listen_opts[0] } },
	{ .name = "name", .contexts = BST_CTX_SERVER, .apply = ap_name, .repeatable = true,
	  .doc = "Host names this server answers to: an exact name, *.example.com (any host below "
		 "it), example.* (any suffix) or ~regex (kept as written; the others are "
		 "lower-cased). The match order is exact, then the longest leading wildcard, then the "
		 "longest trailing wildcard, then regexes in file order. A server with no name is the "
		 "default for its address.",
	  .args = { .min_args = 1, .max_args = 32, .pos = { { .kind = BST_T_STRING } } } },
	{ .name = "location", .contexts = BST_CTX_SERVER | BST_CTX_LOCATION, .apply = ap_location,
	  .repeatable = true, .child_ctx = BST_CTX_LOCATION,
	  .doc = "A location block: [= | ^~ | ~ | ~*] pattern. Locations nest and inherit from the enclosing location.",
	  .args = { .min_args = 1, .max_args = 2, .pos = { { .kind = BST_T_STRING } },
		    .block = BST_BLOCK_REQUIRED } },
	{ .name = "client_max_body_size", .contexts = BST_CTX_SERVER | BST_CTX_LOCATION,
	  .apply = ap_cmbs, .default_value = "1m",
	  .doc = "Largest accepted request body; 0 means unlimited.",
	  POS1({ .kind = BST_T_SIZE }) },
};
BST_DIRECTIVES(core_dirs);

const bst_dirtab *bst_cfg_core_dirtab(void)
{
	return &bst_dirtab_core_dirs;
}

/* Phase 14: `tls auto` will make a server with no `listen` listen on 80 and 443. */
bool bst_cfg_server_implies_listener(const bst_cfg_server *s)
{
	(void)s;
	return false;
}

/* ---- Cross-block checks ---- */

typedef struct lkey {
	const bst_cfg_server *srv;
	const bst_cfg_listen *lis;
	const char *name; /* "" for the default server */
	size_t si, li;    /* server and listen index: file order, the tie-break */
} lkey;

static int cmp_lkey(const void *x, const void *y)
{
	const lkey *a = x, *b = y;
	int c = a->lis->addr.ip.family - b->lis->addr.ip.family;
	if (c == 0)
		c = memcmp(a->lis->addr.ip.b, b->lis->addr.ip.b, sizeof a->lis->addr.ip.b);
	if (c == 0)
		c = (int)a->lis->addr.port - (int)b->lis->addr.port;
	if (c == 0)
		c = strcmp(a->name, b->name);
	if (c == 0) /* keep file order, so the first occurrence sorts first */
		c = a->si != b->si ? (a->si < b->si ? -1 : 1) : a->li < b->li ? -1 : a->li > b->li;
	return c;
}

typedef struct nkey {
	const char *name;
	size_t idx;
} nkey;

static int cmp_nkey(const void *x, const void *y)
{
	const nkey *a = x, *b = y;
	int c = strcmp(a->name, b->name);
	return c != 0 ? c : a->idx < b->idx ? -1 : a->idx > b->idx;
}

/* Duplicate names in one server: sort, then adjacent equal names. The error goes to the
 * earliest second occurrence in file order. */
static int check_server_names(const bst_cfg_server *s, bst_cfg_ctx *c, nkey *tmp, bst_err *e)
{
	if (s->nnames < 2)
		return 0;
	for (size_t i = 0; i < s->nnames; i++)
		tmp[i] = (nkey){ s->names[i], i };
	qsort(tmp, s->nnames, sizeof *tmp, cmp_nkey);
	size_t dup = SIZE_MAX;
	for (size_t i = 1; i < s->nnames; i++)
		if (strcmp(tmp[i - 1].name, tmp[i].name) == 0 && tmp[i].idx < dup)
			dup = tmp[i].idx;
	if (dup == SIZE_MAX)
		return 0;
	char tok[BST_SCHEMA_MAX_TOKEN_SHOWN + 8];
	bst_cfg_shown(s->names[dup], strlen(s->names[dup]), tok, sizeof tok);
	bst_err_set(e, "duplicate server name \"%s\"", tok);
	bst_cfg_err_at(e, bst_cfg_src(c, &s->name_locs[dup]));
	return -1;
}

static void loc_text(const bst_loc *l, char *buf, size_t cap)
{
	char f[BST_CFG_SHOWN_FILE + 8];
	bst_cfg_shown_file(l->file, f, sizeof f);
	snprintf(buf, cap, "%s:%d:%d", f, l->line, l->col);
}

int bst_cfg_core_check(const bst_config *cfg, bst_cfg_ctx *c, bst_err *e)
{
	const bst_cfg_global *g = &cfg->global;
	size_t total = 0, maxnames = 0;
	for (size_t i = 0; i < g->nservers; i++)
		if (g->servers[i]->nnames > maxnames)
			maxnames = g->servers[i]->nnames;
	nkey *ntmp = malloc((maxnames ? maxnames : 1) * sizeof *ntmp);
	if (ntmp == NULL) {
		bst_err_set(e, "out of memory");
		return -1;
	}
	for (size_t i = 0; i < g->nservers; i++)
		if (check_server_names(g->servers[i], c, ntmp, e) != 0) {
			free(ntmp);
			return -1;
		}
	free(ntmp);
	for (size_t i = 0; i < g->nservers; i++) {
		const bst_cfg_server *s = g->servers[i];
		if (s->nlistens == 0 && !bst_cfg_server_implies_listener(s)) {
			bst_err_set(e, "server has no \"listen\": add one, for example "
				       "\"listen 8080;\"");
			bst_cfg_err_at(e, bst_cfg_src(c, &s->loc));
			return -1;
		}
		total += s->nlistens * (s->nnames ? s->nnames : 1);
	}
	lkey *keys = calloc(total ? total : 1, sizeof *keys);
	if (keys == NULL) {
		bst_err_set(e, "out of memory");
		return -1;
	}
	size_t k = 0;
	for (size_t i = 0; i < g->nservers; i++) {
		const bst_cfg_server *s = g->servers[i];
		for (size_t j = 0; j < s->nlistens; j++)
			for (size_t m = 0; m < (s->nnames ? s->nnames : 1); m++)
				keys[k++] = (lkey){ s, &s->listens[j], s->nnames ? s->names[m] : "", i, j };
	}
	qsort(keys, k, sizeof *keys, cmp_lkey);
	int rc = 0;
	for (size_t i = 1; i < k && rc == 0; i++) {
		const lkey *a = &keys[i - 1], *b = &keys[i];
		if (a->lis->addr.port != b->lis->addr.port ||
		    !bst_ip_eq(&a->lis->addr.ip, &b->lis->addr.ip) || strcmp(a->name, b->name) != 0)
			continue;
		char addr[BST_ADDR_STRLEN + 8], l1[200];
		bst_addr_format(&a->lis->addr.ip, addr, sizeof addr);
		loc_text(bst_cfg_src(c, &a->lis->loc), l1, sizeof l1);
		if (a->name[0] == 0)
			bst_err_set(e, "duplicate default server on %s:%u (give one a name); "
				       "first listen at %s", addr, (unsigned)a->lis->addr.port, l1);
		else
			bst_err_set(e, "duplicate listener %s:%u for name \"%.60s\"; first listen at %s",
				    addr, (unsigned)a->lis->addr.port, a->name, l1);
		bst_cfg_err_at(e, bst_cfg_src(c, &b->lis->loc));
		rc = -1;
	}
	free(keys);
	return rc;
}
