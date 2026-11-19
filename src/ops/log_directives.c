/* Access log directives (ops/logger.h): log_format, access_log, log_buffer, log_flush_interval,
 * log_redact_headers, log_redact_query_params, and the built-in `main` (JSON) and `combined`
 * (text) formats. */
#include "config/compile.h"
#include "config/values.h"
#include "core/str.h"
#include "ops/logger.h"

#include <stdlib.h>
#include <string.h>

#define SEC 1000000LL

static int oom(bst_err *e)
{
	bst_err_set(e, "out of memory");
	return -1;
}

static bst_str as_str(const bst_ast_arg *a)
{
	return (bst_str){ a->text, (uint32_t)a->len };
}

static bst_str cstr(const char *s)
{
	return (bst_str){ s, (uint32_t)strlen(s) };
}

static const char *const default_headers[] = { "authorization", "cookie", "proxy-authorization",
						"set-cookie" };

static bst_cfg_logs *logs_of(bst_cfg_ctx *c, bst_err *e)
{
	bst_cfg_global *g = c->global;
	if (g->logs != NULL)
		return g->logs;
	bst_cfg_logs *l = bst_arena_alloc(c->arena, sizeof *l);
	if (l == NULL) {
		oom(e);
		return NULL;
	}
	memset(l, 0, sizeof *l);
	l->buffer = 1u << 20;
	l->flush_ms = 1000;
	for (size_t i = 0; i < sizeof default_headers / sizeof default_headers[0]; i++)
		if (bst_cfg_push_owned(c, &l->headers, &l->nheaders, &l->headers_cap_,
				       sizeof(char *), &default_headers[i], e) != 0)
			return NULL;
	g->logs = l;
	return l;
}

static char *lower_dup(bst_cfg_ctx *c, const char *s, size_t n, bst_err *e)
{
	char *d = bst_cfg_strdup(c, s, n, e);
	if (d != NULL)
		for (size_t i = 0; i < n; i++)
			if (d[i] >= 'A' && d[i] <= 'Z')
				d[i] = (char)(d[i] + 32);
	return d;
}

/* ---- log_format ---- */

static bst_logfmt *find_format(bst_cfg_logs *l, const char *name)
{
	for (size_t i = 0; i < l->nformats; i++)
		if (strcmp(l->formats[i]->name, name) == 0)
			return l->formats[i];
	return NULL;
}

static int ap_log_format(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			 bst_err *e)
{
	bst_cfg_logs *l = logs_of(c, e);
	if (l == NULL)
		return -1;
	const bst_ast_arg *name = bst_dir_pos(d, n, 0), *kind = bst_dir_pos(d, n, 1);
	bool json = kind->len == 4 && memcmp(kind->text, "json", 4) == 0;
	size_t np = bst_dir_npos(d, n);
	if (json && (np != 2 || !n->has_block)) {
		bst_err_set(e, "log_format %s json: the fields go in a { } block", name->text);
		bst_cfg_err_at(e, &n->loc);
		return -1;
	}
	if (!json && (np != 3 || n->has_block)) {
		bst_err_set(e, "log_format %s text: one template, no block", name->text);
		bst_cfg_err_at(e, &n->loc);
		return -1;
	}
	if (find_format(l, name->text) != NULL) {
		bst_err_set(e, "log_format %s: defined twice", name->text);
		bst_cfg_err_at(e, &name->loc);
		return -1;
	}
	bst_logfmt *f = bst_arena_alloc(c->arena, sizeof *f);
	if (f == NULL)
		return oom(e);
	memset(f, 0, sizeof *f);
	f->name = bst_cfg_strdup(c, name->text, name->len, e);
	f->json = json;
	if (f->name == NULL)
		return -1;
	if (!json) {
		f->text = bst_tpl_compile_arg(bst_dir_pos(d, n, 2), c->arena, e);
		if (f->text == NULL)
			return -1;
	}
	if (bst_cfg_push_owned(c, &l->formats, &l->nformats, &l->formats_cap_, sizeof f, &f, e) != 0)
		return -1;
	c->log_format = f;
	return 0;
}

static int ap_log_field(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			bst_err *e)
{
	bst_logfmt *f = c->log_format;
	bst_logfmt_field fl;
	fl.name = bst_cfg_strdup(c, n->name, n->name_len, e);
	if (fl.name == NULL)
		return -1;
	fl.tpl = bst_tpl_compile_arg(bst_dir_pos(d, n, 0), c->arena, e);
	if (fl.tpl == NULL)
		return -1;
	for (size_t i = 0; i < f->nfields; i++)
		if (strcmp(f->fields[i].name, fl.name) == 0) {
			bst_err_set(e, "log_format %s: field %s twice", f->name, fl.name);
			bst_cfg_err_at(e, &n->loc);
			return -1;
		}
	return bst_cfg_push_owned(c, &f->fields, &f->nfields, &f->fields_cap_, sizeof fl, &fl, e);
}

/* ---- access_log ---- */

/* sample=: a fraction 0..1 ("0.1") or a percentage ("10%"). */
static bool parse_sample(const char *s, size_t n, double *out)
{
	char buf[32];
	if (n == 0 || n >= sizeof buf)
		return false;
	memcpy(buf, s, n);
	buf[n] = '\0';
	bool pct = buf[n - 1] == '%';
	if (pct)
		buf[n - 1] = '\0';
	for (const char *p = buf; *p != '\0'; p++)
		if (!((*p >= '0' && *p <= '9') || *p == '.'))
			return false;
	char *end;
	double v = strtod(buf, &end);
	if (end == buf || *end != '\0')
		return false;
	if (pct)
		v /= 100.0;
	if (!(v >= 0.0 && v <= 1.0))
		return false;
	*out = v;
	return true;
}

static int ap_access_log(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			 bst_err *e)
{
	bst_cfg_logs *l = logs_of(c, e);
	if (l == NULL)
		return -1;
	const bst_ast_arg *dst = bst_dir_pos(d, n, 0);
	bst_alog *a = bst_arena_alloc(c->arena, sizeof *a);
	if (a == NULL)
		return oom(e);
	memset(a, 0, sizeof *a);
	a->sample = 1.0;
	a->file = -1;
	if (bst_cfg_loc_of(c, n, &a->loc, e) != 0)
		return -1;
	bool off = dst->len == 3 && memcmp(dst->text, "off", 3) == 0;
	if (!off) {
		a->path = bst_cfg_strdup(c, dst->text, dst->len, e);
		const bst_ast_arg *fa = bst_dir_pos(d, n, 1);
		a->format_name = fa != NULL ? bst_cfg_strdup(c, fa->text, fa->len, e) : "main";
		if (a->path == NULL || a->format_name == NULL)
			return -1;
		bst_ast_arg v;
		if (bst_dir_opt(d, n, "sample=", &v) && !parse_sample(v.text, v.len, &a->sample)) {
			bst_err_set(e, "access_log: sample= takes a fraction from 0 to 1 (0.1) or a "
				       "percentage (10%%)");
			bst_cfg_err_at(e, &v.loc);
			return -1;
		}
		if (bst_dir_opt(d, n, "errors_only=", &v))
			(void)bst_parse_bool(as_str(&v), &a->errors_only); /* validated */
		if (bst_dir_opt(d, n, "if=", &v)) {
			a->cond = bst_tpl_compile_arg(&v, c->arena, e);
			if (a->cond == NULL)
				return -1;
		}
	} else if (bst_dir_npos(d, n) > 1) {
		bst_err_set(e, "access_log off: takes nothing else");
		bst_cfg_err_at(e, &n->loc);
		return -1;
	}
	if (bst_cfg_push_owned(c, &l->entries, &l->nentries, &l->entries_cap_, sizeof a, &a, e) != 0)
		return -1;
	return bst_cfg_list_append(c, &c->common->access_logs, a, e);
}

/* ---- settings ---- */

static int ap_log_buffer(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			 bst_err *e)
{
	bst_cfg_logs *l = logs_of(c, e);
	uint64_t v;
	if (l == NULL)
		return -1;
	if (bst_parse_size(as_str(bst_dir_pos(d, n, 0)), &v)) { /* validated */
		uint64_t p = 1;
		while (p < v)
			p <<= 1; /* a ring is a power of two */
		l->buffer = p;
	}
	return 0;
}

static int ap_log_flush(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	bst_cfg_logs *l = logs_of(c, e);
	uint64_t us;
	if (l == NULL)
		return -1;
	if (bst_parse_duration_us(as_str(bst_dir_pos(d, n, 0)), &us)) /* validated */
		l->flush_ms = (us + 999) / 1000;
	return 0;
}

static int ap_redact(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	bst_cfg_logs *l = logs_of(c, e);
	if (l == NULL)
		return -1;
	bool hdr = strcmp(d->name, "log_redact_headers") == 0;
	for (size_t i = 0; i < bst_dir_npos(d, n); i++) {
		const bst_ast_arg *a = bst_dir_pos(d, n, i);
		if (a->len > 63) {
			bst_err_set(e, "%s: a name is at most 63 bytes", d->name);
			bst_cfg_err_at(e, &a->loc);
			return -1;
		}
		const char *s = lower_dup(c, a->text, a->len, e);
		if (s == NULL)
			return -1;
		int rc = hdr ? bst_cfg_push_owned(c, &l->headers, &l->nheaders, &l->headers_cap_,
						  sizeof s, &s, e)
			     : bst_cfg_push_owned(c, &l->params, &l->nparams, &l->params_cap_,
						  sizeof s, &s, e);
		if (rc != 0)
			return -1;
	}
	return 0;
}

/* ---- post: built-in formats, format names, files ---- */

typedef struct builtin_field {
	const char *name, *tpl;
} builtin_field;

static const builtin_field main_fields[] = {
	{ "time", "$time_iso8601" },
	{ "remote_addr", "$remote_addr" },
	{ "request_id", "$request_id" },
	{ "method", "$request_method" },
	{ "uri", "$request_uri" },
	{ "protocol", "$server_protocol" },
	{ "status", "$status" },
	{ "body_bytes_sent", "$body_bytes_sent" },
	{ "request_time", "$request_time" },
	{ "host", "$host" },
	{ "referer", "$http_referer" },
	{ "user_agent", "$http_user_agent" },
};

#define COMBINED                                                                              \
	"$remote_addr - $auth_user [$time_local] \"$request_method $request_uri "             \
	"$server_protocol\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\""

static int add_builtins(bst_cfg_ctx *c, bst_cfg_logs *l, bst_err *e)
{
	if (find_format(l, "main") == NULL) {
		bst_logfmt *f = bst_arena_alloc(c->arena, sizeof *f);
		if (f == NULL)
			return oom(e);
		memset(f, 0, sizeof *f);
		f->name = "main";
		f->json = true;
		for (size_t i = 0; i < sizeof main_fields / sizeof main_fields[0]; i++) {
			bst_logfmt_field fl = { main_fields[i].name, NULL };
			fl.tpl = bst_tpl_compile(cstr(main_fields[i].tpl), c->arena, e);
			if (fl.tpl == NULL ||
			    bst_cfg_push_owned(c, &f->fields, &f->nfields, &f->fields_cap_, sizeof fl,
					       &fl, e) != 0)
				return -1;
		}
		if (bst_cfg_push_owned(c, &l->formats, &l->nformats, &l->formats_cap_, sizeof f, &f,
				       e) != 0)
			return -1;
	}
	if (find_format(l, "combined") == NULL) {
		bst_logfmt *f = bst_arena_alloc(c->arena, sizeof *f);
		if (f == NULL)
			return oom(e);
		memset(f, 0, sizeof *f);
		f->name = "combined";
		f->text = bst_tpl_compile(BST_S(COMBINED), c->arena, e);
		if (f->text == NULL ||
		    bst_cfg_push_owned(c, &l->formats, &l->nformats, &l->formats_cap_, sizeof f, &f,
				       e) != 0)
			return -1;
	}
	return 0;
}

static int post_access_logs(bst_config *cfg, bst_cfg_ctx *c, bst_err *e)
{
	bst_cfg_logs *l = cfg->global.logs;
	if (l == NULL)
		return 0;
	if (add_builtins(c, l, e) != 0)
		return -1;
	for (size_t i = 0; i < l->nentries; i++) {
		bst_alog *a = l->entries[i];
		if (a->path == NULL)
			continue;
		a->fmt = find_format(l, a->format_name);
		if (a->fmt == NULL) {
			bst_err_set(e, "access_log: no log_format named '%s'", a->format_name);
			bst_cfg_err_at(e, bst_cfg_src(c, &a->loc));
			return -1;
		}
		size_t k = 0;
		while (k < l->npaths && strcmp(l->paths[k], a->path) != 0)
			k++;
		if (k == l->npaths) {
			if (l->npaths == BST_LOG_FILES_MAX) {
				bst_err_set(e, "access_log: more than %d files", BST_LOG_FILES_MAX);
				bst_cfg_err_at(e, bst_cfg_src(c, &a->loc));
				return -1;
			}
			if (bst_cfg_push_owned(c, &l->paths, &l->npaths, &l->paths_cap_,
					       sizeof(char *), &a->path, e) != 0)
				return -1;
		}
		a->file = (int)k;
	}
	l->redact = (bst_var_redact){ .headers = l->headers, .nheaders = l->nheaders,
				      .params = l->params, .nparams = l->nparams };
	return 0;
}
BST_CFG_POST(post_access_logs);

#define LG BST_CTX_GLOBAL
#define SCOPES (BST_CTX_GLOBAL | BST_CTX_SERVER | BST_CTX_LOCATION)

static const char *const fmt_kinds[] = { "json", "text", NULL };
static const char *const kw_dest[] = { "off", NULL };

static const bst_optspec alog_opts[] = {
	{ .key = "sample=", .type = { .kind = BST_T_STRING } },
	{ .key = "errors_only=", .type = { .kind = BST_T_BOOL } },
	{ .key = "if=", .type = { .kind = BST_T_TEMPLATE } },
};

static const bst_directive log_dirs[] = {
	{ .name = "log_format", .contexts = LG, .apply = ap_log_format, .repeatable = true,
	  .child_ctx = BST_CTX_LOG_FORMAT,
	  .doc = "A named access log format. `log_format <name> json { <key> <template>; ... }` "
		 "writes one JSON object per line, each value a string escaped on its own; "
		 "`log_format <name> text \"<template>\"` writes the template with every variable "
		 "escaped (quotes, backslashes, control bytes and invalid UTF-8 as \\xHH), so no "
		 "value can split a line. `main` (JSON) and `combined` (text) are built in.",
	  .args = { .min_args = 2, .max_args = 3,
		    .pos = { { .kind = BST_T_STRING },
			     { .kind = BST_T_ENUM, .enum_values = fmt_kinds },
			     { .kind = BST_T_TEMPLATE } },
		    .block = BST_BLOCK_OPTIONAL } },
	{ .name = "field", .contexts = BST_CTX_LOG_FORMAT, .apply = ap_log_field, .any_name = true,
	  .repeatable = true,
	  .doc = "A field of a JSON log_format: the statement name is the key, the argument the "
		 "template of its value.",
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_TEMPLATE } } } },
	{ .name = "access_log", .contexts = SCOPES, .apply = ap_access_log, .repeatable = true,
	  .doc = "Writes a line per request to a file (opened by master, written by the helper, "
		 "never by a worker), or `stdout`, in a log_format (default main). sample= logs "
		 "that fraction of requests (0.1 or 10%), errors_only=on only status 400 and up, "
		 "and if= only when its template is neither empty nor \"0\"; errors are never "
		 "sampled out. A scope's own access_log statements replace those it inherits; "
		 "`access_log off` logs nothing there. USR1 reopens every file.",
	  .args = { .min_args = 1, .max_args = 2,
		    .pos = { { .kind = BST_T_PATH, .keywords = kw_dest }, { .kind = BST_T_STRING } },
		    .opts = alog_opts, .nopts = sizeof alog_opts / sizeof alog_opts[0] } },
	{ .name = "log_buffer", .contexts = LG, .apply = ap_log_buffer, .default_value = "1m",
	  .doc = "Size of each worker's access log ring in shared memory, rounded up to a power of "
		 "two. A line that does not fit while the helper is behind is dropped and counted "
		 "in bastion_log_dropped_total; the worker never waits.",
	  .args = { .min_args = 1, .max_args = 1,
		    .pos = { { .kind = BST_T_SIZE, .min = 65536, .max = 1073741824LL } } } },
	{ .name = "log_flush_interval", .contexts = LG, .apply = ap_log_flush,
	  .default_value = "1s",
	  .doc = "How often the helper drains the access log rings and writes each file's batch, "
		 "from 10 milliseconds to 60 seconds. A batch is also written as soon as it fills.",
	  .args = { .min_args = 1, .max_args = 1,
		    .pos = { { .kind = BST_T_DURATION, .min = 10000, .max = 60 * SEC } } } },
	{ .name = "log_redact_headers", .contexts = LG, .apply = ap_redact, .repeatable = true,
	  .doc = "Request headers whose $http_NAME reads [REDACTED] in access logs, on top of "
		 "Authorization, Cookie, Proxy-Authorization and Set-Cookie, which are always "
		 "redacted. Listing cookie also hides every $cookie_NAME.",
	  .args = { .min_args = 1, .max_args = 32, .pos = { { .kind = BST_T_STRING } } } },
	{ .name = "log_redact_query_params", .contexts = LG, .apply = ap_redact,
	  .repeatable = true,
	  .doc = "Query parameters whose values read [REDACTED] in access logs: in $arg_NAME, "
		 "$args and $request_uri. Names compare case-insensitively after percent-decoding.",
	  .args = { .min_args = 1, .max_args = 32, .pos = { { .kind = BST_T_STRING } } } },
};
BST_DIRECTIVES(log_dirs);
