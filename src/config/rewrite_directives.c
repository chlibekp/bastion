/* Rewrite, redirect and header directives (Phase 5 task 4). They store compiled templates in
 * bst_cfg_common; src/route/rewrite.c and src/filters/headers.c run them. */
#include "config/compile.h"
#include "config/errfmt.h"
#include "config/template.h"
#include "config/values.h"
#include "http/token.h"
#include "route/vars.h"

#include <string.h>

static bst_str as_str(const bst_ast_arg *a)
{
	return (bst_str){ a->text, (uint32_t)a->len };
}

static unsigned uint_of(const bst_ast_arg *a)
{
	uint64_t v = 0;
	(void)bst_str_to_u64(as_str(a), &v); /* validated by the argspec */
	return (unsigned)v;
}

/* ---- rewrite ---- */

static int ap_rewrite(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *pat = bst_dir_pos(d, n, 0), *rep = bst_dir_pos(d, n, 1),
			  *fl = bst_dir_pos(d, n, 2);
	bst_cfg_rewrite *r = bst_arena_alloc(c->arena, sizeof *r);
	if (r == NULL) {
		bst_err_set(e, "out of memory");
		return -1;
	}
	memset(r, 0, sizeof *r);
	r->pattern = bst_cfg_strdup(c, pat->text, pat->len, e);
	if (r->pattern == NULL || bst_cfg_loc_of(c, n, &r->loc, e) != 0)
		return -1;
	r->repl = bst_tpl_compile_arg(rep, c->arena, e);
	if (r->repl == NULL)
		return -1;
	if (fl != NULL)
		r->flag = fl->text[0] == 'l' ? BST_REWRITE_LAST : BST_REWRITE_BREAK;
	return bst_cfg_list_append(c, &c->common->rewrites, r, e);
}

static int ap_rewrite_max_cycles(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
				 bst_err *e)
{
	(void)e;
	c->common->rewrite_max_cycles = uint_of(bst_dir_pos(d, n, 0));
	return 0;
}

/* ---- redirect ---- */

static int ap_redirect(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *code = bst_dir_pos(d, n, 0), *tgt = bst_dir_pos(d, n, 1);
	const bst_header_tpl *t = bst_tpl_compile_header_arg(tgt, c->arena, e);
	if (t == NULL)
		return -1;
	if (bst_var_is_request_input(bst_header_tpl_first_var(t)))
		bst_cfg_warn_at(c, &tgt->loc,
				"redirect target starts with a value taken from the request: a client "
				"can send visitors anywhere (an open redirect); begin the target with a "
				"fixed scheme and host, or a /path");
	c->common->redirect = (bst_cfg_redirect){ .set = true, .code = uint_of(code), .target = t,
						  .append_query = true };
	c->common->http.ret.set = false;
	return 0;
}

static int ap_redirect_https(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			     bst_err *e)
{
	const bst_ast_arg *code = bst_dir_pos(d, n, 0);
	const bst_var_reg *reg = bst_var_registry(e);
	if (reg == NULL)
		return -1;
	const bst_header_tpl *t = bst_tpl_compile_header_with(reg, BST_S("https://$host$request_uri"),
							      NULL, c->arena, e);
	if (t == NULL)
		return -1;
	c->common->redirect = (bst_cfg_redirect){ .set = true, .code = code ? uint_of(code) : 301,
						  .target = t, .append_query = false };
	c->common->http.ret.set = false;
	return 0;
}

/* ---- headers ---- */

/* Framing and connection headers belong to the protocol, which drops them from a handler's list:
 * an operation on one would silently do nothing, so it is refused. */
static const char *const reserved[] = { "content-length", "transfer-encoding", "connection",
					"keep-alive", "te", "upgrade", "trailer",
					"proxy-connection", "host", NULL };

static int check_name(const bst_ast_arg *a, bool request, bst_err *e)
{
	if (!bst_is_token(as_str(a))) {
		char t[BST_SCHEMA_MAX_TOKEN_SHOWN + 8];
		bst_cfg_shown(a->text, a->len, t, sizeof t);
		bst_err_set(e, "\"%s\" is not a valid header name", t);
		bst_cfg_err_at(e, &a->loc);
		return -1;
	}
	for (size_t i = 0; reserved[i] != NULL; i++) {
		if (strlen(reserved[i]) != a->len || !bst_str_ieq(as_str(a), (bst_str){ reserved[i], (uint32_t)a->len }))
			continue;
		if (request && strcmp(reserved[i], "host") == 0)
			return 0; /* a request's Host may be set, e.g. for a proxy; framing never */
		char t[BST_SCHEMA_MAX_TOKEN_SHOWN + 8];
		bst_cfg_shown(a->text, a->len, t, sizeof t);
		bst_err_set(e, "header \"%s\" is set by the protocol and cannot be changed here", t);
		bst_cfg_err_at(e, &a->loc);
		return -1;
	}
	return 0;
}

static int add_op(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e,
		  bst_hdr_op_kind kind, bool request)
{
	const bst_ast_arg *name = bst_dir_pos(d, n, 0), *val = bst_dir_pos(d, n, 1),
			  *always = bst_dir_pos(d, n, 2);
	if (check_name(name, request, e) != 0)
		return -1;
	bst_cfg_hdr_op *op = bst_arena_alloc(c->arena, sizeof *op);
	if (op == NULL) {
		bst_err_set(e, "out of memory");
		return -1;
	}
	memset(op, 0, sizeof *op);
	op->kind = kind;
	op->name = bst_cfg_strdup(c, name->text, name->len, e);
	op->name_len = (uint32_t)name->len;
	op->always = always != NULL;
	if (op->name == NULL)
		return -1;
	if (kind != BST_HDR_REMOVE) {
		op->value = bst_tpl_compile_header_arg(val, c->arena, e);
		if (op->value == NULL)
			return -1;
	}
	return bst_cfg_list_extend(c, request ? &c->common->req_hdr_ops : &c->common->resp_hdr_ops,
				   op, e);
}

#define OPAP(fn, kind, request)                                                         \
	static int fn(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,    \
		      bst_err *e)                                                        \
	{                                                                                \
		return add_op(c, d, n, e, kind, request);                                \
	}
OPAP(ap_header_add, BST_HDR_ADD, false)
OPAP(ap_header_set, BST_HDR_SET, false)
OPAP(ap_header_remove, BST_HDR_REMOVE, false)
OPAP(ap_req_set, BST_HDR_SET, true)
OPAP(ap_req_remove, BST_HDR_REMOVE, true)

static int ap_expires(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	const bst_ast_arg *a = bst_dir_pos(d, n, 0), *imm = bst_dir_pos(d, n, 1);
	bst_cfg_expires x = { 0 };
	uint64_t us = 0;
	if (bst_parse_duration_us(as_str(a), &us)) {
		x.set = true;
		x.secs = us / 1000000;
		x.immutable = imm != NULL;
	}
	c->common->expires = x; /* "off" leaves it unset: no header */
	return 0;
}

/* ---- table ---- */

#define ALL3 (BST_CTX_GLOBAL | BST_CTX_SERVER | BST_CTX_LOCATION)
#define SL (BST_CTX_SERVER | BST_CTX_LOCATION)

static const char *const ev_flag_rw[] = { "last", "break", NULL };
static const char *const ev_codes[] = { "301", "302", "303", "307", "308", NULL };
static const char *const ev_always[] = { "always", NULL };
static const char *const ev_immutable[] = { "immutable", NULL };
static const char *const kw_off[] = { "off", NULL };

static const bst_directive rewrite_dirs[] = {
	{ .name = "rewrite", .contexts = SL, .apply = ap_rewrite, .repeatable = true,
	  .doc = "Rewrites the request path when the regular expression matches it, to the "
		 "replacement ($1 to $9 are the groups; the query string is kept unless the "
		 "replacement has a '?'). The match runs on the normalized path. Rules of a server "
		 "run before the location is chosen, rules of a location after. Without a flag the "
		 "next rule runs on the new path. last: stop, and search for the location again "
		 "with the new path (at most rewrite_max_cycles times a request). break: stop "
		 "here and keep the location. A rule set in a block replaces the rules it would "
		 "inherit.",
	  .args = { .min_args = 2, .max_args = 3,
		    .pos = { { .kind = BST_T_STRING }, { .kind = BST_T_TEMPLATE },
			     { .kind = BST_T_ENUM, .enum_values = ev_flag_rw } } } },
	{ .name = "rewrite_max_cycles", .contexts = ALL3, .apply = ap_rewrite_max_cycles,
	  .default_value = "10",
	  .doc = "Most times one request may restart the location search through a rewrite with "
		 "the last flag. A request that would go on is answered 500: a rewrite loop.",
	  .args = { .min_args = 1, .max_args = 1,
		    .pos = { { .kind = BST_T_INT, .min = 1, .max = 1000 } } } },
	{ .name = "redirect", .contexts = SL, .apply = ap_redirect,
	  .doc = "Answers with a redirect: status 301, 302, 303, 307 or 308 and the target as "
		 "Location. The target may use variables ($1 of the location's regex, $request_uri); "
		 "when it has no '?' the request's own query string is appended. Prefer "
		 "$request_uri to $uri in a target: $uri is decoded. A target that begins with a "
		 "value from the request ($arg_x, $http_x) is warned about by -t as an open redirect.",
	  .args = { .min_args = 2, .max_args = 2,
		    .pos = { { .kind = BST_T_ENUM, .enum_values = ev_codes },
			     { .kind = BST_T_TEMPLATE } } } },
	{ .name = "redirect_https", .contexts = SL, .apply = ap_redirect_https,
	  .doc = "Answers every request with a redirect to the same host and path on https "
		 "(https://$host$request_uri): 301 by default, or the status given.",
	  .args = { .min_args = 0, .max_args = 1,
		    .pos = { { .kind = BST_T_ENUM, .enum_values = ev_codes } } } },
	{ .name = "header_add", .contexts = ALL3, .apply = ap_header_add, .repeatable = true,
	  .doc = "Adds a response header (another line when the name is already there). The value "
		 "is a template. By default only on 2xx and 3xx responses; with always also on "
		 "errors. A value that expands to a CR or LF is dropped whole, with a warning in "
		 "the log. Operations of the global, server and location blocks all apply, in "
		 "that order.",
	  .args = { .min_args = 2, .max_args = 3,
		    .pos = { { .kind = BST_T_STRING }, { .kind = BST_T_TEMPLATE },
			     { .kind = BST_T_ENUM, .enum_values = ev_always } } } },
	{ .name = "header_set", .contexts = ALL3, .apply = ap_header_set, .repeatable = true,
	  .doc = "Sets a response header, replacing any of that name the handler or an earlier "
		 "operation gave. Same value, always and ordering rules as header_add.",
	  .args = { .min_args = 2, .max_args = 3,
		    .pos = { { .kind = BST_T_STRING }, { .kind = BST_T_TEMPLATE },
			     { .kind = BST_T_ENUM, .enum_values = ev_always } } } },
	{ .name = "header_remove", .contexts = ALL3, .apply = ap_header_remove, .repeatable = true,
	  .doc = "Removes a response header, whatever its value, on every status.",
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_STRING } } } },
	{ .name = "request_header_set", .contexts = ALL3, .apply = ap_req_set, .repeatable = true,
	  .doc = "Sets a request header before the handler sees it (and before a proxy forwards "
		 "it), replacing any of that name the client sent. The value is a template.",
	  .args = { .min_args = 2, .max_args = 2,
		    .pos = { { .kind = BST_T_STRING }, { .kind = BST_T_TEMPLATE } } } },
	{ .name = "request_header_remove", .contexts = ALL3, .apply = ap_req_remove,
	  .repeatable = true,
	  .doc = "Removes a request header the client sent before the handler sees it.",
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_STRING } } } },
	{ .name = "expires", .contexts = ALL3, .apply = ap_expires,
	  .doc = "Adds Expires and Cache-Control: max-age=<duration> to 200, 201, 204, 206, 301, "
		 "302, 303, 304, 307 and 308 responses. immutable adds the immutable directive "
		 "(for files whose name changes with their content). 0s sends no-cache. off: "
		 "nothing is added.",
	  .args = { .min_args = 1, .max_args = 2,
		    .pos = { { .kind = BST_T_DURATION, .keywords = kw_off },
			     { .kind = BST_T_ENUM, .enum_values = ev_immutable } } } },
};
BST_DIRECTIVES(rewrite_dirs);
