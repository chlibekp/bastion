/* Typed values and the argument classifier: how a directive's arguments are checked against
 * its argspec, and the bst_dir_* accessors that apply functions use (one classifier serves
 * both). Part of the schema; see schema.h. */
#include "config/schema.h"

#include "config/errfmt.h"
#include "config/schema_priv.h"
#include "config/values.h"
#include "core/cidr.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- Typed values ---- */

/* True if tpl holds a $variable ($$ is an escaped dollar; a lone trailing $ is text). */
static bool has_variable(const bst_ast_arg *a)
{
	const char *t = a->tpl;
	for (size_t i = 0; i < a->tpl_len; i++) {
		if (t[i] != '$')
			continue;
		if (i + 1 < a->tpl_len && t[i + 1] == '$') {
			i++;
			continue;
		}
		if (i + 1 < a->tpl_len) {
			char c = t[i + 1];
			if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			    (c >= '0' && c <= '9') || c == '_')
				return true;
		}
	}
	return false;
}

/* One value (a whole argument, or one list element) against a type. On failure sets e's
 * message (no location) and returns false. */
static bool atom_ok(const bst_argtype *t, bst_str s, bst_err *e)
{
	char tok[BST_SCHEMA_MAX_TOKEN_SHOWN + 8];
	for (size_t i = 0; t->keywords != NULL && t->keywords[i] != NULL; i++)
		if (strlen(t->keywords[i]) == s.len && memcmp(t->keywords[i], s.p, s.len) == 0)
			return true;
	bst_cfg_shown(s.p, s.len, tok, sizeof tok);
	bool ok = true;
	union {
		uint64_t u;
		bst_rate r;
		bool b;
		size_t i;
		int64_t n;
		uint8_t p;
		uint32_t m;
		bst_cidr c;
	} out;
	switch (t->kind) {
	case BST_T_STRING:
		break;
	case BST_T_PATH:
		if (s.len == 0) {
			bst_err_set(e, "expected a non-empty path");
			ok = false;
		}
		break;
	case BST_T_SIZE:
		ok = bst_parse_size(s, &out.u);
		if (!ok)
			bst_err_set(e, "expected a size (for example 16k), got \"%s\"", tok);
		break;
	case BST_T_DURATION:
		ok = bst_parse_duration_us(s, &out.u);
		if (!ok)
			bst_err_set(e, "expected a duration with a unit (for example 30s), got \"%s\"",
				    tok);
		break;
	case BST_T_RATE:
		ok = bst_parse_rate(s, &out.r);
		if (!ok)
			bst_err_set(e, "expected a non-zero rate (for example 100/s), got \"%s\"", tok);
		break;
	case BST_T_BOOL:
		ok = bst_parse_bool(s, &out.b);
		if (!ok)
			bst_err_set(e, "expected on or off, got \"%s\"", tok);
		break;
	case BST_T_ENUM:
		ok = bst_parse_enum(s, t->enum_values, &out.i);
		if (!ok) {
			char list[160];
			bst_join_names(t->enum_values, list, sizeof list);
			bst_err_set(e, "expected one of %s, got \"%s\"", list, tok);
		}
		break;
	case BST_T_INT:
		ok = bst_parse_int(s, t->min, t->max, &out.n);
		if (!ok)
			bst_err_set(e, "expected an integer in %lld..%lld, got \"%s\"",
				    (long long)t->min, (long long)t->max, tok);
		break;
	case BST_T_PERCENT:
		ok = bst_parse_percent(s, &out.p);
		if (!ok)
			bst_err_set(e, "expected a percentage 0%%..100%%, got \"%s\"", tok);
		break;
	case BST_T_CIDR:
		ok = bst_cidr_parse(s, &out.c);
		if (!ok)
			bst_err_set(e, "expected a CIDR such as 10.0.0.0/8, got \"%s\"", tok);
		break;
	case BST_T_MODE:
		ok = bst_parse_mode(s, &out.m);
		if (!ok)
			bst_err_set(e, "expected a file mode such as 0600, got \"%s\"", tok);
		break;
	default:
		bst_err_set(e, "internal: bad value type");
		ok = false;
	}
	if (!ok && e != NULL && t->keywords != NULL && t->keywords[0] != NULL) {
		char kw[96];
		bst_join_names(t->keywords, kw, sizeof kw);
		size_t l = strlen(e->msg);
		snprintf(e->msg + l, sizeof e->msg - l, " (or one of: %s)", kw);
	}
	return ok;
}

void bst_schema_set_tpl_check(bst_schema *s, bst_tpl_check_fn fn)
{
	s->tpl_check = fn;
}

static int check_value(const bst_schema *s, const bst_argtype *t, const bst_ast_arg *a, bst_err *e)
{
	if (t->kind == BST_T_TEMPLATE)
		return s != NULL && s->tpl_check != NULL ? s->tpl_check(a, e) : 0;
	if (has_variable(a)) {
		char tok[BST_SCHEMA_MAX_TOKEN_SHOWN + 8];
		bst_cfg_shown(a->text, a->len, tok, sizeof tok);
		bst_err_set(e, "variable not allowed here (\"%s\"): this argument is a %s", tok,
			    bst_vtype_name(t->kind));
		bst_cfg_err_at(e, &a->loc);
		return -1;
	}
	bool ok = true;
	if (!t->list) {
		ok = atom_ok(t, (bst_str){ a->text, (uint32_t)a->len }, e);
	} else {
		size_t start = 0;
		for (size_t i = 0; ok && i <= a->len; i++) {
			if (i < a->len && a->text[i] != ',')
				continue;
			if (i == start) {
				bst_err_set(e, "empty element in a comma-separated list");
				ok = false;
			} else {
				ok = atom_ok(t, (bst_str){ a->text + start, (uint32_t)(i - start) }, e);
			}
			start = i + 1;
		}
	}
	if (!ok)
		bst_cfg_err_at(e, &a->loc);
	return ok ? 0 : -1;
}

size_t npos_of(const bst_argspec *sp)
{
	size_t n = 0;
	while (n < BST_ARGSPEC_MAX_POS && sp->pos[n].kind != BST_T_NONE)
		n++;
	return n;
}

/* The one argument classifier, shared by validation and the bst_dir_* accessors. */
enum { CLS_POS = -1, CLS_SUB = -2, CLS_REQ = -3 };

static bool is_require(const bst_directive *d, const bst_ast_arg *a)
{
	return d->require && a->kind == BST_TOK_WORD && a->len == 7 &&
	       memcmp(a->text, "require", 7) == 0;
}

/* Option index (>= 0) or CLS_*. Declared keys match bare and quoted words alike. */
static int arg_class(const bst_directive *d, const bst_ast_arg *args, size_t nargs, size_t i)
{
	if (i == 0 && d->subname != NULL)
		return CLS_SUB;
	if (i + 1 == nargs && is_require(d, &args[i]))
		return CLS_REQ;
	for (size_t k = 0; k < d->args.nopts; k++) {
		size_t kl = strlen(d->args.opts[k].key);
		if (args[i].len >= kl && memcmp(args[i].text, d->args.opts[k].key, kl) == 0)
			return (int)k;
	}
	return CLS_POS;
}

static void opt_value(const bst_ast_arg *a, size_t kl, bst_ast_arg *val)
{
	*val = *a;
	val->text += kl;
	val->len -= kl;
	/* The key is plain config text, so tpl starts with it too. */
	val->tpl = a->tpl + kl;
	val->tpl_len = a->tpl_len - kl;
}

/* A bare word shaped like `name=`: ^[a-z][a-z0-9_]*= */
static bool option_shaped(const bst_ast_arg *a)
{
	if (a->kind != BST_TOK_WORD || a->len < 2 || a->text[0] < 'a' || a->text[0] > 'z')
		return false;
	for (size_t i = 1; i < a->len; i++) {
		char c = a->text[i];
		if (c == '=')
			return true;
		if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'))
			return false;
	}
	return false;
}

static int unknown_option(const bst_directive *d, const char *label, const bst_ast_arg *a,
			  bst_err *e)
{
	const bst_argspec *sp = &d->args;
	size_t kl = 0;
	while (a->text[kl] != '=')
		kl++;
	kl++;
	char tok[BST_SCHEMA_MAX_TOKEN_SHOWN + 8];
	bst_cfg_shown(a->text, kl, tok, sizeof tok);
	if (sp->nopts == 0) {
		bst_err_set(e,
			    "\"%s\" takes no options, got \"%s\" "
			    "(quote the word to use it literally)",
			    label, tok);
	} else {
		const char *best = NULL;
		unsigned bd = BST_SUGGEST_MAX_DIST + 1;
		char list[160] = "";
		size_t n = 0;
		for (size_t k = 0; k < sp->nopts; k++) {
			const char *key = sp->opts[k].key;
			unsigned dist = bst_lev_bounded(a->text, kl - 1, key, strlen(key) - 1,
						    BST_SUGGEST_MAX_DIST);
			if (dist < bd) {
				bd = dist;
				best = key;
			}
			int w = snprintf(list + n, sizeof list - n, "%s%s", n ? ", " : "", key);
			if (w > 0 && (size_t)w < sizeof list - n)
				n += (size_t)w;
		}
		if (best != NULL)
			bst_err_set(e,
				    "unknown option \"%s\", did you mean \"%s\"? (valid: %s) "
				    "(quote the word to use it literally)",
				    tok, best, list);
		else
			bst_err_set(e,
				    "unknown option \"%s\" (valid: %s) "
				    "(quote the word to use it literally)",
				    tok, list);
	}
	bst_cfg_err_at(e, &a->loc);
	return -1;
}

/* Arguments only (shared by AST nodes and defaults). `where` locates count errors. */
int check_args(const bst_schema *s, const bst_directive *d, const char *label,
	       const bst_ast_arg *args, size_t nargs, const bst_loc *where, bst_err *e)
{
	const bst_argspec *sp = &d->args;
	bool seen[BST_ARGSPEC_MAX_OPTS] = { false };
	size_t npos = npos_of(sp), count = 0;
	for (size_t i = 0; i < nargs; i++) {
		const bst_ast_arg *a = &args[i];
		int cls = arg_class(d, args, nargs, i);
		if (cls == CLS_SUB || cls == CLS_REQ)
			continue;
		if (cls >= 0) {
			const bst_optspec *o = &sp->opts[cls];
			size_t kl = strlen(o->key);
			if (a->len == kl) {
				bst_err_set(e, "option \"%s\" has an empty value", o->key);
				bst_cfg_err_at(e, &a->loc);
				return -1;
			}
			if (bst_parse_kv((bst_str){ a->text, (uint32_t)a->len }, o->key,
					 &(bst_str){ 0 }, &seen[cls]) < 0) {
				bst_err_set(e, "repeated option \"%s\"", o->key);
				bst_cfg_err_at(e, &a->loc);
				return -1;
			}
			bst_ast_arg val;
			opt_value(a, kl, &val);
			if (check_value(s, &o->type, &val, e) != 0)
				return -1;
			continue;
		}
		if (option_shaped(a))
			return unknown_option(d, label, a, e);
		if (count >= sp->max_args) {
			bst_err_set(e, "\"%s\" takes at most %u argument%s", label,
				    (unsigned)sp->max_args, sp->max_args == 1 ? "" : "s");
			bst_cfg_err_at(e, &a->loc);
			return -1;
		}
		const bst_argtype *t = &sp->pos[npos ? (count < npos ? count : npos - 1) : 0];
		if (npos != 0 && check_value(s, t, a, e) != 0)
			return -1;
		count++;
	}
	if (count < sp->min_args) {
		bst_err_set(e, "\"%s\" takes at least %u argument%s", label,
			    (unsigned)sp->min_args, sp->min_args == 1 ? "" : "s");
		bst_cfg_err_at(e, where);
		return -1;
	}
	for (size_t k = 0; k < sp->nopts; k++) {
		if (sp->opts[k].required && !seen[k]) {
			bst_err_set(e, "\"%s\" is missing required option \"%s\"", label,
				    sp->opts[k].key);
			bst_cfg_err_at(e, where);
			return -1;
		}
	}
	return 0;
}

size_t bst_dir_npos(const bst_directive *d, const bst_ast_node *n)
{
	size_t count = 0;
	for (size_t i = 0; i < n->nargs; i++)
		if (arg_class(d, n->args, n->nargs, i) == CLS_POS)
			count++;
	return count;
}

const bst_ast_arg *bst_dir_pos(const bst_directive *d, const bst_ast_node *n, size_t want)
{
	size_t count = 0;
	for (size_t i = 0; i < n->nargs; i++) {
		if (arg_class(d, n->args, n->nargs, i) != CLS_POS)
			continue;
		if (count++ == want)
			return &n->args[i];
	}
	return NULL;
}

bool bst_dir_opt(const bst_directive *d, const bst_ast_node *n, const char *key,
		 bst_ast_arg *val)
{
	for (size_t i = 0; i < n->nargs; i++) {
		int cls = arg_class(d, n->args, n->nargs, i);
		if (cls >= 0 && strcmp(d->args.opts[cls].key, key) == 0) {
			opt_value(&n->args[i], strlen(key), val);
			return true;
		}
	}
	return false;
}

bool bst_dir_has_require(const bst_directive *d, const bst_ast_node *n)
{
	return n->nargs > 0 && arg_class(d, n->args, n->nargs, n->nargs - 1) == CLS_REQ;
}

int bst_directive_check_node(const bst_schema *s, const bst_directive *d, const bst_ast_node *n,
			     bst_err *e)
{
	char label[BST_SCHEMA_MAX_TOKEN_SHOWN + 8];
	bst_cfg_shown(n->name, n->name_len, label, sizeof label);
	if (check_args(s, d, label, n->args, n->nargs, &n->loc, e) != 0)
		return -1;
	if (d->args.block == BST_BLOCK_FORBIDDEN && n->has_block) {
		bst_err_set(e, "\"%s\" does not take a block", label);
		bst_cfg_err_at(e, &n->loc);
		return -1;
	}
	if (d->args.block == BST_BLOCK_REQUIRED && !n->has_block) {
		bst_err_set(e, "\"%s\" requires a block", label);
		bst_cfg_err_at(e, &n->loc);
		return -1;
	}
	return 0;
}
