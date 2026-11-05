#include "config/schema.h"

#include "config/values.h"
#include "core/cidr.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern const bst_dirtab *const __start_bst_directives[] __attribute__((weak));
extern const bst_dirtab *const __stop_bst_directives[] __attribute__((weak));

const bst_dirtab *const *bst_dirtabs(size_t *n)
{
	if (__start_bst_directives == NULL || __stop_bst_directives == NULL) {
		*n = 0;
		return NULL;
	}
	*n = (size_t)(__stop_bst_directives - __start_bst_directives);
	return __start_bst_directives;
}

/* ---- Names ---- */

#define BST_CTX_X_NAME(n, s) s,
static const char *const ctx_names[BST_CTX_COUNT] = { BST_CTX_LIST(BST_CTX_X_NAME) };

const char *bst_ctx_name(uint32_t ctx)
{
	for (unsigned i = 0; i < BST_CTX_COUNT; i++)
		if (ctx == 1u << i)
			return ctx_names[i];
	return "?";
}

static const char *const vtype_names[BST_T_COUNT_] = {
	[BST_T_NONE] = "none",	   [BST_T_STRING] = "string",   [BST_T_TEMPLATE] = "template",
	[BST_T_SIZE] = "size",	   [BST_T_DURATION] = "duration", [BST_T_RATE] = "rate",
	[BST_T_BOOL] = "bool",	   [BST_T_ENUM] = "enum",	[BST_T_INT] = "int",
	[BST_T_PERCENT] = "percent", [BST_T_PATH] = "path",	[BST_T_CIDR] = "cidr",
};

const char *bst_vtype_name(bst_vtype t)
{
	return (unsigned)t < BST_T_COUNT_ ? vtype_names[t] : "?";
}

/* Comma-separated context names of a mask, in bit order. */
static void ctx_list(uint32_t mask, char *buf, size_t cap)
{
	size_t n = 0;
	buf[0] = 0;
	for (unsigned i = 0; i < BST_CTX_COUNT; i++) {
		if (!(mask & (1u << i)))
			continue;
		int w = snprintf(buf + n, cap - n, "%s%s", n ? ", " : "", ctx_names[i]);
		if (w < 0 || (size_t)w >= cap - n)
			return;
		n += (size_t)w;
	}
}

/* Printable, bounded copy of untrusted input for an error message. */
static void shown(const char *s, size_t len, char *out, size_t cap)
{
	size_t n = 0, lim = len < BST_SCHEMA_MAX_TOKEN_SHOWN ? len : BST_SCHEMA_MAX_TOKEN_SHOWN;
	for (size_t i = 0; i < lim && n + 4 < cap; i++) {
		unsigned char c = (unsigned char)s[i];
		out[n++] = (c >= 0x20 && c < 0x7f && c != '"' && c != '\\') ? (char)c : '?';
	}
	if (lim < len && n + 4 < cap) {
		out[n++] = '.';
		out[n++] = '.';
		out[n++] = '.';
	}
	out[n] = 0;
}

static void err_at(bst_err *e, const bst_loc *loc)
{
	if (e == NULL)
		return;
	e->file = loc ? loc->file : NULL;
	e->line = loc ? loc->line : 0;
	e->col = loc ? loc->col : 0;
}

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

static int check_value(const bst_argtype *t, const bst_ast_arg *a, bst_err *e)
{
	char tok[BST_SCHEMA_MAX_TOKEN_SHOWN + 8];
	bst_str s = { a->text, (uint32_t)a->len };
	if (t->kind == BST_T_TEMPLATE)
		return 0;
	shown(a->text, a->len, tok, sizeof tok);
	if (has_variable(a)) {
		bst_err_set(e, "variable not allowed here (\"%s\"): this argument is a %s", tok,
			    bst_vtype_name(t->kind));
		err_at(e, &a->loc);
		return -1;
	}
	bool ok = true;
	union {
		uint64_t u;
		bst_rate r;
		bool b;
		size_t i;
		int64_t n;
		uint8_t p;
		bst_cidr c;
	} out;
	switch (t->kind) {
	case BST_T_STRING:
		break;
	case BST_T_PATH:
		if (a->len == 0) {
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
			char list[160] = "";
			size_t n = 0;
			for (size_t i = 0; t->enum_values[i] != NULL; i++) {
				int w = snprintf(list + n, sizeof list - n, "%s%s", n ? ", " : "",
						 t->enum_values[i]);
				if (w < 0 || (size_t)w >= sizeof list - n)
					break;
				n += (size_t)w;
			}
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
	default:
		bst_err_set(e, "internal: bad value type");
		ok = false;
	}
	if (!ok)
		err_at(e, &a->loc);
	return ok ? 0 : -1;
}

static size_t npos_of(const bst_argspec *sp)
{
	size_t n = 0;
	while (n < BST_ARGSPEC_MAX_POS && sp->pos[n].kind != BST_T_NONE)
		n++;
	return n;
}

/* Arguments only (shared by AST nodes and defaults). `where` locates count errors. */
static int check_args(const bst_directive *d, const bst_ast_arg *args, size_t nargs,
		      const bst_loc *where, bst_err *e)
{
	const bst_argspec *sp = &d->args;
	if (d->require && nargs > 0 && args[nargs - 1].kind == BST_TOK_WORD &&
	    args[nargs - 1].len == 7 && memcmp(args[nargs - 1].text, "require", 7) == 0)
		nargs--;

	bool seen[BST_ARGSPEC_MAX_OPTS] = { false };
	size_t npos = npos_of(sp), count = 0;
	for (size_t i = 0; i < nargs; i++) {
		const bst_ast_arg *a = &args[i];
		bool is_opt = false;
		if (a->kind == BST_TOK_WORD) {
			for (size_t k = 0; k < sp->nopts; k++) {
				const bst_optspec *o = &sp->opts[k];
				size_t kl = strlen(o->key);
				if (a->len < kl || memcmp(a->text, o->key, kl) != 0)
					continue;
				is_opt = true;
				if (a->len == kl) {
					bst_err_set(e, "option \"%s\" has an empty value", o->key);
					err_at(e, &a->loc);
					return -1;
				}
				bst_str v;
				if (bst_parse_kv((bst_str){ a->text, (uint32_t)a->len }, o->key, &v,
						 &seen[k]) < 0) {
					bst_err_set(e, "repeated option \"%s\"", o->key);
					err_at(e, &a->loc);
					return -1;
				}
				bst_ast_arg val = *a;
				val.text += kl;
				val.len -= kl;
				/* The key is plain config text, so tpl starts with it too. */
				val.tpl = a->tpl + kl;
				val.tpl_len = a->tpl_len - kl;
				if (check_value(&o->type, &val, e) != 0)
					return -1;
				break;
			}
		}
		if (is_opt)
			continue;
		if (count >= sp->max_args) {
			bst_err_set(e, "\"%s\" takes at most %u argument%s", d->name,
				    (unsigned)sp->max_args, sp->max_args == 1 ? "" : "s");
			err_at(e, &a->loc);
			return -1;
		}
		const bst_argtype *t = &sp->pos[npos ? (count < npos ? count : npos - 1) : 0];
		if (npos != 0 && check_value(t, a, e) != 0)
			return -1;
		count++;
	}
	if (count < sp->min_args) {
		bst_err_set(e, "\"%s\" takes at least %u argument%s", d->name,
			    (unsigned)sp->min_args, sp->min_args == 1 ? "" : "s");
		err_at(e, where);
		return -1;
	}
	for (size_t k = 0; k < sp->nopts; k++) {
		if (sp->opts[k].required && !seen[k]) {
			bst_err_set(e, "\"%s\" is missing required option \"%s\"", d->name,
				    sp->opts[k].key);
			err_at(e, where);
			return -1;
		}
	}
	return 0;
}

int bst_directive_check_node(const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	if (check_args(d, n->args, n->nargs, &n->loc, e) != 0)
		return -1;
	if (d->args.block == BST_BLOCK_FORBIDDEN && n->has_block) {
		bst_err_set(e, "\"%s\" does not take a block", d->name);
		err_at(e, &n->loc);
		return -1;
	}
	if (d->args.block == BST_BLOCK_REQUIRED && !n->has_block) {
		bst_err_set(e, "\"%s\" requires a block", d->name);
		err_at(e, &n->loc);
		return -1;
	}
	return 0;
}

/* ---- Integrity ---- */

static int bad(bst_err *e, const bst_directive *d, const char *what)
{
	bst_err_set(e, "directive \"%s\": %s", d->name ? d->name : "(null)", what);
	return -1;
}

static int check_type(const bst_directive *d, const bst_argtype *t, bst_err *e)
{
	if ((unsigned)t->kind <= BST_T_NONE || (unsigned)t->kind >= BST_T_COUNT_)
		return bad(e, d, "argument type is invalid");
	if (t->kind == BST_T_ENUM && (t->enum_values == NULL || t->enum_values[0] == NULL))
		return bad(e, d, "enum type has no values");
	if (t->kind == BST_T_INT && t->min > t->max)
		return bad(e, d, "int type has min > max");
	return 0;
}

static int check_default(const bst_directive *d, bst_err *e)
{
	char buf[BST_SCHEMA_DEFAULT_MAX_LEN];
	bst_ast_arg args[BST_SCHEMA_DEFAULT_MAX_ARGS];
	size_t n = 0, len = strlen(d->default_value);
	if (len >= sizeof buf)
		return bad(e, d, "default value is too long");
	memcpy(buf, d->default_value, len + 1);
	size_t i = 0;
	while (i < len) {
		while (i < len && buf[i] == ' ')
			i++;
		if (i >= len)
			break;
		size_t start = i;
		while (i < len && buf[i] != ' ')
			i++;
		if (n >= BST_SCHEMA_DEFAULT_MAX_ARGS)
			return bad(e, d, "default has too many arguments");
		buf[i < len ? i : len] = 0;
		args[n] = (bst_ast_arg){ .kind = BST_TOK_WORD, .text = buf + start,
					 .len = i - start, .tpl = buf + start,
					 .tpl_len = i - start };
		n++;
		i++;
	}
	bst_err inner;
	memset(&inner, 0, sizeof inner);
	if (check_args(d, args, n, NULL, &inner) != 0) {
		bst_err_set(e, "directive \"%s\": default \"%s\" does not parse: %s", d->name,
			    d->default_value, inner.msg);
		return -1;
	}
	return 0;
}

int bst_directive_check(const bst_directive *d, bst_err *e)
{
	if (d->name == NULL || d->name[0] == 0)
		return bad(e, d, "empty name");
	size_t nl = strlen(d->name);
	if (nl > BST_SCHEMA_MAX_NAME)
		return bad(e, d, "name is too long");
	for (size_t i = 0; i < nl; i++) {
		char c = d->name[i];
		if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'))
			return bad(e, d, "name must be lower-case letters, digits and '_'");
	}
	if (d->doc == NULL || d->doc[0] == 0)
		return bad(e, d, "doc is required and must be non-empty");
	if (d->contexts == 0 || (d->contexts & ~BST_CTX_ALL) != 0)
		return bad(e, d, "contexts must be a non-empty set of BST_CTX_* bits");
	const bst_argspec *sp = &d->args;
	if (sp->min_args > sp->max_args)
		return bad(e, d, "min_args > max_args");
	size_t npos = npos_of(sp);
	for (size_t i = npos; i < BST_ARGSPEC_MAX_POS; i++)
		if (sp->pos[i].kind != BST_T_NONE)
			return bad(e, d, "positional types must be contiguous");
	if (sp->max_args > 0 && npos == 0)
		return bad(e, d, "takes arguments but declares no positional type");
	for (size_t i = 0; i < npos; i++)
		if (check_type(d, &sp->pos[i], e) != 0)
			return -1;
	if (sp->nopts > BST_ARGSPEC_MAX_OPTS || (sp->nopts > 0 && sp->opts == NULL))
		return bad(e, d, "bad option list");
	for (size_t k = 0; k < sp->nopts; k++) {
		const char *key = sp->opts[k].key;
		size_t kl = key ? strlen(key) : 0;
		if (kl < 2 || key[kl - 1] != '=')
			return bad(e, d, "option key must be non-empty and end with '='");
		if (check_type(d, &sp->opts[k].type, e) != 0)
			return -1;
		for (size_t j = 0; j < k; j++)
			if (strcmp(sp->opts[j].key, key) == 0)
				return bad(e, d, "duplicate option key");
	}
	if (sp->block > BST_BLOCK_OPTIONAL)
		return bad(e, d, "bad block rule");
	if (sp->block == BST_BLOCK_FORBIDDEN) {
		if (d->child_ctx != 0)
			return bad(e, d, "child_ctx set but the directive takes no block");
	} else if (d->child_ctx == 0 || (d->child_ctx & (d->child_ctx - 1)) != 0 ||
		   (d->child_ctx & ~BST_CTX_ALL) != 0) {
		return bad(e, d, "a block needs child_ctx set to exactly one BST_CTX_* bit");
	}
#ifndef BST_TEST
	if (d->apply == NULL)
		return bad(e, d, "apply is required");
#endif
	if (d->default_value != NULL && check_default(d, e) != 0)
		return -1;
	return 0;
}

/* ---- Schema index ---- */

struct bst_schema {
	const bst_directive **idx; /* sorted by name; position is the directive id */
	size_t n;
};

static int cmp_name(const char *a, size_t al, const char *b, size_t bl)
{
	size_t m = al < bl ? al : bl;
	int c = memcmp(a, b, m);
	if (c != 0)
		return c;
	return al < bl ? -1 : al > bl ? 1 : 0;
}

static int cmp_dir(const void *x, const void *y)
{
	const bst_directive *a = *(const bst_directive *const *)x;
	const bst_directive *b = *(const bst_directive *const *)y;
	int c = strcmp(a->name, b->name);
	if (c != 0)
		return c;
	return a < b ? -1 : a > b ? 1 : 0;
}

bst_schema *bst_schema_build(const bst_dirtab *const *tabs, size_t n, bst_err *e)
{
	size_t total = 0;
	for (size_t t = 0; t < n; t++) {
		if (tabs[t]->n > BST_SCHEMA_MAX_DIRECTIVES ||
		    total + tabs[t]->n > BST_SCHEMA_MAX_DIRECTIVES) {
			bst_err_set(e, "too many directives (max %d)", BST_SCHEMA_MAX_DIRECTIVES);
			return NULL;
		}
		total += tabs[t]->n;
	}
	bst_schema *s = calloc(1, sizeof *s);
	const bst_directive **idx = calloc(total ? total : 1, sizeof *idx);
	if (s == NULL || idx == NULL) {
		free(s);
		free(idx);
		bst_err_set(e, "out of memory");
		return NULL;
	}
	s->idx = idx;
	size_t k = 0;
	for (size_t t = 0; t < n; t++) {
		for (size_t i = 0; i < tabs[t]->n; i++) {
			const bst_directive *d = &tabs[t]->dirs[i];
			if (bst_directive_check(d, e) != 0)
				goto fail;
			idx[k++] = d;
		}
	}
	s->n = k;
	qsort(idx, k, sizeof *idx, cmp_dir);
	for (size_t i = 0; i < k; i++) {
		for (size_t j = i + 1; j < k && strcmp(idx[j]->name, idx[i]->name) == 0; j++) {
			uint32_t both = idx[i]->contexts & idx[j]->contexts;
			if (both != 0) {
				char list[200];
				ctx_list(both, list, sizeof list);
				bst_err_set(e, "directive \"%s\" is registered twice in: %s",
					    idx[i]->name, list);
				goto fail;
			}
		}
	}
	return s;
fail:
	bst_schema_free(s);
	return NULL;
}

void bst_schema_free(bst_schema *s)
{
	if (s == NULL)
		return;
	free(s->idx);
	free(s);
}

/* First index position whose name is >= name. */
static size_t lower_bound(const bst_schema *s, const char *name, size_t len)
{
	size_t lo = 0, hi = s->n;
	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;
		const char *en = s->idx[mid]->name;
		if (cmp_name(en, strlen(en), name, len) < 0)
			lo = mid + 1;
		else
			hi = mid;
	}
	return lo;
}

static bool name_at(const bst_schema *s, size_t i, const char *name, size_t len)
{
	return i < s->n && cmp_name(s->idx[i]->name, strlen(s->idx[i]->name), name, len) == 0;
}

static bool find_id(const bst_schema *s, const char *name, size_t len, uint32_t ctx,
		    size_t *id)
{
	for (size_t i = lower_bound(s, name, len); name_at(s, i, name, len); i++) {
		if (s->idx[i]->contexts & ctx) {
			*id = i;
			return true;
		}
	}
	return false;
}

const bst_directive *bst_schema_find(const bst_schema *s, const char *name, size_t len,
				     uint32_t ctx)
{
	size_t id;
	return find_id(s, name, len, ctx, &id) ? s->idx[id] : NULL;
}

/* ---- Registry ---- */

static pthread_once_t reg_once = PTHREAD_ONCE_INIT;
static bst_schema *reg_schema;
static bst_err reg_err;

static void reg_init(void)
{
	size_t n;
	const bst_dirtab *const *tabs = bst_dirtabs(&n);
	reg_schema = bst_schema_build(tabs, n, &reg_err);
}

const bst_schema *bst_schema_registry(bst_err *e)
{
	pthread_once(&reg_once, reg_init);
	if (reg_schema == NULL && e != NULL)
		*e = reg_err;
	return reg_schema;
}

/* ---- Suggestions ---- */

/* Levenshtein distance, or max+1 when it exceeds max. Names are short (checked). */
static unsigned lev_bounded(const char *a, size_t al, const char *b, size_t bl, unsigned max)
{
	if ((al > bl ? al - bl : bl - al) > max || al > BST_SCHEMA_MAX_NAME ||
	    bl > BST_SCHEMA_MAX_NAME)
		return max + 1;
	unsigned prev[BST_SCHEMA_MAX_NAME + 1], cur[BST_SCHEMA_MAX_NAME + 1];
	for (size_t j = 0; j <= bl; j++)
		prev[j] = (unsigned)j;
	for (size_t i = 1; i <= al; i++) {
		cur[0] = (unsigned)i;
		unsigned rowmin = cur[0];
		for (size_t j = 1; j <= bl; j++) {
			unsigned sub = prev[j - 1] + (a[i - 1] == b[j - 1] ? 0u : 1u);
			unsigned del = prev[j] + 1, ins = cur[j - 1] + 1;
			unsigned v = sub < del ? sub : del;
			cur[j] = v < ins ? v : ins;
			if (cur[j] < rowmin)
				rowmin = cur[j];
		}
		if (rowmin > max)
			return max + 1;
		memcpy(prev, cur, (bl + 1) * sizeof prev[0]);
	}
	return prev[bl];
}

/* Closest name valid in ctx within the bound; the index is sorted, so on equal distance
 * the alphabetically first wins. */
static const char *suggest(const bst_schema *s, const char *name, size_t len, uint32_t ctx)
{
	const char *best = NULL;
	unsigned bd = BST_SUGGEST_MAX_DIST + 1;
	for (size_t i = 0; i < s->n; i++) {
		if (!(s->idx[i]->contexts & ctx))
			continue;
		unsigned d = lev_bounded(name, len, s->idx[i]->name, strlen(s->idx[i]->name),
					 BST_SUGGEST_MAX_DIST);
		if (d < bd) {
			bd = d;
			best = s->idx[i]->name;
		}
	}
	return best;
}

/* ---- Validation walk ---- */

#define MAX_SCOPES (BST_CFG_MAX_NESTING + 2)

static int unknown_or_wrong_ctx(const bst_schema *s, const bst_ast_node *n, uint32_t ctx,
				bst_err *e)
{
	char tok[BST_SCHEMA_MAX_TOKEN_SHOWN + 8], list[200];
	shown(n->name, n->name_len, tok, sizeof tok);
	uint32_t elsewhere = 0;
	for (size_t i = lower_bound(s, n->name, n->name_len);
	     name_at(s, i, n->name, n->name_len); i++)
		elsewhere |= s->idx[i]->contexts;
	if (elsewhere != 0) {
		ctx_list(elsewhere, list, sizeof list);
		bst_err_set(e, "\"%s\" is not valid in %s; valid in: %s", tok, bst_ctx_name(ctx),
			    list);
	} else {
		const char *sug = suggest(s, n->name, n->name_len, ctx);
		if (sug != NULL)
			bst_err_set(e, "unknown directive \"%s\", did you mean \"%s\"?", tok, sug);
		else
			bst_err_set(e, "unknown directive \"%s\"", tok);
	}
	err_at(e, &n->loc);
	return -1;
}

int bst_cfg_validate_with(const bst_schema *s, const bst_ast *ast, bst_err *e)
{
	const bst_ast_node *owner[MAX_SCOPES];
	uint32_t ctx[MAX_SCOPES], gen[MAX_SCOPES];
	uint32_t *stamp = NULL;
	const bst_ast_node **first = NULL;
	int rc = -1;
	size_t nd = s->n;

	if (nd > 0) {
		stamp = calloc(MAX_SCOPES * nd, sizeof *stamp);
		first = calloc(MAX_SCOPES * nd, sizeof *first);
		if (stamp == NULL || first == NULL) {
			bst_err_set(e, "out of memory");
			goto out;
		}
	}
	uint32_t next_gen = 0;
	size_t depth = 0;
	owner[0] = &ast->root;
	ctx[0] = BST_CTX_GLOBAL;
	gen[0] = ++next_gen;
	const bst_ast_node *n = ast->root.children;
	for (;;) {
		if (n == NULL) {
			if (depth == 0)
				break;
			n = owner[depth]->next;
			depth--;
			continue;
		}
		size_t id;
		if (!find_id(s, n->name, n->name_len, ctx[depth], &id)) {
			unknown_or_wrong_ctx(s, n, ctx[depth], e);
			goto out;
		}
		const bst_directive *d = s->idx[id];
		if (bst_directive_check_node(d, n, e) != 0)
			goto out;
		if (!d->repeatable) {
			size_t slot = depth * nd + id;
			if (stamp[slot] == gen[depth]) {
				const bst_loc *f = &first[slot]->loc;
				bst_err_set(e, "duplicate \"%s\" (first at %s:%d:%d)", d->name,
					    f->file ? f->file : "?", f->line, f->col);
				err_at(e, &n->loc);
				goto out;
			}
			stamp[slot] = gen[depth];
			first[slot] = n;
		}
		if (n->has_block) {
			if (depth + 1 >= MAX_SCOPES) {
				bst_err_set(e, "blocks nested deeper than %d", BST_CFG_MAX_NESTING);
				err_at(e, &n->loc);
				goto out;
			}
			depth++;
			owner[depth] = n;
			ctx[depth] = d->child_ctx;
			gen[depth] = ++next_gen;
			n = n->children;
		} else {
			n = n->next;
		}
	}
	rc = 0;
out:
	free(stamp);
	free(first);
	return rc;
}

int bst_cfg_validate(const bst_ast *ast, bst_err *e)
{
	const bst_schema *s = bst_schema_registry(e);
	if (s == NULL)
		return -1;
	return bst_cfg_validate_with(s, ast, e);
}
