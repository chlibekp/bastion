#include "config/schema.h"

#include "config/errfmt.h"
#include "config/schema_priv.h"
#include "config/values.h"

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
	[BST_T_MODE] = "mode",
};

const char *bst_vtype_name(bst_vtype t)
{
	return (unsigned)t < BST_T_COUNT_ ? vtype_names[t] : "?";
}

/* Comma-separated context names of a mask, in bit order. */
void bst_ctx_list(uint32_t mask, char *buf, size_t cap)
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

/* "a, b, c" from a NULL-terminated list, truncated to fit. */
void bst_join_names(const char *const *names, char *buf, size_t cap)
{
	size_t n = 0;
	buf[0] = 0;
	for (size_t i = 0; names != NULL && names[i] != NULL; i++) {
		int w = snprintf(buf + n, cap - n, "%s%s", n ? ", " : "", names[i]);
		if (w < 0 || (size_t)w >= cap - n)
			return;
		n += (size_t)w;
	}
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
	if ((t->kind == BST_T_SIZE || t->kind == BST_T_DURATION || t->kind == BST_T_RATE) &&
	    (t->min < 0 || t->max < 0 || (t->max > 0 && t->min > t->max)))
		return bad(e, d, "size, duration or rate bounds must be 0 (none) or positive, "
				 "with min <= max");
	if (t->empty_ok && t->kind != BST_T_STRING && t->kind != BST_T_TEMPLATE)
		return bad(e, d, "empty_ok applies to string and template types only");
	for (size_t i = 0; t->keywords != NULL && t->keywords[i] != NULL; i++)
		if (t->keywords[i][0] == 0)
			return bad(e, d, "empty keyword");
	return 0;
}

static int check_default(const bst_directive *d, bst_err *e)
{
	char buf[BST_SCHEMA_DEFAULT_MAX_LEN];
	bst_ast_arg args[BST_SCHEMA_DEFAULT_MAX_ARGS];
	size_t n = 0, len = strlen(d->default_value);
	if (d->subname != NULL) {
		args[n++] = (bst_ast_arg){ .kind = BST_TOK_WORD, .text = d->subname,
					   .len = strlen(d->subname), .tpl = d->subname,
					   .tpl_len = strlen(d->subname) };
	}
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
	if (bst_schema_check_args(NULL, d, d->name, args, n, NULL, &inner) != 0) {
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
	size_t npos = bst_schema_npos_of(sp);
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
		if (kl > BST_SCHEMA_MAX_NAME)
			return bad(e, d, "option key is too long");
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
	if (d->apply == NULL)
		return bad(e, d, "apply is required");
	if (d->subname_exclusive && d->subname == NULL)
		return bad(e, d, "subname_exclusive needs a subname");
	if (d->any_name && !d->repeatable)
		return bad(e, d, "a catch-all (any_name) must be repeatable");
	if (d->any_name && d->subname != NULL)
		return bad(e, d, "a catch-all cannot have a subname");
	if (d->singleton && d->default_value != NULL)
		return bad(e, d, "a singleton block has no default (its children have)");
	if (d->singleton && sp->min_args != 0)
		return bad(e, d, "an absent singleton is synthesised without arguments: min_args must be 0");
	if (d->singleton && (sp->block == BST_BLOCK_FORBIDDEN || d->repeatable || d->any_name ||
			     d->subname != NULL))
		return bad(e, d, "a singleton must be a block that is neither repeatable, "
				 "a catch-all nor two-word");
	if (d->subname != NULL) {
		size_t sl = strlen(d->subname);
		if (sl == 0 || sl > BST_SCHEMA_MAX_NAME)
			return bad(e, d, "subname is empty or too long");
		for (size_t i = 0; i < sl; i++)
			if (d->subname[i] <= ' ' || d->subname[i] >= 0x7f)
				return bad(e, d, "subname must be printable without spaces");
	}
	if (d->default_value != NULL && check_default(d, e) != 0)
		return -1;
	return 0;
}

/* ---- Schema index ---- */

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
	c = strcmp(a->subname ? a->subname : "", b->subname ? b->subname : "");
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
	size_t *any = calloc(total ? total : 1, sizeof *any);
	if (s == NULL || idx == NULL || any == NULL) {
		free(s);
		free(idx);
		free(any);
		bst_err_set(e, "out of memory");
		return NULL;
	}
	s->idx = idx;
	s->any = any;
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
			const char *si = idx[i]->subname, *sj = idx[j]->subname;
			bool same = si == NULL || sj == NULL || strcmp(si, sj) == 0;
			if (both != 0 && same) {
				char list[200];
				bst_ctx_list(both, list, sizeof list);
				bst_err_set(e, "directive \"%s\" is registered twice in: %s",
					    idx[i]->name, list);
				goto fail;
			}
		}
		if (idx[i]->any_name)
			any[s->nany++] = i;
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
	free(s->any);
	free(s);
}

/* First index position whose name is >= name. */
size_t bst_lower_bound(const bst_schema *s, const char *name, size_t len)
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

bool bst_name_at(const bst_schema *s, size_t i, const char *name, size_t len)
{
	return i < s->n && cmp_name(s->idx[i]->name, strlen(s->idx[i]->name), name, len) == 0;
}

/* Exact lookup in ctx. A two-word name needs sub to select the entry: *family is set
 * when the name has two-word entries in ctx (whether or not one matched). */
bool bst_find_id(const bst_schema *s, const char *name, size_t len, uint32_t ctx,
		    const char *sub, size_t sublen, size_t *id, bool *family)
{
	*family = false;
	for (size_t i = bst_lower_bound(s, name, len); bst_name_at(s, i, name, len); i++) {
		const bst_directive *d = s->idx[i];
		if (!(d->contexts & ctx) || d->any_name)
			continue;
		if (d->subname == NULL) {
			*id = i;
			return true;
		}
		*family = true;
		if (sub != NULL && strlen(d->subname) == sublen && memcmp(d->subname, sub, sublen) == 0) {
			*id = i;
			return true;
		}
	}
	return false;
}

bool bst_find_any(const bst_schema *s, uint32_t ctx, size_t *id)
{
	for (size_t i = 0; i < s->nany; i++) {
		if (s->idx[s->any[i]]->contexts & ctx) {
			*id = s->any[i];
			return true;
		}
	}
	return false;
}

const bst_directive *bst_schema_find(const bst_schema *s, const char *name, size_t len,
				     uint32_t ctx)
{
	for (size_t i = bst_lower_bound(s, name, len); bst_name_at(s, i, name, len); i++)
		if ((s->idx[i]->contexts & ctx) && !s->idx[i]->any_name)
			return s->idx[i];
	return NULL;
}

const bst_directive *bst_schema_find_sub(const bst_schema *s, const char *name, size_t len,
					 uint32_t ctx, const char *sub, size_t sublen)
{
	size_t id;
	bool fam;
	return bst_find_id(s, name, len, ctx, sub, sublen, &id, &fam) ? s->idx[id] : NULL;
}

const bst_directive *bst_schema_match(const bst_schema *s, const bst_ast_node *n, uint32_t ctx)
{
	size_t id;
	bool fam;
	const bst_ast_arg *a = n->nargs > 0 ? &n->args[0] : NULL;
	if (bst_find_id(s, n->name, n->name_len, ctx, a ? a->text : NULL, a ? a->len : 0, &id, &fam))
		return s->idx[id];
	if (!fam && bst_find_any(s, ctx, &id))
		return s->idx[id];
	return NULL;
}

size_t bst_schema_count(const bst_schema *s)
{
	return s->n;
}

const bst_directive *bst_schema_at(const bst_schema *s, size_t i)
{
	return i < s->n ? s->idx[i] : NULL;
}

/* Scopes whose directives are inherited from: global -> server -> location. Other
 * contexts (upstream, tcp_profile, ...) do not inherit. */
static uint32_t ancestors(uint32_t kind)
{
	if (kind == BST_CTX_SERVER)
		return BST_CTX_GLOBAL;
	if (kind == BST_CTX_LOCATION)
		return BST_CTX_GLOBAL | BST_CTX_SERVER;
	return 0;
}

int bst_schema_scope_missing(const bst_schema *s, const bst_ast_node *scope, uint32_t kind,
			     bool fresh, size_t **ids, size_t *nids)
{
	uint32_t anc = ancestors(kind);
	size_t n = 0;
	*ids = NULL;
	*nids = 0;
	if (!fresh)
		return 0;
	size_t *cand = malloc((s->n ? s->n : 1) * sizeof *cand);
	if (cand == NULL)
		return -1;
	for (size_t i = 0; i < s->n; i++) {
		const bst_directive *d = s->idx[i];
		if ((d->default_value != NULL || d->singleton) && !d->any_name && (d->contexts & kind) &&
		    !(d->contexts & anc))
			cand[n++] = i;
	}
	if (n == 0) {
		free(cand);
		return 0;
	}
	bool *set = calloc(n, sizeof *set);
	if (set == NULL) {
		free(cand);
		return -1;
	}
	for (const bst_ast_node *c = scope->children; c != NULL; c = c->next) {
		const bst_directive *m = bst_schema_match(s, c, kind);
		if (m == NULL)
			continue;
		for (size_t j = 0; j < n; j++) {
			const bst_directive *d = s->idx[cand[j]];
			/* Any member of an exclusive family counts as the setting being set. */
			if (m == d || (d->subname_exclusive && m->subname_exclusive &&
				       strcmp(m->name, d->name) == 0))
				set[j] = true;
		}
	}
	size_t k = 0;
	for (size_t j = 0; j < n; j++)
		if (!set[j])
			cand[k++] = cand[j];
	free(set);
	if (k == 0) {
		free(cand);
		return 0;
	}
	*ids = cand;
	*nids = k;
	return 0;
}

/* ---- Suggestions ---- */

/* Levenshtein distance, or max+1 when it exceeds max. Names are short (checked). */
unsigned bst_lev_bounded(const char *a, size_t al, const char *b, size_t bl, unsigned max)
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
