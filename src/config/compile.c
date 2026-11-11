/* Config compiler: validate, then apply every directive into scope structs held in one
 * arena. See compile.h for the model (inheritance by struct copy, order independence,
 * defaults through apply, bounded recursion). */
#include "config/compile.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ARENA_CHUNK ((size_t)64 << 10)

/* Compile-wide state, shared by every scope (the bst_cfg_ctx is copied and restored around
 * blocks, so anything that must persist lives behind st_). Freed when compile ends. */
struct bst_cfg_state {
	const bst_loc **srcs; /* AST positions of everything that recorded a bst_cfg_loc */
	size_t nsrcs, srcs_cap;
	bst_arena *scratch;	  /* synthesised default nodes: not part of the config */
	bst_ast_node **synth;	  /* per directive id: its synthesised node, built once */
	size_t nsynth;
	bst_config *cfg;
	bool oom; /* a warning could not be recorded */
};

const bst_loc *bst_cfg_src(bst_cfg_ctx *c, const bst_cfg_loc *loc)
{
	return c->st_->srcs[loc->src_];
}

char *bst_cfg_strdup(bst_cfg_ctx *c, const char *s, size_t len, bst_err *e)
{
	char *p = len == SIZE_MAX ? NULL : bst_arena_alloc(c->arena, len + 1);
	if (p == NULL) {
		bst_err_set(e, "out of memory");
		return NULL;
	}
	memcpy(p, s, len);
	p[len] = 0;
	return p;
}

int bst_cfg_push_owned(bst_cfg_ctx *c, void *arrp, size_t *n, size_t *cap, size_t elt,
		 const void *item, bst_err *e)
{
	void *arr;
	memcpy(&arr, arrp, sizeof arr);
	if (*n == *cap) {
		size_t ncap = *cap ? *cap * 2 : 4, bytes;
		if (*cap > SIZE_MAX / 4 || __builtin_mul_overflow(ncap, elt, &bytes))
			goto oom;
		void *na = bst_arena_alloc(c->arena, bytes);
		if (na == NULL)
			goto oom;
		if (*n > 0)
			memcpy(na, arr, *n * elt);
		arr = na;
		*cap = ncap;
		memcpy(arrp, &arr, sizeof arr);
	}
	memcpy((char *)arr + *n * elt, item, elt);
	(*n)++;
	return 0;
oom:
	bst_err_set(e, "out of memory");
	return -1;
}

/* Lists: the array is the owner's to grow in place (doubling); a scope that is not the
 * owner never writes to it. */
static int list_push(bst_cfg_ctx *c, bst_cfg_list *l, const void *item, bst_err *e)
{
	const void **arr;
	memcpy(&arr, &l->items, sizeof arr);
	if (l->n == l->cap_) {
		size_t ncap = l->cap_ ? l->cap_ * 2 : 4, bytes;
		if (l->cap_ > SIZE_MAX / 4 || __builtin_mul_overflow(ncap, sizeof *arr, &bytes)) {
			bst_err_set(e, "out of memory");
			return -1;
		}
		const void **na = bst_arena_alloc(c->arena, bytes);
		if (na == NULL) {
			bst_err_set(e, "out of memory");
			return -1;
		}
		if (l->n > 0)
			memcpy(na, arr, l->n * sizeof *na);
		arr = na;
		l->items = (const void *const *)na;
		l->cap_ = ncap;
	}
	arr[l->n++] = item;
	return 0;
}

int bst_cfg_list_append(bst_cfg_ctx *c, bst_cfg_list *l, const void *item, bst_err *e)
{
	if (l->owner_ != c->common) { /* first statement here: replace what was inherited */
		l->items = NULL;
		l->n = 0;
		l->cap_ = 0;
		l->owner_ = c->common;
	}
	return list_push(c, l, item, e);
}

int bst_cfg_list_extend(bst_cfg_ctx *c, bst_cfg_list *l, const void *item, bst_err *e)
{
	if (l->owner_ != c->common) { /* take a private copy of the inherited items */
		const void *const *old = l->items;
		size_t n = l->n;
		l->items = NULL;
		l->n = 0;
		l->cap_ = 0;
		l->owner_ = c->common;
		for (size_t i = 0; i < n; i++)
			if (list_push(c, l, old[i], e) != 0)
				return -1;
	}
	return list_push(c, l, item, e);
}

/* The file name copy for a position, cached per source file. */
static int copy_file(bst_cfg_ctx *c, const char *file, const char **dst, bst_err *e)
{
	if (file == NULL) {
		*dst = NULL;
		return 0;
	}
	if (file != c->src_file_) {
		char *cp = bst_cfg_strdup(c, file, strlen(file), e);
		if (cp == NULL)
			return -1;
		c->src_file_ = file;
		c->dst_file_ = cp;
	}
	*dst = c->dst_file_;
	return 0;
}

int bst_cfg_loc_at(bst_cfg_ctx *c, const bst_loc *loc, bst_cfg_loc *out, bst_err *e)
{
	struct bst_cfg_state *t = c->st_;
	bst_cfg_loc l = { NULL, loc->line, loc->col, 0 };
	if (t->nsrcs == t->srcs_cap) {
		size_t nc = t->srcs_cap ? t->srcs_cap * 2 : 16;
		const bst_loc **nv = realloc(t->srcs, nc * sizeof *nv);
		if (nv == NULL) {
			bst_err_set(e, "out of memory");
			return -1;
		}
		t->srcs = nv;
		t->srcs_cap = nc;
	}
	if (copy_file(c, loc->file, &l.file, e) != 0)
		return -1;
	l.src_ = (uint32_t)t->nsrcs;
	t->srcs[t->nsrcs++] = loc;
	*out = l;
	return 0;
}

int bst_cfg_loc_of(bst_cfg_ctx *c, const bst_ast_node *n, bst_cfg_loc *out, bst_err *e)
{
	return bst_cfg_loc_at(c, &n->loc, out, e);
}

void bst_cfg_warn_at(bst_cfg_ctx *c, const bst_loc *loc, const char *fmt, ...)
{
	char msg[256];
	bst_err e;
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(msg, sizeof msg, fmt, ap);
	va_end(ap);
	bst_config *cfg = c->st_->cfg;
	bst_cfg_warning w = { NULL, loc ? loc->line : 0, loc ? loc->col : 0, NULL };
	w.msg = bst_cfg_strdup(c, msg, strlen(msg), &e);
	if (w.msg == NULL || (loc != NULL && copy_file(c, loc->file, &w.file, &e) != 0) ||
	    bst_cfg_push_owned(c, &cfg->warnings, &cfg->nwarnings, &cfg->warnings_cap_, sizeof w, &w,
			       &e) != 0)
		c->st_->oom = true;
}

void bst_cfg_warn(bst_cfg_ctx *c, const bst_ast_node *n, const char *fmt, ...)
{
	char msg[256];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(msg, sizeof msg, fmt, ap);
	va_end(ap);
	bst_cfg_warn_at(c, n ? &n->loc : NULL, "%s", msg);
}

const bst_cfg_warning *bst_config_warnings(const bst_config *cfg, size_t *n)
{
	*n = cfg->nwarnings;
	return cfg->warnings;
}

/* The node that applies a default (or opens an absent singleton block) for directive `id`,
 * built once per compile in the scratch arena: default text is split on spaces, no
 * quoting. */
static const bst_ast_node *synth_node(bst_cfg_ctx *c, size_t id, const bst_directive *d,
				      bst_err *e)
{
	struct bst_cfg_state *st = c->st_;
	if (st->synth[id] != NULL)
		return st->synth[id];
	const char *dv = d->default_value ? d->default_value : "";
	size_t len = strlen(dv), nargs = 0, cap = 2;
	for (size_t i = 0; i < len; i++)
		cap += dv[i] == ' ';
	bst_ast_node *n = bst_arena_alloc(st->scratch, sizeof *n);
	bst_ast_arg *args = bst_arena_alloc(st->scratch, cap * sizeof *args);
	char *buf = bst_arena_alloc(st->scratch, len + 1);
	if (n == NULL || args == NULL || buf == NULL) {
		bst_err_set(e, "out of memory");
		return NULL;
	}
	memcpy(buf, dv, len + 1);
	memset(n, 0, sizeof *n);
	n->name = d->name;
	n->name_len = strlen(d->name);
	n->has_block = d->singleton;
	if (d->subname != NULL)
		args[nargs++] = (bst_ast_arg){ .kind = BST_TOK_WORD, .text = d->subname,
					       .len = strlen(d->subname), .tpl = d->subname,
					       .tpl_len = strlen(d->subname) };
	for (size_t i = 0; i < len;) {
		while (i < len && buf[i] == ' ')
			i++;
		if (i >= len)
			break;
		size_t start = i;
		while (i < len && buf[i] != ' ')
			i++;
		buf[i] = 0;
		args[nargs++] = (bst_ast_arg){ .kind = BST_TOK_WORD, .text = buf + start,
					       .len = i - start, .tpl = buf + start,
					       .tpl_len = i - start };
		i++;
	}
	n->args = args;
	n->nargs = nargs;
	st->synth[id] = n;
	return n;
}

static int compile_scope(bst_cfg_ctx *c, const bst_schema *s, const bst_ast_node *parent,
			 bool fresh, bst_err *e);

/* Applies a block directive and compiles the block's children from it; the whole ctx is
 * restored afterwards. */
static int compile_block(bst_cfg_ctx *c, const bst_schema *s, const bst_directive *d,
			 const bst_ast_node *n, bst_err *e)
{
	bst_cfg_ctx saved = *c;
	if (d->apply(c, d, n, e) != 0)
		return -1;
	c->kind = d->child_ctx;
	if (compile_scope(c, s, n, saved.kind != d->child_ctx, e) != 0)
		return -1;
	*c = saved;
	return 0;
}

/* fresh: the scope's kind differs from its parent's (a nested location inherits its
 * parent location's defaults instead of reapplying them). */
static int compile_scope(bst_cfg_ctx *c, const bst_schema *s, const bst_ast_node *parent,
			 bool fresh, bst_err *e)
{
	uint32_t kind = c->kind;
	size_t *ids, nids;
	if (bst_schema_scope_missing(s, parent, kind, fresh, &ids, &nids) != 0) {
		bst_err_set(e, "out of memory");
		return -1;
	}
	int rc = -1;
	/* Defaults first, where each directive first becomes valid and the scope does not set it. */
	for (size_t i = 0; i < nids; i++) {
		const bst_directive *d = bst_schema_at(s, ids[i]);
		if (d->singleton)
			continue;
		const bst_ast_node *n = synth_node(c, ids[i], d, e);
		if (n == NULL || d->apply(c, d, n, e) != 0)
			goto out;
	}
	/* Then every plain directive, whatever its position in the block. */
	for (const bst_ast_node *n = parent->children; n != NULL; n = n->next) {
		if (n->has_block)
			continue;
		const bst_directive *d = bst_schema_match(s, n, kind);
		if (d == NULL || d->apply(c, d, n, e) != 0)
			goto out;
	}
	/* Then each child block, from the finished parent. */
	for (const bst_ast_node *n = parent->children; n != NULL; n = n->next) {
		if (!n->has_block)
			continue;
		const bst_directive *d = bst_schema_match(s, n, kind);
		if (d == NULL || compile_block(c, s, d, n, e) != 0)
			goto out;
	}
	/* Singleton blocks the user did not write: an empty scope, so defaults inside apply. */
	for (size_t i = 0; i < nids; i++) {
		const bst_directive *d = bst_schema_at(s, ids[i]);
		if (!d->singleton)
			continue;
		const bst_ast_node *n = synth_node(c, ids[i], d, e);
		if (n == NULL || compile_block(c, s, d, n, e) != 0)
			goto out;
	}
	rc = 0;
out:
	free(ids);
	return rc;
}

extern const bst_cfg_post *const __start_bst_cfg_post[] __attribute__((weak));
extern const bst_cfg_post *const __stop_bst_cfg_post[] __attribute__((weak));

static int cmp_post(const void *x, const void *y)
{
	const bst_cfg_post *a = *(const bst_cfg_post *const *)x, *b = *(const bst_cfg_post *const *)y;
	return strcmp(a->name, b->name);
}

const bst_cfg_post **bst_cfg_post_sort_with(const bst_cfg_post *const *hooks, size_t n,
					    bst_err *e)
{
	const bst_cfg_post **v = malloc((n ? n : 1) * sizeof *v);
	if (v == NULL) {
		bst_err_set(e, "out of memory");
		return NULL;
	}
	if (n > 0)
		memcpy(v, hooks, n * sizeof *v);
	qsort(v, n, sizeof *v, cmp_post);
	for (size_t i = 1; i < n; i++)
		if (strcmp(v[i - 1]->name, v[i]->name) == 0) {
			bst_err_set(e, "duplicate post hook name \"%s\" (hook names must be unique: "
				       "they define the run order)", v[i]->name);
			free(v);
			return NULL;
		}
	return v;
}

static pthread_once_t post_once = PTHREAD_ONCE_INIT;
static const bst_cfg_post **post_sorted;
static size_t post_n;
static bst_err post_err;

static void post_init(void)
{
	size_t n = __start_bst_cfg_post == NULL || __stop_bst_cfg_post == NULL
			   ? 0
			   : (size_t)(__stop_bst_cfg_post - __start_bst_cfg_post);
	post_sorted = bst_cfg_post_sort_with(__start_bst_cfg_post, n, &post_err);
	post_n = post_sorted ? n : 0;
}

int bst_cfg_post_registry(const bst_cfg_post *const **hooks, size_t *n, bst_err *e)
{
	pthread_once(&post_once, post_init);
	if (post_sorted == NULL) {
		if (e != NULL)
			*e = post_err;
		return -1;
	}
	*hooks = (const bst_cfg_post *const *)post_sorted;
	*n = post_n;
	return 0;
}

/* Runs the registered hooks in name order. */
static int run_post_hooks(bst_config *cfg, bst_cfg_ctx *c, bst_err *e)
{
	const bst_cfg_post *const *v;
	size_t n;
	if (bst_cfg_post_registry(&v, &n, e) != 0)
		return -1;
	for (size_t i = 0; i < n; i++)
		if (v[i]->fn(cfg, c, e) != 0)
			return -1;
	return 0;
}

bst_config *bst_cfg_compile_with(const bst_schema *s, const bst_ast *ast, bst_err *e)
{
	if (bst_cfg_validate_with(s, ast, e) != 0)
		return NULL;
	bst_arena *a = bst_arena_new(ARENA_CHUNK);
	bst_config *cfg = a ? bst_arena_alloc(a, sizeof *cfg) : NULL;
	if (cfg == NULL) {
		bst_arena_free(a);
		bst_err_set(e, "out of memory");
		return NULL;
	}
	memset(cfg, 0, sizeof *cfg);
	cfg->arena = a;
	struct bst_cfg_state st = { .cfg = cfg, .nsynth = bst_schema_count(s) };
	st.scratch = bst_arena_new(ARENA_CHUNK);
	st.synth = calloc(st.nsynth ? st.nsynth : 1, sizeof *st.synth);
	if (st.scratch == NULL || st.synth == NULL) {
		bst_err_set(e, "out of memory");
		goto fail;
	}
	bst_cfg_ctx c = { .arena = a, .kind = BST_CTX_GLOBAL, .global = &cfg->global,
			  .common = &cfg->global.common, .st_ = &st };
	if (compile_scope(&c, s, &ast->root, true, e) != 0 || bst_cfg_core_check(cfg, &c, e) != 0 ||
	    run_post_hooks(cfg, &c, e) != 0)
		goto fail;
	if (st.oom) {
		bst_err_set(e, "out of memory");
		goto fail;
	}
	free(st.srcs);
	free(st.synth);
	bst_arena_free(st.scratch);
	return cfg;
fail:
	free(st.srcs);
	free(st.synth);
	bst_arena_free(st.scratch);
	bst_config_free(cfg);
	return NULL;
}

bst_config *bst_cfg_compile(const bst_ast *ast, bst_err *e)
{
	const bst_schema *s = bst_schema_registry(e);
	return s ? bst_cfg_compile_with(s, ast, e) : NULL;
}

int bst_config_on_free(bst_config *cfg, void (*fn)(void *), void *arg, bst_err *e)
{
	if (cfg->ncleanups == cfg->cleanups_cap_) {
		size_t cap = cfg->cleanups_cap_ ? cfg->cleanups_cap_ * 2 : 16;
		bst_cfg_cleanup *v = realloc(cfg->cleanups, cap * sizeof *v);
		if (v == NULL) {
			bst_err_set(e, "out of memory");
			return -1;
		}
		cfg->cleanups = v;
		cfg->cleanups_cap_ = cap;
	}
	cfg->cleanups[cfg->ncleanups++] = (bst_cfg_cleanup){ fn, arg };
	return 0;
}

void bst_config_free(bst_config *cfg)
{
	if (cfg == NULL)
		return;
	for (size_t i = cfg->ncleanups; i > 0; i--)
		cfg->cleanups[i - 1].fn(cfg->cleanups[i - 1].arg);
	free(cfg->cleanups);
	bst_arena_free(cfg->arena); /* cfg itself lives in the arena */
}
