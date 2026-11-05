/* Config compiler: validate, then apply every directive into scope structs held in one
 * arena. See compile.h for the model (inheritance by struct copy, order independence,
 * defaults through apply, bounded recursion). */
#include "config/compile.h"

#include <stdlib.h>
#include <string.h>

#define ARENA_CHUNK ((size_t)64 << 10)

/* Run in order after every block applied (see compile.h). Empty so far. */
static const bst_cfg_post_fn bst_cfg_post_hooks[] = { NULL };

/* AST positions of everything that recorded a bst_cfg_loc, freed when compile ends. */
struct bst_cfg_srcs {
	const bst_loc **v;
	size_t n, cap;
};

const bst_loc *bst_cfg_src(bst_cfg_ctx *c, const bst_cfg_loc *loc)
{
	return c->srcs_->v[loc->src_];
}

void bst_cfg_err_at(bst_err *e, const bst_loc *loc)
{
	if (e == NULL)
		return;
	e->file = loc ? loc->file : NULL;
	e->line = loc ? loc->line : 0;
	e->col = loc ? loc->col : 0;
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

int bst_cfg_list_append(bst_cfg_ctx *c, bst_cfg_list *list, const void *item, bst_err *e)
{
	if (list->n >= SIZE_MAX / sizeof(void *) - 1) {
		bst_err_set(e, "out of memory");
		return -1;
	}
	const void **na = bst_arena_alloc(c->arena, (list->n + 1) * sizeof *na);
	if (na == NULL) {
		bst_err_set(e, "out of memory");
		return -1;
	}
	if (list->n > 0)
		memcpy(na, list->items, list->n * sizeof *na);
	na[list->n] = item;
	list->items = (const void *const *)na;
	list->n++;
	return 0;
}

bst_cfg_loc bst_cfg_loc_of(bst_cfg_ctx *c, const bst_ast_node *n, bst_err *e)
{
	bst_cfg_loc l = { NULL, n->loc.line, n->loc.col, 0 };
	struct bst_cfg_srcs *t = c->srcs_;
	if (t->n == t->cap) {
		size_t nc = t->cap ? t->cap * 2 : 16;
		const bst_loc **nv = realloc(t->v, nc * sizeof *nv);
		if (nv == NULL) {
			bst_err_set(e, "out of memory");
			return l;
		}
		t->v = nv;
		t->cap = nc;
	}
	l.src_ = (uint32_t)t->n;
	t->v[t->n++] = &n->loc;
	if (n->loc.file == NULL)
		return l;
	if (n->loc.file != c->src_file_) {
		char *cp = bst_cfg_strdup(c, n->loc.file, strlen(n->loc.file), e);
		if (cp == NULL)
			return l;
		c->src_file_ = n->loc.file;
		c->dst_file_ = cp;
	}
	l.file = c->dst_file_;
	return l;
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

/* Applies d's default_value through d->apply on a synthesised node. */
static int apply_default(bst_cfg_ctx *c, const bst_directive *d, bst_err *e)
{
	size_t len = strlen(d->default_value), nargs = 0, cap = 2;
	for (size_t i = 0; i < len; i++)
		cap += d->default_value[i] == ' ';
	bst_ast_node *n = bst_arena_alloc(c->arena, sizeof *n);
	bst_ast_arg *args = bst_arena_alloc(c->arena, cap * sizeof *args);
	char *buf = bst_cfg_strdup(c, d->default_value, len, e);
	if (n == NULL || args == NULL || buf == NULL) {
		bst_err_set(e, "out of memory");
		return -1;
	}
	memset(n, 0, sizeof *n);
	n->name = d->name;
	n->name_len = strlen(d->name);
	if (d->subname != NULL) {
		args[nargs++] = (bst_ast_arg){ .kind = BST_TOK_WORD, .text = d->subname,
					       .len = strlen(d->subname), .tpl = d->subname,
					       .tpl_len = strlen(d->subname) };
	}
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
	return d->apply(c, d, n, e);
}

/* fresh: the scope's kind differs from its parent's (a nested location inherits its
 * parent location's defaults instead of reapplying them). */
static int compile_scope(bst_cfg_ctx *c, const bst_schema *s, const bst_ast_node *parent,
			 bool fresh, bst_err *e)
{
	uint32_t kind = c->kind, anc = ancestors(kind);
	/* Defaults first, where each directive first becomes valid. */
	for (size_t i = 0, n = bst_schema_count(s); i < n; i++) {
		const bst_directive *d = bst_schema_at(s, i);
		if (fresh && d->default_value != NULL && !d->any_name && (d->contexts & kind) &&
		    !(d->contexts & anc) && apply_default(c, d, e) != 0)
			return -1;
	}
	/* Then every plain directive, whatever its position in the block. */
	for (const bst_ast_node *n = parent->children; n != NULL; n = n->next) {
		if (n->has_block)
			continue;
		const bst_directive *d = bst_schema_match(s, n, kind);
		if (d == NULL || d->apply(c, d, n, e) != 0)
			return -1;
	}
	/* Then each child block, from the finished parent. */
	for (const bst_ast_node *n = parent->children; n != NULL; n = n->next) {
		if (!n->has_block)
			continue;
		const bst_directive *d = bst_schema_match(s, n, kind);
		if (d == NULL)
			return -1;
		bst_cfg_ctx saved = *c;
		if (d->apply(c, d, n, e) != 0)
			return -1;
		c->kind = d->child_ctx;
		if (compile_scope(c, s, n, saved.kind != d->child_ctx, e) != 0)
			return -1;
		*c = saved;
	}
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
	struct bst_cfg_srcs srcs = { NULL, 0, 0 };
	bst_cfg_ctx c = { .arena = a, .kind = BST_CTX_GLOBAL, .global = &cfg->global,
			  .common = &cfg->global.common, .srcs_ = &srcs };
	if (compile_scope(&c, s, &ast->root, true, e) != 0 || bst_cfg_core_check(cfg, &c, e) != 0)
		goto fail;
	for (size_t i = 0; bst_cfg_post_hooks[i] != NULL; i++)
		if (bst_cfg_post_hooks[i](cfg, e) != 0)
			goto fail;
	free(srcs.v);
	return cfg;
fail:
	free(srcs.v);
	bst_config_free(cfg);
	return NULL;
}

bst_config *bst_cfg_compile(const bst_ast *ast, bst_err *e)
{
	const bst_schema *s = bst_schema_registry(e);
	return s ? bst_cfg_compile_with(s, ast, e) : NULL;
}

void bst_config_free(bst_config *cfg)
{
	if (cfg != NULL)
		bst_arena_free(cfg->arena); /* cfg itself lives in the arena */
}
