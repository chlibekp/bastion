/* See dump.h. */
#include "config/dump.h"

#include "config/errfmt.h"
#include "core/json.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/* ---- Effective config ---- */

typedef struct sb {
	char *p;
	size_t len, cap;
	bool oom;
} sb;

static void sb_put(sb *b, const char *s, size_t n)
{
	if (b->oom)
		return;
	if (n > SIZE_MAX - b->len - 1) {
		b->oom = true;
		return;
	}
	if (b->len + n + 1 > b->cap) {
		size_t nc = b->cap ? b->cap : 256;
		while (nc < b->len + n + 1) {
			if (nc > SIZE_MAX / 2) {
				b->oom = true;
				return;
			}
			nc *= 2;
		}
		char *np = realloc(b->p, nc);
		if (np == NULL) {
			b->oom = true;
			return;
		}
		b->p = np;
		b->cap = nc;
	}
	memcpy(b->p + b->len, s, n);
	b->len += n;
	b->p[b->len] = 0;
}

static void sb_str(sb *b, const char *s)
{
	sb_put(b, s, strlen(s));
}

static bool bare_ok(const char *s, size_t len)
{
	if (len == 0 || s[0] == '#')
		return false;
	for (size_t i = 0; i < len; i++) {
		unsigned char c = (unsigned char)s[i];
		if (c <= ' ' || c == 0x7f || c == ';' || c == '{' || c == '}' || c == '"' || c == '\'')
			return false;
	}
	return true;
}

static bool has_env_ref(const char *s, size_t len)
{
	for (size_t i = 0; i + 1 < len; i++)
		if (s[i] == '$' && s[i + 1] == '{')
			return true;
	return false;
}

typedef enum spell { SP_BARE, SP_DQ, SP_SQ } spell;

/* Appends the candidate spelling of text; false when this spelling cannot hold it. */
static bool spelled(sb *out, spell sp, const char *s, size_t len)
{
	if (has_env_ref(s, len) && sp != SP_SQ)
		return false; /* `${` would be read as an environment reference */
	switch (sp) {
	case SP_BARE:
		if (!bare_ok(s, len))
			return false;
		sb_put(out, s, len);
		return true;
	case SP_SQ:
		if (memchr(s, '\'', len) != NULL)
			return false;
		sb_put(out, "'", 1);
		sb_put(out, s, len);
		sb_put(out, "'", 1);
		return true;
	case SP_DQ:
		sb_put(out, "\"", 1);
		for (size_t i = 0; i < len; i++) {
			switch (s[i]) {
			case '"': sb_str(out, "\\\""); break;
			case '\\': sb_str(out, "\\\\"); break;
			case '\n': sb_str(out, "\\n"); break;
			case '\t': sb_str(out, "\\t"); break;
			case '\r': sb_str(out, "\\r"); break;
			default: sb_put(out, &s[i], 1);
			}
		}
		sb_put(out, "\"", 1);
		return true;
	}
	return false;
}

/* True when `cand` (a spelled argument) lexes back to exactly one argument with the same
 * text and tpl as the original. */
static bool reparses(const sb *cand, const bst_ast_arg *a)
{
	static const char pre[] = "x ";
	sb t = { 0 };
	sb_put(&t, pre, sizeof pre - 1);
	sb_put(&t, cand->p, cand->len);
	sb_put(&t, ";", 1);
	bool ok = false;
	bst_arena *ar = t.oom ? NULL : bst_arena_new(4096);
	if (ar != NULL) {
		bst_err e;
		bst_cfg_opts o = { .no_include = 1 };
		bst_ast *ast = bst_cfg_parse_string(t.p, t.len, "dump", &o, ar, &e);
		const bst_ast_node *n = ast ? ast->root.children : NULL;
		ok = n != NULL && n->nargs == 1 && n->args[0].len == a->len &&
		     memcmp(n->args[0].text, a->text, a->len) == 0 &&
		     n->args[0].tpl_len == a->tpl_len &&
		     memcmp(n->args[0].tpl, a->tpl, a->tpl_len) == 0;
	}
	bst_arena_free(ar);
	free(t.p);
	return ok;
}

static int put_arg(sb *out, const bst_ast_arg *a, bst_err *e)
{
	/* Defence in depth: validation rejects control bytes in strings and paths, but an
	 * argument of another type, or a directive added later, must never write an escape
	 * sequence or a bell to a terminal through -T. Tab is the one allowed control byte. */
	for (size_t i = 0; i < a->len; i++) {
		unsigned char c = (unsigned char)a->text[i];
		if ((c < 0x20 && c != '\t') || c == 0x7f) {
			bst_err_set(e, "cannot print this argument: it contains a control byte "
				       "(0x%02x), which is not allowed in a configuration value", c);
			bst_cfg_err_at(e, &a->loc);
			return -1;
		}
	}
	static const spell order[3][3] = {
		[BST_TOK_WORD] = { SP_BARE, SP_DQ, SP_SQ },
		[BST_TOK_STRING_TPL] = { SP_DQ, SP_SQ, SP_BARE },
		[BST_TOK_STRING_RAW] = { SP_SQ, SP_DQ, SP_BARE },
	};
	for (size_t i = 0; i < 3; i++) {
		sb c = { 0 };
		bool ok = spelled(&c, order[a->kind][i], a->text, a->len) && !c.oom && reparses(&c, a);
		if (ok)
			sb_put(out, c.p, c.len);
		free(c.p);
		if (ok)
			return 0;
	}
	bst_err_set(e, "cannot round-trip this argument: it has a single quote and a '$' that "
		       "must stay literal, and no quoting keeps both");
	bst_cfg_err_at(e, &a->loc);
	return -1;
}

static void indent(sb *out, int depth)
{
	for (int i = 0; i < depth; i++)
		sb_str(out, "    ");
}

static int put_scope(sb *out, const bst_schema *s, const bst_ast_node *scope, uint32_t kind,
		     bool fresh, int depth, bst_err *e);

/* The statements the scope gets without the user writing them (defaults, and singleton
 * blocks that hold defaults), from the same engine function compile uses. */
static int put_missing(sb *out, const bst_schema *s, const bst_ast_node *scope, uint32_t kind,
		       bool fresh, int depth, bst_err *e)
{
	size_t *ids, nids;
	if (bst_schema_scope_missing(s, scope, kind, fresh, &ids, &nids) != 0) {
		bst_err_set(e, "out of memory");
		return -1;
	}
	int rc = -1;
	for (size_t i = 0; i < nids; i++) {
		const bst_directive *d = bst_schema_at(s, ids[i]);
		if (d->singleton) {
			/* An absent block prints only when it holds something (its defaults). */
			static const bst_ast_node empty;
			sb sub = { 0 };
			int r = put_scope(&sub, s, &empty, d->child_ctx, true, depth + 1, e);
			if (r == 0 && sub.len > 0) {
				indent(out, depth);
				sb_str(out, d->name);
				sb_str(out, " {\n");
				sb_put(out, sub.p, sub.len);
				indent(out, depth);
				sb_str(out, "}\n");
			}
			out->oom |= sub.oom;
			free(sub.p);
			if (r != 0)
				goto out;
			continue;
		}
		indent(out, depth);
		sb_str(out, d->name);
		if (d->subname != NULL) {
			sb_put(out, " ", 1);
			sb_str(out, d->subname);
		}
		const char *v = d->default_value;
		for (size_t len = strlen(v), j = 0; j < len;) {
			while (j < len && v[j] == ' ')
				j++;
			size_t st = j;
			while (j < len && v[j] != ' ')
				j++;
			if (j == st)
				break;
			bst_ast_arg a = { .kind = BST_TOK_WORD, .text = v + st, .len = j - st,
					  .tpl = v + st, .tpl_len = j - st };
			sb_put(out, " ", 1);
			if (put_arg(out, &a, e) != 0)
				goto out;
		}
		sb_str(out, ";\n");
	}
	rc = 0;
out:
	free(ids);
	return rc;
}

static int put_scope(sb *out, const bst_schema *s, const bst_ast_node *scope, uint32_t kind,
		     bool fresh, int depth, bst_err *e)
{
	for (const bst_ast_node *n = scope->children; n != NULL; n = n->next) {
		const bst_directive *d = bst_schema_match(s, n, kind);
		if (d == NULL) {
			bst_err_set(e, "internal error: statement does not match the schema");
			e->file = n->loc.file;
			e->line = n->loc.line;
			e->col = n->loc.col;
			return -1;
		}
		indent(out, depth);
		sb_put(out, n->name, n->name_len);
		for (size_t i = 0; i < n->nargs; i++) {
			sb_put(out, " ", 1);
			if (put_arg(out, &n->args[i], e) != 0)
				return -1;
		}
		if (!n->has_block) {
			sb_str(out, ";\n");
			continue;
		}
		sb_str(out, " {\n");
		if (put_scope(out, s, n, d->child_ctx, kind != d->child_ctx, depth + 1, e) != 0)
			return -1;
		indent(out, depth);
		sb_str(out, "}\n");
	}
	return put_missing(out, s, scope, kind, fresh, depth, e);
}

int bst_cfg_dump(const bst_schema *s, const bst_ast *ast, FILE *out, bst_err *e)
{
	sb b = { 0 };
	int rc = put_scope(&b, s, &ast->root, BST_CTX_GLOBAL, true, 0, e);
	if (rc == 0 && b.oom) {
		bst_err_set(e, "out of memory");
		rc = -1;
	}
	if (rc == 0 && b.len > 0 && fwrite(b.p, 1, b.len, out) != b.len) {
		bst_err_set(e, "write error");
		rc = -1;
	}
	free(b.p);
	return rc;
}

/* ---- Schema dump ---- */

static void jkey(bst_jw *w, const char *k)
{
	bst_jw_key(w, (bst_str){ k, (uint32_t)strlen(k) });
}

static void jstr(bst_jw *w, const char *s)
{
	if (s == NULL)
		bst_jw_null(w);
	else
		bst_jw_str(w, (bst_str){ s, (uint32_t)strlen(s) });
}

static void jlist(bst_jw *w, const char *key, const char *const *v)
{
	jkey(w, key);
	bst_jw_arr_begin(w);
	for (; v != NULL && *v != NULL; v++)
		jstr(w, *v);
	bst_jw_arr_end(w);
}

static void jtype(bst_jw *w, const bst_argtype *t)
{
	jkey(w, "type");
	jstr(w, bst_vtype_name(t->kind));
	jlist(w, "keywords", t->keywords);
	jkey(w, "enum");
	if (t->kind == BST_T_ENUM)
		bst_jw_arr_begin(w);
	else
		bst_jw_null(w);
	if (t->kind == BST_T_ENUM) {
		for (const char *const *v = t->enum_values; v != NULL && *v != NULL; v++)
			jstr(w, *v);
		bst_jw_arr_end(w);
	}
	jkey(w, "min");
	if (t->kind == BST_T_INT)
		bst_jw_int(w, t->min);
	else
		bst_jw_null(w);
	jkey(w, "max");
	if (t->kind == BST_T_INT)
		bst_jw_int(w, t->max);
	else
		bst_jw_null(w);
	jkey(w, "list");
	bst_jw_bool(w, t->list);
}

static const char *block_name(bst_block_rule r)
{
	return r == BST_BLOCK_REQUIRED ? "required" : r == BST_BLOCK_OPTIONAL ? "optional"
									     : "forbidden";
}

static void jdirective(bst_jw *w, const bst_directive *d)
{
	bst_jw_obj_begin(w);
	jkey(w, "name");
	jstr(w, d->name);
	jkey(w, "subname");
	jstr(w, d->subname);
	jkey(w, "contexts");
	bst_jw_arr_begin(w);
	for (int i = 0; i < BST_CTX_COUNT; i++)
		if (d->contexts & (1u << i))
			jstr(w, bst_ctx_name(1u << i));
	bst_jw_arr_end(w);
	jkey(w, "child_context");
	jstr(w, d->child_ctx ? bst_ctx_name(d->child_ctx) : NULL);
	jkey(w, "args");
	bst_jw_obj_begin(w);
	jkey(w, "min");
	bst_jw_int(w, d->args.min_args);
	jkey(w, "max");
	if (d->args.max_args == BST_ARGS_ANY)
		bst_jw_null(w);
	else
		bst_jw_int(w, d->args.max_args);
	jkey(w, "pos");
	bst_jw_arr_begin(w);
	for (size_t i = 0; i < BST_ARGSPEC_MAX_POS && d->args.pos[i].kind != BST_T_NONE; i++) {
		bst_jw_obj_begin(w);
		jtype(w, &d->args.pos[i]);
		bst_jw_obj_end(w);
	}
	bst_jw_arr_end(w);
	jkey(w, "options");
	bst_jw_arr_begin(w);
	for (size_t i = 0; i < d->args.nopts; i++) {
		bst_jw_obj_begin(w);
		jkey(w, "key");
		jstr(w, d->args.opts[i].key);
		jtype(w, &d->args.opts[i].type);
		jkey(w, "required");
		bst_jw_bool(w, d->args.opts[i].required);
		bst_jw_obj_end(w);
	}
	bst_jw_arr_end(w);
	bst_jw_obj_end(w);
	jkey(w, "default");
	jstr(w, d->default_value);
	jkey(w, "doc");
	jstr(w, d->doc);
	jkey(w, "block");
	jstr(w, block_name(d->args.block));
	jkey(w, "repeatable");
	bst_jw_bool(w, d->repeatable);
	jkey(w, "require");
	bst_jw_bool(w, d->require);
	jkey(w, "any_name");
	bst_jw_bool(w, d->any_name);
	jkey(w, "subname_exclusive");
	bst_jw_bool(w, d->subname_exclusive);
	bst_jw_obj_end(w);
}

int bst_schema_dump_json(const bst_schema *s, FILE *out, bst_err *e)
{
	bst_jw w;
	bst_jw_init(&w);
	bst_jw_obj_begin(&w);
	jkey(&w, "directives");
	bst_jw_arr_begin(&w);
	for (size_t i = 0, n = bst_schema_count(s); i < n; i++)
		jdirective(&w, bst_schema_at(s, i));
	bst_jw_arr_end(&w);
	bst_jw_obj_end(&w);
	int rc = -1;
	if (!bst_jw_finish(&w))
		bst_err_set(e, "cannot build the schema JSON");
	else if (fwrite(w.buf, 1, w.len, out) != w.len || fputc('\n', out) == EOF)
		bst_err_set(e, "write error");
	else
		rc = 0;
	bst_jw_free(&w);
	return rc;
}
