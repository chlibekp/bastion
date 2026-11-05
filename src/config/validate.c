/* Validation walk: one iterative pass over the AST against the schema, with
 * diagnostics (unknown names with a suggestion, wrong contexts, duplicates). See schema.h. */
#include "config/schema.h"

#include "config/errfmt.h"
#include "config/schema_priv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Closest name valid in ctx within the bound; the index is sorted, so on equal distance
 * the alphabetically first wins. */
static const char *suggest(const bst_schema *s, const char *name, size_t len, uint32_t ctx)
{
	const char *best = NULL;
	unsigned bd = BST_SUGGEST_MAX_DIST + 1;
	for (size_t i = 0; i < s->n; i++) {
		if (!(s->idx[i]->contexts & ctx) || s->idx[i]->any_name)
			continue;
		unsigned d = bst_lev_bounded(name, len, s->idx[i]->name, strlen(s->idx[i]->name),
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
	bst_cfg_shown(n->name, n->name_len, tok, sizeof tok);
	uint32_t elsewhere = 0;
	for (size_t i = bst_lower_bound(s, n->name, n->name_len);
	     bst_name_at(s, i, n->name, n->name_len); i++)
		elsewhere |= s->idx[i]->contexts;
	if (elsewhere != 0) {
		bst_ctx_list(elsewhere, list, sizeof list);
		bst_err_set(e, "\"%s\" is not valid in %s; valid in: %s", tok, bst_ctx_name(ctx),
			    list);
	} else {
		const char *sug = suggest(s, n->name, n->name_len, ctx);
		if (sug != NULL)
			bst_err_set(e, "unknown directive \"%s\", did you mean \"%s\"?", tok, sug);
		else
			bst_err_set(e, "unknown directive \"%s\"", tok);
	}
	bst_cfg_err_at(e, &n->loc);
	return -1;
}

/* The name has two-word entries in ctx but the first argument selects none. */
static int bad_subname(const bst_schema *s, const bst_ast_node *n, uint32_t ctx, bst_err *e)
{
	char tok[BST_SCHEMA_MAX_TOKEN_SHOWN + 8], name[BST_SCHEMA_MAX_TOKEN_SHOWN + 8];
	char list[160] = "";
	size_t ln = 0;
	const char *best = NULL;
	unsigned bd = BST_SUGGEST_MAX_DIST + 1;
	bst_cfg_shown(n->name, n->name_len, name, sizeof name);
	const bst_ast_arg *a = n->nargs > 0 ? &n->args[0] : NULL;
	for (size_t i = bst_lower_bound(s, n->name, n->name_len);
	     bst_name_at(s, i, n->name, n->name_len); i++) {
		const bst_directive *d = s->idx[i];
		if (!(d->contexts & ctx) || d->subname == NULL)
			continue;
		if (a != NULL) {
			unsigned dist = bst_lev_bounded(a->text, a->len, d->subname, strlen(d->subname),
						    BST_SUGGEST_MAX_DIST);
			if (dist < bd) {
				bd = dist;
				best = d->subname;
			}
		}
		int w = snprintf(list + ln, sizeof list - ln, "%s%s", ln ? ", " : "", d->subname);
		if (w > 0 && (size_t)w < sizeof list - ln)
			ln += (size_t)w;
	}
	if (a == NULL) {
		bst_err_set(e, "\"%s\" needs a subcommand (valid: %s)", name, list);
		bst_cfg_err_at(e, &n->loc);
		return -1;
	}
	bst_cfg_shown(a->text, a->len, tok, sizeof tok);
	if (best != NULL)
		bst_err_set(e, "unknown \"%s\" subcommand \"%s\", did you mean \"%s\"?", name, tok,
			    best);
	else
		bst_err_set(e, "unknown \"%s\" subcommand \"%s\" (valid: %s)", name, tok, list);
	bst_cfg_err_at(e, &a->loc);
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
		bool fam;
		const bst_ast_arg *first_arg = n->nargs > 0 ? &n->args[0] : NULL;
		if (!bst_find_id(s, n->name, n->name_len, ctx[depth], first_arg ? first_arg->text : NULL,
			     first_arg ? first_arg->len : 0, &id, &fam)) {
			if (fam)
				bad_subname(s, n, ctx[depth], e);
			else if (bst_find_any(s, ctx[depth], &id))
				goto found;
			else
				unknown_or_wrong_ctx(s, n, ctx[depth], e);
			goto out;
		}
found:;
		const bst_directive *d = s->idx[id];
		if (bst_directive_check_node(d, n, e) != 0)
			goto out;
		if (!d->repeatable) {
			size_t key = id;
			if (d->subname_exclusive)
				key = bst_lower_bound(s, n->name, n->name_len);
			size_t slot = depth * nd + key;
			if (stamp[slot] == gen[depth]) {
				const bst_loc *f = &first[slot]->loc;
				bool sub = d->subname != NULL && !d->subname_exclusive;
				char ff[BST_CFG_SHOWN_FILE + 8];
				bst_cfg_shown_file(f->file, ff, sizeof ff);
				bst_err_set(e, "duplicate \"%s%s%s\" (first at %s:%d:%d)", d->name,
					    sub ? " " : "", sub ? d->subname : "",
					    ff, f->line, f->col);
				bst_cfg_err_at(e, &n->loc);
				goto out;
			}
			stamp[slot] = gen[depth];
			first[slot] = n;
		}
		if (n->has_block) {
			if (depth + 1 >= MAX_SCOPES) {
				bst_err_set(e, "blocks nested deeper than %d", BST_CFG_MAX_NESTING);
				bst_cfg_err_at(e, &n->loc);
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
