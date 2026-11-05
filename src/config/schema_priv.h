/* Schema internals shared by schema.c (index and integrity), schema_args.c (classifier and
 * typed values), validate.c (the walk) and registry.c. Not for other modules. */
#ifndef BST_CONFIG_SCHEMA_PRIV_H
#define BST_CONFIG_SCHEMA_PRIV_H

#include "config/schema.h"

struct bst_schema {
	const bst_directive **idx; /* sorted by name, subname; position is the directive id */
	size_t n;
	size_t *any;		   /* ids of catch-all entries */
	size_t nany;
};

/* schema.c */
void bst_ctx_list(uint32_t mask, char *buf, size_t cap);
void bst_join_names(const char *const *names, char *buf, size_t cap);
unsigned bst_lev_bounded(const char *a, size_t al, const char *b, size_t bl, unsigned max);
size_t bst_lower_bound(const bst_schema *s, const char *name, size_t len);
bool bst_name_at(const bst_schema *s, size_t i, const char *name, size_t len);
bool bst_find_id(const bst_schema *s, const char *name, size_t len, uint32_t ctx,
		 const char *sub, size_t sublen, size_t *id, bool *family);
bool bst_find_any(const bst_schema *s, uint32_t ctx, size_t *id);

/* schema_args.c */
size_t npos_of(const bst_argspec *sp);
/* Arguments only (shared by AST nodes and defaults). `where` locates count errors. */
int check_args(const bst_directive *d, const char *label, const bst_ast_arg *args,
	       size_t nargs, const bst_loc *where, bst_err *e);

#endif
