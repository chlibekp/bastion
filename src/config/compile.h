/* Compiled runtime config: the AST turned into an immutable, scoped structure that every
 * later phase reads. All of it lives in one arena owned by the bst_config, so
 * bst_config_free is one call, a failed compile frees that arena and returns NULL with err
 * set (nothing is left behind, and a config compiled earlier stays untouched: reload relies
 * on both), and nothing points into the AST or its arena (strings are copied, the AST is
 * freed right after compile).
 *
 * How a later phase adds a directive:
 *   1. Declare the field in the scope struct that holds it: bst_cfg_common when it
 *      inherits (global -> server -> location), else bst_cfg_global, bst_cfg_server or
 *      bst_cfg_location.
 *   2. Register a table with BST_DIRECTIVES (name, contexts, argspec, doc, default_value).
 *   3. Write the `apply`: read arguments with bst_dir_pos and friends, store into the
 *      current scope through the bst_cfg_ctx, copy strings with bst_cfg_strdup.
 * Nothing else changes: validation, defaults, inheritance and ordering come from the
 * engine. If the directive references another block by name (`tcp_profile=edge`), apply
 * only records the name; the check that the block exists belongs in a post-apply hook
 * (below), because the referenced block may come later in the file or in another file.
 *
 * Compile model.
 *  - Validate first (bst_cfg_validate), then apply.
 *  - Inheritance is by struct copy. A child scope starts as a copy of its parent's
 *    bst_cfg_common (one assignment), then applies its own directives. Lists replace by
 *    pointer unless a directive's apply appends (copy the list first).
 *  - Order inside a block does not matter: at each level every non-block directive
 *    applies first, then each child block compiles from the finished parent.
 *  - A table's default_value goes through the same `apply`, on a synthesised node, before
 *    any config directive of the scope where the directive first becomes valid (the
 *    outermost of global -> server -> location that accepts it); children inherit it.
 *  - Recursion: compilation recurses once per block level. The parser caps nesting at
 *    BST_CFG_MAX_NESTING (64) and validation runs first, so the depth is bounded by 64
 *    frames of small size; no unbounded recursion.
 *
 * A block directive's `apply` creates its scope (see core_directives.c, `server`), points
 * the bst_cfg_ctx at it and returns; the engine then compiles the block's children and
 * restores the ctx. */
#ifndef BST_CONFIG_COMPILE_H
#define BST_CONFIG_COMPILE_H

#include "config/schema.h"
#include "core/addr.h"
#include "core/arena.h"
#include "core/err.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* A source position whose file name is copied into the config arena. */
typedef struct bst_cfg_loc {
	const char *file;
	int line, col;
} bst_cfg_loc;

/* The inheritable part: copied from parent to child. Later phases add fields here. */
typedef struct bst_cfg_common {
	uint64_t client_max_body_size; /* bytes, 0 means unlimited */
} bst_cfg_common;

typedef struct bst_cfg_listen {
	bst_sockaddr addr; /* port-only `listen 8080` is 0.0.0.0:8080 */
	bst_cfg_loc loc;
	/* Later phases add: tls, http2, http3, tcp_profile, redirect_https. */
} bst_cfg_listen;

typedef enum bst_loc_mod {
	BST_LOC_PREFIX = 0, /* no modifier */
	BST_LOC_EXACT,	    /* = */
	BST_LOC_PREFIX_STOP, /* ^~ */
	BST_LOC_REGEX,	    /* ~ */
	BST_LOC_REGEX_I,    /* ~* */
} bst_loc_mod;

typedef struct bst_cfg_location {
	bst_cfg_common common;
	bst_loc_mod mod;
	const char *pattern; /* matching belongs to Phase 5 */
	bst_cfg_loc loc;
} bst_cfg_location;

typedef struct bst_cfg_server {
	bst_cfg_common common;
	const char **names; /* lower-cased; none means the default server */
	size_t nnames;
	bst_cfg_listen *listens;
	size_t nlistens;
	bst_cfg_location **locations; /* file order */
	size_t nlocations;
	bst_cfg_loc loc;
	size_t names_cap_, listens_cap_, locations_cap_; /* growth bookkeeping */
} bst_cfg_server;

typedef struct bst_cfg_global {
	bst_cfg_common common;
	const char *user; /* NULL when unset */
	bool workers_auto;
	int workers; /* valid when !workers_auto */
	const char *pid; /* NULL when unset */
	const char *error_log; /* NULL means stderr */
	const char *error_log_level; /* "warn" when error_log has no level */
	bst_cfg_server **servers; /* file order */
	size_t nservers;
	size_t servers_cap_;
} bst_cfg_global;

typedef struct bst_config {
	bst_arena *arena;
	bst_cfg_global global;
} bst_config;

/* What `apply` sees: the scope kind (one BST_CTX_* bit) and the current scope structs.
 * server is set inside a server and its locations, location only inside a location;
 * common points at the current scope's inheritable part. */
struct bst_cfg_ctx {
	bst_arena *arena;
	uint32_t kind;
	bst_cfg_global *global;
	bst_cfg_server *server;
	bst_cfg_location *location;
	bst_cfg_common *common;
	const char *src_file_, *dst_file_; /* bst_cfg_loc_of cache */
};

/* Sets err's file, line and col from loc (the file stays the AST's). */
void bst_cfg_err_at(bst_err *err, const bst_loc *loc);
/* Config-arena helpers for apply functions. NULL (with err set) on exhaustion. */
char *bst_cfg_strdup(bst_cfg_ctx *c, const char *s, size_t len, bst_err *err);
/* Appends *item to a growing array of n elements of size elt, cap tracked by the caller. */
int bst_cfg_push(bst_cfg_ctx *c, void *arrp, size_t *n, size_t *cap, size_t elt,
		 const void *item, bst_err *err);
/* The node's position with the file name copied into the config arena. */
bst_cfg_loc bst_cfg_loc_of(bst_cfg_ctx *c, const bst_ast_node *n, bst_err *err);

/* NULL with err set on any failure. With _with, schema holds the directive tables to use
 * (tests pass explicit ones); bst_cfg_compile uses the registry. */
bst_config *bst_cfg_compile_with(const bst_schema *s, const bst_ast *ast, bst_err *err);
bst_config *bst_cfg_compile(const bst_ast *ast, bst_err *err);
void bst_config_free(bst_config *cfg);

/* Post-apply hooks run once after every block has applied, in order, and may validate
 * across blocks (references by name, cross-server rules). Core checks (no listen,
 * duplicate listener) run first; their errors carry the positions in the message text
 * (err->file stays NULL, since the config arena is freed on failure). No phase has registered one yet: add to
 * bst_cfg_post_hooks in compile.c. */
typedef int (*bst_cfg_post_fn)(const bst_config *, bst_err *);

/* Core cross-block checks (core_directives.c). */
int bst_cfg_core_check(const bst_config *cfg, bst_err *err);

/* The core directive table, so tests can build a schema from it plus fixtures. */
const bst_dirtab *bst_cfg_core_dirtab(void);

/* Phase 14 hook: true when `tls auto` makes the server listen implicitly. Always false
 * until `tls auto` is registered. */
bool bst_cfg_server_implies_listener(const bst_cfg_server *s);

#endif
