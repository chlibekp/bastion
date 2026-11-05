/* Compiled runtime config: the AST turned into an immutable, scoped structure that every
 * later phase reads. All of it lives in one arena owned by the bst_config, so
 * bst_config_free is one call, a failed compile frees that arena and returns NULL with err
 * set (nothing is left behind, and a config compiled earlier stays untouched: reload relies
 * on both), and nothing points into the AST or its arena (strings are copied, the AST is
 * freed right after compile).
 *
 * Positions. Every error sets bst_err file, line and col (the offending statement). Those
 * point into the AST and are valid only while the AST is alive: the CLI prints the error
 * before it frees the AST arena, and so must any caller. A bst_cfg_loc stored in the
 * config carries a COPY of the file name in the config arena, for messages that outlive
 * the AST (warnings do this for you); but during compile, and above all in a post hook, an
 * error position must be built from the AST with bst_cfg_src (see below), never from
 * bst_cfg_loc.file: the config arena is freed when compile fails, before the error is
 * printed, and a hook that used it read freed memory.
 *
 * Compile model.
 *  - Validate first (bst_cfg_validate), then apply.
 *  - Inheritance is by struct copy. A child scope starts as a copy of its parent's
 *    bst_cfg_common (one assignment), then applies its own directives. A list in common
 *    replaces by default (see Lists), because a list is replaced as a whole.
 *  - Order inside a block does not matter: at each level every non-block directive
 *    applies first, then each child block compiles from the finished parent.
 *  - Defaults. A table's default_value goes through the same `apply`, on a synthesised
 *    node, in the scope where the directive first becomes valid (the outermost of
 *    global -> server -> location that accepts it); children inherit it. A default is
 *    skipped when the scope sets the directive itself (for a subname_exclusive family,
 *    when it sets any member), so a default never runs next to the user's value and a list
 *    default is simply replaced.
 *  - Singleton blocks. A block directive with .singleton = true may appear at most once in
 *    its parent (a second is a validation error). When it is absent, compile synthesises an
 *    empty scope for it, so its children's defaults apply exactly as if the user had
 *    written `name { }`, and `bastion -T` prints the block with those defaults. Without
 *    this a default inside an unwritten io, sandbox, limits or xdp block would never run.
 *    Non-singleton blocks (server, upstream, ...) are never synthesised. A block that
 *    names things (upstream, tcp_profile) is repeatable and not a singleton.
 *  - Recursion: compilation recurses once per block level. The parser caps nesting at
 *    BST_CFG_MAX_NESTING (64) and validation runs first, so the depth is bounded by 64
 *    frames of small size; no unbounded recursion.
 *
 * How a later phase adds a directive.
 *   1. Declare the field in the scope struct that holds it: bst_cfg_common when it
 *      inherits (global -> server -> location), else bst_cfg_global, bst_cfg_server or
 *      bst_cfg_location. A new block gets its own scope struct (allocate it in the block
 *      directive's `apply`, copy the parent's common into it when it inherits).
 *   2. A new block context: add one line to BST_CTX_LIST (schema.h) and a field for "the
 *      current block" in bst_cfg_ctx (`bst_cfg_upstream *upstream`, next to server and
 *      location). The block directive's `apply` creates the scope, stores it in that field
 *      and returns; the engine then sets ctx->kind to the block's child_ctx, compiles the
 *      children, and restores the WHOLE bst_cfg_ctx it saved before `apply`. So the field
 *      needs no cleanup and the enclosing scope's pointers are back afterwards. Mark a
 *      block that exists once (io, sandbox, limits, xdp) .singleton = true so its
 *      defaults apply when it is not written.
 *   3. Register a table with BST_DIRECTIVES (name, contexts, argspec, doc, default_value).
 *      The argspec (types, bounds, min and max for size, duration and rate) is the whole
 *      validation: apply never re-checks a range the spec states.
 *   4. Write the `apply`: read arguments with bst_dir_pos and friends, store into the
 *      current scope through the bst_cfg_ctx, copy strings with bst_cfg_strdup.
 *   5. Lists in common (see below): bst_cfg_list_append when a scope's own statements
 *      replace what it inherited, bst_cfg_list_extend when they add to it.
 *   6. A reference by name (`tcp_profile=edge`, `proxy upstream_name`): apply records the
 *      name and a position (bst_cfg_loc_of); a post hook resolves it (below), because the
 *      target may come later in the file or in another file.
 *   7. Dangerous but valid config: bst_cfg_warn / bst_cfg_warn_at.
 *   8. Variables in templates: a table with BST_VARS (config/template.h). A directive whose
 *      argument is a template uses BST_T_TEMPLATE; the unknown-variable check is already
 *      wired into the registry schema.
 *   9. Run `./dev make gen-reference` and commit docs/config-reference.md (generated from
 *      the tables; test_reference_up_to_date fails when it is stale).
 * Extending a directive another file registered (`listen` gains `tls`, `http2`, ...):
 * `listen` is declared once, in core_directives.c, and Phase 2 sets max_args = 1 so the
 * schema and the reference do not advertise flags that fail. The phase that adds the first
 * flag raises max_args and the positional types, adds a keyword list of flags to the second
 * positional type (`.keywords`), and in `ap_listen` stores each one on bst_cfg_listen (a
 * new field next to `addr`). It edits that one table entry and that one apply; it does not
 * register a second `listen`, which the schema rejects as a duplicate. The same holds for
 * any directive: one owner file, later phases edit it.
 * Nothing else changes: validation, defaults, inheritance, ordering, the -T printer and the
 * reference come from the engine.
 *
 * Lists. bst_cfg_list carries the address of the scope that owns it. The first
 * bst_cfg_list_append in a scope starts a fresh list there (replacing the parent's, which
 * is what the language specifies for lists), later appends in the same scope add to it,
 * and a child that does not mention the directive inherits the finished list by struct
 * copy. bst_cfg_list_extend instead starts from the inherited items and adds, for a
 * directive documented as "adds to the parent's" (headers set at several levels, say).
 * Never append to .items yourself.
 *
 * Post-apply hooks. `int fn(bst_config *, bst_cfg_ctx *, bst_err *)` registered with
 * BST_CFG_POST(fn), run once after every block applied and after the core checks, in
 * order of the function names (so a hook that must run first is named to sort first). A
 * hook may resolve names to pointers in the config (the config is not const here), run
 * cross-block rules, and warn. To fail: bst_err_set, then bst_cfg_err_at(err,
 * bst_cfg_src(ctx, &the_recorded_loc)), return -1.
 *
 * Warnings. bst_cfg_warn(ctx, node, fmt, ...) and bst_cfg_warn_at(ctx, loc, fmt, ...)
 * record a positioned message in the result (bst_config_warnings), with the position
 * copied into the config arena. `-t` and `-T` print them as `file:line:col: warning:
 * message` on stderr and keep exit status 0. Escape untrusted text with bst_cfg_shown.
 */
#ifndef BST_CONFIG_COMPILE_H
#define BST_CONFIG_COMPILE_H

#include "config/errfmt.h"
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
	uint32_t src_; /* index into the compile-time AST position table; meaningless afterwards */
} bst_cfg_loc;

/* An inherited list. A child's bst_cfg_common is a struct copy, so a child shares the
 * parent's items pointer until it changes the list; the owner tag (the address of the
 * bst_cfg_common that built the array) tells bst_cfg_list_append and _extend whether the
 * array is this scope's to grow. Never touch items, n or the private fields directly. */
typedef struct bst_cfg_list {
	const void *const *items;
	size_t n;
	size_t cap_;
	const void *owner_;
} bst_cfg_list;

/* The inheritable part: copied from parent to child. Later phases add fields here. Lists
 * that inherit use bst_cfg_list; a growable array (bst_cfg_push_owned) must never live here. */
typedef struct bst_cfg_common {
	uint64_t client_max_body_size; /* bytes, 0 means unlimited */
#ifdef BST_TEST
	bst_cfg_list tags, dtags; /* test builds only: inherited lists for the list-semantics tests */
#endif
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
	struct bst_cfg_location *parent; /* NULL for a location directly in a server */
	struct bst_cfg_location **children; /* nested locations, file order */
	size_t nchildren;
	size_t children_cap_;
} bst_cfg_location;

typedef struct bst_cfg_server {
	bst_cfg_common common;
	const char **names; /* lower-cased; none means the default server */
	bst_cfg_loc *name_locs; /* where each name was written, parallel to names */
	size_t nnames;
	bst_cfg_listen *listens;
	size_t nlistens;
	bst_cfg_location **locations; /* file order */
	size_t nlocations;
	bst_cfg_loc loc;
	size_t names_cap_, name_locs_cap_, listens_cap_, locations_cap_; /* growth bookkeeping */
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

/* A load-time warning: dangerous but valid configuration. All strings live in the config
 * arena, so they outlive the AST. */
typedef struct bst_cfg_warning {
	const char *file; /* may be NULL */
	int line, col;
	const char *msg;
} bst_cfg_warning;

typedef struct bst_config {
	bst_arena *arena;
	bst_cfg_global global;
	bst_cfg_warning *warnings;
	size_t nwarnings, warnings_cap_;
} bst_config;

/* The warnings collected while compiling, in the order they were raised. *n may be 0 (the
 * result is then NULL or empty). Valid until bst_config_free. */
const bst_cfg_warning *bst_config_warnings(const bst_config *cfg, size_t *n);

/* What `apply` sees: the scope kind (one BST_CTX_* bit) and the current scope structs.
 * server is set inside a server and its locations, location only inside a location;
 * common points at the current scope's inheritable part. The engine saves the whole
 * struct before a block's `apply` and restores it after the block, so a field a block
 * directive sets (server, location, a later phase's upstream) is back to the enclosing
 * scope's value when the block ends. */
struct bst_cfg_ctx {
	bst_arena *arena;
	uint32_t kind;
	bst_cfg_global *global;
	bst_cfg_server *server;
	bst_cfg_location *location;
	bst_cfg_common *common;
	const char *src_file_, *dst_file_; /* bst_cfg_loc_of cache */
	struct bst_cfg_state *st_;	   /* compile-wide state, shared across blocks */
};

/* Config-arena helpers for apply functions. NULL (with err set) on exhaustion. */
char *bst_cfg_strdup(bst_cfg_ctx *c, const char *s, size_t len, bst_err *err);
/* Appends *item to an array this scope owns alone (names, listens, servers, locations,
 * never a field of bst_cfg_common: a child's copy would share the buffer). cap is tracked
 * by the caller. */
int bst_cfg_push_owned(bst_cfg_ctx *c, void *arrp, size_t *n, size_t *cap, size_t elt,
		 const void *item, bst_err *err);
/* Inherited lists (see Lists above). _append: the first call in a scope replaces what the
 * scope inherited, later calls in the scope add. _extend: starts from the inherited items
 * and adds. Both leave the parent's and sibling scopes' lists untouched. The list must be
 * a field of the current scope's bst_cfg_common (c->common). 0, or -1 with err set. */
int bst_cfg_list_append(bst_cfg_ctx *c, bst_cfg_list *list, const void *item, bst_err *err);
int bst_cfg_list_extend(bst_cfg_ctx *c, bst_cfg_list *list, const void *item, bst_err *err);

/* The position of a node (or of any AST bst_loc, such as an argument's) recorded for later,
 * with the file name copied into the config arena. 0, or -1 with err set (out of memory):
 * the caller must fail, an unrecorded position would make a later error point nowhere. */
int bst_cfg_loc_of(bst_cfg_ctx *c, const bst_ast_node *n, bst_cfg_loc *out, bst_err *err);
int bst_cfg_loc_at(bst_cfg_ctx *c, const bst_loc *loc, bst_cfg_loc *out, bst_err *err);
/* The AST position that a recorded loc was taken from (compile time only: the AST is gone
 * afterwards). This is the position to put in an error; see Positions above. */
const bst_loc *bst_cfg_src(bst_cfg_ctx *c, const bst_cfg_loc *loc);

/* Records a warning at a node or an AST position. fmt is printf-style; text taken from the
 * config goes through bst_cfg_shown first. Never fails the compile on its own (an
 * exhausted arena is reported as an out-of-memory compile error at the end). */
void bst_cfg_warn(bst_cfg_ctx *c, const bst_ast_node *n, const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));
void bst_cfg_warn_at(bst_cfg_ctx *c, const bst_loc *loc, const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));

/* NULL with err set on any failure. With _with, schema holds the directive tables to use
 * (tests pass explicit ones); bst_cfg_compile uses the registry. */
bst_config *bst_cfg_compile_with(const bst_schema *s, const bst_ast *ast, bst_err *err);
bst_config *bst_cfg_compile(const bst_ast *ast, bst_err *err);
void bst_config_free(bst_config *cfg);

/* Post-apply hooks (see the model above). Core checks (no listen, duplicate listener, ...)
 * run first, then every registered hook sorted by name. */
typedef int (*bst_cfg_post_fn)(bst_config *, bst_cfg_ctx *, bst_err *);
typedef struct bst_cfg_post {
	const char *name; /* the function's name, for ordering */
	bst_cfg_post_fn fn;
} bst_cfg_post;

/* Register a hook: `static int post_resolve(bst_config *, bst_cfg_ctx *, bst_err *) {...}
 * BST_CFG_POST(post_resolve);` Same mechanism as BST_DIRECTIVES: a pointer to a static
 * entry (not the entry) in the linker section "bst_cfg_post", marked used and retained, so
 * it works from any translation unit, test files included, and ASan's global redzones do
 * not break the walk. The same project-objects-never-through-an-archive rule applies. */
#define BST_CFG_POST(fn)                                                                \
	static const bst_cfg_post bst_cfg_post_##fn = { #fn, fn };                      \
	static const bst_cfg_post *const bst_cfg_postptr_##fn                           \
		__attribute__((used, section("bst_cfg_post"))) BST_RETAIN_ =            \
			&bst_cfg_post_##fn

/* Core cross-block checks (core_directives.c). They run inside compile, with the AST
 * position table, so their errors carry file, line and col like every other. */
int bst_cfg_core_check(const bst_config *cfg, bst_cfg_ctx *c, bst_err *err);

/* The core directive table, so tests can build a schema from it plus fixtures. */
const bst_dirtab *bst_cfg_core_dirtab(void);

/* Phase 14 hook: true when `tls auto` makes the server listen implicitly. Always false
 * until `tls auto` is registered. */
bool bst_cfg_server_implies_listener(const bst_cfg_server *s);

#endif
