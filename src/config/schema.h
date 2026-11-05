/* Directive schema: the single source of truth for config directives. Each subsystem
 * declares a static table of bst_directive and registers it with BST_DIRECTIVES(table).
 * bst_cfg_validate, the effective-config printer and the reference generator all derive
 * from these tables, so type information lives in the argspec, never in apply functions.
 *
 * Registration. BST_DIRECTIVES puts a pointer to the table (not the table itself) in the
 * linker section "bst_directives", each pointer marked used (and retain where the
 * compiler has it). Pointers, because ASan puts redzones around globals and that would
 * break walking an array of tables laid out in a section. The __start_/__stop_ symbols
 * are weak, so a binary with no tables links and sees zero tables. It works from any
 * translation unit, test files included. Linking: project objects are linked directly
 * (never through an archive), so every table in a src/ object stays; if a library
 * archive is ever introduced, a table's object is dropped unless something else pulls
 * it in, and scripts/check-directives-linked.sh exists to catch that in the release
 * binary.
 *
 * Contexts. A directive is valid in a bitmask of contexts. A block-opening directive
 * names the context its block defines in child_ctx. To add a context, add one line to
 * BST_CTX_LIST: no logic changes (the limit is 32 contexts).
 *
 * Values. A directive's arguments are described declaratively by a bst_argspec:
 * positional count limits, a type per position (the last one repeats), allowed key=value
 * options each with a type, and whether a block is required, forbidden or optional.
 * Typed values are checked against the arg's `text`; only BST_T_TEMPLATE positions accept
 * a $variable (any other position with a variable is an error, never a silent no-op).
 *
 * Argument classification. A word is an option when it starts with a key the directive
 * declares (bare or quoted, so "path=/a b" works); otherwise a bare word shaped like
 * `name=` is an error (a typo must not become a positional value), while any quoted
 * word stays positional. A trailing bare `require` is a flag only where the directive
 * declares `require`. For a two-word directive (subname) the first argument selects the
 * entry and is not counted among the positionals. One classifier serves validation and
 * the bst_dir_* accessors that `apply` functions use.
 *
 * Two-word directives (`tls verify on;`, `balance hash $key;`): several entries share a
 * name, each with its own subname and argspec; the duplicate key is (name, subname), so
 * `tls verify on; tls ca /x;` passes. When the subnames are alternatives of one setting
 * (`balance peak_ewma; balance least_conn;`) set .subname_exclusive on those entries: the
 * duplicate key is then the name alone and the second statement is the error.
 * A catch-all entry (`any_name`) matches any statement name in its context when no exact
 * entry does (log_format fields); it must be repeatable.
 *
 * Integrity (bst_schema_build, once for the registry): non-empty doc, sane names and
 * argspec, non-NULL apply, default_value parses under its own argspec (split on spaces,
 * no quoting), no two directives of one (name, subname) share a context. */
#ifndef BST_CONFIG_SCHEMA_H
#define BST_CONFIG_SCHEMA_H

#include "config/parser.h"
#include "core/err.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* One line per context: X(IDENT, "name"). */
#define BST_CTX_LIST(X)                                                                 \
	X(GLOBAL, "global")                                                             \
	X(IO, "io")                                                                     \
	X(SANDBOX, "sandbox")                                                           \
	X(LIMITS, "limits")                                                             \
	X(XDP, "xdp")                                                                   \
	X(TCP_PROFILE, "tcp_profile")                                                   \
	X(TLS_PROFILE, "tls_profile")                                                   \
	X(LOG_FORMAT, "log_format")                                                     \
	X(UPSTREAM, "upstream")                                                         \
	X(CACHE_STORE, "cache_store")                                                   \
	X(LIMIT_ZONE, "limit_zone")                                                     \
	X(WAF_RULE, "waf_rule")                                                         \
	X(SERVER, "server")                                                             \
	X(LOCATION, "location")                                                         \
	X(METRICS, "metrics")                                                           \
	X(ADMIN, "admin")                                                               \
	X(ACME, "acme")

#define BST_CTX_X_INDEX(n, s) BST_CTXI_##n,
enum { BST_CTX_LIST(BST_CTX_X_INDEX) BST_CTX_COUNT };
#define BST_CTX_X_BIT(n, s) BST_CTX_##n = 1u << BST_CTXI_##n,
enum bst_ctx { BST_CTX_LIST(BST_CTX_X_BIT) };
#define BST_CTX_ALL ((uint32_t)((1u << BST_CTX_COUNT) - 1))
_Static_assert(BST_CTX_COUNT <= 32, "contexts are a 32-bit mask");

/* Name of a single context bit, or "?" for anything else. */
const char *bst_ctx_name(uint32_t ctx);

/* Limits. */
#define BST_ARGSPEC_MAX_POS 8	   /* positional type slots */
#define BST_ARGSPEC_MAX_OPTS 16	   /* key= options per directive */
#define BST_SCHEMA_MAX_NAME 64	   /* directive name length */
#define BST_SCHEMA_MAX_DIRECTIVES 4096
#define BST_SCHEMA_DEFAULT_MAX_ARGS 16
#define BST_SCHEMA_DEFAULT_MAX_LEN 128
#define BST_SCHEMA_MAX_TOKEN_SHOWN 40 /* input bytes echoed in an error message */
#define BST_SUGGEST_MAX_DIST 2	   /* Levenshtein bound for "did you mean" */
#define BST_ARGS_ANY 0xffffu	   /* max_args: no upper bound */

typedef enum bst_vtype {
	BST_T_NONE = 0, /* ends the positional list */
	BST_T_STRING,
	BST_T_TEMPLATE, /* may contain $variables; compiled by the consumer */
	BST_T_SIZE,
	BST_T_DURATION,
	BST_T_RATE,
	BST_T_BOOL,
	BST_T_ENUM, /* enum_values */
	BST_T_INT,  /* min..max */
	BST_T_PERCENT,
	BST_T_PATH, /* non-empty string */
	BST_T_CIDR,
	BST_T_MODE, /* file mode: 3 or 4 octal digits, 0600 */
	BST_T_COUNT_
} bst_vtype;

const char *bst_vtype_name(bst_vtype t);

typedef struct bst_argtype {
	bst_vtype kind;
	const char *const *enum_values; /* NULL-terminated, for BST_T_ENUM */
	int64_t min, max;		/* for BST_T_INT */
	const char *const *keywords;	/* NULL-terminated; accepted verbatim before the type */
	bool list;			/* comma-separated; each element is a keyword or the type */
} bst_argtype;

typedef struct bst_optspec {
	const char *key; /* "weight=": includes the '=' */
	bst_argtype type;
	bool required;
} bst_optspec;

typedef enum bst_block_rule {
	BST_BLOCK_FORBIDDEN = 0,
	BST_BLOCK_REQUIRED,
	BST_BLOCK_OPTIONAL,
} bst_block_rule;

typedef struct bst_argspec {
	uint16_t min_args, max_args; /* positional arguments; options are not counted */
	bst_argtype pos[BST_ARGSPEC_MAX_POS]; /* leading entries; kind NONE ends; last repeats */
	const bst_optspec *opts;
	size_t nopts;
	bst_block_rule block;
} bst_argspec;

/* Opaque here; the compiler (Task 4) defines it as giving the current scope and kind. */
typedef struct bst_cfg_ctx bst_cfg_ctx;
struct bst_directive;
/* d is the matched entry (it differs from the name alone for two-word directives). */
typedef int (*bst_dir_apply)(bst_cfg_ctx *, const struct bst_directive *, const bst_ast_node *,
			     bst_err *);

struct bst_directive {
	const char *name;
	const char *subname;	     /* two-word directive: the required first argument */
	uint32_t contexts;	     /* bitmask of BST_CTX_* */
	bst_argspec args;
	const char *default_value; /* NULL means unset is valid */
	const char *doc;	     /* required, non-empty */
	bst_dir_apply apply;	     /* 0 or -1 with err set; required */
	uint32_t child_ctx;	     /* the one context a block defines; 0 when no block */
	bool repeatable;	     /* may appear more than once in a scope */
	bool require;		     /* a trailing `require` argument is accepted */
	bool any_name;		     /* catch-all for this context; name is only a label */
	bool subname_exclusive;	     /* two-word: the duplicate key is the name alone */
};
typedef struct bst_directive bst_directive;

typedef struct bst_dirtab {
	const bst_directive *dirs;
	size_t n;
} bst_dirtab;

#if defined(__has_attribute)
#if __has_attribute(retain)
#define BST_RETAIN_ __attribute__((retain))
#endif
#endif
#ifndef BST_RETAIN_
#define BST_RETAIN_
#endif

/* Register a table: `static const bst_directive name[] = {...}; BST_DIRECTIVES(name);` */
#define BST_DIRECTIVES(table)                                                           \
	static const bst_dirtab bst_dirtab_##table = { (table),                         \
						       sizeof(table) / sizeof((table)[0]) }; \
	static const bst_dirtab *const bst_dirptr_##table                               \
		__attribute__((used, section("bst_directives"))) BST_RETAIN_ =          \
			&bst_dirtab_##table

/* The registered tables (from the linker section). *n is 0 and NULL is returned when
 * none are registered. */
const bst_dirtab *const *bst_dirtabs(size_t *n);

/* Integrity of one directive (doc, argspec, default). 0 or -1 with err set. */
int bst_directive_check(const bst_directive *d, bst_err *err);

typedef struct bst_schema bst_schema;

/* Checks and indexes tables. NULL with err set on any integrity failure, including a
 * duplicate name in overlapping contexts. */
bst_schema *bst_schema_build(const bst_dirtab *const *tabs, size_t n, bst_err *err);
void bst_schema_free(bst_schema *s);
/* The registry schema, built from the linker section once (thread-safe); the same result
 * every call. NULL with err set when the registered tables fail integrity. */
const bst_schema *bst_schema_registry(bst_err *err);
/* The directive called name valid in the single context ctx, or NULL. */
const bst_directive *bst_schema_find(const bst_schema *s, const char *name, size_t len,
				     uint32_t ctx);

/* The entry that governs statement n in ctx, exactly as validation resolves it (exact name,
 * two-word subname, then the catch-all), or NULL. */
const bst_directive *bst_schema_match(const bst_schema *s, const bst_ast_node *n, uint32_t ctx);
/* Every directive of the schema, in index order (for default application and printers). */
size_t bst_schema_count(const bst_schema *s);
const bst_directive *bst_schema_at(const bst_schema *s, size_t i);

/* Same, for a two-word directive: the entry whose subname is exactly sub. */
const bst_directive *bst_schema_find_sub(const bst_schema *s, const char *name, size_t len,
					 uint32_t ctx, const char *sub, size_t sublen);

/* Accessors for apply functions, sharing the validator's classifier. Positions count
 * positional arguments only: options, the `require` flag and a two-word directive's
 * subname are skipped. */
size_t bst_dir_npos(const bst_directive *d, const bst_ast_node *n);
/* The i-th positional argument, or NULL. */
const bst_ast_arg *bst_dir_pos(const bst_directive *d, const bst_ast_node *n, size_t i);
/* The option with key (for example "weight="); on a match fills *val with the value part
 * (text, tpl and their lengths; kind and loc are the whole argument's) and returns true. */
bool bst_dir_opt(const bst_directive *d, const bst_ast_node *n, const char *key,
		 bst_ast_arg *val);
bool bst_dir_has_require(const bst_directive *d, const bst_ast_node *n);

/* Checks one statement's arguments, options and block against d's argspec. */
int bst_directive_check_node(const bst_directive *d, const bst_ast_node *n, bst_err *err);

/* Template check hook. A BST_T_TEMPLATE position is checked by this function when set, so
 * an unknown variable fails at `-t`; schema.c itself knows nothing about variables or the
 * hot-path template code. Startup installs bst_tpl_check_arg (config/template.h) once,
 * before any validation and before workers exist; it is a plain pointer with no locking.
 * With no hook, templates are not checked. The function returns 0, or -1 with err set
 * (including the arg's position). */
typedef int (*bst_tpl_check_fn)(const bst_ast_arg *, bst_err *);
void bst_schema_set_tpl_check(bst_tpl_check_fn fn);

/* Validates a whole AST against the registry (or a given schema): unknown directives
 * with a suggestion, wrong contexts, argument types, duplicate scalars. Iterative. Stops
 * at the first error: 0 or -1 with err set (file/line/col from the offending node). */
int bst_cfg_validate(const bst_ast *ast, bst_err *err);
int bst_cfg_validate_with(const bst_schema *s, const bst_ast *ast, bst_err *err);

#endif
