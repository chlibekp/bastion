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
 *      directive's `apply`, copy the parent's common into it when it inherits); if a struct
 *      above it refers to the new one (bst_cfg_location to an upstream), forward-declare the
 *      typedef before that struct.
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
 * (`listen` already gained its first option, `tcp_profile=`, resolved by a post hook: the
 * pattern for a reference by name.)
 * Extending a directive another file registered (`listen` gains `tls`, `http2`, ...):
 * `listen` is declared once, in core_directives.c, and Phase 2 sets max_args = 1 so the
 * schema and the reference do not advertise flags that fail. The phase that adds the first
 * flag raises max_args and the positional types, adds the flags as a BST_T_ENUM positional
 * with `enum_values` (not `.keywords`: a typo is rejected with a suggestion, where a
 * keyword list lets it through as a plain word), and in `ap_listen` stores each one on
 * bst_cfg_listen (a new field next to `addr`). It edits that one table entry and that one apply; it does not
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
#include "config/template.h"
#include "core/addr.h"
#include "core/arena.h"
#include "core/err.h"
#include "io/backend_kind.h"
#include "io/tcp_profile.h"

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

/* `return <status> [text]` (src/http/return.c): the built-in handler. */
typedef struct bst_cfg_return {
	bool set;
	unsigned status;
	const char *text; /* NULL when none given */
	/* The text compiled: a Location (header template) for a redirect status, else the body. */
	const bst_tpl *body;
	const bst_header_tpl *location;
} bst_cfg_return;

/* `rewrite <regex> <replacement> [last|break]` (route/rewrite.c). The regex is compiled by the
 * router's post hook (config/route_directives.c): the pattern and its position are kept here. */
typedef enum bst_rewrite_flag { BST_REWRITE_NONE, BST_REWRITE_LAST, BST_REWRITE_BREAK } bst_rewrite_flag;

typedef struct bst_cfg_rewrite {
	const char *pattern;
	bst_cfg_loc loc;
	struct bst_regex *re;
	const bst_tpl *repl;
	bst_rewrite_flag flag;
} bst_cfg_rewrite;

/* `redirect <code> <target>` and `redirect_https`: answers with a Location and no handler. */
typedef struct bst_cfg_redirect {
	bool set;
	unsigned code;
	const bst_header_tpl *target;
	bool append_query; /* the request's query follows a target that has none of its own */
} bst_cfg_redirect;

/* header_add, header_set, header_remove and their request twins (filters/headers.c). */
typedef enum bst_hdr_op_kind { BST_HDR_ADD, BST_HDR_SET, BST_HDR_REMOVE } bst_hdr_op_kind;

typedef struct bst_cfg_hdr_op {
	bst_hdr_op_kind kind;
	const char *name;
	uint32_t name_len;
	const bst_header_tpl *value; /* NULL for a remove */
	bool always;		     /* also on 4xx and 5xx responses */
} bst_cfg_hdr_op;

/* `expires <duration|off> [immutable]` */
typedef struct bst_cfg_expires {
	bool set;
	uint64_t secs;
	bool immutable;
} bst_cfg_expires;

/* Files (Phase 5 task 5, config/files_directives.c). A serving root is opened once by the master,
 * before any sandbox, and every worker inherits the descriptor: resolution below it is by
 * openat2 relative to that fd, so a path never leaves it. */
typedef struct bst_cfg_root {
	const char *path; /* absolute, no trailing slash (except "/") */
	int fd;		  /* O_PATH directory, -1 until the master opened it */
} bst_cfg_root;

typedef enum bst_symlinks { BST_SYMLINKS_OFF, BST_SYMLINKS_ON, BST_SYMLINKS_OWNER } bst_symlinks;

typedef struct bst_cfg_mime {
	const char *ext; /* lower case, no dot */
	uint32_t ext_len;
	const char *type;
} bst_cfg_mime;

/* error_page <codes> <uri> (config/static_directives.c) */
typedef struct bst_cfg_error_page {
	unsigned codes[16];
	unsigned ncodes;
	const char *uri;
} bst_cfg_error_page;

typedef struct bst_cfg_files {
	bst_cfg_root *root; /* NULL: this scope serves no files */
	bool alias;	    /* the location's own prefix is replaced by the path, not added to it */
	bst_symlinks symlinks;
	bool dotfiles_allow;
	unsigned max_ranges; /* most range specs one Range header may carry */
	bool etag;	     /* send an ETag and honour If-Match and If-None-Match */
	const char *default_type;
	bool sendfile;		    /* file bodies go kernel to socket, else through read buffers */
	uint64_t sendfile_max_chunk; /* bytes one file segment may cover */
	uint64_t read_chunk_size;    /* bytes per read with sendfile off */
	bst_cfg_list mime;	     /* const bst_cfg_mime *, from `types` */
	bst_cfg_list index_files;    /* const char *: names tried for a directory */
	bst_cfg_list try_files;	     /* const bst_tpl *: candidates, then the fallback below */
	bool has_try;
	const bst_tpl *try_uri;	     /* the fallback: re-route to this URI ... */
	unsigned try_code;	     /* ... or answer with this status when non-zero */
	bool autoindex, autoindex_json;
	bool internal;		     /* reachable only through try_files and error_page */
	bst_cfg_list error_pages;    /* const bst_cfg_error_page * */
} bst_cfg_files;

/* The HTTP directives (config/http_directives.c). Connection-level figures are read from the
 * server a connection first reaches (its listener's default server), the rest per request. */
typedef struct bst_cfg_http {
	uint32_t client_max_uri_size;    /* bytes of request-target; more is 414 */
	uint32_t client_max_header_count; /* header lines; more is 431 */
	bool http1_allow_bare_lf;
	uint32_t chunk_ext_limit;        /* bytes of chunk extensions per chunk */
	uint32_t client_max_trailer_size; /* bytes of trailer section */
	uint64_t client_header_timeout_ms;
	uint64_t client_body_timeout_ms;
	uint64_t client_body_min_rate;   /* bytes per second */
	uint64_t send_timeout_ms;
	uint64_t send_min_rate;          /* bytes per second */
	uint64_t keepalive_timeout_ms;
	uint32_t keepalive_requests;
	uint32_t client_header_buffer_size;
	uint32_t large_client_header_buffers; /* largest request line + headers, bytes */
	uint32_t http1_max_pipeline;
	bool lingering_close;
	uint64_t lingering_timeout_ms;
	bool server_tokens;
	bst_cfg_return ret;
} bst_cfg_http;

/* TLS (Phase 6, config/tls_directives.c and src/tls/). A tls_profile block holds the hardened
 * protocol choices, which every server that names it shares; a server holds its certificates and
 * client-authentication policy. The compiled SSL_CTX of each server is built by a post hook, so
 * `bastion -t` loads every certificate and key and fails on a mismatch; master keeps the contexts,
 * and workers inherit them through fork (keys never leave memory and sandboxed workers cannot read
 * the key files). */
typedef enum bst_ktls_mode { BST_KTLS_OFF, BST_KTLS_TX, BST_KTLS_TXRX } bst_ktls_mode;

typedef struct bst_cfg_tls_profile {
	const char *name;
	int min_version, max_version; /* 0x0303 (TLS 1.2) or 0x0304 (TLS 1.3) */
	const char *groups;	      /* ':' separated, as OpenSSL wants them */
	const char *ciphers_tls12;
	const char *ciphersuites_tls13;
	const char *sigalgs;
	bool prefer_server_ciphers;
	bool dh_none;		      /* no finite-field Diffie-Hellman, whatever ciphers say */
	uint64_t handshake_timeout_ms;
	bst_ktls_mode ktls;
	bool ktls_require;
	bst_cfg_loc ktls_loc;
	bool tickets;
	uint64_t tickets_rotate_ms;
	unsigned tickets_keep;
	const char *tickets_file;
	bool ocsp_stapling;
	bool early_data;
	uint32_t early_methods;	      /* bit (1 << bst_method) */
	uint64_t early_max_size;
} bst_cfg_tls_profile;

typedef struct bst_cfg_tls_cert {
	const char *crt, *key;
	bst_cfg_loc loc;
} bst_cfg_tls_cert;

typedef enum bst_client_auth { BST_CLIENT_AUTH_OFF, BST_CLIENT_AUTH_OPTIONAL, BST_CLIENT_AUTH_REQUIRED } bst_client_auth;
typedef enum bst_host_sni { BST_HOST_SNI_421, BST_HOST_SNI_ALLOW } bst_host_sni;
typedef enum bst_http_on_tls { BST_HTTP_ON_TLS_CLOSE, BST_HTTP_ON_TLS_RESPOND } bst_http_on_tls;

typedef struct bst_cfg_tls {
	const char *profile_name; /* NULL: the documented default profile */
	bst_cfg_loc profile_loc;
	const bst_cfg_tls_profile *profile; /* resolved by the post hook, never NULL once certs exist */
	bst_cfg_tls_cert *certs;
	size_t ncerts, certs_cap_;
	bst_cfg_tls_cert default_cert; /* tls_default_cert: the fallback when SNI is absent or unknown */
	bool has_default_cert;
	bool sni_required;	    /* no SNI: the handshake fails */
	bool ja4;		    /* tls_ja4: fingerprint the ClientHello for $ja4 (read on the default server) */
	bool sni_reject;	    /* unknown SNI: unrecognized_name alert, else the default certificate */
	bst_host_sni host_sni;
	bst_client_auth client_auth;
	const char *client_ca, *client_crl;
	unsigned verify_depth;
	bst_http_on_tls http_on_tls;
	const char **ocsp_files;    /* ocsp_file, repeatable */
	size_t nocsp_files, ocsp_files_cap_;
	const char *ocsp_responder; /* ocsp_responder_override */
	void *ctx;		    /* SSL_CTX *, built by the post hook, freed with the config */
	void *default_ctx;	    /* SSL_CTX * of tls_default_cert, or NULL */
	void *ocsp;		    /* struct bst_ocsp_cert set, master-side; see tls/ocsp.h */
} bst_cfg_tls;

/* The inheritable part: copied from parent to child. Later phases add fields here. Lists
 * that inherit use bst_cfg_list; a growable array (bst_cfg_push_owned) must never live here. */
typedef struct bst_cfg_common {
	uint64_t client_max_body_size; /* bytes, 0 means unlimited */
	bool merge_slashes;	       /* "//a" routes as "/a" (read on the server) */
	bst_cfg_http http;
	/* Routing (Phase 5). rewrites: a scope that writes its own replaces what it inherited;
	 * the header operations add to the parent's, so global, then server, then location. */
	bst_cfg_list rewrites;	    /* const bst_cfg_rewrite * */
	bst_cfg_list resp_hdr_ops;  /* const bst_cfg_hdr_op * */
	bst_cfg_list req_hdr_ops;
	bst_cfg_expires expires;
	bst_cfg_redirect redirect;
	unsigned rewrite_max_cycles; /* restarts of the location search per request */
	bst_cfg_files files;
	bool auth_mtls; /* a request needs a verified client certificate: 403 without (tls/conn.c) */
	/* Engine test list fields, kept in the shipped layout so tests run on the real struct;
	 * replace with the first production list field, Phase 11 `add_header` or earlier. */
	bst_cfg_list tags, dtags;
} bst_cfg_common;

typedef struct bst_cfg_listen {
	bst_sockaddr addr; /* port-only `listen 8080` is 0.0.0.0:8080 */
	bst_cfg_loc loc;
	/* tcp_profile=<name>: the name as written (NULL when absent) and where, for the post hook
	 * that resolves it. After compile, tcp is never NULL: the named profile, else the one
	 * another listen on the same address names, else the documented default. */
	const char *tcp_profile_name;
	bst_cfg_loc tcp_loc;
	const bst_tcp_profile *tcp;
	bool default_server; /* `listen 80 default_server`: the server for a Host no name matches */
	bool tls;	     /* `listen 443 tls`: every connection starts with a TLS handshake */
	/* Later phases add: http2, http3, redirect_https. */
} bst_cfg_listen;

/* `unknown_host`: what a request does when its Host matches no server name of the listener. */
typedef enum bst_unknown_host {
	BST_UNKNOWN_HOST_DEFAULT = 0, /* the default server answers */
	BST_UNKNOWN_HOST_421,	      /* 421 Misdirected Request */
	BST_UNKNOWN_HOST_CLOSE,	      /* close the connection without a response */
} bst_unknown_host;

typedef enum bst_loc_mod {
	BST_LOC_PREFIX = 0, /* no modifier */
	BST_LOC_EXACT,	    /* = */
	BST_LOC_PREFIX_STOP, /* ^~ */
	BST_LOC_REGEX,	    /* ~ */
	BST_LOC_REGEX_I,    /* ~* */
} bst_loc_mod;

struct bst_regex;
struct bst_loc_level;

typedef struct bst_cfg_location {
	bst_cfg_common common;
	bst_loc_mod mod;
	const char *pattern;
	struct bst_regex *re;	     /* the compiled pattern of a ~ or ~* location (route/location.c) */
	struct bst_loc_level *lvl;   /* index of the children, NULL when there are none */
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
	bst_unknown_host unknown_host; /* read on the listener's default server */
	bst_cfg_tls tls;		/* certificates and client authentication (Phase 6) */
	struct bst_regex **name_res;   /* parallel to names: the compiled ~regex names, else NULL */
	struct bst_loc_level *lvl;     /* index of the top-level locations; NULL when there are none */
	bst_cfg_loc loc;
	size_t names_cap_, name_locs_cap_, listens_cap_, locations_cap_; /* growth bookkeeping */
} bst_cfg_server;

/* The io { } block (config/io_directives.c). Every field has its default applied even when
 * the block is absent. bst_io_loop_cfg (io/backend.h) turns it into a bst_loop_cfg. */
typedef struct bst_cfg_io {
	bst_backend backend;
	unsigned uring_entries;  /* power of two */
	unsigned uring_bufs;     /* power of two */
	unsigned sqpoll_ms;      /* 0 = off */
	bool napi, napi_require;
	bst_cfg_loc napi_loc;    /* the `uring_napi ... require` statement, when napi_require */
	uint64_t send_zc_min;    /* bytes, 0 = off */
	bool aio_auto;           /* CPU count, capped at BST_AIO_THREADS_AUTO_MAX */
	unsigned aio_threads;    /* valid when !aio_auto */
	unsigned aio_queue;
} bst_cfg_io;

/* The sandbox { } block (config/sandbox_directives.c), a singleton like io. *_require: what the
 * kernel or the environment refuses is a startup error, not a warning. */
typedef enum bst_seccomp_mode { BST_SECCOMP_OFF, BST_SECCOMP_ON, BST_SECCOMP_LOG } bst_seccomp_mode;

typedef struct bst_cfg_sandbox {
	bst_seccomp_mode seccomp;
	bool seccomp_require;
	bool landlock, landlock_require;
	bool namespaces, namespaces_require;
	bool drop_caps, drop_caps_require;
	const char **extra_read, **extra_write; /* absolute paths */
	size_t nextra_read, nextra_write;
	size_t extra_read_cap_, extra_write_cap_;
} bst_cfg_sandbox;

/* The limits { } block (config/limits_directives.c), a singleton like io. Overload protection
 * (proc/admission.h): every figure is per worker. */
#define BST_LIMITS_RESERVE_FDS_MAX 64
typedef struct bst_cfg_limits {
	unsigned max_connections;      /* open connections one worker holds */
	uint64_t worker_memory;        /* bytes of request state one worker may hold */
	unsigned overload_status;      /* HTTP status of a request refused for overload */
	unsigned overload_retry_after; /* seconds, the Retry-After of that response */
	unsigned reserve_fds;          /* descriptors held back to accept-and-close at EMFILE */
	unsigned accept_backoff_ms;    /* how long a listener rests after an accept failure */
} bst_cfg_limits;

typedef struct bst_cfg_global {
	bst_cfg_common common;
	bst_cfg_io io;
	bst_cfg_sandbox sandbox;
	bst_cfg_limits limits;
	const char *user; /* NULL when unset */
	const char *group; /* NULL when unset: the primary group of user */
	bool workers_auto;
	int workers; /* valid when !workers_auto */
	unsigned worker_rlimit_nofile; /* 0 when unset: keep the inherited limit */
	uint64_t shutdown_timeout_ms;
	const char *pid; /* NULL when unset */
	const char *error_log; /* NULL means stderr */
	const char *error_log_level; /* "warn" when error_log has no level */
	bst_cfg_server **servers; /* file order */
	size_t nservers;
	size_t servers_cap_;
	bst_tcp_profile **tcp_profiles; /* file order, names unique after the post hook */
	bst_cfg_loc *tcp_profile_locs;  /* parallel to tcp_profiles */
	size_t ntcp_profiles;
	size_t tcp_profiles_cap_, tcp_profile_locs_cap_;
	bst_tcp_profile tcp_default; /* for a listener with no tcp_profile (set by the post hook) */
	uint32_t regex_match_limit;  /* PCRE2 match limit of every regex match (route/regex.h) */
	uint32_t regex_depth_limit;  /* and its depth limit */
	bst_cfg_tls_profile **tls_profiles; /* file order, names unique after the post hook */
	bst_cfg_loc *tls_profile_locs;	    /* parallel to tls_profiles */
	size_t ntls_profiles, tls_profiles_cap_, tls_profile_locs_cap_;
	bst_cfg_tls_profile tls_default;    /* the profile of a server that names none */
	bst_cfg_root **roots;	     /* every root and alias path, once each (files_directives.c) */
	size_t nroots, roots_cap_;
	size_t ofc_max;		     /* open_file_cache: entries per worker, 0 = off */
	uint64_t ofc_ttl_ms;
	bool ofc_errors;	     /* failures are cached too */
} bst_cfg_global;

/* A load-time warning: dangerous but valid configuration. All strings live in the config
 * arena, so they outlive the AST. */
typedef struct bst_cfg_warning {
	const char *file; /* may be NULL */
	int line, col;
	const char *msg;
} bst_cfg_warning;

typedef struct bst_cfg_cleanup {
	void (*fn)(void *);
	void *arg;
} bst_cfg_cleanup;

typedef struct bst_config {
	bst_arena *arena;
	bst_cfg_global global;
	bst_cfg_warning *warnings;
	size_t nwarnings, warnings_cap_;
	bst_cfg_cleanup *cleanups; /* things the arena cannot free (compiled regexes), malloc'd */
	size_t ncleanups, cleanups_cap_;
} bst_config;

/* Runs fn(arg) when the config is freed (also when the compile that was building it fails). For
 * what lives outside the config arena. 0, or -1 with err set on exhaustion; fn is not called
 * then, the caller frees arg itself. */
int bst_config_on_free(bst_config *cfg, void (*fn)(void *), void *arg, bst_err *err);

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
	bst_tcp_profile *tcp; /* inside a tcp_profile block */
	bst_cfg_tls_profile *tls_profile; /* inside a tls_profile block */
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

/* The hooks sorted by name, built once (thread-safe) from the linker section and checked for
 * duplicate names, which would make their order depend on the linker. 0 with *hooks and *n
 * set (valid for the life of the process), or -1 with err set (the same error every call).
 * bst_cfg_compile fails with it, so a duplicate shows up on the first compile. */
int bst_cfg_post_registry(const bst_cfg_post *const **hooks, size_t *n, bst_err *err);
/* The same for an explicit list (tests): a malloc'd copy sorted by name, to free(), or NULL
 * with err set on a duplicate name or exhaustion. */
const bst_cfg_post **bst_cfg_post_sort_with(const bst_cfg_post *const *hooks, size_t n,
					    bst_err *err);

/* Core cross-block checks (core_directives.c). They run inside compile, with the AST
 * position table, so their errors carry file, line and col like every other. */
int bst_cfg_core_check(const bst_config *cfg, bst_cfg_ctx *c, bst_err *err);

/* The core directive table, so tests can build a schema from it plus fixtures. */
const bst_dirtab *bst_cfg_core_dirtab(void);

/* Phase 14 hook: true when `tls auto` makes the server listen implicitly. Always false
 * until `tls auto` is registered. */
bool bst_cfg_server_implies_listener(const bst_cfg_server *s);

#endif
