/* File-serving directives (Phase 5 task 5): where files are, and how a path may reach them.
 * handlers/resolve.c does the opening; the master opens each root (handlers/roots.c). */
#include "config/compile.h"
#include "config/errfmt.h"
#include "config/values.h"

#include <string.h>

static bst_str as_str(const bst_ast_arg *a)
{
	return (bst_str){ a->text, (uint32_t)a->len };
}

/* The root entry for a path, made on first use: one descriptor per distinct path. */
static bst_cfg_root *root_for(bst_cfg_ctx *c, const bst_ast_arg *a, bst_err *e)
{
	if (a->len == 0 || a->text[0] != '/') {
		char t[BST_SCHEMA_MAX_TOKEN_SHOWN + 8];
		bst_cfg_shown(a->text, a->len, t, sizeof t);
		bst_err_set(e, "\"%s\" is not an absolute path", t);
		bst_cfg_err_at(e, &a->loc);
		return NULL;
	}
	size_t len = a->len;
	while (len > 1 && a->text[len - 1] == '/')
		len--;
	bst_cfg_global *g = c->global;
	for (size_t i = 0; i < g->nroots; i++)
		if (strlen(g->roots[i]->path) == len && memcmp(g->roots[i]->path, a->text, len) == 0)
			return g->roots[i];
	bst_cfg_root *r = bst_arena_alloc(c->arena, sizeof *r);
	if (r == NULL) {
		bst_err_set(e, "out of memory");
		return NULL;
	}
	r->path = bst_cfg_strdup(c, a->text, len, e);
	r->fd = -1;
	if (r->path == NULL ||
	    bst_cfg_push_owned(c, &g->roots, &g->nroots, &g->roots_cap_, sizeof r, &r, e) != 0)
		return NULL;
	return r;
}

static int ap_root(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	bst_cfg_root *r = root_for(c, bst_dir_pos(d, n, 0), e);
	if (r == NULL)
		return -1;
	c->common->files.root = r;
	c->common->files.alias = false;
	return 0;
}

static int ap_alias(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	bst_cfg_root *r = root_for(c, bst_dir_pos(d, n, 0), e);
	if (r == NULL)
		return -1;
	c->common->files.root = r;
	c->common->files.alias = true;
	return 0;
}

static int ap_symlinks(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	c->common->files.symlinks = a->text[1] == 'n' ? BST_SYMLINKS_ON
				    : a->text[1] == 'f' ? BST_SYMLINKS_OFF
							: BST_SYMLINKS_OWNER;
	return 0;
}

static int ap_dotfiles(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	c->common->files.dotfiles_allow = bst_dir_pos(d, n, 0)->text[0] == 'a';
	return 0;
}

static int ap_max_ranges(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	uint64_t v = 0;
	(void)bst_str_to_u64(as_str(bst_dir_pos(d, n, 0)), &v);
	c->common->files.max_ranges = (unsigned)v;
	return 0;
}

static int ap_etag(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	bool v = true;
	(void)bst_parse_bool(as_str(bst_dir_pos(d, n, 0)), &v);
	c->common->files.etag = v;
	return 0;
}

static int ap_types(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *type = bst_dir_pos(d, n, 0);
	if (memchr(type->text, '/', type->len) == NULL) {
		char t[BST_SCHEMA_MAX_TOKEN_SHOWN + 8];
		bst_cfg_shown(type->text, type->len, t, sizeof t);
		bst_err_set(e, "\"%s\" is not a media type (type/subtype)", t);
		bst_cfg_err_at(e, &type->loc);
		return -1;
	}
	const char *ty = bst_cfg_strdup(c, type->text, type->len, e);
	if (ty == NULL)
		return -1;
	for (size_t i = 1; bst_dir_pos(d, n, i) != NULL; i++) {
		const bst_ast_arg *x = bst_dir_pos(d, n, i);
		const char *t = x->text;
		size_t len = x->len;
		if (len > 0 && t[0] == '.') {
			t++;
			len--;
		}
		bst_cfg_mime *m = bst_arena_alloc(c->arena, sizeof *m);
		char *lower = bst_arena_alloc(c->arena, len + 1);
		if (m == NULL || lower == NULL || len == 0) {
			bst_err_set(e, len == 0 ? "empty file extension" : "out of memory");
			if (len == 0)
				bst_cfg_err_at(e, &x->loc);
			return -1;
		}
		for (size_t k = 0; k < len; k++)
			lower[k] = t[k] >= 'A' && t[k] <= 'Z' ? (char)(t[k] + 32) : t[k];
		lower[len] = '\0';
		*m = (bst_cfg_mime){ lower, (uint32_t)len, ty };
		if (bst_cfg_list_extend(c, &c->common->files.mime, m, e) != 0)
			return -1;
	}
	return 0;
}

static int ap_default_type(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	const char *v = bst_cfg_strdup(c, a->text, a->len, e);
	if (v == NULL)
		return -1;
	c->common->files.default_type = v;
	return 0;
}

static int ap_sendfile(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	bool v = true;
	(void)bst_parse_bool(as_str(bst_dir_pos(d, n, 0)), &v);
	c->common->files.sendfile = v;
	return 0;
}

static int ap_sendfile_max_chunk(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
				 bst_err *e)
{
	(void)e;
	uint64_t v = 0;
	(void)bst_parse_size(as_str(bst_dir_pos(d, n, 0)), &v);
	c->common->files.sendfile_max_chunk = v;
	return 0;
}

static int ap_read_chunk_size(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			      bst_err *e)
{
	(void)e;
	uint64_t v = 0;
	(void)bst_parse_size(as_str(bst_dir_pos(d, n, 0)), &v);
	c->common->files.read_chunk_size = v;
	return 0;
}

static int ap_open_file_cache(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			      bst_err *e)
{
	(void)e;
	bst_cfg_global *g = c->global;
	const bst_ast_arg *first = bst_dir_pos(d, n, 0);
	g->ofc_max = 0;
	g->ofc_ttl_ms = 0;
	g->ofc_errors = false;
	if (first != NULL) /* "off" */
		return 0;
	bst_ast_arg v;
	uint64_t x = 0;
	if (bst_dir_opt(d, n, "max=", &v) && bst_str_to_u64(as_str(&v), &x))
		g->ofc_max = (size_t)x;
	uint64_t us = 0;
	if (bst_dir_opt(d, n, "ttl=", &v) && bst_parse_duration_us(as_str(&v), &us))
		g->ofc_ttl_ms = us / 1000;
	bool b = false;
	if (bst_dir_opt(d, n, "errors=", &v) && bst_parse_bool(as_str(&v), &b))
		g->ofc_errors = b;
	return 0;
}

#define SL (BST_CTX_SERVER | BST_CTX_LOCATION)

static const char *const ev_symlinks[] = { "on", "off", "owner_match", NULL };
static const char *const ev_dotfiles[] = { "deny", "allow", NULL };
static const char *const kw_off[] = { "off", NULL };

static const bst_optspec ofc_opts[] = {
	{ .key = "max=", .type = { .kind = BST_T_INT, .min = 1, .max = 1000000 }, .required = false },
	{ .key = "ttl=", .type = { .kind = BST_T_DURATION, .min = 1000000, .max = 86400000000ll },
	  .required = false },
	{ .key = "errors=", .type = { .kind = BST_T_BOOL }, .required = false },
};

static const bst_directive files_dirs[] = {
	{ .name = "root", .contexts = BST_CTX_GLOBAL | SL, .apply = ap_root,
	  .doc = "The directory the files of this scope are served from: the request path is "
		 "appended to it. An absolute path. The directory is opened once at startup (a "
		 "missing one is a startup error) and the workers may read nothing outside the "
		 "served roots, extra_read and what the sandbox allows. A path can never leave the "
		 "root: '..' is removed by normalization and the kernel refuses anything that "
		 "resolves above it (openat2 with RESOLVE_BENEATH).",
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_PATH } } } },
	{ .name = "alias", .contexts = BST_CTX_LOCATION, .apply = ap_alias,
	  .doc = "Like root, but the part of the request path that the location matched is replaced "
		 "by this path instead of the path being appended: location /img/ { alias "
		 "/srv/pics/; } serves /img/a.png from /srv/pics/a.png. Use it with a prefix "
		 "location.",
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_PATH } } } },
	{ .name = "symlinks", .contexts = BST_CTX_GLOBAL | SL, .apply = ap_symlinks,
	  .default_value = "off",
	  .doc = "Whether a symbolic link inside a root may be followed. off: never, a link is a 404. "
		 "on: followed, but only while the result stays inside the root. owner_match: "
		 "followed when the target belongs to the same owner as the root directory, and "
		 "still never out of the root. Magic links (/proc/self/...) are always refused.",
	  .args = { .min_args = 1, .max_args = 1,
		    .pos = { { .kind = BST_T_ENUM, .enum_values = ev_symlinks } } } },
	{ .name = "dotfiles", .contexts = BST_CTX_GLOBAL | SL, .apply = ap_dotfiles,
	  .default_value = "deny",
	  .doc = "Whether a path with a component that starts with '.' (/.env, /.git/config) is "
		 "served. deny: it is a 404 whatever exists there. allow: it is treated like any "
		 "other file. /.well-known/ is not special: allow it in its own location.",
	  .args = { .min_args = 1, .max_args = 1,
		    .pos = { { .kind = BST_T_ENUM, .enum_values = ev_dotfiles } } } },
	{ .name = "max_ranges", .contexts = BST_CTX_GLOBAL | SL, .apply = ap_max_ranges,
	  .default_value = "10",
	  .doc = "Most byte ranges one Range header may ask for. A request with more is answered with "
		 "the whole file and status 200, which the protocol allows and which keeps a client "
		 "from making the server assemble thousands of pieces. Overlapping and adjacent "
		 "ranges are merged first; 1 serves single ranges only.",
	  .args = { .min_args = 1, .max_args = 1,
		    .pos = { { .kind = BST_T_INT, .min = 1, .max = 1000 } } } },
	{ .name = "etag", .contexts = BST_CTX_GLOBAL | SL, .apply = ap_etag, .default_value = "on",
	  .doc = "Whether static files carry an ETag (\"<mtime in hex>-<size in hex>\", strong) and "
		 "If-Match, If-None-Match and If-Range are evaluated against it. With off only "
		 "Last-Modified validates.",
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_BOOL } } } },
	{ .name = "types", .contexts = BST_CTX_GLOBAL | SL, .apply = ap_types, .repeatable = true,
	  .doc = "Maps file extensions to a media type for Content-Type: types text/x-markdown md "
		 "markdown; The extension is the last one in the file name, compared without case. "
		 "These add to the built-in table (about eighty common types) and win over it, and "
		 "the ones of an outer block apply in an inner one. A text type should carry its "
		 "charset: types \"text/plain; charset=utf-8\" txt;",
	  .args = { .min_args = 2, .max_args = BST_ARGS_ANY,
		    .pos = { { .kind = BST_T_STRING }, { .kind = BST_T_STRING } } } },
	{ .name = "default_type", .contexts = BST_CTX_GLOBAL | SL, .apply = ap_default_type,
	  .default_value = "application/octet-stream",
	  .doc = "The Content-Type of a file whose extension is in no `types` entry or the built-in "
		 "table.",
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_STRING } } } },
	{ .name = "sendfile", .contexts = BST_CTX_GLOBAL | SL, .apply = ap_sendfile,
	  .default_value = "on",
	  .doc = "Send file bodies from the page cache to the socket inside the kernel (sendfile, or "
		 "splice on io_uring), so the bytes never enter the worker. With off the worker reads "
		 "each file in read_chunk_size pieces on its thread pool and sends them: slower, and "
		 "the way to serve a file system that does not support sendfile.",
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_BOOL } } } },
	{ .name = "sendfile_max_chunk", .contexts = BST_CTX_GLOBAL | SL,
	  .apply = ap_sendfile_max_chunk, .default_value = "1m",
	  .doc = "The most bytes one sendfile or splice step moves for one connection before the "
		 "worker serves others: it keeps one fast client downloading a huge file from "
		 "starving the rest.",
	  .args = { .min_args = 1, .max_args = 1,
		    .pos = { { .kind = BST_T_SIZE, .min = 4096, .max = 1073741824 } } } },
	{ .name = "read_chunk_size", .contexts = BST_CTX_GLOBAL | SL, .apply = ap_read_chunk_size,
	  .default_value = "64k",
	  .doc = "With sendfile off: the size of each read from the file. One buffer of this size is "
		 "held per downloading connection, so memory is connections times this.",
	  .args = { .min_args = 1, .max_args = 1,
		    .pos = { { .kind = BST_T_SIZE, .min = 4096, .max = 16777216 } } } },
	{ .name = "open_file_cache", .contexts = BST_CTX_GLOBAL, .apply = ap_open_file_cache,
	  .default_value = "off",
	  .doc = "Keeps the descriptor and size of recently served files, per worker, so a hot file "
		 "is not opened and stat'ed for every request. max=<n> entries (each holds one open "
		 "descriptor, so n counts against the open-file limit), ttl=<duration> how long an "
		 "entry is trusted before the file is looked at again (a file replaced inside the "
		 "ttl is served as it was), errors=on also remembers files that were not found. "
		 "off disables the cache.",
	  .args = { .min_args = 0, .max_args = 1, .opts = ofc_opts,
		    .nopts = sizeof ofc_opts / sizeof ofc_opts[0],
		    .pos = { { .kind = BST_T_ENUM, .enum_values = kw_off } } } },
};
BST_DIRECTIVES(files_dirs);

/* Without a ttl or a max the cache would never expire or never hold anything. */
static int post_files_check(bst_config *cfg, bst_cfg_ctx *c, bst_err *e)
{
	(void)c;
	bst_cfg_global *g = &cfg->global;
	if (g->ofc_max > 0 && g->ofc_ttl_ms == 0)
		g->ofc_ttl_ms = 60000;
	(void)e;
	return 0;
}
BST_CFG_POST(post_files_check);
