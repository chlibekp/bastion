/* index, try_files, autoindex, error_page and internal (Phase 5 task 8): what a request for a
 * directory, a missing file or an error does. handlers/static.c runs them. */
#include "config/compile.h"
#include "config/errfmt.h"
#include "config/template.h"
#include "config/values.h"

#include <string.h>

static bst_str as_str(const bst_ast_arg *a)
{
	return (bst_str){ a->text, (uint32_t)a->len };
}

static int ap_index(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	for (size_t i = 0; bst_dir_pos(d, n, i) != NULL; i++) {
		const bst_ast_arg *a = bst_dir_pos(d, n, i);
		if (memchr(a->text, '/', a->len) != NULL) {
			bst_err_set(e, "an index name is a file name, not a path");
			bst_cfg_err_at(e, &a->loc);
			return -1;
		}
		const char *nm = bst_cfg_strdup(c, a->text, a->len, e);
		if (nm == NULL || bst_cfg_list_append(c, &c->common->files.index_files, nm, e) != 0)
			return -1;
	}
	return 0;
}

static int ap_try_files(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	size_t np = bst_dir_npos(d, n);
	bst_cfg_files *f = &c->common->files;
	f->try_files = (bst_cfg_list){ 0 }; /* a statement replaces, never extends, the inherited list */
	f->try_uri = NULL;
	f->try_code = 0;
	for (size_t i = 0; i + 1 < np; i++) {
		const bst_tpl *t = bst_tpl_compile_arg(bst_dir_pos(d, n, i), c->arena, e);
		if (t == NULL || bst_cfg_list_append(c, &f->try_files, t, e) != 0)
			return -1;
	}
	const bst_ast_arg *last = bst_dir_pos(d, n, np - 1);
	if (last->len > 0 && last->text[0] == '=') {
		uint64_t code = 0;
		if (!bst_str_to_u64((bst_str){ last->text + 1, (uint32_t)last->len - 1 }, &code) ||
		    code < 200 || code > 599) {
			bst_err_set(e, "\"=code\" needs a status from 200 to 599");
			bst_cfg_err_at(e, &last->loc);
			return -1;
		}
		f->try_code = (unsigned)code;
	} else {
		if (last->len == 0 || last->text[0] != '/') {
			bst_err_set(e, "the last try_files argument is a URI starting with '/' or =code");
			bst_cfg_err_at(e, &last->loc);
			return -1;
		}
		f->try_uri = bst_tpl_compile_arg(last, c->arena, e);
		if (f->try_uri == NULL)
			return -1;
	}
	f->has_try = true;
	return 0;
}

static int ap_autoindex(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	bool v = false;
	(void)bst_parse_bool(as_str(bst_dir_pos(d, n, 0)), &v);
	c->common->files.autoindex = v;
	return 0;
}

static int ap_autoindex_format(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			       bst_err *e)
{
	(void)e;
	c->common->files.autoindex_json = bst_dir_pos(d, n, 0)->text[0] == 'j';
	return 0;
}

static int ap_internal(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)d, (void)n, (void)e;
	c->common->files.internal = true;
	return 0;
}

static int ap_error_page(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	size_t np = bst_dir_npos(d, n);
	const bst_ast_arg *uri = bst_dir_pos(d, n, np - 1);
	if (np - 1 > 16) {
		bst_err_set(e, "error_page takes at most 16 status codes");
		bst_cfg_err_at(e, &uri->loc);
		return -1;
	}
	if (uri->len == 0 || uri->text[0] != '/') {
		bst_err_set(e, "the error_page target is a URI starting with '/'");
		bst_cfg_err_at(e, &uri->loc);
		return -1;
	}
	bst_cfg_error_page *p = bst_arena_alloc(c->arena, sizeof *p);
	if (p == NULL) {
		bst_err_set(e, "out of memory");
		return -1;
	}
	memset(p, 0, sizeof *p);
	for (size_t i = 0; i + 1 < np; i++) {
		uint64_t code = 0;
		const bst_ast_arg *a = bst_dir_pos(d, n, i);
		if (!bst_str_to_u64(as_str(a), &code) || code < 400 || code > 599) {
			bst_err_set(e, "error_page codes are statuses from 400 to 599");
			bst_cfg_err_at(e, &a->loc);
			return -1;
		}
		p->codes[p->ncodes++] = (unsigned)code;
	}
	p->uri = bst_cfg_strdup(c, uri->text, uri->len, e);
	if (p->uri == NULL)
		return -1;
	return bst_cfg_list_extend(c, &c->common->files.error_pages, p, e);
}

#define SL (BST_CTX_SERVER | BST_CTX_LOCATION)
#define ALL3 (BST_CTX_GLOBAL | SL)

static const char *const ev_format[] = { "html", "json", NULL };

static const bst_directive static_dirs[] = {
	{ .name = "index", .contexts = ALL3, .apply = ap_index, .default_value = "index.html",
	  .doc = "The files a request for a directory (a path ending in '/') tries, in order; the "
		 "first that exists is served. When none does, the directory is listed if autoindex "
		 "is on, else the answer is 403. A name is a file name only.",
	  .args = { .min_args = 1, .max_args = BST_ARGS_ANY, .pos = { { .kind = BST_T_STRING } } } },
	{ .name = "try_files", .contexts = SL, .apply = ap_try_files,
	  .doc = "Looks for each argument but the last as a file (a name ending in '/' is a "
		 "directory) below the root, and serves the first that exists. If none does, the last "
		 "argument decides: a URI the request is re-routed to, or =code to answer with that "
		 "status. Arguments may use variables: try_files $uri $uri/ /index.html; gives a "
		 "single-page application its fallback. A re-route counts against rewrite_max_cycles.",
	  .args = { .min_args = 2, .max_args = BST_ARGS_ANY, .pos = { { .kind = BST_T_TEMPLATE } } } },
	{ .name = "autoindex", .contexts = ALL3, .apply = ap_autoindex, .default_value = "off",
	  .doc = "List a directory that has no index file. The listing streams in directory order "
		 "(it is never sorted, so a directory of a million files costs bounded memory); names "
		 "starting with '.' are left out unless dotfiles allow, and links unless symlinks is on.",
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_BOOL } } } },
	{ .name = "autoindex_format", .contexts = ALL3, .apply = ap_autoindex_format,
	  .default_value = "html",
	  .doc = "The listing as an html page, or as a json array of {name, type, mtime, size}.",
	  .args = { .min_args = 1, .max_args = 1,
		    .pos = { { .kind = BST_T_ENUM, .enum_values = ev_format } } } },
	{ .name = "error_page", .contexts = ALL3, .apply = ap_error_page, .repeatable = true,
	  .doc = "Answers the listed statuses (400 to 599) with the page at a URI of this server, "
		 "keeping the status: error_page 404 /404.html; The page is served through the router "
		 "once; if it fails too, the built-in page for that failure is sent, so a missing error "
		 "page never loops. Put the page in a location marked internal to hide it from direct "
		 "requests. The statuses of a block add to those of its parent.",
	  .args = { .min_args = 2, .max_args = BST_ARGS_ANY, .pos = { { .kind = BST_T_STRING } } } },
	{ .name = "internal", .contexts = BST_CTX_LOCATION, .apply = ap_internal,
	  .doc = "Marks the location as reachable only by internal redirects (try_files and "
		 "error_page): a client asking for it directly gets 404.",
	  .args = { .min_args = 0, .max_args = 0 } },
};
BST_DIRECTIVES(static_dirs);
