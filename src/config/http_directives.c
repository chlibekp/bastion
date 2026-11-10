/* HTTP directives (Phase 4): request limits, timeouts and the h1 connection's figures. They live
 * in bst_cfg_common.http, set per server (a connection takes its figures from the default
 * server of its listener, before the Host header says which server it is for). `return` and
 * client_max_body_size are per server and location. Every figure here is a directive with a
 * default; nothing in src/http carries a constant an operator might need to change. */
#include "config/compile.h"
#include "config/values.h"
#include "core/str.h"

#define SEC 1000000LL

static bst_str as_str(const bst_ast_arg *a)
{
	return (bst_str){ a->text, (uint32_t)a->len };
}

static uint64_t u64_of(const bst_directive *d, const bst_ast_node *n)
{
	uint64_t v = 0;
	(void)bst_str_to_u64(as_str(bst_dir_pos(d, n, 0)), &v); /* validated by the argspec */
	return v;
}

static uint64_t size_of(const bst_directive *d, const bst_ast_node *n)
{
	uint64_t v = 0;
	(void)bst_parse_size(as_str(bst_dir_pos(d, n, 0)), &v);
	return v;
}

static bool bool_of(const bst_directive *d, const bst_ast_node *n)
{
	bool v = false;
	(void)bst_parse_bool(as_str(bst_dir_pos(d, n, 0)), &v);
	return v;
}

#define AP(fn, field, expr)                                                             \
	static int fn(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,    \
		      bst_err *e)                                                        \
	{                                                                                \
		(void)e;                                                                 \
		c->common->http.field = (expr);                                          \
		return 0;                                                                \
	}

AP(ap_uri_size, client_max_uri_size, (uint32_t)size_of(d, n))
AP(ap_header_count, client_max_header_count, (uint32_t)u64_of(d, n))
AP(ap_bare_lf, http1_allow_bare_lf, bool_of(d, n))
AP(ap_chunk_ext, chunk_ext_limit, (uint32_t)size_of(d, n))
AP(ap_trailer_size, client_max_trailer_size, (uint32_t)size_of(d, n))

#define ARG1(...) .args = { .min_args = 1, .max_args = 1, .pos = { __VA_ARGS__ } }
#define SRV BST_CTX_SERVER

static const bst_directive http_dirs[] = {
	{ .name = "client_max_uri_size", .contexts = SRV, .apply = ap_uri_size,
	  .default_value = "8k",
	  .doc = "Largest request-target (path and query), in bytes. A longer one is refused with "
		 "414 as soon as the byte over the limit arrives, so the server never buffers it. "
		 "It must fit inside large_client_header_buffers.",
	  ARG1({ .kind = BST_T_SIZE, .min = 256, .max = 1 << 20 }) },
	{ .name = "client_max_header_count", .contexts = SRV, .apply = ap_header_count,
	  .default_value = "100",
	  .doc = "Most header lines in one request. One more is refused with 431.",
	  ARG1({ .kind = BST_T_INT, .min = 1, .max = 4096 }) },
	{ .name = "http1_allow_bare_lf", .contexts = SRV, .apply = ap_bare_lf,
	  .default_value = "off",
	  .doc = "Accept a lone LF as a line ending in HTTP/1.1 requests (RFC 9112 section 2.2 "
		 "allows it, but proxies that disagree about line endings enable request "
		 "smuggling). Off by default: a bare LF is answered 400. A bare CR is always "
		 "refused.",
	  ARG1({ .kind = BST_T_BOOL }) },
	{ .name = "chunk_ext_limit", .contexts = SRV, .apply = ap_chunk_ext, .default_value = "1k",
	  .doc = "Most bytes of chunk extensions (the text after a ';' on a chunk-size line) one "
		 "chunk of a request body may carry. Extensions are ignored; more than this is "
		 "answered 400 and the connection closed.",
	  ARG1({ .kind = BST_T_SIZE, .min = 16, .max = 65536 }) },
	{ .name = "client_max_trailer_size", .contexts = SRV, .apply = ap_trailer_size,
	  .default_value = "8k",
	  .doc = "Largest trailer section (the header lines after the last chunk) of a chunked "
		 "request body, in bytes. A larger one is refused with 431. Trailer fields that "
		 "could change how a message is framed, routed or authenticated are dropped.",
	  ARG1({ .kind = BST_T_SIZE, .min = 0, .max = 1 << 20 }) },
};
BST_DIRECTIVES(http_dirs);
