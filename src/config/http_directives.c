/* HTTP directives (Phase 4): request limits, timeouts and the h1 connection's figures. They live
 * in bst_cfg_common.http, set per server (a connection takes its figures from the default
 * server of its listener, before the Host header says which server it is for). `return` and
 * client_max_body_size are per server and location. Every figure here is a directive with a
 * default; nothing in src/http carries a constant an operator might need to change. */
#include "config/compile.h"
#include "config/values.h"
#include "route/vars.h"
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
static uint64_t ms_of(const bst_directive *d, const bst_ast_node *n)
{
	uint64_t us = 0;
	(void)bst_parse_duration_us(as_str(bst_dir_pos(d, n, 0)), &us);
	return us / 1000;
}

AP(ap_hdr_timeout, client_header_timeout_ms, ms_of(d, n))
AP(ap_body_timeout, client_body_timeout_ms, ms_of(d, n))
AP(ap_body_rate, client_body_min_rate, size_of(d, n))
AP(ap_send_timeout, send_timeout_ms, ms_of(d, n))
AP(ap_send_rate, send_min_rate, size_of(d, n))
AP(ap_ka_timeout, keepalive_timeout_ms, ms_of(d, n))
AP(ap_ka_requests, keepalive_requests, (uint32_t)u64_of(d, n))
AP(ap_hdr_buf, client_header_buffer_size, (uint32_t)size_of(d, n))
AP(ap_large_hdr, large_client_header_buffers, (uint32_t)size_of(d, n))
AP(ap_pipeline, http1_max_pipeline, (uint32_t)u64_of(d, n))
AP(ap_linger, lingering_close, bool_of(d, n))
AP(ap_linger_timeout, lingering_timeout_ms, ms_of(d, n))
AP(ap_tokens, server_tokens, bool_of(d, n))

static int ap_return(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *st = bst_dir_pos(d, n, 0), *tx = bst_dir_pos(d, n, 1);
	uint64_t v = 0;
	(void)bst_str_to_u64(as_str(st), &v); /* validated by the argspec */
	bst_cfg_return r = { .set = true, .status = (unsigned)v, .text = NULL };
	if (tx != NULL) {
		r.text = bst_cfg_strdup(c, tx->text, tx->len, e);
		if (r.text == NULL)
			return -1;
		bool redirect = r.status == 301 || r.status == 302 || r.status == 303 ||
				r.status == 307 || r.status == 308;
		if (redirect) {
			r.location = bst_tpl_compile_header_arg(tx, c->arena, e);
			if (r.location == NULL)
				return -1;
			if (bst_var_is_request_input(bst_header_tpl_first_var(r.location)))
				bst_cfg_warn_at(c, &tx->loc,
						"the Location starts with a value taken from the request: "
						"an open redirect");
		} else {
			r.body = bst_tpl_compile_arg(tx, c->arena, e);
			if (r.body == NULL)
				return -1;
		}
	}
	c->common->http.ret = r;
	c->common->redirect.set = false; /* the later statement, or the nearer scope, answers */
	return 0;
}

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
	{ .name = "client_header_timeout", .contexts = SRV, .apply = ap_hdr_timeout,
	  .default_value = "10s",
	  .doc = "Time a client has to send a complete request head, counted from its first byte "
		 "(or from the connection, for the first request). A slow head is answered 408 and "
		 "the connection closed. The limit is on the whole head, so trickling bytes does not "
		 "extend it.",
	  ARG1({ .kind = BST_T_DURATION, .min = 1000, .max = (int64_t)3600 * 1000000 }) },
	{ .name = "client_body_timeout", .contexts = SRV, .apply = ap_body_timeout,
	  .default_value = "30s",
	  .doc = "Window in which a request body must make progress: every window, at least "
		 "client_body_min_rate bytes per second must have arrived, or the request is "
		 "answered 408 and the connection closed.",
	  ARG1({ .kind = BST_T_DURATION, .min = 1000, .max = (int64_t)3600 * 1000000 }) },
	{ .name = "client_body_min_rate", .contexts = SRV, .apply = ap_body_rate,
	  .default_value = "1k",
	  .doc = "Slowest accepted request body, in bytes per second, averaged over "
		 "client_body_timeout. 0 turns the rate check off (only a body that stops "
		 "completely times out).",
	  ARG1({ .kind = BST_T_SIZE }) },
	{ .name = "send_timeout", .contexts = SRV, .apply = ap_send_timeout,
	  .default_value = "30s",
	  .doc = "Window in which a response must make progress: every window, at least "
		 "send_min_rate bytes per second must have been accepted by the client, or the "
		 "connection is closed. Frees workers held by clients that never read.",
	  ARG1({ .kind = BST_T_DURATION, .min = 1000, .max = (int64_t)3600 * 1000000 }) },
	{ .name = "send_min_rate", .contexts = SRV, .apply = ap_send_rate, .default_value = "1k",
	  .doc = "Slowest accepted reader of a response, in bytes per second, averaged over "
		 "send_timeout. 0 turns the rate check off.",
	  ARG1({ .kind = BST_T_SIZE }) },
	{ .name = "keepalive_timeout", .contexts = SRV, .apply = ap_ka_timeout,
	  .default_value = "75s",
	  .doc = "How long an idle connection waits for its next request. 0s turns keep-alive off: "
		 "every response closes the connection.",
	  ARG1({ .kind = BST_T_DURATION, .min = 0, .max = (int64_t)86400 * 1000000 }) },
	{ .name = "keepalive_requests", .contexts = SRV, .apply = ap_ka_requests,
	  .default_value = "1000",
	  .doc = "Most requests one connection serves; the last response carries Connection: close.",
	  ARG1({ .kind = BST_T_INT, .min = 1, .max = 1 << 30 }) },
	{ .name = "client_header_buffer_size", .contexts = SRV, .apply = ap_hdr_buf,
	  .default_value = "1k",
	  .doc = "Initial read buffer for a request head. It grows up to large_client_header_buffers "
		 "when a head needs more; most requests never do.",
	  ARG1({ .kind = BST_T_SIZE, .min = 256, .max = 1 << 20 }) },
	{ .name = "large_client_header_buffers", .contexts = SRV, .apply = ap_large_hdr,
	  .default_value = "16k",
	  .doc = "Largest request head (request line and all header lines), in bytes. A larger one "
		 "is refused with 431. Must be at least client_max_uri_size.",
	  ARG1({ .kind = BST_T_SIZE, .min = 1024, .max = 1 << 20 }) },
	{ .name = "http1_max_pipeline", .contexts = SRV, .apply = ap_pipeline,
	  .default_value = "8",
	  .doc = "Most requests of one HTTP/1.1 connection that may be accepted ahead of their "
		 "responses. Beyond it the server stops reading the connection until responses go "
		 "out, so a client that pipelines and never reads cannot grow server memory.",
	  ARG1({ .kind = BST_T_INT, .min = 1, .max = 1024 }) },
	{ .name = "lingering_close", .contexts = SRV, .apply = ap_linger, .default_value = "on",
	  .doc = "When the server closes a connection after an error response, send FIN, then keep "
		 "reading (and discarding) for up to lingering_timeout so the client sees the "
		 "response rather than a reset caused by unread request bytes.",
	  ARG1({ .kind = BST_T_BOOL }) },
	{ .name = "lingering_timeout", .contexts = SRV, .apply = ap_linger_timeout,
	  .default_value = "5s",
	  .doc = "Longest a lingering close keeps draining the client.",
	  ARG1({ .kind = BST_T_DURATION, .min = 1000, .max = (int64_t)60 * 1000000 }) },
	{ .name = "server_tokens", .contexts = SRV, .apply = ap_tokens, .default_value = "on",
	  .doc = "Whether the Server header names the version (bastion/x.y) or only bastion.",
	  ARG1({ .kind = BST_T_BOOL }) },
	{ .name = "return", .contexts = SRV | BST_CTX_LOCATION, .apply = ap_return,
	  .doc = "Answers every request with a fixed status. The text is the body; for 301, 302, "
		 "303, 307 and 308 it is the Location instead. Both may use variables ($uri, "
		 "$arg_x, $1 of the location's regex). With no text the body is the standard error "
		 "page for the status.",
	  .args = { .min_args = 1, .max_args = 2,
		    .pos = { { .kind = BST_T_INT, .min = 200, .max = 599 },
			     { .kind = BST_T_TEMPLATE, .empty_ok = true } } } },
};
BST_DIRECTIVES(http_dirs);
