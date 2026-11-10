/* The limits { } block: overload protection (architecture section 4, proc/admission.h). A
 * singleton block, so every default applies when the block is not written. Every figure is per
 * worker: a server with 4 workers holds four times as much. */
#include "config/compile.h"
#include "config/values.h"
#include "core/str.h"

#define SEC 1000000

static bst_str as_str(const bst_ast_arg *a)
{
	return (bst_str){ a->text, (uint32_t)a->len };
}

static int ap_limits(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)c, (void)d, (void)n, (void)e; /* the scope is c->global->limits; children fill it */
	return 0;
}

static int ap_max_connections(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			      bst_err *e)
{
	uint64_t v;
	(void)e;
	if (bst_str_to_u64(as_str(bst_dir_pos(d, n, 0)), &v)) /* validated */
		c->global->limits.max_connections = (unsigned)v;
	return 0;
}

static int ap_worker_memory(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			    bst_err *e)
{
	uint64_t v;
	(void)e;
	if (bst_parse_size(as_str(bst_dir_pos(d, n, 0)), &v)) /* validated */
		c->global->limits.worker_memory = v;
	return 0;
}

static int ap_overload_status(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			      bst_err *e)
{
	uint64_t v;
	(void)e;
	if (bst_str_to_u64(as_str(bst_dir_pos(d, n, 0)), &v)) /* validated */
		c->global->limits.overload_status = (unsigned)v;
	return 0;
}

static int ap_retry_after(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			  bst_err *e)
{
	uint64_t us;
	(void)e;
	if (bst_parse_duration_us(as_str(bst_dir_pos(d, n, 0)), &us)) /* validated 1s..1h */
		c->global->limits.overload_retry_after = (unsigned)((us + SEC - 1) / SEC);
	return 0;
}

static int ap_reserve_fds(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			  bst_err *e)
{
	uint64_t v;
	(void)e;
	if (bst_str_to_u64(as_str(bst_dir_pos(d, n, 0)), &v)) /* validated */
		c->global->limits.reserve_fds = (unsigned)v;
	return 0;
}

static int ap_accept_backoff(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			     bst_err *e)
{
	uint64_t us;
	(void)e;
	if (bst_parse_duration_us(as_str(bst_dir_pos(d, n, 0)), &us)) /* validated 1ms..60s */
		c->global->limits.accept_backoff_ms = (unsigned)((us + 999) / 1000);
	return 0;
}

#define LIM1(...) .args = { .min_args = 1, .max_args = 1, .pos = { __VA_ARGS__ } }

static const bst_directive limits_dirs[] = {
	{ .name = "limits", .contexts = BST_CTX_GLOBAL, .apply = ap_limits, .singleton = true,
	  .child_ctx = BST_CTX_LIMITS,
	  .doc = "Overload protection, per worker. Every default applies when the block is absent.",
	  .args = { .block = BST_BLOCK_REQUIRED } },
	{ .name = "max_connections", .contexts = BST_CTX_LIMITS, .apply = ap_max_connections,
	  .default_value = "10240",
	  .doc = "Most connections one worker holds open. A connection arriving past it is accepted "
		 "and closed at once, without a response, and counted in the worker's overload log "
		 "line. Keep it below worker_rlimit_nofile minus reserve_fds and the descriptors "
		 "files and upstream connections need, or the worker meets the descriptor limit "
		 "first.",
	  LIM1({ .kind = BST_T_INT, .min = 1, .max = 1048576 }) },
	{ .name = "worker_memory", .contexts = BST_CTX_LIMITS, .apply = ap_worker_memory,
	  .default_value = "1g",
	  .doc = "Memory one worker may spend on request state (buffered bodies, headers, response "
		 "buffers). Past it, new requests get overload_status with Retry-After instead of "
		 "growing the process, and requests already running finish. It is a budget the "
		 "worker keeps, not an operating system limit: allocator overhead, TLS state and "
		 "the page cache come on top.",
	  LIM1({ .kind = BST_T_SIZE, .min = 1048576, .max = 1099511627776LL }) },
	{ .name = "overload_status", .contexts = BST_CTX_LIMITS, .apply = ap_overload_status,
	  .default_value = "503",
	  .doc = "The HTTP status of a request refused because the worker is over worker_memory. "
		 "503 tells clients and load balancers to try elsewhere; 429 tells well-behaved "
		 "clients to slow down.",
	  LIM1({ .kind = BST_T_INT, .min = 400, .max = 599 }) },
	{ .name = "overload_retry_after", .contexts = BST_CTX_LIMITS, .apply = ap_retry_after,
	  .default_value = "1s",
	  .doc = "The Retry-After of an overload response, from 1 second to 1 hour, rounded up to "
		 "whole seconds. Set it to about how long a burst lasts: a short value brings "
		 "retries back into a worker that is still full.",
	  LIM1({ .kind = BST_T_DURATION, .min = 1 * SEC, .max = 3600LL * SEC }) },
	{ .name = "reserve_fds", .contexts = BST_CTX_LIMITS, .apply = ap_reserve_fds,
	  .default_value = "1",
	  .doc = "Descriptors each worker holds open and unused. When the process is out of "
		 "descriptors (EMFILE) it gives them up to accept waiting connections and close "
		 "them at once, so clients see a reset instead of waiting in the listen queue, "
		 "then takes them back. They count against worker_rlimit_nofile.",
	  LIM1({ .kind = BST_T_INT, .min = 1, .max = BST_LIMITS_RESERVE_FDS_MAX }) },
	{ .name = "accept_backoff", .contexts = BST_CTX_LIMITS, .apply = ap_accept_backoff,
	  .default_value = "100ms",
	  .doc = "How long a listener stops accepting after accept fails with EMFILE, ENFILE, "
		 "ENOBUFS or ENOMEM, from 1 millisecond to 60 seconds. A short time recovers "
		 "quickly once descriptors free up; a long one costs less CPU while they do not.",
	  LIM1({ .kind = BST_T_DURATION, .min = 1000, .max = 60LL * SEC }) },
};
BST_DIRECTIVES(limits_dirs);
