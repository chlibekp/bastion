/* The io { } block: backend selection and its tuning (architecture section 3). A singleton
 * block, so every default applies when the block is not written. bst_io_loop_cfg
 * (io/backend.h) turns the result into a bst_loop_cfg. */
#include "config/compile.h"
#include "config/values.h"
#include "core/str.h"
#include "io/aio.h"
#include "io/backend.h"
#include "io/loop.h"

#include <stdio.h>
#include <string.h>

static bst_str as_str(const bst_ast_arg *a)
{
	return (bst_str){ a->text, (uint32_t)a->len };
}

static unsigned round_pow2(unsigned v)
{
	unsigned p = 1;
	while (p < v)
		p <<= 1;
	return p;
}

static int ap_io(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)c, (void)d, (void)n, (void)e; /* the scope is c->global->io; children fill it */
	return 0;
}

static const char *const io_backends[] = { "auto", "uring", "epoll", NULL };

static int ap_backend(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	size_t idx = 0;
	(void)e;
	if (bst_parse_enum(as_str(bst_dir_pos(d, n, 0)), io_backends, &idx)) /* validated */
		c->global->io.backend = (bst_backend)idx; /* same order as the enum */
	return 0;
}

/* A power of two, rounded UP with a warning when the user wrote something else: the kernel
 * rounds ring sizes up anyway, so saying so beats a silent surprise. */
static int pow2_arg(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
		    unsigned *out, const char *what)
{
	uint64_t v;
	if (!bst_str_to_u64(as_str(bst_dir_pos(d, n, 0)), &v)) /* validated */
		return 0;
	unsigned u = (unsigned)v, p = round_pow2(u);
	if (p != u)
		bst_cfg_warn(c, n, "%s %u is not a power of two: rounded up to %u", what, u, p);
	*out = p;
	return 0;
}

static int ap_entries(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	return pow2_arg(c, d, n, &c->global->io.uring_entries, "uring_entries");
}

static int ap_bufs(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	return pow2_arg(c, d, n, &c->global->io.uring_bufs, "uring_bufs");
}

static int ap_sqpoll(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	uint64_t us;
	(void)e;
	if (strcmp(a->text, "off") == 0)
		c->global->io.sqpoll_ms = 0;
	else if (bst_parse_duration_us(as_str(a), &us)) /* validated 1ms..1m */
		c->global->io.sqpoll_ms = (unsigned)((us + 999) / 1000);
	return 0;
}

static int ap_napi(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	bool on = false;
	if (bst_parse_bool(as_str(bst_dir_pos(d, n, 0)), &on)) /* validated */
		c->global->io.napi = on;
	bool req = on && bst_dir_has_require(d, n);
	c->global->io.napi_require = req;
	if (req && bst_cfg_loc_of(c, n, &c->global->io.napi_loc, e) != 0)
		return -1;
	return 0;
}

/* `uring_napi on require` needs io_uring: epoll has no NAPI busy polling. (Under backend
 * auto the loop refuses to fall back to epoll for the same reason, at startup.) */
static int post_io_napi(bst_config *cfg, bst_cfg_ctx *c, bst_err *e)
{
	const bst_cfg_io *io = &cfg->global.io;
	if (io->napi_require && io->backend == BST_BACKEND_EPOLL) {
		bst_err_set(e, "NAPI busy polling (uring_napi on require) cannot be met with backend epoll");
		bst_cfg_err_at(e, bst_cfg_src(c, &io->napi_loc));
		return -1;
	}
	return 0;
}
BST_CFG_POST(post_io_napi);

static int ap_zc_min(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	uint64_t v;
	(void)e;
	if (bst_parse_size(as_str(bst_dir_pos(d, n, 0)), &v)) /* validated */
		c->global->io.send_zc_min = v;
	return 0;
}

static int ap_aio_threads(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			  bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	uint64_t v;
	(void)e;
	if (strcmp(a->text, "auto") == 0) {
		c->global->io.aio_auto = true;
		c->global->io.aio_threads = 0;
	} else if (bst_str_to_u64(as_str(a), &v)) { /* validated */
		c->global->io.aio_auto = false;
		c->global->io.aio_threads = (unsigned)v;
	}
	return 0;
}

static int ap_aio_queue(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	uint64_t v;
	(void)e;
	if (bst_str_to_u64(as_str(bst_dir_pos(d, n, 0)), &v)) /* validated */
		c->global->io.aio_queue = (unsigned)v;
	return 0;
}

#define IO1(...) .args = { .min_args = 1, .max_args = 1, .pos = { __VA_ARGS__ } }

static const char *const kw_off[] = { "off", NULL };
static const char *const kw_auto[] = { "auto", NULL };
/* The default strings above must match the constants the loop uses. */
_Static_assert(BST_URING_ENTRIES_DEFAULT == 256 && BST_URING_BUFS_DEFAULT == 256 &&
		       BST_AIO_QUEUE_DEFAULT == 256 && BST_AIO_THREADS_AUTO_MAX == 8,
	       "update the io directive defaults and docs");

static const bst_directive io_dirs[] = {
	{ .name = "io", .contexts = BST_CTX_GLOBAL, .apply = ap_io, .singleton = true,
	  .child_ctx = BST_CTX_IO, .doc = "I/O backend and its tuning; every default applies when the block is absent.",
	  .args = { .block = BST_BLOCK_REQUIRED } },
	{ .name = "backend", .contexts = BST_CTX_IO, .apply = ap_backend, .default_value = "auto",
	  .doc = "Event loop: auto picks io_uring and falls back to epoll when it is unavailable "
		 "(ENOSYS, EPERM from seccomp or kernel.io_uring_disabled, a missing opcode), uring "
		 "makes that a startup error, epoll never tries io_uring. The choice and its reason "
		 "are logged at start and shown by `bastion -t`.",
	  IO1({ .kind = BST_T_ENUM, .enum_values = io_backends }) },
	{ .name = "uring_entries", .contexts = BST_CTX_IO, .apply = ap_entries,
	  .default_value = "256",
	  .doc = "io_uring submission queue size per worker (the completion queue is twice that). "
		 "Rounded up to a power of two, with a warning. Costs about 64 bytes per submission "
		 "entry and 16 per completion entry, per worker; too small makes submissions wait.",
	  IO1({ .kind = BST_T_INT, .min = 2, .max = BST_URING_ENTRIES_MAX }) },
	{ .name = "uring_bufs", .contexts = BST_CTX_IO, .apply = ap_bufs,
	  .default_value = "256",
	  .doc = "Receive buffers in each worker's io_uring provided-buffer ring, 16 KiB each. "
		 "Rounded up to a power of two, with a warning. Memory is the count times 16 KiB per "
		 "worker; a ring that runs dry only delays receiving until buffers come back.",
	  IO1({ .kind = BST_T_INT, .min = 2, .max = BST_URING_BUFS_MAX }) },
	{ .name = "uring_sqpoll", .contexts = BST_CTX_IO, .apply = ap_sqpoll, .default_value = "off",
	  .doc = "off, or how long the io_uring submission-polling kernel thread spins idle before "
		 "sleeping (1ms to 1m; rounded up to whole milliseconds). Saves a syscall per batch "
		 "at the cost of a kernel thread per worker that burns a CPU while busy and for this "
		 "long after.",
	  IO1({ .kind = BST_T_DURATION, .min = 1000, .max = 60000000, .keywords = kw_off }) },
	{ .name = "uring_napi", .contexts = BST_CTX_IO, .apply = ap_napi, .default_value = "off",
	  .require = true,
	  .doc = "NAPI busy polling for io_uring (Linux 6.9 or later): lower latency, paid for with "
		 "CPU spent polling the network device. On an older kernel it logs a warning and runs "
		 "without it; add `require` to make that a startup error (so is backend epoll, which has no NAPI). `bastion -t` shows whether NAPI is on.",
	  IO1({ .kind = BST_T_BOOL }) },
	{ .name = "uring_send_zc_min", .contexts = BST_CTX_IO, .apply = ap_zc_min,
	  .default_value = "0",
	  .doc = "Memory sends of at least this size use io_uring zero-copy send; 0 turns it off. "
		 "Saves a copy on large sends but holds the pages until the kernel is done, and "
		 "closing a socket with such pages queued resets the connection. It costs more than "
		 "it saves for small sends, so it is off until measured.",
	  IO1({ .kind = BST_T_SIZE }) },
	{ .name = "aio_threads", .contexts = BST_CTX_IO, .apply = ap_aio_threads,
	  .default_value = "auto",
	  .doc = "Disk thread pool size per worker (blocking reads and readahead), or auto for the "
		 "CPU count, at most 8. Each thread costs a 256 KiB "
		 "stack; too few makes cold-file reads queue.",
	  IO1({ .kind = BST_T_INT, .min = 1, .max = BST_AIO_THREADS_MAX, .keywords = kw_auto }) },
	{ .name = "aio_queue", .contexts = BST_CTX_IO, .apply = ap_aio_queue,
	  .default_value = "256",
	  .doc = "Most disk jobs queued, running or awaiting completion per worker; past it a read "
		 "fails with EAGAIN instead of growing memory. Each queued job costs a small record.",
	  IO1({ .kind = BST_T_INT, .min = 1, .max = BST_AIO_QUEUE_MAX }) },
};
BST_DIRECTIVES(io_dirs);
