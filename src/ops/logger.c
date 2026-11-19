/* See logger.h. */
#include "ops/logger.h"

#include "core/counters.h"
#include "core/log.h"
#include "core/ring.h"
#include "core/shm.h"
#include "core/time.h"
#include "proc/channel.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define SLOT_HDR 64u
#define BATCH_BYTES (64u << 10) /* a file's batch: one write() each */
#define RECORD_MAX (1u + BST_ACCESS_LINE_MAX)
#define DROP_REPORT_MS 1000u
#define STOP_POLL_MS 50u

_Static_assert(BATCH_BYTES >= BST_ACCESS_LINE_MAX, "a batch holds the longest line");

/* The head of each worker's slot in the shared region, before its ring. */
typedef struct slot_hdr {
	_Atomic uint64_t dropped; /* lines the worker could not push */
	_Atomic uint32_t closed;  /* the worker exited: its ring gets nothing more */
} slot_hdr;
_Static_assert(sizeof(slot_hdr) <= SLOT_HDR, "slot header");

/* Set in master before fork; children inherit them. */
static const bst_config *g_cfg;
static const bst_cfg_logs *g_logs;
static int g_fds[BST_LOG_FILES_MAX];
static size_t g_nfiles;
static unsigned char *g_region;
static size_t g_region_size, g_slot_size, g_cap;
static int g_nworkers;
static bst_counter_id g_drop_ctr = BST_COUNTER_INVALID;

static slot_hdr *hdr_of(int slot)
{
	return (slot_hdr *)(void *)(g_region + (size_t)slot * g_slot_size);
}

static void *ring_of(int slot)
{
	return g_region + (size_t)slot * g_slot_size + SLOT_HDR;
}

/* ---- master ---- */

static int open_file(const char *path, bst_err *e)
{
	if (strcmp(path, BST_LOG_STDOUT) == 0) {
		/* A description of our own: O_NONBLOCK must not reach whoever gave us stdout. */
		struct stat st;
		if (fstat(STDOUT_FILENO, &st) == 0 && !S_ISREG(st.st_mode)) {
			int fd = open("/proc/self/fd/1", O_WRONLY | O_NONBLOCK | O_CLOEXEC | O_NOCTTY);
			if (fd >= 0)
				return fd;
		}
		int fd = fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, 3);
		if (fd < 0)
			bst_err_set(e, "access_log stdout: %s", strerror(errno));
		return fd;
	}
	int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOCTTY | O_NONBLOCK, 0640);
	if (fd < 0)
		bst_err_set(e, "access_log %s: %s", path, strerror(errno));
	return fd;
}

int bst_logger_setup(const bst_config *cfg, int nworkers, bst_err *e)
{
	const bst_cfg_logs *l = cfg->global.logs;
	g_cfg = cfg;
	g_drop_ctr = bst_counter_register("bastion_log_dropped_total",
					  "access log lines dropped: a full ring or a failed write",
					  NULL);
	if (l == NULL || l->npaths == 0 || nworkers <= 0)
		return 0;
	for (size_t i = 0; i < l->npaths; i++) {
		int fd = open_file(l->paths[i], e);
		if (fd < 0) {
			bst_logger_teardown();
			return -1;
		}
		g_fds[g_nfiles++] = fd;
	}
	g_cap = (size_t)l->buffer;
	g_slot_size = SLOT_HDR + BST_SPSC_BYTES(g_cap);
	g_region_size = g_slot_size * (size_t)nworkers;
	g_region = bst_shm_create("bastion-access-log", g_region_size, NULL);
	if (g_region == NULL) {
		g_region_size = 0;
		bst_err_set(e, "access log rings: %s", strerror(errno));
		bst_logger_teardown();
		return -1;
	}
	for (int i = 0; i < nworkers; i++) {
		bst_spsc *r = bst_spsc_init(ring_of(i), g_cap);
		if (r == NULL) {
			bst_err_set(e, "access log rings: bad size %zu", g_cap);
			bst_logger_teardown();
			return -1;
		}
		bst_spsc_free(r);
		atomic_store(&hdr_of(i)->closed, 1u); /* until a worker attaches */
	}
	g_nworkers = nworkers;
	g_logs = l;
	return 0;
}

void bst_logger_reopen(int helper_chan)
{
	if (g_logs == NULL)
		return;
	size_t ok = 0;
	for (size_t i = 0; i < g_nfiles; i++) {
		const char *path = g_logs->paths[i];
		if (strcmp(path, BST_LOG_STDOUT) == 0)
			continue;
		bst_err e = { .msg = "" };
		int fd = open_file(path, &e);
		if (fd < 0) {
			bst_log(BST_LOG_ERROR, "USR1: %s; still writing the old file", e.msg);
			continue;
		}
		if (helper_chan >= 0) {
			bst_msg m = { .type = BST_MSG_LOG_REOPEN, .log_reopen = { .file = (unsigned char)i } };
			int rc = bst_chan_send_fd(helper_chan, &m, fd);
			if (rc != 0)
				bst_log(BST_LOG_ERROR, "USR1: access_log %s: passing it to the helper: %s",
					path, strerror(-rc));
		}
		close(g_fds[i]); /* kept for a helper that respawns */
		g_fds[i] = fd;
		ok++;
	}
	bst_log(BST_LOG_INFO, "USR1: reopened %zu access log file(s)", ok);
}

void bst_logger_worker_exited(int slot)
{
	if (g_region != NULL && slot >= 0 && slot < g_nworkers)
		atomic_store(&hdr_of(slot)->closed, 1u);
}

void bst_logger_teardown(void)
{
	for (size_t i = 0; i < g_nfiles; i++)
		close(g_fds[i]);
	g_nfiles = 0;
	if (g_region != NULL)
		munmap(g_region, g_region_size);
	g_region = NULL;
	g_logs = NULL;
}

/* ---- worker ---- */

static bst_spsc *w_ring;
static slot_hdr *w_hdr;
static uint64_t w_rand;

void bst_logger_worker_start(int slot)
{
	for (size_t i = 0; i < g_nfiles; i++)
		close(g_fds[i]); /* the helper writes the files */
	g_nfiles = 0;
	if (g_region == NULL || slot < 0 || slot >= g_nworkers)
		return;
	if (getrandom(&w_rand, sizeof w_rand, 0) != (ssize_t)sizeof w_rand || w_rand == 0)
		w_rand = 0x9e3779b97f4a7c15ull ^ (uint64_t)getpid();
	w_hdr = hdr_of(slot);
	w_ring = bst_spsc_attach(ring_of(slot), g_cap);
	if (w_ring == NULL) {
		bst_log(BST_LOG_ERROR, "access log: cannot attach the ring: nothing is logged");
		return;
	}
	atomic_store(&w_hdr->closed, 0u);
}

void bst_logger_worker_exit(void)
{
	if (w_hdr != NULL)
		atomic_store(&w_hdr->closed, 1u);
}

static double next_rand(void)
{
	uint64_t x = w_rand; /* xorshift64 */
	x ^= x << 13;
	x ^= x >> 7;
	x ^= x << 17;
	w_rand = x;
	return (double)(x >> 11) * (1.0 / 9007199254740992.0);
}

static void drop(void)
{
	atomic_fetch_add_explicit(&w_hdr->dropped, 1, memory_order_relaxed);
	bst_counter_add(g_drop_ctr, 1);
}

void bst_access_log(bst_stream *s)
{
	if (w_ring == NULL || s->log_status == 0)
		return;
	const bst_cfg_common *cc = s->cfg != NULL ? s->cfg
				 : s->server != NULL ? &s->server->common
						     : &g_cfg->global.common;
	const bst_cfg_list *list = &cc->access_logs;
	if (list->n == 0)
		return;
	bst_var_ctx ctx;
	bst_var_ctx_init(&ctx, s);
	ctx.status = s->log_status;
	ctx.redact = &g_logs->redact;
	bool error = s->log_status >= 400;
	static char rec[RECORD_MAX];
	for (size_t i = 0; i < list->n; i++) {
		const bst_alog *a = list->items[i];
		if (a->file < 0 || a->fmt == NULL)
			continue;
		if (a->errors_only && !error)
			continue;
		if (!error && a->sample < 1.0 && next_rand() >= a->sample)
			continue; /* errors are never sampled out */
		if (a->cond != NULL) {
			bst_str v = bst_tpl_eval(a->cond, &ctx, s->arena);
			if (bst_str_failed(v) || v.len == 0 || (v.len == 1 && v.p[0] == '0'))
				continue;
		}
		rec[0] = (char)(unsigned char)a->file;
		size_t n = bst_logfmt_render(a->fmt, &ctx, rec + 1, BST_ACCESS_LINE_MAX);
		if (n == 0 || !bst_spsc_push(w_ring, rec, (uint32_t)(n + 1)))
			drop();
	}
}

/* ---- helper ---- */

typedef struct hfile {
	char *buf;
	size_t len, lines;
} hfile;

static struct {
	bst_loop *loop;
	bst_timer timer;
	bst_spsc **rings;
	hfile files[BST_LOG_FILES_MAX];
	uint64_t write_drops; /* the helper's own */
	uint64_t reported;
	uint64_t report_at;
	bool stopping;
	uint64_t stop_deadline;
} H;

static void flush_file(size_t i)
{
	hfile *f = &H.files[i];
	if (f->len == 0)
		return;
	ssize_t w;
	do
		w = write(g_fds[i], f->buf, f->len);
	while (w < 0 && errno == EINTR);
	if (w < 0 || (size_t)w != f->len) {
		/* Disk full, a deleted directory, a full pipe: the unwritten lines are lost. The
		 * rest of a partial write is not retried, a retry would block or tear the file. */
		size_t done = w > 0 ? (size_t)w : 0, lost = 0;
		for (size_t k = done; k < f->len; k++)
			lost += f->buf[k] == '\n';
		H.write_drops += lost;
		bst_counter_add(g_drop_ctr, lost);
	}
	f->len = f->lines = 0;
}

static void report_drops(bool now)
{
	uint64_t total = H.write_drops;
	for (int i = 0; i < g_nworkers; i++)
		total += atomic_load_explicit(&hdr_of(i)->dropped, memory_order_relaxed);
	uint64_t t = bst_now_ms();
	if (total == H.reported || (!now && t < H.report_at))
		return;
	bst_log(BST_LOG_WARN, "access log: %llu line(s) dropped (%llu in all): a full ring or a "
			      "failed write", (unsigned long long)(total - H.reported),
		(unsigned long long)total);
	H.reported = total;
	H.report_at = t + DROP_REPORT_MS;
}

static void drain(void)
{
	static char rec[RECORD_MAX];
	for (int r = 0; r < g_nworkers; r++) {
		if (H.rings[r] == NULL)
			continue;
		for (;;) {
			int32_t n = bst_spsc_pop(H.rings[r], rec, RECORD_MAX);
			if (n == BST_SPSC_EMPTY)
				break;
			if (n < 0) { /* the worker broke framing: skip what it wrote, once a tick */
				bst_log(BST_LOG_WARN, "access log: worker %d's ring is corrupt: skipped", r);
				bst_spsc_resync(H.rings[r]);
				break;
			}
			unsigned idx = (unsigned char)rec[0];
			if (n < 2 || idx >= g_nfiles)
				continue;
			hfile *f = &H.files[idx];
			size_t len = (size_t)n - 1;
			if (f->len + len > BATCH_BYTES)
				flush_file(idx);
			memcpy(f->buf + f->len, rec + 1, len);
			f->len += len;
			f->lines++;
		}
	}
	for (size_t i = 0; i < g_nfiles; i++)
		flush_file(i);
}

static bool all_closed(void)
{
	for (int i = 0; i < g_nworkers; i++)
		if (atomic_load(&hdr_of(i)->closed) == 0)
			return false;
	return true;
}

static void on_tick(void *ud)
{
	(void)ud;
	drain();
	report_drops(false);
	if (H.stopping) {
		if (all_closed() || bst_now_ms() >= H.stop_deadline) {
			drain();
			report_drops(true);
			_exit(0);
		}
		bst_loop_timer_arm(H.loop, &H.timer, STOP_POLL_MS, on_tick, NULL);
		return;
	}
	bst_loop_timer_arm(H.loop, &H.timer, g_logs->flush_ms, on_tick, NULL);
}

void bst_logger_helper_start(bst_loop *l)
{
	if (g_region == NULL)
		return;
	H.loop = l;
	H.rings = calloc((size_t)g_nworkers, sizeof *H.rings);
	if (H.rings == NULL) {
		bst_log(BST_LOG_ERROR, "access log: out of memory: nothing is written");
		return;
	}
	for (size_t i = 0; i < g_nfiles; i++) {
		H.files[i].buf = malloc(BATCH_BYTES);
		if (H.files[i].buf == NULL) {
			bst_log(BST_LOG_ERROR, "access log: out of memory: nothing is written");
			free(H.rings);
			H.rings = NULL;
			return;
		}
	}
	for (int i = 0; i < g_nworkers; i++) {
		H.rings[i] = bst_spsc_attach(ring_of(i), g_cap);
		if (H.rings[i] == NULL)
			bst_log(BST_LOG_ERROR, "access log: cannot attach worker %d's ring", i);
	}
	bst_timer_init(&H.timer);
	bst_loop_timer_arm(l, &H.timer, g_logs->flush_ms, on_tick, NULL);
}

void bst_logger_helper_reopened(unsigned file, int fd)
{
	if (file >= g_nfiles || H.rings == NULL) {
		close(fd);
		return;
	}
	flush_file(file); /* what was drained so far belongs to the old file */
	close(g_fds[file]);
	g_fds[file] = fd;
}

bool bst_logger_helper_stop(bool graceful)
{
	if (H.rings == NULL)
		return true;
	drain();
	if (!graceful || all_closed()) {
		report_drops(true);
		return true;
	}
	if (!H.stopping) { /* a reload's old generation: its workers are still finishing */
		H.stopping = true;
		H.stop_deadline = bst_now_ms() + g_cfg->global.shutdown_timeout_ms;
		bst_loop_timer_arm(H.loop, &H.timer, STOP_POLL_MS, on_tick, NULL);
	}
	return false;
}

/* ---- variables for log formats ---- */

static bst_str fmt_arena(const bst_var_ctx *c, size_t cap, const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));

static bst_str fmt_arena(const bst_var_ctx *c, size_t cap, const char *fmt, ...)
{
	char *b = bst_arena_alloc(c->s->arena, cap);
	if (b == NULL)
		return (bst_str){ NULL, 0 };
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(b, cap, fmt, ap);
	va_end(ap);
	if (n < 0 || (size_t)n >= cap)
		return (bst_str){ NULL, 0 };
	return (bst_str){ b, (uint32_t)n };
}

static bool utc_now(struct tm *tm)
{
	time_t t = time(NULL);
	return gmtime_r(&t, tm) != NULL;
}

static bst_str var_time_iso8601(const bst_var_ctx *c, bst_str sfx)
{
	(void)sfx;
	struct tm tm;
	if (!utc_now(&tm))
		return (bst_str){ "", 0 };
	return fmt_arena(c, 32, "%04d-%02d-%02dT%02d:%02d:%02d+00:00", tm.tm_year + 1900,
			 tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
}

static bst_str var_time_local(const bst_var_ctx *c, bst_str sfx)
{
	(void)sfx;
	static const char mon[12][4] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
					 "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
	struct tm tm;
	if (!utc_now(&tm))
		return (bst_str){ "", 0 };
	return fmt_arena(c, 32, "%02d/%s/%04d:%02d:%02d:%02d +0000", tm.tm_mday, mon[tm.tm_mon % 12],
			 tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec);
}

static bst_str var_request_time(const bst_var_ctx *c, bst_str sfx)
{
	(void)sfx;
	const bst_stream *s = c->s;
	if (s->log_start_us == 0)
		return (bst_str){ "", 0 };
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	uint64_t now = (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
	uint64_t ms = now > s->log_start_us ? (now - s->log_start_us) / 1000u : 0;
	return fmt_arena(c, 32, "%llu.%03llu", (unsigned long long)(ms / 1000),
			 (unsigned long long)(ms % 1000));
}

static bst_str var_body_bytes_sent(const bst_var_ctx *c, bst_str sfx)
{
	(void)sfx;
	return fmt_arena(c, 24, "%llu", (unsigned long long)c->s->log_body_bytes);
}

static bst_str var_server_protocol(const bst_var_ctx *c, bst_str sfx)
{
	(void)sfx;
	switch (c->s->log_proto) {
	case 1:
		return c->s->req.head.version_minor == 0 ? BST_S("HTTP/1.0") : BST_S("HTTP/1.1");
	case 2:
		return BST_S("HTTP/2.0");
	case 3:
		return BST_S("HTTP/3.0");
	default:
		return (bst_str){ "", 0 };
	}
}

static const bst_var_def log_vars[] = {
	{ "time_iso8601", var_time_iso8601, false },
	{ "time_local", var_time_local, false },
	{ "request_time", var_request_time, false },
	{ "body_bytes_sent", var_body_bytes_sent, false },
	{ "server_protocol", var_server_protocol, false },
};
BST_VARS(log_vars);
