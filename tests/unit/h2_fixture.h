/* Shared by the HTTP/2 unit tests: a real socket pair whose server end runs bst_conn_h2_start_loop
 * (real transport, router and `return` handler) and whose client end the test drives by hand,
 * frame by frame. Include once per test binary. */
#ifndef BST_TEST_H2_FIXTURE_H
#define BST_TEST_H2_FIXTURE_H

#include "config/compile.h"
#include "config/parser.h"
#include "core/arena.h"
#include "core/log.h"
#include "http/h2/conn.h"
#include "http/h2/frame.h"
#include "http/h2/hpack.h"
#include "http/transport.h"
#include "io/loop.h"
#include "io/net.h"
#include "route/vhost.h"
#include "tap.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static bst_backend test_backend(void)
{
	const char *b = getenv("BST_TEST_BACKEND");
	return b != NULL && strcmp(b, "uring") == 0 ? BST_BACKEND_URING : BST_BACKEND_EPOLL;
}

static void on_stop_timer(void *ud)
{
	bst_loop_stop(ud);
}

static void run_for(bst_loop *l, uint64_t ms)
{
	bst_timer t;
	bst_timer_init(&t);
	bst_loop_timer_arm(l, &t, ms, on_stop_timer, l);
	(void)bst_loop_run(l);
	bst_timer_cancel(&t);
}

typedef struct fx {
	bst_loop *l;
	bst_arena *arena;
	bst_config *cfg;
	bst_listener_set *set;
	int fd; /* the client's end */
	bst_hpack_enc enc;
	bst_hpack_dec dec;
	uint8_t buf[1 << 17];
	size_t n;
	bool eof;
} fx;

static bst_err E;

static int fx_start(fx *f, const char *conf)
{
	memset(f, 0, sizeof *f);
	signal(SIGPIPE, SIG_IGN); /* a server that closed on us is an assertion, not a crash */
	bst_loop_cfg lc = { .backend = test_backend() };
	f->l = bst_loop_new(&lc, &E);
	if (f->l == NULL)
		return -1;
	f->arena = bst_arena_new(1 << 16);
	bst_ast *ast = bst_cfg_parse_string(conf, strlen(conf), "t.conf", NULL, f->arena, &E);
	f->cfg = ast ? bst_cfg_compile(ast, &E) : NULL;
	if (f->cfg == NULL) {
		fprintf(stderr, "# config: %s\n", E.msg);
		return -1;
	}
	f->set = bst_vhost_set_new(f->cfg, &f->cfg->global.servers[0]->listens[0]);
	int sv[2];
	if (f->set == NULL || socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv) != 0)
		return -1;
	bst_sock *s = bst_sock_wrap(f->l, sv[0]);
	bst_transport *t = s ? bst_transport_plain(s) : NULL;
	if (t == NULL)
		return -1;
	f->fd = sv[1];
	bst_hpack_enc_init(&f->enc, 4096);
	f->enc.policy = BST_HPACK_POLICY_INDEX_ALL_RAW;
	bst_hpack_dec_init(&f->dec, 4096);
	return bst_conn_h2_start_loop(f->l, NULL, t, f->set, NULL, NULL, 0, false);
}

static void fx_end(fx *f)
{
	close(f->fd);
	run_for(f->l, 20);
	bst_hpack_enc_free(&f->enc);
	bst_hpack_dec_free(&f->dec);
	bst_vhost_set_free(f->set);
	bst_config_free(f->cfg);
	bst_arena_free(f->arena);
	bst_loop_free(f->l);
}

#define CONF(extra) "server { listen 8080; " extra " location / { return 200 \"hello\"; } }"

static void put(fx *f, const void *p, size_t n)
{
	const uint8_t *b = p;
	while (n > 0) {
		ssize_t w = write(f->fd, b, n);
		if (w < 0 && errno == EAGAIN) {
			run_for(f->l, 5); /* let the server read */
			continue;
		}
		if (w <= 0)
			return;
		b += w;
		n -= (size_t)w;
	}
}

/* Reads what the server has sent so far (the loop runs for ms first). */
static void collect(fx *f, uint64_t ms)
{
	run_for(f->l, ms);
	for (;;) {
		ssize_t r = read(f->fd, f->buf + f->n, sizeof f->buf - f->n);
		if (r > 0) {
			f->n += (size_t)r;
			continue;
		}
		if (r == 0)
			f->eof = true;
		break;
	}
}

static int count(fx *f, uint8_t type, uint32_t sid);

/* Collects until a frame of the type (any stream) has arrived, or limit_ms. For a step that
 * must produce output: a fixed window misses it whenever the sanitizer build in Docker stalls
 * longer than the window, which happens (tens of ms) under load. */
static inline void collect_until(fx *f, uint8_t type, uint64_t limit_ms)
{
	for (uint64_t waited = 0; waited < limit_ms && count(f, type, 0) == 0; waited += 10)
		collect(f, 10);
}

static void put_frame(fx *f, uint8_t type, uint8_t flags, uint32_t sid, const void *pl, size_t n)
{
	uint8_t h[BST_H2_FRAME_HDR];
	bst_h2_put_head(h, (uint32_t)n, type, flags, sid);
	put(f, h, sizeof h);
	if (n > 0)
		put(f, pl, n);
}

static void hello(fx *f)
{
	put(f, BST_H2_PREFACE, BST_H2_PREFACE_LEN);
	put_frame(f, BST_H2_SETTINGS, 0, 0, NULL, 0);
}

/* The header block of GET path, encoded with the fixture's own HPACK state. */
static size_t get_block(fx *f, uint8_t *out, size_t cap, const char *path, const char *extra_name,
			const char *extra_value)
{
	bst_headers h;
	bst_headers_init(&h, f->arena);
	bst_headers_add(&h, BST_S(":method"), BST_S("GET"));
	bst_headers_add(&h, BST_S(":scheme"), BST_S("https"));
	bst_headers_add(&h, BST_S(":authority"), BST_S("example.test"));
	bst_headers_add(&h, BST_S(":path"), (bst_str){ path, (uint32_t)strlen(path) });
	if (extra_name != NULL)
		bst_headers_add(&h, (bst_str){ extra_name, (uint32_t)strlen(extra_name) },
				(bst_str){ extra_value, (uint32_t)strlen(extra_value) });
	bst_h2_wr w = { 0 };
	if (bst_hpack_encode(&f->enc, &h, &w) != 0)
		return 0;
	size_t n = w.len < cap ? w.len : cap;
	memcpy(out, w.p, n);
	bst_h2_wr_free(&w);
	return n;
}

static void get_with(fx *f, uint32_t sid, bool end, const char *path, const char *name, const char *value)
{
	uint8_t blk[512];
	size_t n = get_block(f, blk, sizeof blk, path, name, value);
	put_frame(f, BST_H2_HEADERS, (uint8_t)(BST_H2_F_END_HEADERS | (end ? BST_H2_F_END_STREAM : 0)), sid, blk, n);
}

static void get(fx *f, uint32_t sid, bool end)
{
	get_with(f, sid, end, "/", NULL, NULL);
}

/* Counts the frames of a type (and stream, 0 = any) in what was collected. */
static int count(fx *f, uint8_t type, uint32_t sid)
{
	size_t pos = 0;
	int n = 0;
	bst_h2_frame fr;
	bst_h2_err err;
	ssize_t r;
	while ((r = bst_h2_frame_parse(f->buf + pos, f->n - pos, 1 << 24, &fr, &err)) > 0) {
		pos += (size_t)r;
		if (fr.type == type && (sid == 0 || fr.stream_id == sid))
			n++;
	}
	return n;
}

/* The first frame of a type; its data pointer stays valid in f->buf. */
static bool find(fx *f, uint8_t type, uint32_t sid, bst_h2_frame *out)
{
	size_t pos = 0;
	bst_h2_err err;
	ssize_t r;
	while ((r = bst_h2_frame_parse(f->buf + pos, f->n - pos, 1 << 24, out, &err)) > 0) {
		pos += (size_t)r;
		if (out->type == type && (sid == 0 || out->stream_id == sid))
			return true;
	}
	return false;
}

/* The place (from 0, among all frames) of the first frame of a type on a stream; -1 when none. */
__attribute__((unused)) static long position_of(fx *f, uint8_t type, uint32_t sid)
{
	size_t pos = 0;
	long idx = 0;
	bst_h2_frame fr;
	bst_h2_err err;
	ssize_t r;
	while ((r = bst_h2_frame_parse(f->buf + pos, f->n - pos, 1 << 24, &fr, &err)) > 0) {
		pos += (size_t)r;
		if (fr.type == type && fr.stream_id == sid)
			return idx;
		idx++;
	}
	return -1;
}

/* What arrived, for a failing assertion's sake. */
__attribute__((unused)) static void dump(fx *f)
{
	size_t pos = 0;
	bst_h2_frame fr;
	bst_h2_err err;
	ssize_t r;
	fprintf(stderr, "# frames:");
	while ((r = bst_h2_frame_parse(f->buf + pos, f->n - pos, 1 << 24, &fr, &err)) > 0) {
		pos += (size_t)r;
		fprintf(stderr, " [type=%u flags=%02x sid=%u len=%u val=%u]", fr.type, fr.flags, fr.stream_id,
			fr.length, fr.value);
	}
	fprintf(stderr, "%s\n", f->eof ? " EOF" : "");
}

/* True when a GOAWAY with this error code arrived. */
static bool goaway_with(fx *f, uint32_t code)
{
	bst_h2_frame fr;
	return find(f, BST_H2_GOAWAY, 0, &fr) && fr.value == code;
}

__attribute__((unused)) static bool rst_with(fx *f, uint32_t sid, uint32_t code)
{
	bst_h2_frame fr;
	return find(f, BST_H2_RST_STREAM, sid, &fr) && fr.value == code;
}

#endif
