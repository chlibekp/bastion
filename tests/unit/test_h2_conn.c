/* The HTTP/2 connection (src/http/h2/conn.c, frames.c, stream.c, bridge.c) over a real socket pair:
 * the test is the client, writes frames by hand and reads what the server answers. The server
 * side runs the real transport, the router and the `return` handler. */
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

/* The header block of GET / for authority a. */
static size_t get_block(fx *f, uint8_t *out, size_t cap, const char *path)
{
	bst_headers h;
	bst_headers_init(&h, f->arena);
	bst_headers_add(&h, BST_S(":method"), BST_S("GET"));
	bst_headers_add(&h, BST_S(":scheme"), BST_S("https"));
	bst_headers_add(&h, BST_S(":authority"), BST_S("example.test"));
	bst_headers_add(&h, BST_S(":path"), (bst_str){ path, (uint32_t)strlen(path) });
	bst_h2_wr w = { 0 };
	if (bst_hpack_encode(&f->enc, &h, &w) != 0)
		return 0;
	size_t n = w.len < cap ? w.len : cap;
	memcpy(out, w.p, n);
	bst_h2_wr_free(&w);
	return n;
}

static void get(fx *f, uint32_t sid, bool end)
{
	uint8_t blk[256];
	size_t n = get_block(f, blk, sizeof blk, "/");
	put_frame(f, BST_H2_HEADERS, (uint8_t)(BST_H2_F_END_HEADERS | (end ? BST_H2_F_END_STREAM : 0)), sid, blk, n);
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

/* The first frame of a type, copied out (its data pointer stays valid in f->buf). */
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

static bool rst_with(fx *f, uint32_t sid, uint32_t code)
{
	bst_h2_frame fr;
	return find(f, BST_H2_RST_STREAM, sid, &fr) && fr.value == code;
}

TEST(config_defaults)
{
	fx f;
	ASSERT_EQ(fx_start(&f, CONF("")), 0);
	const bst_cfg_h2 *h = &f.cfg->global.servers[0]->common.http.h2;
	ASSERT_EQ(h->max_concurrent_streams, 128);
	ASSERT_EQ(h->initial_window, 65536);
	ASSERT_EQ(h->connection_window, 1 << 20);
	ASSERT_EQ(h->max_frame_size, 16384);
	ASSERT_EQ(h->max_header_list_size, 16384);
	ASSERT_EQ(h->idle_timeout_ms, 120000);
	ASSERT_EQ(h->header_table_size, 4096);
	ASSERT(h->priorities);
	ASSERT_EQ(h->write_chunk, 65536);
	ASSERT_EQ(h->abuse.rst_rate, 200);
	ASSERT_EQ(h->abuse.continuation_max, 32);
	ASSERT_EQ(h->abuse.control_queue_max, 1 << 20);
	ASSERT(!h->connect_protocol);
	fx_end(&f);
}

TEST(serves_a_get)
{
	fx f;
	ASSERT_EQ(fx_start(&f, CONF("")), 0);
	hello(&f);
	get(&f, 1, true);
	collect(&f, 50);
	bst_h2_frame fr;
	ASSERT(find(&f, BST_H2_SETTINGS, 0, &fr) && !(fr.flags & BST_H2_F_ACK)); /* the server's own */
	ASSERT_EQ(count(&f, BST_H2_SETTINGS, 0), 2); /* its SETTINGS and the acknowledgement of ours */
	ASSERT(find(&f, BST_H2_HEADERS, 1, &fr));
	bst_headers h;
	bst_headers_init(&h, f.arena);
	bst_hpack_limits lim = { 1 << 20 };
	ASSERT_EQ(bst_hpack_decode(&f.dec, fr.data, fr.data_len, f.arena, &h, &lim), 0);
	const bst_header *st = bst_headers_get_name(&h, BST_S(":status"));
	ASSERT(st != NULL && bst_str_eq(st->value, BST_S("200")));
	ASSERT(bst_headers_get_name(&h, BST_S("date")) != NULL);
	const bst_header *cl = bst_headers_get_name(&h, BST_S("content-length"));
	ASSERT(cl != NULL && bst_str_eq(cl->value, BST_S("5")));
	ASSERT(find(&f, BST_H2_DATA, 1, &fr));
	ASSERT(fr.data_len == 5 && memcmp(fr.data, "hello", 5) == 0 && (fr.flags & BST_H2_F_END_STREAM));
	fx_end(&f);
}

TEST(preface_required)
{
	fx f;
	ASSERT_EQ(fx_start(&f, CONF("")), 0);
	put(&f, "GET / HTTP/1.1\r\nHost: x\r\n\r\n", 28); /* not an HTTP/2 client */
	collect(&f, 50);
	ASSERT(goaway_with(&f, BST_H2_PROTOCOL_ERROR));
	fx_end(&f);
}

TEST(first_frame_must_be_settings)
{
	fx f;
	ASSERT_EQ(fx_start(&f, CONF("")), 0);
	put(&f, BST_H2_PREFACE, BST_H2_PREFACE_LEN);
	uint8_t data[8] = { 0 };
	put_frame(&f, BST_H2_PING, 0, 0, data, 8); /* RFC 9113 section 3.4: SETTINGS comes first */
	collect(&f, 50);
	ASSERT(goaway_with(&f, BST_H2_PROTOCOL_ERROR));
	fx_end(&f);
}

TEST(settings_ack)
{
	fx f;
	ASSERT_EQ(fx_start(&f, CONF("")), 0);
	put(&f, BST_H2_PREFACE, BST_H2_PREFACE_LEN);
	uint8_t e[6] = { 0, 4, 0, 0, 0, 100 }; /* INITIAL_WINDOW_SIZE = 100 */
	put_frame(&f, BST_H2_SETTINGS, 0, 0, e, 6);
	collect(&f, 50);
	bst_h2_frame fr;
	size_t pos = 0;
	int acks = 0;
	bst_h2_err err;
	ssize_t r;
	while ((r = bst_h2_frame_parse(f.buf + pos, f.n - pos, 1 << 24, &fr, &err)) > 0) {
		pos += (size_t)r;
		if (fr.type == BST_H2_SETTINGS && (fr.flags & BST_H2_F_ACK))
			acks++;
	}
	ASSERT_EQ(acks, 1);
	/* an acknowledgement that carries a payload is a frame size error */
	put_frame(&f, BST_H2_SETTINGS, BST_H2_F_ACK, 0, e, 6);
	f.n = 0;
	collect(&f, 50);
	ASSERT(goaway_with(&f, BST_H2_FRAME_SIZE_ERROR));
	fx_end(&f);
}

TEST(stream_id_rules)
{
	fx f;
	ASSERT_EQ(fx_start(&f, CONF("")), 0);
	hello(&f);
	get(&f, 2, true); /* a client stream id is odd */
	collect(&f, 50);
	ASSERT(goaway_with(&f, BST_H2_PROTOCOL_ERROR));
	fx_end(&f);

	ASSERT_EQ(fx_start(&f, CONF("")), 0);
	hello(&f);
	get(&f, 7, true);
	get(&f, 5, true); /* smaller than one already used (RFC 9113 section 5.1.1) */
	collect(&f, 50);
	ASSERT(goaway_with(&f, BST_H2_PROTOCOL_ERROR));
	fx_end(&f);
}

TEST(state_machine)
{
	fx f;
	ASSERT_EQ(fx_start(&f, CONF("")), 0);
	hello(&f);
	put_frame(&f, BST_H2_DATA, 0, 9, "x", 1); /* DATA on a stream that was never opened */
	collect(&f, 50);
	ASSERT(goaway_with(&f, BST_H2_PROTOCOL_ERROR));
	fx_end(&f);

	ASSERT_EQ(fx_start(&f, CONF("")), 0);
	hello(&f);
	get(&f, 1, true);
	collect(&f, 50); /* the response is complete: the stream is closed */
	f.n = 0;
	put_frame(&f, BST_H2_DATA, 0, 1, "x", 1); /* DATA on a closed stream */
	collect(&f, 50);
	ASSERT(rst_with(&f, 1, BST_H2_STREAM_CLOSED));
	fx_end(&f);

	ASSERT_EQ(fx_start(&f, CONF("")), 0);
	hello(&f);
	uint8_t rst[4] = { 0, 0, 0, 8 };
	put_frame(&f, BST_H2_RST_STREAM, 0, 3, rst, 4); /* RST_STREAM on an idle stream */
	collect(&f, 50);
	ASSERT(goaway_with(&f, BST_H2_PROTOCOL_ERROR));
	fx_end(&f);
}

TEST(max_concurrent_refuses)
{
	fx f;
	ASSERT_EQ(fx_start(&f, CONF("http2_max_concurrent_streams 2;")), 0);
	hello(&f);
	/* one burst: no response has been written yet when the third request arrives */
	uint8_t blk[256];
	size_t n = get_block(&f, blk, sizeof blk, "/");
	uint8_t all[3 * (BST_H2_FRAME_HDR + 256)];
	size_t off = 0;
	for (uint32_t sid = 1; sid <= 5; sid += 2) {
		bst_h2_put_head(all + off, (uint32_t)n, BST_H2_HEADERS, BST_H2_F_END_HEADERS | BST_H2_F_END_STREAM, sid);
		memcpy(all + off + BST_H2_FRAME_HDR, blk, n);
		off += BST_H2_FRAME_HDR + n;
		n = get_block(&f, blk, sizeof blk, "/"); /* later blocks are indexed: shorter, in order */
	}
	put(&f, all, off);
	collect(&f, 80);
	ASSERT(rst_with(&f, 5, BST_H2_REFUSED_STREAM));
	ASSERT(count(&f, BST_H2_HEADERS, 1) == 1 && count(&f, BST_H2_HEADERS, 3) == 1);
	fx_end(&f);
}

TEST(headers_while_continuation)
{
	fx f;
	ASSERT_EQ(fx_start(&f, CONF("")), 0);
	hello(&f);
	uint8_t blk[256];
	size_t n = get_block(&f, blk, sizeof blk, "/");
	put_frame(&f, BST_H2_HEADERS, BST_H2_F_END_STREAM, 1, blk, n / 2); /* no END_HEADERS */
	uint8_t data[8] = { 0 };
	put_frame(&f, BST_H2_PING, 0, 0, data, 8); /* only CONTINUATION may follow (section 6.10) */
	collect(&f, 50);
	ASSERT(goaway_with(&f, BST_H2_PROTOCOL_ERROR));
	fx_end(&f);

	/* a block split over HEADERS and CONTINUATION is one request */
	ASSERT_EQ(fx_start(&f, CONF("")), 0);
	hello(&f);
	n = get_block(&f, blk, sizeof blk, "/");
	put_frame(&f, BST_H2_HEADERS, BST_H2_F_END_STREAM, 1, blk, n / 2);
	put_frame(&f, BST_H2_CONTINUATION, BST_H2_F_END_HEADERS, 1, blk + n / 2, n - n / 2);
	collect(&f, 50);
	bst_h2_frame fr;
	ASSERT(find(&f, BST_H2_DATA, 1, &fr) && fr.data_len == 5);
	fx_end(&f);
}

TEST(bad_header_block_is_a_compression_error)
{
	fx f;
	ASSERT_EQ(fx_start(&f, CONF("")), 0);
	hello(&f);
	uint8_t bad[2] = { 0xff, 0xff }; /* an index past the tables, and an unfinished integer */
	put_frame(&f, BST_H2_HEADERS, BST_H2_F_END_HEADERS | BST_H2_F_END_STREAM, 1, bad, 2);
	collect(&f, 50);
	ASSERT(goaway_with(&f, BST_H2_COMPRESSION_ERROR));
	fx_end(&f);
}

TEST(ping_is_answered)
{
	fx f;
	ASSERT_EQ(fx_start(&f, CONF("")), 0);
	hello(&f);
	uint8_t data[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	put_frame(&f, BST_H2_PING, 0, 0, data, 8);
	collect(&f, 50);
	bst_h2_frame fr;
	ASSERT(find(&f, BST_H2_PING, 0, &fr));
	ASSERT((fr.flags & BST_H2_F_ACK) && memcmp(fr.ping, data, 8) == 0);
	fx_end(&f);
}

TEST(graceful_goaway)
{
	fx f;
	ASSERT_EQ(fx_start(&f, CONF("")), 0);
	hello(&f);
	get(&f, 1, false); /* a request still in progress keeps the connection up */
	collect(&f, 50);
	f.n = 0;
	bst_h2_drain(NULL); /* the worker's drain: phase one is a GOAWAY that names no limit, and a PING */
	collect(&f, 50);
	bst_h2_frame fr;
	ASSERT(find(&f, BST_H2_GOAWAY, 0, &fr) && fr.last_stream == 0x7fffffffu && fr.value == BST_H2_NO_ERROR);
	ASSERT(find(&f, BST_H2_PING, 0, &fr) && !(fr.flags & BST_H2_F_ACK));
	uint8_t tok[8];
	memcpy(tok, fr.ping, 8);
	f.n = 0;
	put_frame(&f, BST_H2_PING, BST_H2_F_ACK, 0, tok, 8); /* the client has seen the first GOAWAY */
	collect(&f, 50);
	ASSERT(find(&f, BST_H2_GOAWAY, 0, &fr) && fr.last_stream == 1); /* phase two: the last stream served */
	f.n = 0;
	get(&f, 3, true); /* a request after the GOAWAY is refused */
	collect(&f, 50);
	ASSERT(rst_with(&f, 3, BST_H2_REFUSED_STREAM));
	fx_end(&f);
}

TAP_MAIN()
