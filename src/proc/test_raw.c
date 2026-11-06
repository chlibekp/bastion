/* See test_hooks.h. Connections are kept simple: no per-connection limits, no timeouts. */
#ifdef BST_TEST
#include "core/buf.h"
#include "core/chain.h"
#include "core/log.h"
#include "core/wheel.h"
#include "io/net.h"
#include "proc/test_hooks.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef enum { RAW_ECHO, RAW_SLOW, RAW_RESPOND } raw_mode;

typedef struct raw_conn {
	bst_worker *w;
	bst_sock *s;
	bst_chain out, queued;
	bool sending, eof;
	uint64_t sent;
	bst_timer t;
} raw_conn;

static raw_mode mode;
static uint64_t slow_total = 4194304, slow_chunk = 65536, slow_ms = 10;
static long log_lines;
static bst_slab *segs;

static void raw_close(raw_conn *c)
{
	bst_timer_cancel(&c->t);
	bst_sock_close(c->s);
	bst_chain_clear(&c->out);
	bst_chain_clear(&c->queued);
	bst_worker *w = c->w;
	free(c);
	bst_worker_conn_closed(w);
}

static void slow_tick(void *ud);

static void on_sent(void *ud, size_t bytes, int err)
{
	raw_conn *c = ud;
	c->sending = false;
	c->sent += bytes;
	if (err < 0) {
		raw_close(c);
		return;
	}
	bst_chain_clear(&c->out);
	if (mode == RAW_SLOW && c->sent < slow_total) {
		bst_loop_timer_arm(bst_worker_loop(c->w), &c->t, slow_ms, slow_tick, c);
		return;
	}
	if (mode == RAW_ECHO && bst_chain_len(&c->queued) > 0) {
		bst_chain t = c->out;
		c->out = c->queued;
		c->queued = t;
		c->sending = true;
		if (bst_io_send(c->s, &c->out, on_sent, c) != 0)
			raw_close(c);
		return;
	}
	if (mode != RAW_ECHO || c->eof)
		raw_close(c);
}

static void slow_tick(void *ud)
{
	raw_conn *c = ud;
	uint64_t n = slow_total - c->sent;
	n = n < slow_chunk ? n : slow_chunk;
	bst_buf *b = bst_buf_new((size_t)n);
	if (b == NULL) {
		raw_close(c);
		return;
	}
	for (uint64_t i = 0; i < n; i++)
		b->data[i] = (unsigned char)((c->sent + i) % 251);
	b->len = (size_t)n;
	int rc = bst_chain_add_mem(&c->out, b, 0, (size_t)n);
	bst_buf_unref(b);
	c->sending = true;
	if (rc != 0 || bst_io_send(c->s, &c->out, on_sent, c) != 0)
		raw_close(c);
}

static void on_recv(void *ud, bst_buf *data, int err)
{
	raw_conn *c = ud;
	if (data == NULL) {
		(void)err;
		c->eof = true;
		if (!c->sending)
			raw_close(c);
		return;
	}
	bst_chain *to = c->sending ? &c->queued : &c->out;
	int rc = bst_chain_add_mem(to, data, 0, data->len);
	bst_buf_unref(data);
	if (rc != 0) {
		raw_close(c);
		return;
	}
	if (!c->sending) {
		c->sending = true;
		if (bst_io_send(c->s, &c->out, on_sent, c) != 0)
			raw_close(c);
	}
}

static void on_conn(bst_worker *w, int fd, const bst_sockaddr *peer, const bst_cfg_listen *l)
{
	(void)peer, (void)l;
	for (long i = 0; i < log_lines; i++)
		bst_log(BST_LOG_WARN, "raw log noise %ld %0800d", i, 0);
	raw_conn *c = calloc(1, sizeof *c);
	bst_sock *s = c != NULL ? bst_sock_wrap(bst_worker_loop(w), fd) : NULL;
	if (s == NULL) {
		free(c);
		close(fd);
		return;
	}
	c->w = w;
	c->s = s;
	bst_chain_init(&c->out, segs);
	bst_chain_init(&c->queued, segs);
	bst_timer_init(&c->t);
	bst_worker_conn_opened(w);
	if (mode == RAW_ECHO) {
		if (bst_io_recv_start(s, on_recv, c) != 0)
			raw_close(c);
	} else if (mode == RAW_SLOW) {
		slow_tick(c);
	} else {
		static const char line[] = "bastion raw response\n";
		bst_buf *b = bst_buf_new(sizeof line - 1);
		if (b == NULL) {
			raw_close(c);
			return;
		}
		memcpy(b->data, line, sizeof line - 1);
		b->len = sizeof line - 1;
		int rc = bst_chain_add_mem(&c->out, b, 0, b->len);
		bst_buf_unref(b);
		c->sending = true;
		if (rc != 0 || bst_io_send(s, &c->out, on_sent, c) != 0)
			raw_close(c);
	}
}

void bst_test_raw_install(void)
{
	const char *m = getenv("BST_TEST_RAW_MODE");
	if (m == NULL)
		return;
	if (strcmp(m, "echo") == 0)
		mode = RAW_ECHO;
	else if (strcmp(m, "slow") == 0)
		mode = RAW_SLOW;
	else if (strcmp(m, "respond") == 0)
		mode = RAW_RESPOND;
	else
		abort();
	const char *s = getenv("BST_TEST_RAW_SLOW");
	unsigned long long total, chunk, ms;
	if (s != NULL && sscanf(s, "%llu:%llu:%llu", &total, &chunk, &ms) == 3) {
		slow_total = total;
		slow_chunk = chunk;
		slow_ms = ms;
	}
	const char *lines = getenv("BST_TEST_RAW_LOG_LINES");
	log_lines = lines != NULL ? atol(lines) : 0;
	segs = bst_chain_slab_new(256);
	if (segs == NULL)
		abort();
	bst_worker_on_conn = on_conn;
}
#endif
