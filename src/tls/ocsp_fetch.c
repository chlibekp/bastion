/* The helper's side of OCSP: fetch a response over plain HTTP/1.0 on the helper's own loop, never
 * blocking it, validate it and publish it (tls/ocsp.c); then schedule the next fetch. */
#include "core/buf.h"
#include "core/chain.h"
#include "core/log.h"
#include "io/net.h"
#include "io/sock.h"
#include "tls/ocsp.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define FETCH_TIMEOUT_MS 10000u
#define RESP_MAX (BST_OCSP_MAX + 2048) /* headers and the largest response we staple */

typedef struct fetch {
	bst_loop *loop;
	bst_ocsp_cert *cert;
	bst_sock *s;
	bst_timer t;
	bst_chain out;
	bst_buf *req;
	unsigned char *in;
	size_t in_len;
	void (*done)(bst_ocsp_cert *, bool);
	bool finished;
} fetch;

static bst_slab *g_slab;

static void finish(fetch *f, bool ok, const char *why)
{
	if (f->finished)
		return;
	f->finished = true;
	bst_timer_cancel(&f->t);
	if (!ok)
		bst_log(BST_LOG_WARN, "tls: OCSP fetch for %s failed: %s", bst_ocsp_name(f->cert), why);
	if (f->s != NULL)
		bst_sock_close(f->s);
	bst_chain_clear(&f->out);
	bst_buf_unref(f->req);
	void (*done)(bst_ocsp_cert *, bool) = f->done;
	bst_ocsp_cert *c = f->cert;
	free(f->in);
	free(f);
	done(c, ok);
}

static void on_timeout(void *ud)
{
	finish(ud, false, "timed out");
}

static void on_response(fetch *f)
{
	const char *p = (const char *)f->in;
	const char *body = NULL;
	for (size_t i = 0; i + 3 < f->in_len; i++)
		if (memcmp(p + i, "\r\n\r\n", 4) == 0) {
			body = p + i + 4;
			break;
		}
	if (body == NULL || f->in_len < 12 || strncmp(p, "HTTP/1.", 7) != 0 || memcmp(p + 8, " 200", 4) != 0) {
		finish(f, false, "not an HTTP 200 response");
		return;
	}
	const char *why = "";
	if (bst_ocsp_accept(f->cert, (const unsigned char *)body, f->in_len - (size_t)(body - p), &why) != 0) {
		finish(f, false, why);
		return;
	}
	finish(f, true, "");
}

static void on_recv(void *ud, bst_buf *b, int err)
{
	fetch *f = ud;
	if (b == NULL) {
		if (err == 0)
			on_response(f); /* HTTP/1.0: the end of the body is the end of the connection */
		else
			finish(f, false, strerror(-err));
		return;
	}
	if (f->in_len + b->len > RESP_MAX) {
		bst_buf_unref(b);
		finish(f, false, "response too large");
		return;
	}
	unsigned char *n = realloc(f->in, f->in_len + b->len);
	if (n == NULL) {
		bst_buf_unref(b);
		finish(f, false, "out of memory");
		return;
	}
	f->in = n;
	memcpy(f->in + f->in_len, b->data, b->len);
	f->in_len += b->len;
	bst_buf_unref(b);
}

static void on_sent(void *ud, size_t bytes, int err)
{
	fetch *f = ud;
	(void)bytes;
	if (err != 0) {
		finish(f, false, strerror(-err));
		return;
	}
	if (bst_io_recv_start(f->s, on_recv, f) != 0)
		finish(f, false, "cannot read the response");
}

static void on_connected(void *ud, size_t bytes, int err)
{
	fetch *f = ud;
	(void)bytes;
	if (err != 0) {
		finish(f, false, strerror(-err));
		return;
	}
	if (bst_io_send(f->s, &f->out, on_sent, f) != 0)
		finish(f, false, "cannot send the request");
}

void bst_ocsp_fetch(bst_loop *loop, bst_ocsp_cert *c, void (*done)(bst_ocsp_cert *, bool))
{
	fetch *f = calloc(1, sizeof *f);
	if (g_slab == NULL)
		g_slab = bst_chain_slab_new(8);
	if (f == NULL || g_slab == NULL) {
		free(f);
		done(c, false);
		return;
	}
	f->loop = loop;
	f->cert = c;
	f->done = done;
	bst_timer_init(&f->t);
	bst_chain_init(&f->out, g_slab);
	int rlen;
	const unsigned char *rq = bst_ocsp_request(c, &rlen);
	char head[512];
	int hl = snprintf(head, sizeof head,
			  "POST %s HTTP/1.0\r\nHost: %s\r\nContent-Type: application/ocsp-request\r\n"
			  "Content-Length: %d\r\nConnection: close\r\nAccept: application/ocsp-response\r\n\r\n",
			  bst_ocsp_path(c), bst_ocsp_host(c), rlen);
	f->req = hl > 0 && hl < (int)sizeof head ? bst_buf_new((size_t)hl + (size_t)rlen) : NULL;
	if (f->req == NULL) {
		free(f);
		done(c, false);
		return;
	}
	memcpy(f->req->data, head, (size_t)hl);
	memcpy(f->req->data + hl, rq, (size_t)rlen);
	f->req->len = (size_t)hl + (size_t)rlen;
	(void)bst_chain_add_mem(&f->out, f->req, 0, f->req->len);
	bst_sockaddr a = bst_ocsp_addr(c);
	int fd = socket(a.ip.family == BST_IP_V6 ? AF_INET6 : AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	f->s = fd >= 0 ? bst_sock_wrap(loop, fd) : NULL;
	if (f->s == NULL) {
		if (fd >= 0)
			close(fd);
		finish(f, false, "cannot make a socket");
		return;
	}
	bst_loop_timer_arm(loop, &f->t, FETCH_TIMEOUT_MS, on_timeout, f);
	if (bst_io_connect(f->s, &a, on_connected, f) != 0)
		finish(f, false, "cannot connect");
}

/* ---- the schedule ---- */

typedef struct sched {
	bst_loop *loop;
	bst_ocsp_cert *cert;
	bst_timer t;
} sched;

static sched g_sched[BST_OCSP_SLOTS];

static uint64_t env_ms(const char *name, uint64_t dflt)
{
#ifdef BST_TEST
	const char *v = getenv(name);
	if (v != NULL)
		return (uint64_t)strtoull(v, NULL, 10);
#else
	(void)name;
#endif
	return dflt;
}

static void run(void *ud);

static sched *sched_of(const bst_ocsp_cert *c)
{
	for (size_t i = 0; i < bst_ocsp_count(); i++)
		if (bst_ocsp_at(i) == c)
			return &g_sched[i];
	return &g_sched[0];
}

static void fetched(bst_ocsp_cert *c, bool ok)
{
	sched *s = sched_of(c);
	uint64_t next;
	if (ok) {
		/* half the remaining validity, between a minute and half a day */
		uint64_t now = (uint64_t)time(NULL) * 1000, exp = bst_ocsp_expiry(c);
		next = exp > now ? (exp - now) / 2 : 60000;
		if (next < 60000)
			next = 60000;
		if (next > 12ULL * 3600 * 1000)
			next = 12ULL * 3600 * 1000;
		next = env_ms("BST_TEST_OCSP_REFRESH_MS", next);
	} else {
		next = env_ms("BST_TEST_OCSP_RETRY_MS", 300000); /* a failed fetch is retried in 5 minutes */
	}
	bst_loop_timer_arm(s->loop, &s->t, next, run, s);
}

static void run(void *ud)
{
	sched *s = ud;
	bst_ocsp_fetch(s->loop, s->cert, fetched);
}

void bst_ocsp_helper_start(bst_loop *loop)
{
	for (size_t i = 0; i < bst_ocsp_count(); i++) {
		bst_ocsp_cert *c = bst_ocsp_at(i);
		if (!bst_ocsp_fetchable(c))
			continue;
		g_sched[i].loop = loop;
		g_sched[i].cert = c;
		bst_timer_init(&g_sched[i].t);
		bst_loop_timer_arm(loop, &g_sched[i].t, 1, run, &g_sched[i]);
	}
}
