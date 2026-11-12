/* See health.h. */
#include "proxy/health.h"

#include "core/log.h"
#include "io/net.h"
#include "io/sock.h"
#include "proxy/upstream.h"

#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct hjob hjob;

typedef struct probe {
	hjob *j;
	size_t peer;
	bst_sock *sk;
	bst_timer tm;
	bool busy;
	char buf[128];
	size_t len;
	unsigned ok_run, fail_run;
	bool down;
} probe;

struct hjob {
	const bst_cfg_upstream *u;
	bst_loop *l;
	bst_timer tick;
	probe *pr;
};

bool bst_health_parse_expect(const char *s, size_t n, unsigned *lo, unsigned *hi)
{
	unsigned v[2] = { 0, 0 };
	int k = 0, digits = 0;
	for (size_t i = 0; i < n; i++) {
		if (s[i] >= '0' && s[i] <= '9' && digits < 3) {
			v[k] = v[k] * 10 + (unsigned)(s[i] - '0');
			digits++;
		} else if (s[i] == '-' && k == 0 && digits == 3) {
			k = 1;
			digits = 0;
		} else {
			return false;
		}
	}
	if (digits != 3)
		return false;
	if (k == 0)
		v[1] = v[0];
	if (v[0] < 100 || v[1] > 599 || v[0] > v[1])
		return false;
	*lo = v[0];
	*hi = v[1];
	return true;
}

static void peer_name(const bst_cfg_upstream *u, size_t i, char *out, size_t cap)
{
	const bst_up_server *s = &u->servers[u->peers[i].server];
	snprintf(out, cap, "%s:%u", s->host, s->port);
}

static void probe_done(probe *p, bool ok, const char *why)
{
	const bst_cfg_upstream *u = p->j->u;
	bst_timer_cancel(&p->tm);
	if (p->sk != NULL) {
		bst_sock_close(p->sk);
		p->sk = NULL;
	}
	p->busy = false;
	const bst_peer *peer = &u->peers[p->peer];
	char name[300];
	if (ok) {
		p->fail_run = 0;
		p->ok_run++;
		if (p->down && p->ok_run >= u->health.passes) {
			p->down = false;
			bst_peer_set_down(peer, false);
			peer_name(u, p->peer, name, sizeof name);
			bst_log(BST_LOG_INFO, "upstream %s: server %s passed %u health checks: up",
				u->name, name, p->ok_run);
		}
		return;
	}
	p->ok_run = 0;
	p->fail_run++;
	if (!p->down && p->fail_run >= u->health.fails) {
		p->down = true;
		bst_peer_set_down(peer, true);
		peer_name(u, p->peer, name, sizeof name);
		bst_log(BST_LOG_WARN, "upstream %s: server %s failed %u health checks (%s): down",
			u->name, name, p->fail_run, why);
	}
}

static void on_timeout(void *ud)
{
	probe_done(ud, false, "timed out");
}

static void on_readable(void *ud, uint32_t events, int err)
{
	probe *p = ud;
	(void)events;
	if (!p->busy || p->sk == NULL)
		return;
	for (;;) {
		ssize_t n = recv(bst_sock_fd(p->sk), p->buf + p->len, sizeof p->buf - 1 - p->len, 0);
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) && err == 0)
			break;
		if (n <= 0) {
			probe_done(p, false, n == 0 ? "closed before a status line" : strerror(errno));
			return;
		}
		p->len += (size_t)n;
		p->buf[p->len] = 0;
		char *eol = strstr(p->buf, "\r\n");
		if (eol == NULL && p->len < sizeof p->buf - 1)
			continue;
		unsigned st = 0;
		if (eol == NULL || strncmp(p->buf, "HTTP/1.", 7) != 0 || p->len < 12 ||
		    sscanf(p->buf + 9, "%3u", &st) != 1) {
			probe_done(p, false, "not an HTTP response");
			return;
		}
		const bst_up_health *h = &p->j->u->health;
		char why[48];
		snprintf(why, sizeof why, "status %u", st);
		probe_done(p, st >= h->expect_lo && st <= h->expect_hi, why);
		return;
	}
	if (bst_io_poll(p->sk, POLLIN | POLLRDHUP, on_readable, p) != 0)
		probe_done(p, false, "poll failed");
}

static void on_connected(void *ud, size_t bytes, int err)
{
	probe *p = ud;
	(void)bytes;
	if (!p->busy)
		return;
	if (err != 0) {
		probe_done(p, false, strerror(-err));
		return;
	}
	const bst_cfg_upstream *u = p->j->u;
	if (u->tls) { /* no HTTP over a TLS upstream here: the connect is the check */
		probe_done(p, true, "connected");
		return;
	}
	const bst_up_server *s = &u->servers[u->peers[p->peer].server];
	char req[1024];
	int n = snprintf(req, sizeof req,
			 "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: bastion-health-check\r\n"
			 "Connection: close\r\n\r\n",
			 u->health.path, s->host);
	if (n <= 0 || (size_t)n >= sizeof req ||
	    send(bst_sock_fd(p->sk), req, (size_t)n, MSG_NOSIGNAL) != n) {
		probe_done(p, false, "send failed");
		return;
	}
	if (bst_io_poll(p->sk, POLLIN | POLLRDHUP, on_readable, p) != 0)
		probe_done(p, false, "poll failed");
}

static void probe_start(probe *p)
{
	const bst_cfg_upstream *u = p->j->u;
	bst_sockaddr a;
	if (p->busy || !bst_peer_addr(&u->peers[p->peer], &a))
		return;
	int fd = socket(a.ip.family == BST_IP_V4 ? AF_INET : AF_INET6,
			SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		probe_done(p, false, strerror(errno));
		return;
	}
	p->sk = bst_sock_wrap(p->j->l, fd);
	if (p->sk == NULL) {
		close(fd);
		probe_done(p, false, "out of memory");
		return;
	}
	p->busy = true;
	p->len = 0;
	bst_loop_timer_arm(p->j->l, &p->tm, u->health.timeout_ms, on_timeout, p);
	if (bst_io_connect(p->sk, &a, on_connected, p) != 0)
		probe_done(p, false, "connect failed");
}

static void on_tick(void *ud)
{
	hjob *j = ud;
	for (size_t i = 0; i < j->u->npeers; i++)
		probe_start(&j->pr[i]);
	bst_loop_timer_arm(j->l, &j->tick, j->u->health.interval_ms, on_tick, j);
}

void bst_health_check_run(bst_loop *l, const bst_config *cfg)
{
	const bst_cfg_global *g = &cfg->global;
	for (size_t i = 0; i < g->nupstreams; i++) {
		const bst_cfg_upstream *u = g->upstreams[i];
		if (!u->health.on || u->npeers == 0)
			continue;
		hjob *j = calloc(1, sizeof *j); /* lives as long as the helper */
		probe *pr = j == NULL ? NULL : calloc(u->npeers, sizeof *pr);
		if (pr == NULL) {
			free(j);
			bst_log(BST_LOG_ERROR, "upstream %s: out of memory for health checks", u->name);
			return;
		}
		j->u = u;
		j->l = l;
		j->pr = pr;
		for (size_t k = 0; k < u->npeers; k++) {
			pr[k].j = j;
			pr[k].peer = k;
			bst_timer_init(&pr[k].tm);
		}
		bst_timer_init(&j->tick);
		bst_loop_timer_arm(l, &j->tick, 1, on_tick, j);
	}
}
