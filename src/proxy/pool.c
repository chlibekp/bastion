/* See pool.h. */
#include "proxy/pool.h"

#include "core/log.h"
#include "io/net.h"

#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifdef BST_TEST
unsigned long bst_test_pool_connects;
#endif

typedef struct idle_list {
	bst_upconn *head;
	size_t n;
} idle_list;

/* This worker's state: one process, one loop, so plain globals. */
static idle_list *g_idle; /* by upstream index */
static size_t g_nidle;
static unsigned *g_active; /* by peer state slot */
static size_t g_nactive;

static idle_list *idle_of(const bst_cfg_upstream *u)
{
	if (u->index >= g_nidle) {
		size_t n = u->index + 8;
		idle_list *nl = realloc(g_idle, n * sizeof *nl);
		if (nl == NULL)
			return NULL;
		memset(nl + g_nidle, 0, (n - g_nidle) * sizeof *nl);
		g_idle = nl;
		g_nidle = n;
	}
	return &g_idle[u->index];
}

static unsigned *active_of(const bst_peer *p)
{
	if (p->state >= g_nactive) {
		size_t n = p->state + 64;
		unsigned *na = realloc(g_active, n * sizeof *na);
		if (na == NULL)
			return NULL;
		memset(na + g_nactive, 0, (n - g_nactive) * sizeof *na);
		g_active = na;
		g_nactive = n;
	}
	return &g_active[p->state];
}

unsigned bst_pool_active(const bst_peer *peer)
{
	return peer->state < g_nactive ? g_active[peer->state] : 0;
}

size_t bst_pool_idle(const bst_cfg_upstream *u)
{
	return u->index < g_nidle ? g_idle[u->index].n : 0;
}

static void active_add(const bst_peer *p, int d)
{
	unsigned *a = active_of(p);
	if (a != NULL)
		*a = (unsigned)((int)*a + d);
}

static void unlink_idle(bst_upconn *c)
{
	idle_list *l = idle_of(c->up);
	if (!c->idle || l == NULL)
		return;
	if (c->prev != NULL)
		c->prev->next = c->next;
	else
		l->head = c->next;
	if (c->next != NULL)
		c->next->prev = c->prev;
	c->next = c->prev = NULL;
	c->idle = false;
	l->n--;
}

static void destroy(bst_upconn *c)
{
	bst_timer_cancel(&c->timer);
	if (c->idle)
		unlink_idle(c);
	else
		active_add(c->peer, -1);
	bst_sock_close(c->sk);
	free(c);
}

void bst_pool_close(bst_upconn *c)
{
	if (c != NULL)
		destroy(c);
}

static void sockaddr_of(const bst_sockaddr *a, struct sockaddr_storage *ss)
{
	memset(ss, 0, sizeof *ss);
	if (a->ip.family == BST_IP_V4) {
		struct sockaddr_in *s4 = (struct sockaddr_in *)ss;
		s4->sin_family = AF_INET;
		s4->sin_port = htons(a->port);
		memcpy(&s4->sin_addr, a->ip.b, 4);
	} else {
		struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)ss;
		s6->sin6_family = AF_INET6;
		s6->sin6_port = htons(a->port);
		memcpy(&s6->sin6_addr, a->ip.b, 16);
	}
}

static void on_connect_timeout(void *ud)
{
	bst_upconn *c = ud;
	bst_pool_cb cb = c->cb;
	void *cud = c->ud;
	destroy(c);
	cb(cud, NULL, -ETIMEDOUT);
}

static void on_connected(void *ud, size_t bytes, int err)
{
	bst_upconn *c = ud;
	(void)bytes;
	bst_timer_cancel(&c->timer);
	c->connecting = false;
	bst_pool_cb cb = c->cb;
	void *cud = c->ud;
	if (err != 0) {
		destroy(c);
		cb(cud, NULL, err);
		return;
	}
	cb(cud, c, 0);
}

/* A connection whose idle peer spoke: it closed (or sent bytes nobody asked for). Either way it
 * cannot carry a request any more. */
static void on_idle_event(void *ud, uint32_t events, int err)
{
	bst_upconn *c = ud;
	(void)events, (void)err;
	if (c->idle)
		destroy(c);
}

static void on_idle_timeout(void *ud)
{
	destroy(ud);
}

int bst_pool_get(bst_loop *l, const bst_cfg_upstream *u, const bst_peer *peer,
		 const bst_sockaddr *addr, bst_pool_cb cb, void *ud, bst_upconn **out)
{
	idle_list *il = idle_of(u);
	if (il == NULL)
		return -ENOMEM;
	for (bst_upconn *c = il->head; c != NULL; c = c->next) {
		if (c->peer != peer || c->addr.port != addr->port || !bst_ip_eq(&c->addr.ip, &addr->ip))
			continue;
		unlink_idle(c);
		bst_timer_cancel(&c->timer);
		active_add(peer, 1);
		*out = c;
		return 1;
	}
	struct sockaddr_storage ss;
	sockaddr_of(addr, &ss);
	int fd = socket(ss.ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;
	int one = 1; /* requests are written whole: never wait for an ACK to send the rest */
	(void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
	bst_upconn *c = calloc(1, sizeof *c);
	bst_sock *sk = c == NULL ? NULL : bst_sock_wrap(l, fd);
	if (sk == NULL) {
		free(c);
		close(fd);
		return -ENOMEM;
	}
	c->sk = sk;
	c->loop = l;
	c->up = u;
	c->peer = peer;
	c->addr = *addr;
	c->cb = cb;
	c->ud = ud;
	c->connecting = true;
	bst_timer_init(&c->timer);
	active_add(peer, 1);
	int rc = bst_io_connect(sk, addr, on_connected, c);
	if (rc != 0) {
		destroy(c);
		return rc;
	}
#ifdef BST_TEST
	bst_test_pool_connects++;
#endif
	bst_loop_timer_arm(l, &c->timer, u->connect_timeout_ms, on_connect_timeout, c);
	*out = NULL;
	return 0;
}

void bst_pool_put(bst_upconn *c)
{
	const bst_cfg_upstream *u = c->up;
	idle_list *il = idle_of(u);
	c->requests++;
	if (il == NULL || u->keepalive == 0 || il->n >= u->keepalive ||
	    c->requests >= u->keepalive_requests) {
		destroy(c);
		return;
	}
	active_add(c->peer, -1);
	c->idle = true;
	c->cb = NULL;
	c->ud = NULL;
	c->prev = NULL;
	c->next = il->head;
	if (il->head != NULL)
		il->head->prev = c;
	il->head = c;
	il->n++;
	if (bst_io_poll(c->sk, POLLIN | POLLRDHUP, on_idle_event, c) != 0) {
		destroy(c);
		return;
	}
	bst_loop_timer_arm(c->loop, &c->timer, u->keepalive_timeout_ms, on_idle_timeout, c);
}
