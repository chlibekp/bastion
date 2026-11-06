/* See listener.h. */
#include "io/listener.h"

#include "core/addr.h"

#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifdef BST_TEST
int bst_test_ncpu;
#endif

int bst_listener_ncpu(void)
{
#ifdef BST_TEST
	if (bst_test_ncpu > 0)
		return bst_test_ncpu;
#endif
	long n = sysconf(_SC_NPROCESSORS_ONLN);
	return n > 0 ? (int)n : 1;
}

static void close_all(int *fds, int slots)
{
	for (int i = 0; i < slots; i++) {
		if (fds[i] >= 0)
			close(fds[i]);
		fds[i] = -1;
	}
}

static void fmt_addr(const bst_sockaddr *a, char *out, size_t cap)
{
	char ip[BST_ADDR_STRLEN];
	if (bst_addr_format(&a->ip, ip, sizeof ip) == 0)
		snprintf(ip, sizeof ip, "?");
	if (a->ip.family == BST_IP_V6)
		snprintf(out, cap, "[%s]:%u", ip, (unsigned)a->port);
	else
		snprintf(out, cap, "%s:%u", ip, (unsigned)a->port);
}

/* Fills ss for the address; returns its length. */
static socklen_t to_sockaddr(const bst_sockaddr *a, struct sockaddr_storage *ss)
{
	memset(ss, 0, sizeof *ss);
	if (a->ip.family == BST_IP_V6) {
		struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)ss;
		s6->sin6_family = AF_INET6;
		s6->sin6_port = htons(a->port);
		memcpy(&s6->sin6_addr, a->ip.b, 16);
		return sizeof *s6;
	}
	struct sockaddr_in *s4 = (struct sockaddr_in *)ss;
	s4->sin_family = AF_INET;
	s4->sin_port = htons(a->port);
	memcpy(&s4->sin_addr, a->ip.b, 4);
	return sizeof *s4;
}

static int fail(bst_err *e, const char *what, const char *addr, int en)
{
	bst_err_set(e, "%s %s: %s", what, addr, strerror(en));
	return -1;
}

int bst_listener_create(const bst_cfg_listen *l, int slots, int *fds, bst_err *e)
{
	if (slots < 1 || slots > BST_LISTENER_MAX_SLOTS) {
		bst_err_set(e, "invalid listener slot count %d (want 1 to %d)", slots,
			    BST_LISTENER_MAX_SLOTS);
		return -1;
	}
	bst_tcp_profile dflt;
	bst_tcp_profile_defaults(&dflt, "default");
	const bst_tcp_profile *p = l->tcp != NULL ? l->tcp : &dflt;
	char addr[BST_ADDR_STRLEN + 16];
	fmt_addr(&l->addr, addr, sizeof addr);
	struct sockaddr_storage ss;
	socklen_t sslen = to_sockaddr(&l->addr, &ss);
	bool v6 = l->addr.ip.family == BST_IP_V6;
	int ncpu = bst_listener_ncpu();
	uint32_t reported = 0; /* one warning per option for the whole listener, not per slot */

	for (int i = 0; i < slots; i++)
		fds[i] = -1;
	for (int i = 0; i < slots; i++) {
		int one = 1;
		int fd = socket(v6 ? AF_INET6 : AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
		if (fd < 0) {
			fail(e, "socket for", addr, errno);
			goto bad;
		}
		fds[i] = fd;
		/* SO_REUSEADDR lets a restart bind while old connections sit in TIME_WAIT. */
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one) != 0) {
			fail(e, "SO_REUSEPORT on", addr, errno);
			goto bad;
		}
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) != 0) {
			fail(e, "SO_REUSEADDR on", addr, errno);
			goto bad;
		}
		if (v6 && setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one) != 0) {
			fail(e, "IPV6_V6ONLY on", addr, errno);
			goto bad;
		}
		bst_sockopt_target t = { .fd = fd, .family = v6 ? AF_INET6 : AF_INET, .slot = i,
					 .ncpu = ncpu, .addr = addr };
		if (bst_sockopts_apply_(&t, p, BST_SO_BEFORE_BIND, &reported, e) != 0)
			goto bad;
		if (bind(fd, (struct sockaddr *)&ss, sslen) != 0) {
			fail(e, "bind", addr, errno);
			goto bad;
		}
		int backlog = p->backlog > 0 ? p->backlog : BST_TCP_DEFAULT_BACKLOG;
		if (listen(fd, backlog) != 0) {
			fail(e, "listen on", addr, errno);
			goto bad;
		}
		if (bst_sockopts_apply_(&t, p, BST_SO_LISTENING, &reported, e) != 0)
			goto bad;
	}
	return 0;
bad:
	close_all(fds, slots);
	return -1;
}

/* ---- distinct addresses ---- */

typedef struct akey {
	const bst_cfg_listen *l;
	size_t idx; /* config order */
} akey;

static int cmp_addr(const void *x, const void *y)
{
	const akey *a = x, *b = y;
	int c = a->l->addr.ip.family - b->l->addr.ip.family;
	if (c == 0)
		c = memcmp(a->l->addr.ip.b, b->l->addr.ip.b, sizeof a->l->addr.ip.b);
	if (c == 0)
		c = (int)a->l->addr.port - (int)b->l->addr.port;
	if (c == 0)
		c = a->idx < b->idx ? -1 : a->idx > b->idx;
	return c;
}

static int cmp_idx(const void *x, const void *y)
{
	const akey *a = x, *b = y;
	return a->idx < b->idx ? -1 : a->idx > b->idx;
}

int bst_config_listeners(const bst_config *cfg, const bst_cfg_listen ***out, size_t *n,
			 bst_err *e)
{
	const bst_cfg_global *g = &cfg->global;
	size_t total = 0;
	for (size_t i = 0; i < g->nservers; i++)
		total += g->servers[i]->nlistens;
	akey *keys = malloc((total ? total : 1) * sizeof *keys);
	if (keys == NULL) {
		bst_err_set(e, "out of memory");
		return -1;
	}
	size_t k = 0;
	for (size_t i = 0; i < g->nservers; i++)
		for (size_t j = 0; j < g->servers[i]->nlistens; j++, k++)
			keys[k] = (akey){ &g->servers[i]->listens[j], k };
	qsort(keys, k, sizeof *keys, cmp_addr);
	/* The sort puts equal addresses together, lowest config index first: keep each run's head. */
	size_t u = 0;
	for (size_t i = 0; i < k; i++) {
		bool head = i == 0 || keys[i - 1].l->addr.port != keys[i].l->addr.port ||
			    !bst_ip_eq(&keys[i - 1].l->addr.ip, &keys[i].l->addr.ip);
		if (head)
			keys[u++] = keys[i]; /* u <= i: the compared previous entry is already read */
	}
	qsort(keys, u, sizeof *keys, cmp_idx);
	const bst_cfg_listen **v = malloc((u ? u : 1) * sizeof *v);
	if (v == NULL) {
		free(keys);
		bst_err_set(e, "out of memory");
		return -1;
	}
	for (size_t i = 0; i < u; i++)
		v[i] = keys[i].l;
	free(keys);
	*out = v;
	*n = u;
	return 0;
}
