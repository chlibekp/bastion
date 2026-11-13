/* See upstream.h. */
#include "proxy/upstream.h"

#include "core/log.h"
#include "core/shm.h"
#include "io/net.h"
#include "io/sock.h"
#include "proxy/dns.h"

#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

void bst_upstream_defaults(bst_cfg_upstream *u)
{
	u->retry = (bst_up_retry){ .set = true, .attempts = 1, .budget_pct = 20,
				   .on = BST_RETRY_ON_ERROR };
	u->breaker.for_ms = 10000;
	u->keepalive = BST_UP_KEEPALIVE;
	u->keepalive_timeout_ms = BST_UP_KEEPALIVE_TIMEOUT_MS;
	u->keepalive_requests = BST_UP_KEEPALIVE_REQUESTS;
	u->connect_timeout_ms = BST_UP_CONNECT_TIMEOUT_MS;
	u->send_timeout_ms = BST_UP_SEND_TIMEOUT_MS;
	u->read_timeout_ms = BST_UP_READ_TIMEOUT_MS;
	u->h2_max_streams = BST_UP_H2_MAX_STREAMS;
}

bst_cfg_upstream *bst_upstream_find(const bst_cfg_global *g, const char *name, size_t len)
{
	for (size_t i = 0; i < g->nupstreams; i++) {
		bst_cfg_upstream *u = g->upstreams[i];
		if (!u->implicit && strlen(u->name) == len && memcmp(u->name, name, len) == 0)
			return u;
	}
	return NULL;
}

/* ---- shared state ---- */

typedef struct region_hdr {
	_Alignas(64) atomic_uint gen;
} region_hdr;

static region_hdr *g_hdr;
static bst_upstate_slot *g_slots;
static size_t g_nslots;

size_t bst_upstate_nslots(const bst_config *cfg)
{
	size_t n = 0;
	for (size_t i = 0; i < cfg->global.nupstreams; i++)
		n += cfg->global.upstreams[i]->npeers;
	return n;
}

static void slot_write(bst_upstate_slot *s, const bst_sockaddr *a, bool valid)
{
	unsigned q = atomic_load_explicit(&s->seq, memory_order_relaxed);
	atomic_store_explicit(&s->seq, q + 1, memory_order_relaxed);
	atomic_thread_fence(memory_order_release);
	if (a != NULL)
		s->addr = *a;
	s->valid = valid;
	atomic_store_explicit(&s->seq, q + 2, memory_order_release);
}

int bst_upstate_setup(const bst_config *cfg, bst_err *err)
{
	size_t n = bst_upstate_nslots(cfg);
	if (n == 0)
		return 0;
	size_t size = sizeof(region_hdr) + n * sizeof(bst_upstate_slot);
	void *m = bst_shm_create("bastion-upstream", size, NULL);
	if (m == NULL) {
		bst_err_set(err, "upstream state: shared memory: %s", strerror(errno));
		return -1;
	}
	g_hdr = m;
	g_slots = (bst_upstate_slot *)((char *)m + sizeof(region_hdr));
	g_nslots = n;
	for (size_t i = 0; i < cfg->global.nupstreams; i++) {
		const bst_cfg_upstream *u = cfg->global.upstreams[i];
		for (size_t k = 0; k < u->npeers; k++) {
			const bst_peer *p = &u->peers[k];
			if (!p->dynamic && p->state < n)
				slot_write(&g_slots[p->state], &p->addr, true);
		}
	}
	return 0;
}

unsigned bst_upstate_gen(void)
{
	return g_hdr == NULL ? 0 : atomic_load_explicit(&g_hdr->gen, memory_order_acquire);
}

bool bst_peer_addr(const bst_peer *p, bst_sockaddr *out)
{
	if (!p->dynamic) {
		*out = p->addr;
		return true;
	}
	if (g_slots == NULL || p->state >= g_nslots)
		return false;
	bst_upstate_slot *s = &g_slots[p->state];
	for (int tries = 0; tries < 64; tries++) {
		unsigned a = atomic_load_explicit(&s->seq, memory_order_acquire);
		if (a & 1u)
			continue;
		bst_sockaddr addr = s->addr;
		bool valid = s->valid != 0;
		atomic_thread_fence(memory_order_acquire);
		if (atomic_load_explicit(&s->seq, memory_order_relaxed) != a)
			continue;
		if (valid)
			*out = addr;
		return valid;
	}
	return false; /* the helper is mid-write for that long: try again on the next request */
}

uint64_t bst_mono_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

bool bst_peer_up(const bst_peer *p)
{
	if (g_slots == NULL || p->state >= g_nslots)
		return true;
	bst_upstate_slot *s = &g_slots[p->state];
	if (atomic_load_explicit(&s->down, memory_order_relaxed) != 0)
		return false;
	uint64_t until = atomic_load_explicit(&s->eject_until, memory_order_relaxed);
	return until == 0 || bst_mono_ms() >= until;
}

bool bst_peer_passive_fail(const bst_peer *p, const bst_up_passive *cfg, uint64_t now)
{
	if (cfg->fails == 0 || g_slots == NULL || p->state >= g_nslots)
		return false;
	bst_upstate_slot *s = &g_slots[p->state];
	uint64_t w = atomic_load_explicit(&s->pwin, memory_order_relaxed);
	if (w == 0 || now - w > cfg->window_ms) {
		/* a new window: whoever moves pwin also clears the count (a lost race only loses a
		 * failure or two, never ejects early) */
		if (atomic_compare_exchange_strong(&s->pwin, &w, now))
			atomic_store_explicit(&s->pfails, 0, memory_order_relaxed);
	}
	unsigned n = atomic_fetch_add_explicit(&s->pfails, 1, memory_order_relaxed) + 1;
	if (n != cfg->fails)
		return false;
	atomic_store_explicit(&s->eject_until, now + cfg->for_ms, memory_order_relaxed);
	atomic_store_explicit(&s->pwin, 0, memory_order_relaxed);
	atomic_fetch_add_explicit(&g_hdr->gen, 1, memory_order_release);
	return true;
}

bool bst_upstream_any_addr(const bst_cfg_upstream *u)
{
	bst_sockaddr a;
	for (size_t i = 0; i < u->npeers; i++)
		if (bst_peer_addr(&u->peers[i], &a))
			return true;
	return false;
}

void bst_peer_set_down(const bst_peer *p, bool down)
{
	if (g_slots == NULL || p->state >= g_nslots)
		return;
	unsigned old = atomic_exchange_explicit(&g_slots[p->state].down, down ? 1u : 0u,
						memory_order_relaxed);
	if (old != (down ? 1u : 0u))
		atomic_fetch_add_explicit(&g_hdr->gen, 1, memory_order_release);
}

void bst_upstate_publish(const bst_cfg_upstream *u, const bst_up_server *srv, const bst_ip *ips,
			 size_t n)
{
	if (g_slots == NULL)
		return;
	for (size_t i = 0; i < srv->npeers; i++) {
		const bst_peer *p = &u->peers[srv->first_peer + i];
		if (p->state >= g_nslots)
			continue;
		if (i < n) {
			bst_sockaddr a = { .ip = ips[i], .port = srv->port };
			slot_write(&g_slots[p->state], &a, true);
		} else {
			slot_write(&g_slots[p->state], NULL, false);
		}
	}
	atomic_fetch_add_explicit(&g_hdr->gen, 1, memory_order_release);
}

#ifdef BST_TEST
void bst_upstate_test_map(size_t n)
{
	static char *mem;
	free(mem);
	mem = aligned_alloc(64, sizeof(region_hdr) + n * sizeof(bst_upstate_slot));
	memset(mem, 0, sizeof(region_hdr) + n * sizeof(bst_upstate_slot));
	g_hdr = (region_hdr *)mem;
	g_slots = (bst_upstate_slot *)(mem + sizeof(region_hdr));
	g_nslots = n;
}

void bst_upstate_test_reset(void)
{
	g_hdr = NULL;
	g_slots = NULL;
	g_nslots = 0;
}
#endif

/* ---- the resolver in the helper ---- */

typedef struct rjob {
	const bst_config *cfg;
	const bst_cfg_upstream *u;
	const bst_up_server *srv;
	bst_loop *loop;
	bst_timer timer;
	bst_sock *sk;
	uint16_t id;
	uint16_t qtype;	     /* A, then AAAA */
	bool waiting;	     /* a query is out: the timer is its timeout */
	unsigned next_resolver;
	bst_ip got[BST_DNS_MAX_ADDRS];
	size_t ngot;
	uint32_t ttl;
	bool answered;	     /* some query of this round had an authoritative answer */
	const char *why;     /* the failure of this round, for the warning */
	size_t published;    /* addresses in use now */
	bool ever;	     /* published at least once */
} rjob;

static void job_query(rjob *j);
static void job_round(void *ud);

static void job_close(rjob *j)
{
	if (j->sk != NULL) {
		bst_sock_close(j->sk);
		j->sk = NULL;
	}
}

static void job_schedule(rjob *j, uint64_t ms)
{
	j->waiting = false;
	job_close(j);
	bst_loop_timer_arm(j->loop, &j->timer, ms == 0 ? 1 : ms, job_round, j);
}

/* The round is over: publish what it found, or keep the old addresses. */
static void job_finish(rjob *j)
{
	const bst_cfg_resolver *r = &j->cfg->global.resolver;
	if (!j->answered) {
		bst_log(BST_LOG_WARN,
			"upstream %s: resolving %s failed (%s): keeping the %zu address%s it had",
			j->u->name, j->srv->host, j->why ? j->why : "no answer", j->published,
			j->published == 1 ? "" : "es");
		job_schedule(j, r->ttl_min_ms);
		return;
	}
	size_t n = j->ngot < BST_UP_RESOLVE_SLOTS ? j->ngot : BST_UP_RESOLVE_SLOTS;
	bst_upstate_publish(j->u, j->srv, j->got, n);
	if (n == 0)
		bst_log(BST_LOG_WARN, "upstream %s: %s has no address (%s)", j->u->name, j->srv->host,
			j->why ? j->why : "no records");
	else if (!j->ever || n != j->published)
		bst_log(BST_LOG_INFO, "upstream %s: %s resolved to %zu address%s", j->u->name,
			j->srv->host, n, n == 1 ? "" : "es");
	j->published = n;
	j->ever = true;
	uint64_t ms = (uint64_t)j->ttl * 1000u;
	if (ms < r->ttl_min_ms)
		ms = r->ttl_min_ms;
	if (ms > r->ttl_max_ms)
		ms = r->ttl_max_ms;
	job_schedule(j, ms);
}

/* One query of the round is done (answered or not): the next type, or the end. */
static void job_next(rjob *j)
{
	job_close(j);
	if (j->qtype == BST_DNS_TYPE_A) {
		j->qtype = BST_DNS_TYPE_AAAA;
		job_query(j);
		return;
	}
	job_finish(j);
}

static void on_timeout(void *ud)
{
	rjob *j = ud;
	if (!j->waiting)
		return;
	j->waiting = false;
	j->why = "the resolver did not answer in time";
	job_next(j);
}

static void on_readable(void *ud, uint32_t events, int err)
{
	rjob *j = ud;
	(void)events;
	if (!j->waiting)
		return;
	uint8_t msg[BST_DNS_MAX_MSG];
	for (;;) {
		ssize_t n = recv(bst_sock_fd(j->sk), msg, sizeof msg, 0);
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) && err == 0)
			break;
		if (n < 0) { /* ICMP unreachable and friends: the resolver is not there */
			j->why = "the resolver refused the query";
			bst_timer_cancel(&j->timer);
			j->waiting = false;
			job_next(j);
			return;
		}
		bst_dns_answer a;
		bst_dns_status st = bst_dns_parse(msg, (size_t)n, j->id, j->srv->host, j->qtype, &a);
		if (st == BST_DNS_IGNORE)
			continue; /* not ours (a stale or spoofed datagram): keep waiting */
		bst_timer_cancel(&j->timer);
		j->waiting = false;
		if (st == BST_DNS_OK || st == BST_DNS_NXDOMAIN) {
			j->answered = true;
			if (st == BST_DNS_NXDOMAIN)
				j->why = "no such name";
			for (size_t i = 0; i < a.naddrs && j->ngot < BST_DNS_MAX_ADDRS; i++)
				j->got[j->ngot++] = a.addrs[i];
			if (a.naddrs > 0 && a.ttl < j->ttl)
				j->ttl = a.ttl;
		} else {
			j->why = bst_dns_status_str(st);
		}
		job_next(j);
		return;
	}
	if (bst_io_poll(j->sk, POLLIN, on_readable, j) != 0) {
		j->why = "poll failed";
		bst_timer_cancel(&j->timer);
		j->waiting = false;
		job_next(j);
	}
}

static void sockaddr_of(const bst_sockaddr *a, struct sockaddr_storage *ss, socklen_t *len)
{
	memset(ss, 0, sizeof *ss);
	if (a->ip.family == BST_IP_V4) {
		struct sockaddr_in *s4 = (struct sockaddr_in *)ss;
		s4->sin_family = AF_INET;
		s4->sin_port = htons(a->port);
		memcpy(&s4->sin_addr, a->ip.b, 4);
		*len = sizeof *s4;
	} else {
		struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)ss;
		s6->sin6_family = AF_INET6;
		s6->sin6_port = htons(a->port);
		memcpy(&s6->sin6_addr, a->ip.b, 16);
		*len = sizeof *s6;
	}
}

/* Sends one query on a fresh socket: a new ephemeral port each time (the kernel picks it at
 * random), a new ID from the CSPRNG, and a connected socket so only the resolver's address and
 * port can answer. */
static void job_query(rjob *j)
{
	const bst_cfg_resolver *r = &j->cfg->global.resolver;
	if (j->qtype == 0) { /* a new round */
		j->qtype = BST_DNS_TYPE_A;
		j->ngot = 0;
		j->ttl = UINT32_MAX;
		j->answered = false;
		j->why = NULL;
	}
	const bst_sockaddr *to = &r->addrs[j->next_resolver++ % r->naddrs];
	uint8_t q[512];
	if (getrandom(&j->id, sizeof j->id, 0) != (ssize_t)sizeof j->id) {
		j->why = "no randomness for the query ID";
		job_next(j);
		return;
	}
	size_t ql = bst_dns_query(q, sizeof q, j->id, j->srv->host, j->qtype);
	struct sockaddr_storage ss;
	socklen_t sl;
	sockaddr_of(to, &ss, &sl);
	int fd = socket(ss.ss_family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (ql == 0 || fd < 0 || connect(fd, (struct sockaddr *)&ss, sl) != 0 ||
	    send(fd, q, ql, 0) != (ssize_t)ql) {
		j->why = ql == 0 ? "not a valid host name" : strerror(errno);
		if (fd >= 0)
			close(fd);
		job_next(j);
		return;
	}
	j->sk = bst_sock_wrap(j->loop, fd);
	if (j->sk == NULL) {
		close(fd);
		j->why = "out of memory";
		job_next(j);
		return;
	}
	j->waiting = true;
	if (bst_io_poll(j->sk, POLLIN, on_readable, j) != 0) {
		j->waiting = false;
		j->why = "poll failed";
		job_next(j);
		return;
	}
	bst_loop_timer_arm(j->loop, &j->timer, r->timeout_ms, on_timeout, j);
}

static void job_round(void *ud)
{
	rjob *j = ud;
	j->qtype = 0;
	job_query(j);
}

void bst_resolver_helper_start(bst_loop *l, const bst_config *cfg)
{
	const bst_cfg_global *g = &cfg->global;
	if (g->resolver.naddrs == 0)
		return;
	for (size_t i = 0; i < g->nupstreams; i++) {
		const bst_cfg_upstream *u = g->upstreams[i];
		for (size_t k = 0; k < u->nservers; k++) {
			if (!u->servers[k].resolve)
				continue;
			rjob *j = calloc(1, sizeof *j); /* lives as long as the helper */
			if (j == NULL) {
				bst_log(BST_LOG_ERROR, "upstream %s: out of memory for the resolver",
					u->name);
				return;
			}
			j->cfg = cfg;
			j->u = u;
			j->srv = &u->servers[k];
			j->loop = l;
			bst_timer_init(&j->timer);
			bst_loop_timer_arm(l, &j->timer, 1, job_round, j);
		}
	}
}
