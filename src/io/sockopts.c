/* The TCP option table: every tcp_profile option, how it is applied, and the checks for
 * options that can succeed and still do nothing. One function walks the table for the
 * listener (bst_sockopts_apply_) and one for accepted connections (bst_sock_apply_accepted),
 * so an option is added in exactly one place. See listener.h for the policy. */
#include "core/addr.h"
#include "core/log.h"
#include "io/listener.h"

#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

/* Older headers lack these (Linux 5.11). */
#ifndef SO_PREFER_BUSY_POLL
#define SO_PREFER_BUSY_POLL 69
#endif
#ifndef SO_BUSY_POLL_BUDGET
#define SO_BUSY_POLL_BUDGET 70
#endif
#ifndef TCP_FASTOPEN_KEY
#define TCP_FASTOPEN_KEY 33
#endif
#ifndef IPV6_FREEBIND
#define IPV6_FREEBIND 78
#endif

#ifdef BST_TEST
unsigned bst_test_sockopt_calls;
#endif

typedef struct opt_ctx {
	const bst_sockopt_target *t;
	const char *what; /* the setsockopt name last tried, for the message */
	char note[200];   /* set instead of an errno for a check that failed after success */
} opt_ctx;

#define ERR_NOTE (-1) /* apply: the option went in but does nothing; ctx->note says why */

/* One setsockopt, remembering its name. Returns 0 or errno. */
static int put(opt_ctx *c, const char *what, int level, int opt, const void *val, socklen_t len)
{
	c->what = what;
#ifdef BST_TEST
	bst_test_sockopt_calls++;
#endif
	return setsockopt(c->t->fd, level, opt, val, len) == 0 ? 0 : errno;
}

static int put_int(opt_ctx *c, const char *what, int level, int opt, int v)
{
	return put(c, what, level, opt, &v, sizeof v);
}

/* A kernel number from /proc/sys; false when the file cannot be read (a restricted
 * container, say: then there is nothing to compare with and no warning). */
static bool sysctl_int(const char *path, long *out)
{
	FILE *f = fopen(path, "re");
	if (f == NULL)
		return false;
	long v;
	int ok = fscanf(f, "%ld", &v) == 1;
	fclose(f);
	if (ok)
		*out = v;
	return ok != 0;
}

/* ---- apply functions: 0, an errno, or ERR_NOTE ---- */

typedef int (*apply_fn)(opt_ctx *, const bst_tcp_profile *);

static int ap_fastopen(opt_ctx *c, const bst_tcp_profile *p)
{
	int rc = put_int(c, "TCP_FASTOPEN", IPPROTO_TCP, TCP_FASTOPEN, p->fastopen);
	long v;
	/* The socket option alone is not enough: the server bit (2) of the sysctl switches
	 * server-side Fast Open on, and stock kernels ship it off (1, client only). */
	if (rc == 0 && sysctl_int("/proc/sys/net/ipv4/tcp_fastopen", &v) && (v & 2) == 0) {
		snprintf(c->note, sizeof c->note,
			 "TCP_FASTOPEN is set but net.ipv4.tcp_fastopen=%ld lacks the server bit (2), "
			 "so the kernel ignores Fast Open until it is %ld",
			 v, v | 2);
		return ERR_NOTE;
	}
	return rc;
}

static int ap_fastopen_key(opt_ctx *c, const bst_tcp_profile *p)
{
	return put(c, "TCP_FASTOPEN_KEY", IPPROTO_TCP, TCP_FASTOPEN_KEY, p->fastopen_key,
		   sizeof p->fastopen_key);
}

static int ap_defer_accept(opt_ctx *c, const bst_tcp_profile *p)
{
	return put_int(c, "TCP_DEFER_ACCEPT", IPPROTO_TCP, TCP_DEFER_ACCEPT, (int)p->defer_accept_s);
}

static int ap_busy_poll(opt_ctx *c, const bst_tcp_profile *p)
{
	return put_int(c, "SO_BUSY_POLL", SOL_SOCKET, SO_BUSY_POLL, (int)p->busy_poll_us);
}

static int ap_prefer_busy_poll(opt_ctx *c, const bst_tcp_profile *p)
{
	return put_int(c, "SO_PREFER_BUSY_POLL", SOL_SOCKET, SO_PREFER_BUSY_POLL,
		       p->prefer_busy_poll);
}

static int ap_busy_poll_budget(opt_ctx *c, const bst_tcp_profile *p)
{
	return put_int(c, "SO_BUSY_POLL_BUDGET", SOL_SOCKET, SO_BUSY_POLL_BUDGET,
		       (int)p->busy_poll_budget);
}

static int ap_nodelay(opt_ctx *c, const bst_tcp_profile *p)
{
	return put_int(c, "TCP_NODELAY", IPPROTO_TCP, TCP_NODELAY, p->nodelay);
}

static int ap_quickack(opt_ctx *c, const bst_tcp_profile *p)
{
	return put_int(c, "TCP_QUICKACK", IPPROTO_TCP, TCP_QUICKACK, p->quickack);
}

static int ap_congestion(opt_ctx *c, const bst_tcp_profile *p)
{
	return put(c, "TCP_CONGESTION", IPPROTO_TCP, TCP_CONGESTION, p->congestion,
		   (socklen_t)strlen(p->congestion));
}

static int ap_notsent_lowat(opt_ctx *c, const bst_tcp_profile *p)
{
	return put_int(c, "TCP_NOTSENT_LOWAT", IPPROTO_TCP, TCP_NOTSENT_LOWAT,
		       (int)p->notsent_lowat);
}

static int ap_user_timeout(opt_ctx *c, const bst_tcp_profile *p)
{
	return put_int(c, "TCP_USER_TIMEOUT", IPPROTO_TCP, TCP_USER_TIMEOUT,
		       (int)p->user_timeout_ms);
}

static int ap_keepalive(opt_ctx *c, const bst_tcp_profile *p)
{
	int rc = put_int(c, "SO_KEEPALIVE", SOL_SOCKET, SO_KEEPALIVE, 1);
	if (rc == 0)
		rc = put_int(c, "TCP_KEEPIDLE", IPPROTO_TCP, TCP_KEEPIDLE, (int)p->ka_idle_s);
	if (rc == 0)
		rc = put_int(c, "TCP_KEEPINTVL", IPPROTO_TCP, TCP_KEEPINTVL, (int)p->ka_interval_s);
	if (rc == 0)
		rc = put_int(c, "TCP_KEEPCNT", IPPROTO_TCP, TCP_KEEPCNT, (int)p->ka_count);
	return rc;
}

/* The kernel clamps a buffer to net.core.{r,w}mem_max without an error, then doubles what is
 * left for bookkeeping: reading it back shows whether the request was honoured. */
static int ap_buf(opt_ctx *c, const char *what, int opt, uint32_t want, const char *sysctl)
{
	int rc = put_int(c, what, SOL_SOCKET, opt, (int)want);
	if (rc != 0)
		return rc;
	int got = 0;
	socklen_t len = sizeof got;
	if (getsockopt(c->t->fd, SOL_SOCKET, opt, &got, &len) == 0 && (uint64_t)got < 2 * (uint64_t)want) {
		snprintf(c->note, sizeof c->note,
			 "%s asked for %u bytes but the kernel gave %d (it counts twice what it grants): "
			 "clamped by %s, raise that sysctl",
			 what, (unsigned)want, got / 2, sysctl);
		return ERR_NOTE;
	}
	return 0;
}

static int ap_rcvbuf(opt_ctx *c, const bst_tcp_profile *p)
{
	return ap_buf(c, "SO_RCVBUF", SO_RCVBUF, p->rcvbuf, "net.core.rmem_max");
}

static int ap_sndbuf(opt_ctx *c, const bst_tcp_profile *p)
{
	return ap_buf(c, "SO_SNDBUF", SO_SNDBUF, p->sndbuf, "net.core.wmem_max");
}

static int ap_pacing_rate(opt_ctx *c, const bst_tcp_profile *p)
{
	return put(c, "SO_MAX_PACING_RATE", SOL_SOCKET, SO_MAX_PACING_RATE, &p->pacing_rate,
		   sizeof p->pacing_rate);
}

static int ap_mark(opt_ctx *c, const bst_tcp_profile *p)
{
	return put_int(c, "SO_MARK", SOL_SOCKET, SO_MARK, (int)p->mark);
}

static int ap_freebind(opt_ctx *c, const bst_tcp_profile *p)
{
	bool v6 = c->t->family == AF_INET6;
	return put_int(c, v6 ? "IPV6_FREEBIND" : "IP_FREEBIND", v6 ? IPPROTO_IPV6 : IPPROTO_IP,
		       v6 ? IPV6_FREEBIND : IP_FREEBIND, p->freebind);
}

/* listen(2) has already run with this value; the kernel caps it at net.core.somaxconn. */
static int ap_backlog(opt_ctx *c, const bst_tcp_profile *p)
{
	long v;
	if (sysctl_int("/proc/sys/net/core/somaxconn", &v) && p->backlog > v) {
		snprintf(c->note, sizeof c->note,
			 "backlog %d exceeds net.core.somaxconn=%ld, which caps it: raise that sysctl",
			 p->backlog, v);
		return ERR_NOTE;
	}
	return 0;
}

static int ap_steering(opt_ctx *c, const bst_tcp_profile *p)
{
	(void)p;
	int cpu = c->t->slot % (c->t->ncpu > 0 ? c->t->ncpu : 1);
	return put_int(c, "SO_INCOMING_CPU", SOL_SOCKET, SO_INCOMING_CPU, cpu);
}

/* ---- the table ---- */

typedef enum val_kind {
	V_NONE,   /* nothing worth printing */
	V_UINT,   /* unsigned at offset */
	V_INT,
	V_BOOL,
	V_STR,    /* char array at offset */
} val_kind;

typedef struct opt_desc {
	const char *name; /* the directive */
	apply_fn apply;
	unsigned char stage;   /* bst_sockopt_stage, or STAGE_ACCEPT */
	val_kind kind;
	unsigned short off;    /* offsetof the value in bst_tcp_profile */
	bool (*is_default)(const bst_tcp_profile *); /* the kernel already has this: skip */
} opt_desc;

#define STAGE_ACCEPT 2

static bool def_off(const bst_tcp_profile *p) { return !p->nodelay; }
static bool def_prefer(const bst_tcp_profile *p) { return !p->prefer_busy_poll; }
static bool def_quickack(const bst_tcp_profile *p) { return p->quickack; } /* new sockets start in quickack mode */
static bool def_freebind(const bst_tcp_profile *p) { return !p->freebind; }
static bool def_steer(const bst_tcp_profile *p) { return p->steering == BST_STEER_NONE; }

#define OFF(f) ((unsigned short)offsetof(bst_tcp_profile, f))
static const opt_desc table[BST_TCP_OPT_COUNT] = {
	[BST_TCP_FASTOPEN] = { "fastopen", ap_fastopen, BST_SO_LISTENING, V_INT, OFF(fastopen), NULL },
	[BST_TCP_FASTOPEN_KEY] = { "fastopen_key", ap_fastopen_key, BST_SO_LISTENING, V_NONE, 0, NULL },
	[BST_TCP_DEFER_ACCEPT] = { "defer_accept", ap_defer_accept, BST_SO_BEFORE_BIND, V_UINT,
				   OFF(defer_accept_s), NULL },
	[BST_TCP_BUSY_POLL] = { "busy_poll", ap_busy_poll, BST_SO_BEFORE_BIND, V_UINT, OFF(busy_poll_us), NULL },
	[BST_TCP_PREFER_BUSY_POLL] = { "prefer_busy_poll", ap_prefer_busy_poll, BST_SO_BEFORE_BIND,
				       V_BOOL, OFF(prefer_busy_poll), def_prefer },
	[BST_TCP_BUSY_POLL_BUDGET] = { "busy_poll_budget", ap_busy_poll_budget, BST_SO_BEFORE_BIND,
				       V_UINT, OFF(busy_poll_budget), NULL },
	[BST_TCP_NODELAY] = { "nodelay", ap_nodelay, BST_SO_BEFORE_BIND, V_BOOL, OFF(nodelay), def_off },
	[BST_TCP_QUICKACK] = { "quickack", ap_quickack, STAGE_ACCEPT, V_BOOL, OFF(quickack), def_quickack },
	[BST_TCP_CONGESTION] = { "congestion", ap_congestion, BST_SO_BEFORE_BIND, V_STR, OFF(congestion), NULL },
	[BST_TCP_NOTSENT_LOWAT] = { "notsent_lowat", ap_notsent_lowat, BST_SO_BEFORE_BIND, V_UINT,
				    OFF(notsent_lowat), NULL },
	[BST_TCP_USER_TIMEOUT] = { "user_timeout", ap_user_timeout, BST_SO_BEFORE_BIND, V_UINT,
				   OFF(user_timeout_ms), NULL },
	[BST_TCP_KEEPALIVE] = { "keepalive", ap_keepalive, BST_SO_BEFORE_BIND, V_NONE, 0, NULL },
	[BST_TCP_RCVBUF] = { "rcvbuf", ap_rcvbuf, BST_SO_BEFORE_BIND, V_UINT, OFF(rcvbuf), NULL },
	[BST_TCP_SNDBUF] = { "sndbuf", ap_sndbuf, BST_SO_BEFORE_BIND, V_UINT, OFF(sndbuf), NULL },
	[BST_TCP_PACING_RATE] = { "pacing_rate", ap_pacing_rate, BST_SO_BEFORE_BIND, V_UINT,
				  OFF(pacing_rate), NULL },
	[BST_TCP_MARK] = { "mark", ap_mark, BST_SO_BEFORE_BIND, V_UINT, OFF(mark), NULL },
	[BST_TCP_FREEBIND] = { "freebind", ap_freebind, BST_SO_BEFORE_BIND, V_BOOL, OFF(freebind), def_freebind },
	[BST_TCP_BACKLOG] = { "backlog", ap_backlog, BST_SO_LISTENING, V_INT, OFF(backlog), NULL },
	[BST_TCP_STEERING] = { "steering", ap_steering, BST_SO_BEFORE_BIND, V_NONE, 0, def_steer },
};

/* The value as written, for a message ("" when there is nothing to show). */
static void show(const opt_desc *d, const bst_tcp_profile *p, char *out, size_t cap)
{
	const char *base = (const char *)p + d->off;
	out[0] = 0;
	switch (d->kind) {
	case V_UINT: {
		unsigned long long v = 0;
		/* every unsigned field is 4 bytes (uint32_t or unsigned) */
		unsigned u;
		memcpy(&u, base, sizeof u);
		v = u;
		snprintf(out, cap, " (%llu)", v);
		break;
	}
	case V_INT: {
		int v;
		memcpy(&v, base, sizeof v);
		snprintf(out, cap, " (%d)", v);
		break;
	}
	case V_BOOL:
		snprintf(out, cap, " (%s)", *(const bool *)base ? "on" : "off");
		break;
	case V_STR:
		snprintf(out, cap, " (%.*s)", BST_TCP_CA_NAME_MAX - 1, base);
		break;
	case V_NONE:
		break;
	}
}

/* "<errno text>" for a refused call, or the note for a check. */
static void reason(const opt_ctx *c, int rc, char *out, size_t cap)
{
	if (rc == ERR_NOTE)
		snprintf(out, cap, "%s", c->note);
	else
		snprintf(out, cap, "%s: %s (errno %d)", c->what ? c->what : "setsockopt", strerror(rc), rc);
}

int bst_sockopts_apply_(const bst_sockopt_target *t, const bst_tcp_profile *p,
			bst_sockopt_stage stage, uint32_t *reported, bst_err *err)
{
	for (int o = 0; o < BST_TCP_OPT_COUNT; o++) {
		const opt_desc *d = &table[o];
		if (!BST_TCP_HAS(p, o) || d->stage != stage || (d->is_default && d->is_default(p)))
			continue;
		opt_ctx c = { .t = t };
		int rc = d->apply(&c, p);
		if (rc == 0)
			continue;
		char val[48], why[300];
		show(d, p, val, sizeof val);
		reason(&c, rc, why, sizeof why);
		if (BST_TCP_REQUIRED(p, o)) {
			bst_err_set(err, "tcp_profile \"%s\": option %s%s require failed on %s: %s",
				    p->name ? p->name : "?", d->name, val, t->addr, why);
			return -1;
		}
		if (reported == NULL || !((*reported >> o) & 1u)) {
			bst_log(BST_LOG_WARN, "tcp_profile \"%s\": option %s%s not applied on %s: %s",
				p->name ? p->name : "?", d->name, val, t->addr, why);
			if (reported != NULL)
				*reported |= 1u << o;
		}
	}
	return 0;
}

int bst_sock_apply_accepted(int fd, const bst_tcp_profile *p)
{
	static _Atomic uint32_t logged; /* options already reported: one line each per process */
	if (p == NULL)
		return 0;
	int first = 0;
	bst_sockopt_target t = { .fd = fd };
	for (int o = 0; o < BST_TCP_OPT_COUNT; o++) {
		const opt_desc *d = &table[o];
		if (!BST_TCP_HAS(p, o) || d->stage != STAGE_ACCEPT || (d->is_default && d->is_default(p)))
			continue;
		opt_ctx c = { .t = &t };
		int rc = d->apply(&c, p);
		if (rc == 0)
			continue;
		if (rc == ERR_NOTE)
			rc = EINVAL; /* no accept-time check is a note today */
		if (first == 0)
			first = -rc;
		uint32_t bit = 1u << o;
		if (!(atomic_fetch_or(&logged, bit) & bit)) {
			char val[48];
			show(d, p, val, sizeof val);
			bst_log(BST_LOG_WARN, "tcp_profile \"%s\": option %s%s not applied to accepted "
					      "connections: %s: %s", p->name ? p->name : "?", d->name, val,
				c.what ? c.what : "setsockopt", strerror(rc));
		}
	}
	return first;
}
