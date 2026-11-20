/* See metrics.h. */
#include "ops/metrics.h"

#include "auth/basic.h"
#include "cache/filter.h"
#include "core/b64.h"
#include "core/counters.h"
#include "core/log.h"
#include "core/shm.h"
#include "http/stream.h"
#include "io/sock.h"
#include "proc/runtime.h"
#include "proxy/upstream.h"
#include "sec/sec.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define METRICS_FD_VAR "BASTION_METRICS_FD" /* the listener, across a reload or upgrade exec */
#define NCLASS 5 /* 1xx..5xx */
#define NPROTO 3 /* HTTP/1.x, 2, 3 */
#define LABEL_VALUE_MAX 48

static const char *const proto_names[NPROTO] = { "http1", "http2", "http3" };

/* ---- request series, registered by master before fork ---- */

typedef struct srv_ids {
	const void *key; /* the bst_cfg_server or bst_cfg_location; NULL: empty bucket */
	bst_counter_id req[NCLASS][NPROTO];
} srv_ids;

typedef struct ptr_map {
	srv_ids *v;
	size_t cap; /* power of two, or 0 */
} ptr_map;

static ptr_map g_servers, g_locations;
static srv_ids g_other; /* Host matched no server name */
static bst_counter_id g_duration[NPROTO];
static bst_counter_id g_reload_ok = BST_COUNTER_INVALID, g_restarts = BST_COUNTER_INVALID;
static const bst_cfg_metrics *g_mcfg;
static const bst_basic_users *g_users;
static int g_listen_fd = -1;

static size_t ptr_hash(const void *p, size_t cap)
{
	uint64_t x = (uint64_t)(uintptr_t)p * 0x9e3779b97f4a7c15ull;
	return (size_t)(x >> 17) & (cap - 1);
}

static srv_ids *map_slot(ptr_map *m, const void *key)
{
	if (m->cap == 0)
		return NULL;
	for (size_t i = ptr_hash(key, m->cap), n = 0; n < m->cap; i = (i + 1) & (m->cap - 1), n++) {
		if (m->v[i].key == key || m->v[i].key == NULL)
			return &m->v[i];
	}
	return NULL;
}

static int map_init(ptr_map *m, size_t n)
{
	size_t cap = 8;
	while (cap < n * 2)
		cap <<= 1;
	free(m->v);
	m->v = calloc(cap, sizeof *m->v);
	m->cap = m->v != NULL ? cap : 0;
	return m->v != NULL ? 0 : -1;
}

void bst_metrics_label_value(const char *s, char *out, size_t cap)
{
	size_t o = 0;
	for (; s != NULL && *s != '\0' && o + 1 < cap; s++) {
		char ch = *s;
		bool ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
			  ch == '.' || ch == '_' || ch == '*' || ch == '~' || ch == '/' || ch == '-';
		out[o++] = ok ? ch : '_';
	}
	if (o == 0 && cap > 1)
		out[o++] = '_';
	out[o] = '\0';
}

/* Registers the requests series of one server label into ids. false when the table is full. */
static bool register_requests(srv_ids *ids, const char *server)
{
	char labels[BST_COUNTER_LABELS_MAX];
	for (int c = 0; c < NCLASS; c++)
		for (int p = 0; p < NPROTO; p++) {
			snprintf(labels, sizeof labels, "server=%s,code=%dxx,protocol=%s", server, c + 1,
				 proto_names[p]);
			ids->req[c][p] = bst_counter_register("bastion_http_requests_total",
							      "client requests answered, by server, status class "
							      "and protocol", labels);
			if (ids->req[c][p] == BST_COUNTER_INVALID)
				return false;
		}
	return true;
}

static void register_location(const bst_cfg_server *srv, const char *server, const bst_cfg_location *loc)
{
	char lv[LABEL_VALUE_MAX], labels[BST_COUNTER_LABELS_MAX];
	bst_metrics_label_value(loc->pattern, lv, sizeof lv);
	snprintf(labels, sizeof labels, "server=%s,location=%s", server, lv);
	srv_ids *slot = map_slot(&g_locations, loc);
	if (slot != NULL && slot->key == NULL) {
		slot->key = loc;
		slot->req[0][0] = bst_counter_register("bastion_http_location_requests_total",
						       "client requests answered, by location", labels);
	}
	for (size_t i = 0; i < loc->nchildren; i++)
		register_location(srv, server, loc->children[i]);
}

static size_t count_locations(const bst_cfg_location *loc)
{
	size_t n = 1;
	for (size_t i = 0; i < loc->nchildren; i++)
		n += count_locations(loc->children[i]);
	return n;
}

static int register_series(const bst_config *cfg, bst_err *e)
{
	const bst_cfg_global *g = &cfg->global;
	if (!register_requests(&g_other, "_other") || map_init(&g_servers, g->nservers) != 0) {
		bst_err_set(e, "metrics: cannot register the request counters");
		return -1;
	}
	unsigned full = 0;
	for (size_t i = 0; i < g->nservers; i++) {
		const bst_cfg_server *s = g->servers[i];
		srv_ids *slot = map_slot(&g_servers, s);
		if (slot == NULL)
			continue;
		slot->key = s;
		if (s->nnames == 0) { /* only ever answers as the default: _other */
			memcpy(slot->req, g_other.req, sizeof slot->req);
			continue;
		}
		char sv[LABEL_VALUE_MAX];
		bst_metrics_label_value(s->names[0], sv, sizeof sv);
		if (!register_requests(slot, sv)) {
			memcpy(slot->req, g_other.req, sizeof slot->req); /* past the table: _other */
			full++;
		}
	}
	if (full > 0)
		bst_log(BST_LOG_WARN, "metrics: the counter table is full: %u servers count under "
				      "server=\"_other\"", full);
	for (int p = 0; p < NPROTO; p++) {
		char labels[32];
		snprintf(labels, sizeof labels, "protocol=%s", proto_names[p]);
		g_duration[p] = bst_histogram_register("bastion_http_request_duration_seconds",
						       "time from the request head to the end of the response",
						       labels);
	}
	if (g->metrics != NULL && g->metrics->per_location) {
		size_t n = 0;
		for (size_t i = 0; i < g->nservers; i++)
			for (size_t j = 0; j < g->servers[i]->nlocations; j++)
				n += count_locations(g->servers[i]->locations[j]);
		if (map_init(&g_locations, n) != 0) {
			bst_err_set(e, "out of memory");
			return -1;
		}
		for (size_t i = 0; i < g->nservers; i++) {
			const bst_cfg_server *s = g->servers[i];
			char sv[LABEL_VALUE_MAX];
			bst_metrics_label_value(s->nnames > 0 ? s->names[0] : "_", sv, sizeof sv);
			for (size_t j = 0; j < s->nlocations; j++)
				register_location(s, sv, s->locations[j]);
		}
	}
	char build[BST_COUNTER_LABELS_MAX];
	snprintf(build, sizeof build, "version=%s", BST_VERSION);
	bst_gauge_set(bst_gauge_register("bastion_build_info", "the running build, always 1", build), 1);
	g_reload_ok = bst_gauge_register("bastion_config_reload_success",
					 "1 when the last configuration load or reload succeeded", NULL);
	bst_gauge_set(g_reload_ok, 1); /* this image runs, so its load succeeded */
	g_restarts = bst_counter_register("bastion_worker_restarts_total",
					  "workers and helpers respawned after an unasked exit", NULL);
	bst_cache_metrics_init();
	return 0;
}

static int64_t now_us(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

void bst_metrics_request(const bst_stream *s)
{
	if (s->log_status < 100 || s->log_status > 599 || s->log_proto < 1 || s->log_proto > NPROTO)
		return;
	int c = s->log_status / 100 - 1, p = s->log_proto - 1;
	const srv_ids *ids = &g_other;
	if (s->server != NULL && s->host_matched) {
		const srv_ids *x = map_slot(&g_servers, s->server);
		if (x != NULL && x->key != NULL)
			ids = x;
	}
	bst_counter_add(ids->req[c][p], 1);
	if (s->log_start_us != 0) {
		int64_t d = now_us() - (int64_t)s->log_start_us;
		bst_histogram_observe(g_duration[p], d > 0 ? (uint64_t)d : 0);
	}
	if (g_locations.cap != 0 && s->loc != NULL) {
		const srv_ids *x = map_slot(&g_locations, s->loc);
		if (x != NULL && x->key != NULL)
			bst_counter_add(x->req[0][0], 1);
	}
}

/* ---- master ---- */

static int bind_listener(const bst_cfg_metrics *m, bst_err *e)
{
	struct sockaddr_storage ss;
	socklen_t sl;
	memset(&ss, 0, sizeof ss);
	if (m->listen.ip.family == BST_IP_V4) {
		struct sockaddr_in *a = (struct sockaddr_in *)&ss;
		a->sin_family = AF_INET;
		a->sin_port = htons(m->listen.port);
		memcpy(&a->sin_addr, m->listen.ip.b, 4);
		sl = sizeof *a;
	} else {
		struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ss;
		a->sin6_family = AF_INET6;
		a->sin6_port = htons(m->listen.port);
		memcpy(&a->sin6_addr, m->listen.ip.b, 16);
		sl = sizeof *a;
	}
	char host[BST_ADDR_STRLEN];
	bst_addr_format(&m->listen.ip, host, sizeof host);
	/* The previous image's socket (reload, upgrade): kept when it is still the configured
	 * address, so no scrape queued on it is reset and no second bind is needed. */
	const char *inh = getenv(METRICS_FD_VAR);
	if (inh != NULL) {
		int ifd = atoi(inh);
		unsetenv(METRICS_FD_VAR);
		struct sockaddr_storage cur;
		socklen_t cl = sizeof cur;
		if (ifd > 2 && getsockname(ifd, (struct sockaddr *)&cur, &cl) == 0 && cl == sl &&
		    memcmp(&cur, &ss, sl) == 0 && fcntl(ifd, F_SETFD, FD_CLOEXEC) == 0) {
			g_listen_fd = ifd;
			bst_log(BST_LOG_INFO, "metrics: serving %s on %s:%u (kept)", m->path, host, m->listen.port);
			return 0;
		}
		if (ifd > 2)
			close(ifd);
	}
	int fd = socket(ss.ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	int one = 1;
	if (fd < 0 || setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) != 0 ||
	    (ss.ss_family == AF_INET6 && setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one) != 0) ||
	    bind(fd, (struct sockaddr *)&ss, sl) != 0 || listen(fd, 64) != 0) {
		bst_err_set(e, "metrics listen %s:%u: %s", host, m->listen.port, strerror(errno));
		if (fd >= 0)
			close(fd);
		return -1;
	}
	g_listen_fd = fd;
	bst_log(BST_LOG_INFO, "metrics: serving %s on %s:%u", m->path, host, m->listen.port);
	return 0;
}

int bst_metrics_setup(const bst_config *cfg, bst_err *e)
{
	/* Two regions, both kept across reload and upgrade: the registry (names, kinds, indices),
	 * which children see read-only, and the values every process adds into. */
	bool reg_kept = false, val_kept = false;
	size_t rsz = bst_counters_registry_size();
	void *rmem = bst_shm_create_kept("bastion-metrics-reg", rsz, &reg_kept);
	void *vmem = bst_shm_create_kept("bastion-metrics", bst_counters_values_size(), &val_kept);
	const void *rro = rmem != NULL ? bst_shm_ro_view(rmem, bst_shm_kept_fd(rmem), rsz, false) : NULL;
	if (rmem == NULL || vmem == NULL || rro == NULL) {
		bst_err_set(e, "metrics shared memory: %s", strerror(errno));
		return -1;
	}
	if (bst_counters_attach_shared(rmem, vmem, reg_kept && val_kept) != 0)
		bst_log(BST_LOG_WARN, "metrics: the kept counters have another layout: starting from zero");
	bst_counters_set_view(rro);
	if (register_series(cfg, e) != 0)
		return -1;
	g_mcfg = cfg->global.metrics;
	if (g_mcfg == NULL) {
		const char *inh = getenv(METRICS_FD_VAR); /* metrics turned off by this reload */
		if (inh != NULL && atoi(inh) > 2)
			close(atoi(inh));
		unsetenv(METRICS_FD_VAR);
		return 0;
	}
	if (g_mcfg->auth_file != NULL) {
		char why[256];
		unsigned weak = 0;
		g_users = bst_basic_users_load(g_mcfg->auth_file, &weak, why, sizeof why);
		if (g_users == NULL) {
			bst_err_set(e, "metrics auth_basic %s: %s", g_mcfg->auth_file, why);
			return -1;
		}
		if (weak > 0)
			bst_log(BST_LOG_WARN, "metrics auth_basic %s: %u entries are weaker than m=19456, t=2",
				g_mcfg->auth_file, weak);
	}
	return bind_listener(g_mcfg, e);
}

void bst_metrics_reload_result(bool ok)
{
	bst_gauge_set(g_reload_ok, ok ? 1 : 0);
}

void bst_metrics_worker_restart(void)
{
	bst_counter_add(g_restarts, 1);
}

void bst_metrics_before_exec(void)
{
	char v[16];
	if (g_listen_fd < 0 || fcntl(g_listen_fd, F_SETFD, 0) != 0)
		return;
	snprintf(v, sizeof v, "%d", g_listen_fd);
	(void)setenv(METRICS_FD_VAR, v, 1);
}

void bst_metrics_exec_failed(void)
{
	unsetenv(METRICS_FD_VAR);
	if (g_listen_fd >= 0)
		(void)fcntl(g_listen_fd, F_SETFD, FD_CLOEXEC);
}

void bst_metrics_teardown(void)
{
	if (g_listen_fd >= 0)
		close(g_listen_fd);
	g_listen_fd = -1;
}

/* ---- children ---- */

void bst_metrics_child_start(int slot)
{
	bst_counters_use_slot(slot < 0 ? BST_COUNTER_SLOT_HELPER : bst_counter_worker_slot(slot));
	bst_counters_child(); /* the registry's writable mapping goes (bst_shm_child_readonly) */
	if (slot >= 0 && g_listen_fd >= 0) {
		close(g_listen_fd);
		g_listen_fd = -1;
	}
	if (slot >= 0 && g_users != NULL) {
		bst_basic_users_free((void *)g_users); /* a worker never checks them */
		g_users = NULL;
	}
}

/* ---- exposition ---- */

typedef struct obuf {
	char *p;
	size_t len, cap;
	bool oom;
} obuf;

static void put(obuf *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void put(obuf *b, const char *fmt, ...)
{
	if (b->oom)
		return;
	for (;;) {
		va_list ap;
		va_start(ap, fmt);
		int n = vsnprintf(b->p + b->len, b->cap - b->len, fmt, ap);
		va_end(ap);
		if (n < 0) {
			b->oom = true;
			return;
		}
		if ((size_t)n < b->cap - b->len) {
			b->len += (size_t)n;
			return;
		}
		size_t cap = b->cap * 2 + (size_t)n + 1;
		char *q = realloc(b->p, cap);
		if (q == NULL) {
			b->oom = true;
			return;
		}
		b->p = q;
		b->cap = cap;
	}
}

/* HELP text: backslash and newline escaped. */
static void put_help(obuf *b, const char *name, const char *help, const char *type)
{
	put(b, "# HELP %s ", name);
	for (const char *h = help; *h != '\0'; h++) {
		if (*h == '\\')
			put(b, "\\\\");
		else if (*h == '\n')
			put(b, "\\n");
		else
			put(b, "%c", *h);
	}
	put(b, "\n# TYPE %s %s\n", name, type);
}

/* `k=v,k2=v2` as `k="v",k2="v2"` (quote, backslash and newline escaped), plus extra (already
 * formatted, may be NULL). Nothing at all when both are empty. */
static void put_labels(obuf *b, const char *labels, const char *extra)
{
	bool any = labels[0] != '\0' || (extra != NULL && extra[0] != '\0');
	if (!any)
		return;
	put(b, "{");
	const char *p = labels;
	bool first = true;
	while (*p != '\0') {
		const char *comma = strchr(p, ',');
		size_t n = comma != NULL ? (size_t)(comma - p) : strlen(p);
		const char *eq = memchr(p, '=', n);
		if (eq != NULL) {
			put(b, "%s%.*s=\"", first ? "" : ",", (int)(eq - p), p);
			for (const char *v = eq + 1; v < p + n; v++) {
				if (*v == '"' || *v == '\\')
					put(b, "\\%c", *v);
				else if (*v == '\n')
					put(b, "\\n");
				else
					put(b, "%c", *v);
			}
			put(b, "\"");
			first = false;
		}
		p += n;
		if (*p == ',')
			p++;
	}
	if (extra != NULL && extra[0] != '\0')
		put(b, "%s%s", first ? "" : ",", extra);
	put(b, "}");
}

/* Histogram bounds in microseconds, exposed in seconds. */
static const uint64_t le_us[] = { 1000, 2500, 5000, 10000, 25000, 50000, 100000, 250000,
				  500000, 1000000, 2500000, 5000000, 10000000 };
#define NLE (sizeof le_us / sizeof le_us[0])

static void put_histogram(obuf *b, bst_counter_id id, const bst_counter_info *ci)
{
	/* Each log-linear bucket goes to the first `le` at or above its upper bound, so a bound
	 * may count observations up to a quarter above it (the buckets' resolution). */
	uint64_t cum[NLE];
	memset(cum, 0, sizeof cum);
	uint64_t total = 0;
	for (unsigned k = 0; k < BST_HIST_BUCKETS; k++) {
		uint64_t n = bst_histogram_bucket(id, k);
		if (n == 0)
			continue;
		total += n;
		uint64_t up = bst_histogram_bucket_upper(k);
		for (size_t j = 0; j < NLE; j++)
			if (up <= le_us[j])
				cum[j] += n;
	}
	for (size_t j = 0; j < NLE; j++) {
		char le[48];
		snprintf(le, sizeof le, "le=\"%g\"", (double)le_us[j] / 1e6);
		put(b, "%s_bucket", ci->name);
		put_labels(b, ci->labels, le);
		put(b, " %llu\n", (unsigned long long)cum[j]);
	}
	put(b, "%s_bucket", ci->name);
	put_labels(b, ci->labels, "le=\"+Inf\"");
	put(b, " %llu\n", (unsigned long long)total);
	put(b, "%s_sum", ci->name);
	put_labels(b, ci->labels, NULL);
	put(b, " %.6f\n", (double)bst_histogram_sum(id) / 1e6);
	put(b, "%s_count", ci->name);
	put_labels(b, ci->labels, NULL);
	put(b, " %llu\n", (unsigned long long)total);
}

typedef struct sorted {
	bst_counter_info ci;
	bst_counter_id id;
} sorted;

static int sorted_cmp(const void *a, const void *b)
{
	const sorted *x = a, *y = b;
	int c = strcmp(x->ci.name, y->ci.name);
	return c != 0 ? c : (x->id < y->id ? -1 : x->id > y->id);
}

static void put_upstreams(obuf *b, const bst_config *cfg)
{
	if (cfg == NULL || cfg->global.nupstreams == 0)
		return;
	put_help(b, "bastion_upstream_peers_up", "upstream peers currently taking traffic (not down "
						  "by health checks or passive ejection)", "gauge");
	for (int pass = 0; pass < 2; pass++) {
		if (pass == 1)
			put_help(b, "bastion_upstream_peers", "upstream peers configured or resolved", "gauge");
		for (size_t i = 0; i < cfg->global.nupstreams; i++) {
			const bst_cfg_upstream *u = cfg->global.upstreams[i];
			for (size_t k = 0; k < u->nservers; k++) {
				const bst_up_server *sv = &u->servers[k];
				unsigned up = 0;
				for (size_t p = 0; p < sv->npeers; p++)
					up += bst_peer_up(&u->peers[sv->first_peer + p]);
				char un[LABEL_VALUE_MAX], hn[LABEL_VALUE_MAX], labels[BST_COUNTER_LABELS_MAX];
				bst_metrics_label_value(u->name, un, sizeof un);
				bst_metrics_label_value(sv->host, hn, sizeof hn);
				snprintf(labels, sizeof labels, "upstream=%s,server=%s_%u", un, hn, sv->port);
				put(b, pass == 0 ? "bastion_upstream_peers_up" : "bastion_upstream_peers");
				put_labels(b, labels, NULL);
				put(b, " %u\n", pass == 0 ? up : (unsigned)sv->npeers);
			}
		}
	}
}

static const bst_config *g_render_cfg; /* the helper's config, for the upstream gauges */

char *bst_metrics_render(size_t *len, int64_t conns, int attack)
{
	obuf b = { .cap = 16384 };
	b.p = malloc(b.cap);
	if (b.p == NULL)
		return NULL;
	b.p[0] = '\0';
	size_t n = bst_counter_count();
	sorted *v = calloc(n ? n : 1, sizeof *v);
	if (v == NULL) {
		free(b.p);
		return NULL;
	}
	size_t m = 0;
	for (size_t i = 0; i < n; i++) {
		bst_counter_id id = bst_counter_nth(i);
		if (!bst_counter_info_get(id, &v[m].ci))
			continue;
		v[m++].id = id;
	}
	qsort(v, m, sizeof *v, sorted_cmp);
	for (size_t i = 0; i < m; i++) {
		const bst_counter_info *ci = &v[i].ci;
		if (i == 0 || strcmp(ci->name, v[i - 1].ci.name) != 0)
			put_help(&b, ci->name, ci->help,
				 ci->kind == BST_METRIC_HISTOGRAM ? "histogram"
				 : ci->kind == BST_METRIC_GAUGE	  ? "gauge"
								  : "counter");
		if (ci->kind == BST_METRIC_HISTOGRAM) {
			put_histogram(&b, v[i].id, ci);
			continue;
		}
		put(&b, "%s", ci->name);
		put_labels(&b, ci->labels, NULL);
		if (ci->kind == BST_METRIC_GAUGE)
			put(&b, " %lld\n", (long long)bst_gauge_get(v[i].id));
		else
			put(&b, " %llu\n", (unsigned long long)bst_counter_get(v[i].id));
	}
	free(v);
	if (conns >= 0) {
		put_help(&b, "bastion_connections", "client connections open in the workers", "gauge");
		put(&b, "bastion_connections %lld\n", (long long)conns);
	}
	if (attack >= 0) {
		put_help(&b, "bastion_under_attack",
			 "1 while challenge auto considers the server under attack, else 0", "gauge");
		put(&b, "bastion_under_attack %d\n", attack);
	}
	put_upstreams(&b, g_render_cfg);
	if (b.oom) {
		free(b.p);
		return NULL;
	}
	*len = b.len;
	return b.p;
}

/* ---- helper: the scrape endpoint ---- */

#define MAX_CONNS 16
#define REQ_MAX 8192
#define CONN_TIMEOUT_MS 10000

typedef struct mconn {
	bst_sock *sock;
	bst_timer timer;
	bst_ip peer;
	char req[REQ_MAX];
	size_t rlen;
	char *out;
	size_t olen, off;
	bool used;
} mconn;

static struct {
	bst_loop *loop;
	const bst_runtime *rt;
	bst_sock *lsock;
	mconn conns[MAX_CONNS];
	uint8_t good_auth[SHA256_DIGEST_LENGTH]; /* the last Authorization value that passed */
	bool have_good;
	bool exit_when_idle;
} H;

static void conn_close(mconn *c)
{
	if (!c->used)
		return;
	bst_timer_cancel(&c->timer);
	bst_sock_close(c->sock);
	free(c->out);
	c->out = NULL;
	c->used = false;
	if (H.exit_when_idle && bst_metrics_helper_idle())
		_exit(0); /* the helper was told to stop and only waited for these scrapes */
}

bool bst_metrics_helper_idle(void)
{
	for (size_t i = 0; i < MAX_CONNS; i++)
		if (H.conns[i].used)
			return false;
	return true;
}

void bst_metrics_helper_exit_when_idle(void)
{
	H.exit_when_idle = true;
}

static void on_timeout(void *ud)
{
	conn_close(ud);
}

static void on_write(void *ud, uint32_t events, int err);

static void flush_out(mconn *c)
{
	int fd = bst_sock_fd(c->sock);
	while (c->off < c->olen) {
		ssize_t w = write(fd, c->out + c->off, c->olen - c->off);
		if (w > 0) {
			c->off += (size_t)w;
			continue;
		}
		if (w < 0 && errno == EINTR)
			continue;
		if (w < 0 && errno == EAGAIN) {
			if (bst_io_poll(c->sock, POLLOUT, on_write, c) != 0)
				conn_close(c);
			return;
		}
		conn_close(c); /* the scraper went away */
		return;
	}
	conn_close(c);
}

static void on_write(void *ud, uint32_t events, int err)
{
	(void)events;
	mconn *c = ud;
	if (err != 0) {
		conn_close(c);
		return;
	}
	flush_out(c);
}

static void respond(mconn *c, int status, const char *reason, const char *extra, const char *body,
		    size_t blen, bool head)
{
	char hdr[512];
	int hn = snprintf(hdr, sizeof hdr,
			  "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\n%s"
			  "Cache-Control: no-store\r\nConnection: close\r\n\r\n",
			  status, reason,
			  status == 200 ? "text/plain; version=0.0.4; charset=utf-8" : "text/plain",
			  blen, extra != NULL ? extra : "");
	size_t total = (size_t)hn + (head ? 0 : blen);
	c->out = malloc(total);
	if (c->out == NULL) {
		conn_close(c);
		return;
	}
	memcpy(c->out, hdr, (size_t)hn);
	if (!head)
		memcpy(c->out + hn, body, blen);
	c->olen = total;
	c->off = 0;
	flush_out(c);
}

static void respond_text(mconn *c, int status, const char *reason, const char *extra)
{
	char body[64];
	int n = snprintf(body, sizeof body, "%d %s\n", status, reason);
	respond(c, status, reason, extra, body, (size_t)n, false);
}

static bool peer_allowed(const bst_ip *ip)
{
	const bst_cfg_metrics *m = g_mcfg;
	if (m->nallow == 0)
		return true;
	bst_ip a = bst_ip_canon(ip);
	for (size_t i = 0; i < m->nallow; i++) {
		const bst_cidr *x = &m->allow[i];
		if (x->ip.family != a.family)
			continue;
		unsigned bits = x->prefix, full = bits / 8, rest = bits % 8;
		if (memcmp(a.b, x->ip.b, full) != 0)
			continue;
		if (rest != 0) {
			uint8_t mask = (uint8_t)(0xffu << (8 - rest));
			if ((a.b[full] & mask) != (x->ip.b[full] & mask))
				continue;
		}
		return true;
	}
	return false;
}

/* The value of header name (lower-case) in the head, or a zero-length string. */
static bst_str header_value(const char *head, size_t n, const char *name)
{
	size_t nl = strlen(name);
	const char *p = memchr(head, '\n', n);
	while (p != NULL && (size_t)(p + 1 - head) < n) {
		const char *line = p + 1, *end = memchr(line, '\n', n - (size_t)(line - head));
		if (end == NULL)
			break;
		if ((size_t)(end - line) > nl && line[nl] == ':' && strncasecmp(line, name, nl) == 0) {
			const char *v = line + nl + 1, *ve = end;
			while (v < ve && (*v == ' ' || *v == '\t'))
				v++;
			while (ve > v && (ve[-1] == '\r' || ve[-1] == ' ' || ve[-1] == '\t'))
				ve--;
			return (bst_str){ v, (uint32_t)(ve - v) };
		}
		p = end;
	}
	return (bst_str){ "", 0 };
}

static bool authorized(const char *head, size_t n)
{
	if (g_users == NULL)
		return true;
	bst_str v = header_value(head, n, "authorization");
	if (v.len == 0 || v.len > 1024)
		return false;
	uint8_t dg[SHA256_DIGEST_LENGTH];
	SHA256((const unsigned char *)v.p, v.len, dg);
	if (H.have_good && CRYPTO_memcmp(dg, H.good_auth, sizeof dg) == 0)
		return true; /* the same credentials as the last scrape: no new hash */
	char buf[1100];
	bst_str user, pass;
	bool ok = bst_basic_decode(v, buf, sizeof buf, &user, &pass) == 0 &&
		  bst_basic_users_check(g_users, user, pass);
	OPENSSL_cleanse(buf, sizeof buf);
	if (ok) {
		memcpy(H.good_auth, dg, sizeof dg);
		H.have_good = true;
	}
	return ok;
}

static void handle(mconn *c)
{
	char *head = c->req;
	size_t n = c->rlen;
	if (!peer_allowed(&c->peer)) { /* answered once the request is read: no reset */
		respond_text(c, 403, "Forbidden", NULL);
		return;
	}
	const char *sp1 = memchr(head, ' ', n);
	if (sp1 == NULL) {
		respond_text(c, 400, "Bad Request", NULL);
		return;
	}
	bool get = (size_t)(sp1 - head) == 3 && memcmp(head, "GET", 3) == 0;
	bool hd = (size_t)(sp1 - head) == 4 && memcmp(head, "HEAD", 4) == 0;
	const char *target = sp1 + 1, *sp2 = memchr(target, ' ', n - (size_t)(target - head));
	if (sp2 == NULL) {
		respond_text(c, 400, "Bad Request", NULL);
		return;
	}
	size_t tlen = (size_t)(sp2 - target);
	const char *q = memchr(target, '?', tlen);
	if (q != NULL)
		tlen = (size_t)(q - target);
	if (!get && !hd) {
		respond_text(c, 405, "Method Not Allowed", "Allow: GET, HEAD\r\n");
		return;
	}
	if (tlen != strlen(g_mcfg->path) || memcmp(target, g_mcfg->path, tlen) != 0) {
		respond_text(c, 404, "Not Found", NULL);
		return;
	}
	if (!authorized(head, n)) {
		respond_text(c, 401, "Unauthorized", "WWW-Authenticate: Basic realm=\"metrics\"\r\n");
		return;
	}
	int64_t conns = 0;
	if (H.rt->stats != NULL)
		for (int i = 0; i < H.rt->nworkers; i++)
			conns += (int64_t)atomic_load_explicit(&H.rt->stats[i].conns, memory_order_relaxed);
	size_t blen = 0;
	char *body = bst_metrics_render(&blen, H.rt->stats != NULL ? conns : -1, bst_sec_under_attack());
	if (body == NULL) {
		respond_text(c, 503, "Service Unavailable", NULL);
		return;
	}
	respond(c, 200, "OK", NULL, body, blen, hd);
	free(body);
}

static void on_read(void *ud, uint32_t events, int err)
{
	(void)events;
	mconn *c = ud;
	if (err != 0) {
		conn_close(c);
		return;
	}
	int fd = bst_sock_fd(c->sock);
	for (;;) {
		if (c->rlen == sizeof c->req) {
			respond_text(c, 431, "Request Header Fields Too Large", NULL);
			return;
		}
		ssize_t r = read(fd, c->req + c->rlen, sizeof c->req - c->rlen);
		if (r > 0) {
			c->rlen += (size_t)r;
			if (memmem(c->req, c->rlen, "\r\n\r\n", 4) != NULL ||
			    memmem(c->req, c->rlen, "\n\n", 2) != NULL) {
				handle(c);
				return;
			}
			continue;
		}
		if (r < 0 && errno == EINTR)
			continue;
		if (r < 0 && errno == EAGAIN) {
			if (bst_io_poll(c->sock, POLLIN | POLLRDHUP, on_read, c) != 0)
				conn_close(c);
			return;
		}
		conn_close(c); /* EOF or an error before a whole head */
		return;
	}
}

static void on_accept(void *ud, uint32_t events, int err)
{
	(void)ud, (void)events, (void)err;
	for (;;) {
		struct sockaddr_storage ss;
		socklen_t sl = sizeof ss;
		int fd = accept4(g_listen_fd, (struct sockaddr *)&ss, &sl, SOCK_NONBLOCK | SOCK_CLOEXEC);
		if (fd < 0) {
			if (errno == EINTR || errno == ECONNABORTED)
				continue;
			if (errno != EAGAIN)
				bst_log(BST_LOG_WARN, "metrics: accept: %s", strerror(errno));
			break;
		}
		mconn *c = NULL;
		for (size_t i = 0; i < MAX_CONNS && c == NULL; i++)
			if (!H.conns[i].used)
				c = &H.conns[i];
		bst_ip ip;
		memset(&ip, 0, sizeof ip);
		if (ss.ss_family == AF_INET) {
			ip.family = BST_IP_V4;
			memcpy(ip.b, &((struct sockaddr_in *)&ss)->sin_addr, 4);
		} else {
			ip.family = BST_IP_V6;
			memcpy(ip.b, &((struct sockaddr_in6 *)&ss)->sin6_addr, 16);
		}
		if (c == NULL) { /* scrapes are few: a crowd is turned away */
			close(fd);
			continue;
		}
		memset(c, 0, sizeof *c);
		c->sock = bst_sock_wrap(H.loop, fd);
		if (c->sock == NULL) {
			close(fd);
			continue;
		}
		c->used = true;
		c->peer = ip;
		bst_timer_init(&c->timer);
		bst_loop_timer_arm(H.loop, &c->timer, CONN_TIMEOUT_MS, on_timeout, c);
		if (bst_io_poll(c->sock, POLLIN | POLLRDHUP, on_read, c) != 0)
			conn_close(c);
	}
	if (H.lsock != NULL && bst_io_poll(H.lsock, POLLIN, on_accept, NULL) != 0)
		bst_log(BST_LOG_ERROR, "metrics: cannot wait for scrapes");
}

void bst_metrics_helper_start(bst_loop *l, const bst_runtime *rt)
{
	g_render_cfg = rt->cfg;
	if (g_listen_fd < 0 || g_mcfg == NULL)
		return;
	H.loop = l;
	H.rt = rt;
	H.lsock = bst_sock_wrap_borrowed(l, g_listen_fd);
	if (H.lsock == NULL || bst_io_poll(H.lsock, POLLIN, on_accept, NULL) != 0)
		bst_log(BST_LOG_ERROR, "metrics: cannot serve scrapes: %s", strerror(errno));
}

void bst_metrics_helper_stop(void)
{
	/* The socket itself lives on in the next generation (handed over across exec), so closing
	 * our reference loses nothing queued on it. */
	if (H.lsock != NULL) {
		bst_sock_close(H.lsock);
		H.lsock = NULL;
	}
	if (g_listen_fd >= 0) {
		close(g_listen_fd);
		g_listen_fd = -1;
	}
}
