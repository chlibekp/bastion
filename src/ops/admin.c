/* See admin.h. */
#include "ops/admin.h"

#include "config/compile.h"
#include "config/values.h"
#include "core/addr.h"
#include "core/arena.h"
#include "core/json.h"
#include "core/log.h"
#include "core/shm.h"
#include "core/str.h"
#include "io/sock.h"
#include "proc/channel.h"
#include "proc/runtime.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#define ADMIN_FD_VAR "BASTION_ADMIN_FD" /* the listener, across a reload or upgrade exec */

/* ---- the mailbox: one shared region, created by master before any fork ---- */

typedef struct mailbox {
	_Atomic uint32_t req_seq; /* the helper's last request, published after req */
	bst_admin_req req;
	_Atomic uint32_t resp_seq; /* master's last answer, published after the rest */
	uint32_t status;
	uint32_t len;
	char body[BST_ADMIN_BODY_MAX];
} mailbox;

static mailbox *g_box;
static int g_listen_fd = -1;
static const bst_cfg_admin *g_acfg;
static uid_t g_owner_uid;

/* ---- configuration: admin { socket <path> [mode=0600] [group=name]; } ---- */

static bst_cfg_admin *A(bst_cfg_ctx *c)
{
	return c->global->admin;
}

static int ap_admin(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)d, (void)n;
	bst_cfg_admin *a = bst_arena_alloc(c->arena, sizeof *a);
	if (a == NULL) {
		bst_err_set(e, "out of memory");
		return -1;
	}
	a->socket = BST_ADMIN_DEFAULT_SOCKET;
	a->mode = 0600;
	a->group = NULL;
	c->global->admin = a;
	return 0;
}

static int ap_socket(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *p = bst_dir_pos(d, n, 0);
	if (p->len == 0 || p->text[0] != '/' || p->len >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
		bst_err_set(e, "admin socket: an absolute path shorter than %zu bytes",
			    sizeof(((struct sockaddr_un *)0)->sun_path));
		bst_cfg_err_at(e, &p->loc);
		return -1;
	}
	char *path = bst_cfg_strdup(c, p->text, p->len, e);
	if (path == NULL)
		return -1;
	A(c)->socket = path;
	bst_ast_arg v;
	if (bst_dir_opt(d, n, "mode=", &v)) {
		uint32_t mode = 0;
		(void)bst_parse_mode((bst_str){ v.text, (uint32_t)v.len }, &mode); /* validated */
		if ((mode & 0007) != 0 || (mode & ~0777u) != 0) {
			bst_err_set(e, "admin socket mode=%.*s gives other users access: use 0600 or "
				       "0660 with group=", (int)v.len, v.text);
			bst_cfg_err_at(e, &v.loc);
			return -1;
		}
		A(c)->mode = mode;
	}
	if (bst_dir_opt(d, n, "group=", &v)) {
		A(c)->group = bst_cfg_strdup(c, v.text, v.len, e);
		if (A(c)->group == NULL)
			return -1;
	}
	return 0;
}

static const bst_optspec socket_opts[] = {
	{ .key = "mode=", .type = { .kind = BST_T_MODE } },
	{ .key = "group=", .type = { .kind = BST_T_STRING } },
};

static const bst_directive admin_dirs[] = {
	{ .name = "admin", .contexts = BST_CTX_GLOBAL, .apply = ap_admin, .child_ctx = BST_CTX_ADMIN,
	  .doc = "The local admin API (docs/admin-api.md), off without this block: HTTP/1.1 over a "
		 "Unix socket served by the helper, never a network listener. Access is the "
		 "socket's file mode; write actions are logged with the caller's pid, uid and gid.",
	  .args = { .block = BST_BLOCK_REQUIRED } },
	{ .name = "socket", .contexts = BST_CTX_ADMIN, .apply = ap_socket,
	  .default_value = BST_ADMIN_DEFAULT_SOCKET,
	  .doc = "The socket path, with mode= (default 0600, owner root) and group= (the group "
		 "that may connect with a mode such as 0660). A mode that lets other users in is "
		 "refused.",
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_PATH } },
		    .opts = socket_opts, .nopts = sizeof socket_opts / sizeof socket_opts[0] } },
};
BST_DIRECTIVES(admin_dirs);

/* ---- master ---- */

static bool same_path(int fd, const struct sockaddr_un *want)
{
	struct sockaddr_un cur;
	socklen_t cl = sizeof cur;
	memset(&cur, 0, sizeof cur);
	return getsockname(fd, (struct sockaddr *)&cur, &cl) == 0 && cur.sun_family == AF_UNIX &&
	       strcmp(cur.sun_path, want->sun_path) == 0;
}

/* A socket file left by a stopped server is removed; one a live server answers on is not. */
static int clear_stale(const char *path, bst_err *e)
{
	struct stat st;
	if (lstat(path, &st) != 0)
		return errno == ENOENT ? 0 : (bst_err_set(e, "admin socket %s: %s", path, strerror(errno)), -1);
	if (!S_ISSOCK(st.st_mode)) {
		bst_err_set(e, "admin socket %s: exists and is not a socket", path);
		return -1;
	}
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	struct sockaddr_un sa = { .sun_family = AF_UNIX };
	snprintf(sa.sun_path, sizeof sa.sun_path, "%s", path);
	if (fd >= 0 && connect(fd, (struct sockaddr *)&sa, sizeof sa) == 0) {
		close(fd);
		bst_err_set(e, "admin socket %s: another server is serving it", path);
		return -1;
	}
	if (fd >= 0)
		close(fd);
	if (unlink(path) != 0 && errno != ENOENT) {
		bst_err_set(e, "admin socket %s: %s", path, strerror(errno));
		return -1;
	}
	return 0;
}

static int bind_listener(const bst_cfg_admin *a, bst_err *e)
{
	struct sockaddr_un sa = { .sun_family = AF_UNIX };
	snprintf(sa.sun_path, sizeof sa.sun_path, "%s", a->socket);
	gid_t gid = (gid_t)-1;
	if (a->group != NULL) {
		struct group *g = getgrnam(a->group);
		if (g == NULL) {
			bst_err_set(e, "admin socket group=%s: no such group", a->group);
			return -1;
		}
		gid = g->gr_gid;
	}
	g_owner_uid = geteuid();
	const char *inh = getenv(ADMIN_FD_VAR);
	if (inh != NULL) {
		int ifd = atoi(inh);
		unsetenv(ADMIN_FD_VAR);
		if (ifd > 2 && same_path(ifd, &sa) && fcntl(ifd, F_SETFD, FD_CLOEXEC) == 0) {
			g_listen_fd = ifd;
			/* the mode and group may have changed with the configuration */
			if (chmod(a->socket, (mode_t)a->mode) != 0 ||
			    (gid != (gid_t)-1 && chown(a->socket, (uid_t)-1, gid) != 0))
				bst_log(BST_LOG_WARN, "admin socket %s: %s", a->socket, strerror(errno));
			bst_log(BST_LOG_INFO, "admin: serving on %s (kept)", a->socket);
			return 0;
		}
		if (ifd > 2)
			close(ifd);
	}
	if (clear_stale(a->socket, e) != 0)
		return -1;
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		bst_err_set(e, "admin socket: %s", strerror(errno));
		return -1;
	}
	mode_t old = umask(0177); /* nobody else can connect before the chmod below */
	int rc = bind(fd, (struct sockaddr *)&sa, sizeof sa);
	int err = errno;
	umask(old);
	if (rc != 0 || chmod(a->socket, (mode_t)a->mode) != 0 ||
	    (gid != (gid_t)-1 && chown(a->socket, (uid_t)-1, gid) != 0) || listen(fd, 16) != 0) {
		bst_err_set(e, "admin socket %s: %s", a->socket, strerror(rc != 0 ? err : errno));
		close(fd);
		if (rc == 0)
			(void)unlink(a->socket);
		return -1;
	}
	g_listen_fd = fd;
	bst_log(BST_LOG_INFO, "admin: serving on %s (mode %04o)", a->socket, a->mode);
	return 0;
}

int bst_admin_setup(const bst_config *cfg, bst_err *e)
{
	g_acfg = cfg->global.admin;
	if (g_acfg == NULL) {
		const char *inh = getenv(ADMIN_FD_VAR); /* admin turned off by this reload */
		if (inh != NULL && atoi(inh) > 2)
			close(atoi(inh));
		unsetenv(ADMIN_FD_VAR);
		return 0;
	}
	g_box = bst_shm_create("bastion-admin", sizeof(mailbox), NULL);
	if (g_box == NULL) {
		bst_err_set(e, "admin: shared memory: %s", strerror(errno));
		return -1;
	}
	return bind_listener(g_acfg, e);
}

void bst_admin_before_exec(void)
{
	char v[16];
	if (g_listen_fd < 0 || fcntl(g_listen_fd, F_SETFD, 0) != 0)
		return;
	snprintf(v, sizeof v, "%d", g_listen_fd);
	(void)setenv(ADMIN_FD_VAR, v, 1);
}

void bst_admin_exec_failed(void)
{
	unsetenv(ADMIN_FD_VAR);
	if (g_listen_fd >= 0)
		(void)fcntl(g_listen_fd, F_SETFD, FD_CLOEXEC);
}

void bst_admin_teardown(void)
{
	/* The socket file stays: a live upgrade's other master may be serving it. A later start
	 * removes it once nobody answers on it. */
	if (g_listen_fd >= 0)
		close(g_listen_fd);
	g_listen_fd = -1;
}

bool bst_admin_take(unsigned seq, bst_admin_req *out)
{
	if (g_box == NULL)
		return false;
	if (atomic_load_explicit(&g_box->req_seq, memory_order_acquire) != seq) {
		bst_log(BST_LOG_WARN, "admin: stale request %u from the helper", seq);
		return false;
	}
	memcpy(out, &g_box->req, sizeof *out); /* copied once, then checked: the helper may write */
	bool ok = out->op >= BST_ADMIN_STATUS && out->op < BST_ADMIN_OP_MAX_;
	if (ok && (out->op == BST_ADMIN_BLOCK || out->op == BST_ADMIN_UNBLOCK))
		ok = (out->family == 4 && out->prefix <= 32) || (out->family == 6 && out->prefix <= 128);
	/* within those bounds bst_block_apply judges the request (and answers 400) */
	if (!ok)
		bst_log(BST_LOG_WARN, "admin: malformed request from the helper (op %u)", out->op);
	return ok;
}

void bst_admin_answer(unsigned seq, int status, const char *body, size_t len)
{
	if (g_box == NULL)
		return;
	if (len > BST_ADMIN_BODY_MAX)
		len = BST_ADMIN_BODY_MAX;
	memcpy(g_box->body, body, len);
	g_box->len = (uint32_t)len;
	g_box->status = (uint32_t)status;
	atomic_store_explicit(&g_box->resp_seq, seq, memory_order_release);
}

/* ---- children ---- */

void bst_admin_child_start(int slot)
{
	if (slot >= 0 && g_listen_fd >= 0) {
		close(g_listen_fd);
		g_listen_fd = -1;
	}
}

/* ---- helper: the HTTP side ---- */

#define MAX_CONNS 8
#define REQ_MAX (64u << 10) /* head and body */
#define CONN_TIMEOUT_MS 10000
#define MASTER_TIMEOUT_MS 60000 /* a reload's validation may take 30 s */

typedef struct aconn {
	bst_sock *sock;
	bst_timer timer;
	char req[REQ_MAX];
	size_t rlen;
	char *out;
	size_t olen, off;
	bool used, waiting;
	struct ucred cred;
} aconn;

static struct {
	bst_loop *loop;
	const bst_runtime *rt;
	bst_sock *lsock;
	aconn conns[MAX_CONNS];
	aconn *pending; /* the one waiting for master */
	uint32_t seq;
} H;

static void conn_close(aconn *c)
{
	if (!c->used)
		return;
	if (H.pending == c)
		H.pending = NULL; /* master's late answer is dropped by its sequence */
	bst_timer_cancel(&c->timer);
	bst_sock_close(c->sock);
	free(c->out);
	c->out = NULL;
	c->used = c->waiting = false;
}

bool bst_admin_helper_idle(void)
{
	for (size_t i = 0; i < MAX_CONNS; i++)
		if (H.conns[i].used)
			return false;
	return true;
}

static void on_timeout(void *ud)
{
	conn_close(ud);
}

static void on_write(void *ud, uint32_t events, int err);

static void flush_out(aconn *c)
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
		break; /* the client went away */
	}
	conn_close(c);
}

static void on_write(void *ud, uint32_t events, int err)
{
	(void)events;
	if (err != 0) {
		conn_close(ud);
		return;
	}
	flush_out(ud);
}

static const char *reason(int status)
{
	switch (status) {
	case 200: return "OK";
	case 202: return "Accepted";
	case 400: return "Bad Request";
	case 403: return "Forbidden";
	case 404: return "Not Found";
	case 405: return "Method Not Allowed";
	case 409: return "Conflict";
	case 413: return "Content Too Large";
	case 501: return "Not Implemented";
	case 503: return "Service Unavailable";
	default: return "Internal Server Error";
	}
}

static void respond(aconn *c, int status, const char *body, size_t blen)
{
	char hdr[256];
	int hn = snprintf(hdr, sizeof hdr,
			  "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %zu\r\n"
			  "Cache-Control: no-store\r\nConnection: close\r\n\r\n",
			  status, reason(status), blen);
	c->out = malloc((size_t)hn + blen);
	if (c->out == NULL) {
		conn_close(c);
		return;
	}
	memcpy(c->out, hdr, (size_t)hn);
	memcpy(c->out + hn, body, blen);
	c->olen = (size_t)hn + blen;
	c->off = 0;
	c->waiting = false;
	bst_loop_timer_arm(H.loop, &c->timer, CONN_TIMEOUT_MS, on_timeout, c);
	flush_out(c);
}

/* {"error": msg} */
static void respond_error(aconn *c, int status, const char *msg)
{
	bst_jw w;
	bst_jw_init(&w);
	bst_jw_obj_begin(&w);
	bst_jw_key(&w, BST_S("error"));
	bst_jw_str_lossy(&w, (bst_str){ msg, (uint32_t)strlen(msg) });
	bst_jw_obj_end(&w);
	if (bst_jw_finish(&w))
		respond(c, status, w.buf, w.len);
	else
		respond(c, 500, "{}", 2);
	bst_jw_free(&w);
}

/* "addr" or "addr/prefix" in the body's "addr", optional "ttl" seconds. */
static const char *parse_target(const char *body, size_t blen, bool want_ttl, bst_admin_req *r)
{
	bst_arena *a = bst_arena_new(16u << 10);
	if (a == NULL)
		return "out of memory";
	bst_err e = { .msg = "" };
	const char *why = NULL;
	const bst_json *j = bst_json_parse(a, body, blen, &e);
	const bst_json *ja = j != NULL ? bst_json_get(j, "addr") : NULL;
	bst_str s;
	if (j == NULL || bst_json_typeof(j) != BST_JSON_OBJ)
		why = "the body must be a JSON object";
	else if (ja == NULL || !bst_json_str(ja, &s) || s.len == 0 || s.len > 64)
		why = "\"addr\": an IP address, optionally with /prefix";
	if (why == NULL) {
		const char *slash = memchr(s.p, '/', s.len);
		bst_str host = { s.p, slash ? (uint32_t)(slash - s.p) : s.len };
		bst_ip ip;
		int64_t pfx = -1;
		if (!bst_addr_parse(host, &ip)) {
			why = "\"addr\": not an IP address";
		} else {
			if (slash != NULL &&
			    !bst_parse_int((bst_str){ slash + 1, (uint32_t)(s.len - host.len - 1) }, 0, 128, &pfx))
				why = "\"addr\": bad /prefix";
			r->family = ip.family == BST_IP_V4 ? 4 : 6;
			r->prefix = pfx >= 0 ? (uint32_t)pfx : (ip.family == BST_IP_V4 ? 32u : 128u);
			if (ip.family == BST_IP_V4 && r->prefix > 32)
				why = "\"addr\": bad /prefix";
			memcpy(r->addr, ip.b, 16);
		}
	}
	if (why == NULL && want_ttl) {
		const bst_json *jt = bst_json_get(j, "ttl");
		int64_t ttl = 3600;
		if (jt != NULL && bst_json_int(jt, &ttl) != BST_JSON_INT_OK)
			why = "\"ttl\": whole seconds";
		else if (ttl < 1 || ttl > 86400)
			why = "\"ttl\": 1 to 86400 seconds (a block always expires)";
		r->ttl_us = (uint64_t)ttl * 1000000u;
	}
	bst_arena_free(a);
	return why;
}

static void to_master(aconn *c, const bst_admin_req *r)
{
	if (g_box == NULL) {
		respond_error(c, 503, "the admin mailbox is not available");
		return;
	}
	if (H.pending != NULL) {
		respond_error(c, 503, "another admin request is in progress: retry");
		return;
	}
	H.seq++;
	g_box->req = *r;
	atomic_store_explicit(&g_box->req_seq, H.seq, memory_order_release);
	bst_msg m = { .type = BST_MSG_ADMIN, .admin = { .seq = H.seq } };
	if (bst_chan_send(H.rt->channel, &m) != 0) {
		respond_error(c, 503, "master is not reachable");
		return;
	}
	H.pending = c;
	c->waiting = true;
	bst_loop_timer_arm(H.loop, &c->timer, MASTER_TIMEOUT_MS, on_timeout, c);
}

void bst_admin_helper_done(unsigned seq)
{
	aconn *c = H.pending;
	if (g_box == NULL || c == NULL || seq != H.seq ||
	    atomic_load_explicit(&g_box->resp_seq, memory_order_acquire) != seq)
		return;
	H.pending = NULL;
	uint32_t len = g_box->len, st = g_box->status;
	if (len > BST_ADMIN_BODY_MAX || st < 100 || st > 599) {
		respond_error(c, 500, "master's answer is malformed");
		return;
	}
	respond(c, (int)st, g_box->body, len);
}

static bool route_is(const char *t, size_t tl, const char *want)
{
	return tl == strlen(want) && memcmp(t, want, tl) == 0;
}

/* The request is complete in c->req: head and Content-Length bytes of body. */
static void handle(aconn *c, size_t head_len, size_t blen)
{
	const char *head = c->req, *body = c->req + head_len;
	const char *sp1 = memchr(head, ' ', head_len);
	const char *target = sp1 ? sp1 + 1 : NULL;
	const char *sp2 = target ? memchr(target, ' ', head_len - (size_t)(target - head)) : NULL;
	if (sp2 == NULL) {
		respond_error(c, 400, "not an HTTP request line");
		return;
	}
	size_t ml = (size_t)(sp1 - head), tl = (size_t)(sp2 - target);
	const char *q = memchr(target, '?', tl);
	if (q != NULL)
		tl = (size_t)(q - target);
	bool get = ml == 3 && memcmp(head, "GET", 3) == 0;
	bool post = ml == 4 && memcmp(head, "POST", 4) == 0;
	bool del = ml == 6 && memcmp(head, "DELETE", 6) == 0;
	bst_admin_req r;
	memset(&r, 0, sizeof r);
	r.peer_pid = c->cred.pid;
	r.peer_uid = c->cred.uid;
	r.peer_gid = c->cred.gid;
	if (!get) /* every write action, with who asked */
		bst_log(BST_LOG_INFO, "admin: %.*s %.*s from pid=%ld uid=%lu gid=%lu", (int)ml, head,
			(int)(tl > 64 ? 64 : tl), target, (long)c->cred.pid, (unsigned long)c->cred.uid,
			(unsigned long)c->cred.gid);
	if (route_is(target, tl, "/status")) {
		if (!get)
			return respond_error(c, 405, "GET /status");
		r.op = BST_ADMIN_STATUS;
	} else if (route_is(target, tl, "/reload") || route_is(target, tl, "/upgrade")) {
		if (!post)
			return respond_error(c, 405, "POST only");
		r.op = tl == 7 ? BST_ADMIN_RELOAD : BST_ADMIN_UPGRADE;
	} else if (route_is(target, tl, "/blocks")) {
		if (get) {
			r.op = BST_ADMIN_BLOCKS;
		} else if (post || del) {
			const char *why = parse_target(body, blen, post, &r);
			if (why != NULL)
				return respond_error(c, 400, why);
			r.op = post ? BST_ADMIN_BLOCK : BST_ADMIN_UNBLOCK;
		} else {
			return respond_error(c, 405, "GET, POST or DELETE /blocks");
		}
	} else if (route_is(target, tl, "/config") || route_is(target, tl, "/upstreams") ||
		   (tl > 11 && memcmp(target, "/upstreams/", 11) == 0) ||
		   route_is(target, tl, "/cache/purge") || route_is(target, tl, "/maintenance") ||
		   route_is(target, tl, "/challenge")) {
		return respond_error(c, 501, "not implemented in this version");
	} else {
		return respond_error(c, 404, "no such endpoint");
	}
	to_master(c, &r);
}

/* Content-Length of the head (lower-case match), 0 when absent, -1 when malformed. */
static long content_length(const char *head, size_t n)
{
	static const char name[] = "\ncontent-length:";
	for (size_t i = 0; i + sizeof name - 1 <= n; i++) {
		if (strncasecmp(head + i, name, sizeof name - 1) != 0)
			continue;
		const char *p = head + i + sizeof name - 1, *end = head + n;
		while (p < end && (*p == ' ' || *p == '\t'))
			p++;
		long v = 0;
		const char *start = p;
		while (p < end && *p >= '0' && *p <= '9' && v <= (long)REQ_MAX)
			v = v * 10 + (*p++ - '0');
		return p == start || v > (long)REQ_MAX ? -1 : v;
	}
	return 0;
}

static void on_read(void *ud, uint32_t events, int err)
{
	(void)events;
	aconn *c = ud;
	if (err != 0) {
		conn_close(c);
		return;
	}
	int fd = bst_sock_fd(c->sock);
	for (;;) {
		char *eoh = memmem(c->req, c->rlen, "\r\n\r\n", 4);
		if (eoh != NULL) {
			size_t hl = (size_t)(eoh - c->req) + 4;
			long cl = content_length(c->req, hl);
			if (cl < 0)
				return respond_error(c, 400, "bad Content-Length");
			if (hl + (size_t)cl > sizeof c->req)
				return respond_error(c, 413, "the request is larger than 64 KiB");
			if (c->rlen >= hl + (size_t)cl)
				return handle(c, hl, (size_t)cl);
		} else if (c->rlen == sizeof c->req) {
			return respond_error(c, 413, "the request head is larger than 64 KiB");
		}
		ssize_t r = read(fd, c->req + c->rlen, sizeof c->req - c->rlen);
		if (r > 0) {
			c->rlen += (size_t)r;
			continue;
		}
		if (r < 0 && errno == EINTR)
			continue;
		if (r < 0 && errno == EAGAIN) {
			if (bst_io_poll(c->sock, POLLIN | POLLRDHUP, on_read, c) != 0)
				conn_close(c);
			return;
		}
		conn_close(c); /* EOF or an error before a whole request */
		return;
	}
}

static bool peer_allowed(const struct ucred *u)
{
	if (u->uid == 0 || u->uid == g_owner_uid)
		return true;
	/* with group=, the socket's mode (checked by the kernel at connect) let this peer in */
	return g_acfg != NULL && g_acfg->group != NULL;
}

static void on_accept(void *ud, uint32_t events, int err)
{
	(void)ud, (void)events, (void)err;
	for (;;) {
		int fd = accept4(g_listen_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
		if (fd < 0) {
			if (errno == EINTR || errno == ECONNABORTED)
				continue;
			if (errno != EAGAIN)
				bst_log(BST_LOG_WARN, "admin: accept: %s", strerror(errno));
			break;
		}
		struct ucred u;
		socklen_t ul = sizeof u;
		if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &u, &ul) != 0 || ul != sizeof u) {
			bst_log(BST_LOG_WARN, "admin: SO_PEERCRED: %s: refused", strerror(errno));
			close(fd);
			continue;
		}
		if (!peer_allowed(&u)) {
			bst_log(BST_LOG_WARN, "admin: refused pid=%ld uid=%lu gid=%lu", (long)u.pid,
				(unsigned long)u.uid, (unsigned long)u.gid);
			close(fd);
			continue;
		}
		aconn *c = NULL;
		for (size_t i = 0; i < MAX_CONNS && c == NULL; i++)
			if (!H.conns[i].used)
				c = &H.conns[i];
		if (c == NULL) {
			close(fd);
			continue;
		}
		c->sock = bst_sock_wrap(H.loop, fd);
		if (c->sock == NULL) {
			close(fd);
			continue;
		}
		c->rlen = c->olen = c->off = 0;
		c->out = NULL;
		c->used = true;
		c->waiting = false;
		c->cred = u;
		bst_timer_init(&c->timer);
		bst_loop_timer_arm(H.loop, &c->timer, CONN_TIMEOUT_MS, on_timeout, c);
		if (bst_io_poll(c->sock, POLLIN | POLLRDHUP, on_read, c) != 0)
			conn_close(c);
	}
	if (H.lsock != NULL && bst_io_poll(H.lsock, POLLIN, on_accept, NULL) != 0)
		bst_log(BST_LOG_ERROR, "admin: cannot wait for clients");
}

void bst_admin_helper_start(bst_loop *l, const bst_runtime *rt)
{
	if (g_listen_fd < 0 || g_acfg == NULL)
		return;
	H.loop = l;
	H.rt = rt;
	H.lsock = bst_sock_wrap_borrowed(l, g_listen_fd);
	if (H.lsock == NULL || bst_io_poll(H.lsock, POLLIN, on_accept, NULL) != 0)
		bst_log(BST_LOG_ERROR, "admin: cannot serve: %s", strerror(errno));
}

void bst_admin_helper_stop(void)
{
	if (H.lsock != NULL) {
		bst_sock_close(H.lsock);
		H.lsock = NULL;
	}
	if (g_listen_fd >= 0) {
		close(g_listen_fd);
		g_listen_fd = -1;
	}
}
