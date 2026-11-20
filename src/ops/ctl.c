/* See ctl.h. */
#include "ops/ctl.h"

#include "config/compile.h"
#include "config/parser.h"
#include "config/template.h"
#include "core/arena.h"
#include "core/json.h"
#include "ops/admin.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static const char usage_text[] =
	"usage: bastionctl upgrade (-p pidfile | -c config) [--timeout s] [--settle s]\n"
	"                          [--check host:port]\n"
	"\n"
	"  upgrade   live binary upgrade: start the binary now installed at master's path beside\n"
	"            the running master, drain the old workers, then stop the old master.\n"
	"            Rolls back by itself when the new master fails or --check fails.\n"
	"  -p file   the master's PID file\n"
	"  -c file   its configuration (for the `pid` directive)\n"
	"  --timeout seconds to wait for each step (default 60)\n"
	"  --settle  seconds the new master must keep running after the old workers drain\n"
	"            (default 1)\n"
	"  --check   a TCP address that must accept a connection before and after the drain\n"
	"\n"
	"\n"
	"       bastionctl [-s socket | -c config] [--json] status | reload | upgrade\n"
	"       bastionctl [-s socket | -c config] [--json] blocks\n"
	"       bastionctl [-s socket | -c config] [--json] block <addr[/prefix]> [--ttl s]\n"
	"       bastionctl [-s socket | -c config] [--json] unblock <addr[/prefix]>\n"
	"       bastionctl [-s socket | -c config] [--json] config\n"
	"       bastionctl [-s socket | -c config] [--json] upstreams [name]\n"
	"       bastionctl [-s socket | -c config] [--json] upstream drain|enable <name> <peer>\n"
	"       bastionctl [-s socket | -c config] [--json] purge --tag t | --host h | --all\n"
	"                                                  [--store name]\n"
	"       bastionctl [-s socket | -c config] [--json] maintenance on|off [--server name]\n"
	"       bastionctl [-s socket | -c config] [--json] challenge on|off|auto\n"
	"\n"
	"  These talk to the admin API (`admin {}`) over its Unix socket (default\n"
	"  " BST_ADMIN_DEFAULT_SOCKET ", or the one -c's configuration names). `upgrade` without\n"
	"  -p asks master to start the upgrade and returns at once. Runtime changes are not\n"
	"  written to the configuration: blocks last their TTL (default 3600 s, at most a day),\n"
	"  also across a reload; drains, maintenance and challenge overrides last until the next\n"
	"  reload. <peer> is a server's index or host:port as `upstreams` lists it.\n"
	"  --json prints the API's answer as it came.\n"
	"\n"
	"exit status: 0 done, 1 failed (old master kept or restored; refused by the API; the\n"
	"admin socket unreachable), 2 usage error\n";

static uint64_t mono_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static void nap(void)
{
	struct timespec ts = {.tv_nsec = 50 * 1000000L};
	nanosleep(&ts, NULL);
}

/* The PID in path: > 0, 0 for an empty file (a new master not ready yet), -1 for none. */
static long read_pid(const char *path)
{
	char buf[32];
	int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return -1;
	ssize_t n = read(fd, buf, sizeof buf - 1);
	close(fd);
	if (n < 0)
		return -1;
	buf[n] = 0;
	if (n == 0)
		return 0;
	char *end;
	errno = 0;
	long v = strtol(buf, &end, 10);
	if (errno != 0 || end == buf || (*end != '\n' && *end != 0) || v <= 1 || v > INT_MAX)
		return -1;
	return v;
}

/* Alive and not a zombie. */
static bool alive(long pid)
{
	if (pid <= 0 || kill((pid_t)pid, 0) != 0)
		return errno == EPERM && pid > 0;
	char path[64], buf[512];
	snprintf(path, sizeof path, "/proc/%ld/stat", pid);
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return true;
	ssize_t n = read(fd, buf, sizeof buf - 1);
	close(fd);
	if (n <= 0)
		return true;
	buf[n] = 0;
	const char *rp = strrchr(buf, ')');
	return rp == NULL || rp[1] != ' ' || rp[2] != 'Z';
}

static bool check_tcp(const char *hostport, char *why, size_t cap)
{
	char host[256];
	snprintf(host, sizeof host, "%s", hostport);
	char *colon = strrchr(host, ':');
	if (colon == NULL) {
		snprintf(why, cap, "--check %s: want host:port", hostport);
		return false;
	}
	*colon = 0;
	const char *port = colon + 1, *h = host;
	size_t hl = strlen(host);
	if (hl >= 2 && host[0] == '[' && host[hl - 1] == ']') { /* [v6]:port */
		host[hl - 1] = 0;
		h = host + 1;
	}
	struct addrinfo hints = {.ai_socktype = SOCK_STREAM, .ai_flags = AI_NUMERICSERV};
	struct addrinfo *res = NULL;
	int rc = getaddrinfo(h, port, &hints, &res);
	if (rc != 0) {
		snprintf(why, cap, "--check %s: %s", hostport, gai_strerror(rc));
		return false;
	}
	bool ok = false;
	for (struct addrinfo *a = res; a != NULL && !ok; a = a->ai_next) {
		int fd = socket(a->ai_family, a->ai_socktype | SOCK_CLOEXEC | SOCK_NONBLOCK, a->ai_protocol);
		if (fd < 0)
			continue;
		if (connect(fd, a->ai_addr, a->ai_addrlen) == 0) {
			ok = true;
		} else if (errno == EINPROGRESS) {
			struct pollfd pf = {.fd = fd, .events = POLLOUT};
			int err = 0;
			socklen_t el = sizeof err;
			ok = poll(&pf, 1, 2000) == 1 && getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) == 0 &&
			     err == 0;
		}
		close(fd);
	}
	freeaddrinfo(res);
	if (!ok)
		snprintf(why, cap, "--check %s: no connection", hostport);
	return ok;
}

typedef struct upgrade_opts {
	const char *pidfile;
	const char *check;
	unsigned timeout_s, settle_s;
} upgrade_opts;

static int rollback(long old, long neu, const char *why)
{
	fprintf(stderr, "bastionctl: upgrade failed: %s\n", why);
	if (kill((pid_t)old, SIGHUP) != 0) {
		fprintf(stderr, "bastionctl: cannot signal the old master %ld: %s\n", old, strerror(errno));
		return 1;
	}
	uint64_t deadline = mono_ms() + 30000;
	while (neu > 0 && alive(neu) && mono_ms() < deadline)
		nap();
	fprintf(stderr, "bastionctl: rolled back: master pid %ld keeps serving\n", old);
	return 1;
}

static int upgrade(const upgrade_opts *o)
{
	char oldbin[PATH_MAX], why[512];
	if (snprintf(oldbin, sizeof oldbin, "%s.oldbin", o->pidfile) >= (int)sizeof oldbin) {
		fprintf(stderr, "bastionctl: %s: path too long\n", o->pidfile);
		return 1;
	}
	long old = read_pid(o->pidfile);
	if (old <= 0 || !alive(old)) {
		fprintf(stderr, "bastionctl: %s names no running master\n", o->pidfile);
		return 1;
	}
	if (read_pid(oldbin) > 0 && alive(read_pid(oldbin))) {
		fprintf(stderr, "bastionctl: an upgrade is already in progress (%s)\n", oldbin);
		return 1;
	}
	if (kill((pid_t)old, SIGUSR2) != 0) {
		fprintf(stderr, "bastionctl: cannot signal master %ld: %s\n", old, strerror(errno));
		return 1;
	}
	uint64_t step = (uint64_t)o->timeout_s * 1000u;
	/* 1. The binary passed its checks and the new master was started. */
	uint64_t deadline = mono_ms() + step;
	while (read_pid(oldbin) != old) {
		if (!alive(old)) {
			fprintf(stderr, "bastionctl: master %ld exited\n", old);
			return 1;
		}
		if (mono_ms() >= deadline) {
			fprintf(stderr, "bastionctl: upgrade refused or not started by master %ld: see its "
					"error log\n", old);
			return 1;
		}
		nap();
	}
	/* 2. The new master names itself in the PID file once every worker is ready. */
	long neu = -1;
	deadline = mono_ms() + step;
	for (;;) {
		long p = read_pid(o->pidfile);
		if (p > 0 && p != old && alive(p)) {
			neu = p;
			break;
		}
		if (read_pid(oldbin) != old) { /* moved back: the new master failed */
			fprintf(stderr, "bastionctl: the new master failed to start; master %ld keeps "
					"serving: see its error log\n", old);
			return 1;
		}
		if (mono_ms() >= deadline)
			return rollback(old, p > 0 && p != old ? p : 0, "the new master did not become ready");
		nap();
	}
	if (o->check != NULL && !check_tcp(o->check, why, sizeof why))
		return rollback(old, neu, why);
	/* 3. The old workers drain; the new master must hold on its own. */
	if (kill((pid_t)old, SIGWINCH) != 0)
		return rollback(old, neu, "cannot send WINCH to the old master");
	deadline = mono_ms() + (uint64_t)o->settle_s * 1000u;
	while (mono_ms() < deadline) {
		if (!alive(neu))
			return rollback(old, 0, "the new master exited");
		nap();
	}
	if (o->check != NULL && !check_tcp(o->check, why, sizeof why))
		return rollback(old, neu, why);
	if (!alive(neu))
		return rollback(old, 0, "the new master exited");
	/* 4. Commit. */
	if (kill((pid_t)old, SIGQUIT) != 0) {
		fprintf(stderr, "bastionctl: cannot send QUIT to the old master %ld: %s\n", old,
			strerror(errno));
		return 1;
	}
	deadline = mono_ms() + step;
	while (alive(old) && mono_ms() < deadline)
		nap();
	if (alive(old))
		fprintf(stderr, "bastionctl: the old master %ld is still draining\n", old);
	printf("upgraded: master pid %ld -> %ld\n", old, neu);
	return 0;
}

/* The `pid` directive of a configuration file. A malloc'd path, or NULL (reported). */
static char *pid_of_config(const char *path)
{
	bst_err e = {.msg = ""};
	bst_arena *a = bst_arena_new((size_t)64 << 10);
	if (a == NULL) {
		fprintf(stderr, "bastionctl: out of memory\n");
		return NULL;
	}
	bst_cfg_opts popts = {.known_var = bst_tpl_var_known};
	bst_ast *ast = bst_cfg_parse_file_opts(path, &popts, a, &e);
	bst_config *cfg = ast ? bst_cfg_compile(ast, &e) : NULL;
	char *out = NULL;
	if (cfg == NULL)
		fprintf(stderr, "bastionctl: %s: %s\n", path, e.msg);
	else if (cfg->global.pid == NULL)
		fprintf(stderr, "bastionctl: %s has no `pid` directive: use -p\n", path);
	else if ((out = strdup(cfg->global.pid)) == NULL)
		fprintf(stderr, "bastionctl: out of memory\n");
	bst_config_free(cfg);
	bst_arena_free(a);
	return out;
}

static bool seconds(const char *s, unsigned *out)
{
	char *end;
	errno = 0;
	unsigned long v = s ? strtoul(s, &end, 10) : 0;
	if (s == NULL || errno != 0 || end == s || *end != 0 || v > 86400)
		return false;
	*out = (unsigned)v;
	return true;
}

static int usage_err(const char *msg, const char *arg)
{
	fprintf(stderr, "bastionctl: %s%s\n%s", msg, arg ? arg : "", usage_text);
	return 2;
}

/* ---- the admin API client ---- */

/* The admin socket of a configuration file. A malloc'd path, or NULL (reported). */
static char *socket_of_config(const char *path)
{
	bst_err e = {.msg = ""};
	bst_arena *a = bst_arena_new((size_t)64 << 10);
	if (a == NULL) {
		fprintf(stderr, "bastionctl: out of memory\n");
		return NULL;
	}
	bst_cfg_opts popts = {.known_var = bst_tpl_var_known};
	bst_ast *ast = bst_cfg_parse_file_opts(path, &popts, a, &e);
	bst_config *cfg = ast ? bst_cfg_compile(ast, &e) : NULL;
	char *out = NULL;
	if (cfg == NULL)
		fprintf(stderr, "bastionctl: %s: %s\n", path, e.msg);
	else if (cfg->global.admin == NULL)
		fprintf(stderr, "bastionctl: %s has no `admin {}` block: the admin API is off\n", path);
	else if ((out = strdup(cfg->global.admin->socket)) == NULL)
		fprintf(stderr, "bastionctl: out of memory\n");
	bst_config_free(cfg);
	bst_arena_free(a);
	return out;
}

#define RESP_MAX (BST_ADMIN_BODY_MAX + 4096)

/* One request over the socket. The status code (body in *out, malloc'd and NUL-terminated), or
 * -1 when the API cannot be reached (reported). */
static int api_call(const char *sock, const char *method, const char *path, const char *body,
		    char **out)
{
	struct sockaddr_un sa = {.sun_family = AF_UNIX};
	if (strlen(sock) >= sizeof sa.sun_path) {
		fprintf(stderr, "bastionctl: socket path too long: %s\n", sock);
		return -1;
	}
	snprintf(sa.sun_path, sizeof sa.sun_path, "%s", sock);
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0 || connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
		int err = errno;
		fprintf(stderr, "bastionctl: cannot reach the admin API at %s: %s (is bastion running "
				"with `admin {}`, and may this user open the socket?)\n", sock, strerror(err));
		if (fd >= 0)
			close(fd);
		return -1;
	}
	size_t blen = body ? strlen(body) : 0;
	char head[512];
	int hn = snprintf(head, sizeof head,
			  "%s %s HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n"
			  "Content-Length: %zu\r\nConnection: close\r\n\r\n", method, path, blen);
	char *buf = malloc(RESP_MAX + 1);
	size_t n = 0;
	bool ok = buf != NULL && write(fd, head, (size_t)hn) == hn &&
		  (blen == 0 || write(fd, body, blen) == (ssize_t)blen);
	struct pollfd p = {.fd = fd, .events = POLLIN};
	while (ok && n < RESP_MAX) {
		if (poll(&p, 1, 70000) != 1) { /* longer than a reload's validation */
			ok = false;
			break;
		}
		ssize_t r = read(fd, buf + n, RESP_MAX - n);
		if (r < 0 && errno == EINTR)
			continue;
		if (r <= 0)
			break;
		n += (size_t)r;
	}
	close(fd);
	int status = -1;
	char *eoh = ok && n > 12 ? memmem(buf, n, "\r\n\r\n", 4) : NULL;
	if (eoh != NULL && strncmp(buf, "HTTP/1.1 ", 9) == 0)
		status = atoi(buf + 9);
	if (status < 100) {
		fprintf(stderr, "bastionctl: no answer from the admin API at %s (helper down?)\n", sock);
		free(buf);
		return -1;
	}
	buf[n] = '\0';
	size_t off = (size_t)(eoh + 4 - buf);
	memmove(buf, buf + off, n - off + 1);
	*out = buf;
	return status;
}

/* Prints an answer: as it came with --json, else its "status" or "error" (or the whole body). */
static void print_answer(int status, const char *body, bool json)
{
	FILE *f = status >= 200 && status < 300 ? stdout : stderr;
	if (json) {
		fprintf(f, "%s\n", body);
		return;
	}
	bst_arena *a = bst_arena_new(16u << 10);
	bst_err e = {.msg = ""};
	const bst_json *j = a ? bst_json_parse(a, body, strlen(body), &e) : NULL;
	bst_str s;
	const bst_json *m = j ? bst_json_get(j, f == stdout ? "status" : "error") : NULL;
	if (m != NULL && bst_json_str(m, &s))
		fprintf(f, "%s%.*s\n", f == stdout ? "" : "bastionctl: ", (int)s.len, s.p);
	else
		fprintf(f, "%s\n", body);
	bst_arena_free(a);
}

/* Appends s percent-encoded (all but unreserved bytes) to out at *o. False when it does not fit. */
static bool pct(const char *s, char *out, size_t *o, size_t cap)
{
	static const char hex[] = "0123456789ABCDEF";
	for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
		bool plain = (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') ||
			     *p == '-' || *p == '.' || *p == '_' || *p == '~' || *p == ':' || *p == '[' || *p == ']';
		if (*o + (plain ? 1 : 3) >= cap)
			return false;
		if (plain) {
			out[(*o)++] = (char)*p;
		} else {
			out[(*o)++] = '%';
			out[(*o)++] = hex[*p >> 4];
			out[(*o)++] = hex[*p & 15];
		}
	}
	out[*o] = 0;
	return true;
}

/* {"k": "v", ...} from n key/value pairs (a NULL key is skipped), plus "flag": true. Escaped by
 * the JSON writer, so an argument can never change the request's shape. */
static bool json_body(char *out, size_t cap, const char *const *kv, int n, const char *flag)
{
	bst_jw w;
	bst_jw_init(&w);
	bst_jw_obj_begin(&w);
	for (int i = 0; i < n; i++) {
		if (kv[2 * i] == NULL)
			continue;
		bst_jw_key(&w, (bst_str){ kv[2 * i], (uint32_t)strlen(kv[2 * i]) });
		bst_jw_str_lossy(&w, (bst_str){ kv[2 * i + 1], (uint32_t)strlen(kv[2 * i + 1]) });
	}
	if (flag != NULL) {
		bst_jw_key(&w, (bst_str){ flag, (uint32_t)strlen(flag) });
		bst_jw_bool(&w, true);
	}
	bst_jw_obj_end(&w);
	bool ok = bst_jw_finish(&w) && w.len < cap;
	if (ok) {
		memcpy(out, w.buf, w.len);
		out[w.len] = 0;
	}
	bst_jw_free(&w);
	return ok;
}

static int api_main(int argc, char **argv)
{
	const char *sock = NULL, *conf = NULL, *cmd = NULL, *ttl = NULL, *pos[3] = { NULL, NULL, NULL };
	const char *tag = NULL, *host = NULL, *store = NULL, *server = NULL;
	bool json = false, all = false;
	int npos = 0;
	for (int i = 1; i < argc; i++) {
		const char *a = argv[i], *v = i + 1 < argc ? argv[i + 1] : NULL;
		if (strcmp(a, "-s") == 0 && v)
			sock = argv[++i];
		else if (strcmp(a, "-c") == 0 && v)
			conf = argv[++i];
		else if (strcmp(a, "--ttl") == 0 && v)
			ttl = argv[++i];
		else if (strcmp(a, "--tag") == 0 && v)
			tag = argv[++i];
		else if (strcmp(a, "--host") == 0 && v)
			host = argv[++i];
		else if (strcmp(a, "--store") == 0 && v)
			store = argv[++i];
		else if (strcmp(a, "--server") == 0 && v)
			server = argv[++i];
		else if (strcmp(a, "--all") == 0)
			all = true;
		else if (strcmp(a, "--json") == 0)
			json = true;
		else if (a[0] == '-')
			return usage_err("unknown or incomplete option ", a);
		else if (cmd == NULL)
			cmd = a;
		else if (npos < 3)
			pos[npos++] = a;
		else
			return usage_err("unexpected argument ", a);
	}
	if (cmd == NULL)
		return usage_err("no command", NULL);
	if (sock != NULL && conf != NULL)
		return usage_err("give at most one of -s and -c", NULL);
	const char *target = pos[0];
	bool needs_target = strcmp(cmd, "block") == 0 || strcmp(cmd, "unblock") == 0;
	int want = needs_target ? 1 : strcmp(cmd, "upstream") == 0 ? 3 : strcmp(cmd, "maintenance") == 0 || strcmp(cmd, "challenge") == 0 ? 1 : strcmp(cmd, "upstreams") == 0 ? (npos > 0 ? 1 : 0) : 0;
	if (npos != want)
		return usage_err(npos < want ? "missing arguments for " : "unexpected arguments for ", cmd);
	if (ttl != NULL && strcmp(cmd, "block") != 0)
		return usage_err("--ttl is for block", NULL);
	if ((tag || host || all || store) && strcmp(cmd, "purge") != 0)
		return usage_err("--tag, --host, --all and --store are for purge", NULL);
	if (server != NULL && strcmp(cmd, "maintenance") != 0)
		return usage_err("--server is for maintenance", NULL);
	unsigned ttl_s = 3600;
	if (ttl != NULL && (!seconds(ttl, &ttl_s) || ttl_s == 0 || ttl_s > 86400))
		return usage_err("--ttl: 1 to 86400 seconds: ", ttl);
	const char *method, *path;
	char body[4096] = "", pbuf[1024];
	if (strcmp(cmd, "config") == 0) {
		method = "GET", path = "/config";
	} else if (strcmp(cmd, "upstreams") == 0) {
		method = "GET", path = "/upstreams";
		if (npos == 1) {
			size_t o = (size_t)snprintf(pbuf, sizeof pbuf, "/upstreams/");
			if (!pct(pos[0], pbuf, &o, sizeof pbuf))
				return usage_err("name too long: ", pos[0]);
			path = pbuf;
		}
	} else if (strcmp(cmd, "upstream") == 0) {
		if (strcmp(pos[0], "drain") != 0 && strcmp(pos[0], "enable") != 0)
			return usage_err("upstream drain|enable <upstream> <peer>, not ", pos[0]);
		size_t o = (size_t)snprintf(pbuf, sizeof pbuf, "/upstreams/");
		if (!pct(pos[1], pbuf, &o, sizeof pbuf) || o + 1 >= sizeof pbuf)
			return usage_err("name too long: ", pos[1]);
		pbuf[o++] = '/';
		if (!pct(pos[2], pbuf, &o, sizeof pbuf) ||
		    o + strlen(pos[0]) + 2 >= sizeof pbuf)
			return usage_err("peer too long: ", pos[2]);
		snprintf(pbuf + o, sizeof pbuf - o, "/%s", pos[0]);
		method = "POST", path = pbuf;
	} else if (strcmp(cmd, "purge") == 0) {
		if ((tag != NULL) + (host != NULL) + all != 1)
			return usage_err("purge needs exactly one of --tag, --host and --all", NULL);
		const char *kv[4] = { tag ? "tag" : host ? "host" : NULL, tag ? tag : host, store ? "store" : NULL, store };
		if (!json_body(body, sizeof body, kv, 2, all ? "all" : NULL))
			return usage_err("arguments too long", NULL);
		method = "POST", path = "/cache/purge";
	} else if (strcmp(cmd, "maintenance") == 0) {
		if (strcmp(target, "on") != 0 && strcmp(target, "off") != 0)
			return usage_err("maintenance on|off, not ", target);
		const char *kv[2] = { server ? "server" : NULL, server };
		if (!json_body(body, sizeof body, kv, 1, NULL))
			return usage_err("arguments too long", NULL);
		/* json_body ends with '}': put "on" in front of it */
		size_t bl = strlen(body);
		snprintf(body + bl - 1, sizeof body - bl + 1, "%s\"on\":%s}", bl > 2 ? "," : "",
			 target[1] == 'n' ? "true" : "false");
		method = "POST", path = "/maintenance";
	} else if (strcmp(cmd, "challenge") == 0) {
		if (strcmp(target, "on") != 0 && strcmp(target, "off") != 0 && strcmp(target, "auto") != 0)
			return usage_err("challenge on|off|auto, not ", target);
		snprintf(body, sizeof body, "{\"mode\":\"%s\"}", target);
		method = "POST", path = "/challenge";
	} else if (strcmp(cmd, "status") == 0) {
		method = "GET", path = "/status";
	} else if (strcmp(cmd, "reload") == 0) {
		method = "POST", path = "/reload";
	} else if (strcmp(cmd, "upgrade") == 0) {
		method = "POST", path = "/upgrade";
	} else if (strcmp(cmd, "blocks") == 0) {
		method = "GET", path = "/blocks";
	} else if (needs_target) {
		for (const char *p = target; *p; p++) /* an address, never JSON */
			if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') ||
			      (*p >= 'A' && *p <= 'F') || *p == '.' || *p == ':' || *p == '/'))
				return usage_err("not an address: ", target);
		if (strlen(target) > 64)
			return usage_err("not an address: ", target);
		method = cmd[0] == 'b' ? "POST" : "DELETE", path = "/blocks";
		if (cmd[0] == 'b')
			snprintf(body, sizeof body, "{\"addr\":\"%s\",\"ttl\":%u}", target, ttl_s);
		else
			snprintf(body, sizeof body, "{\"addr\":\"%s\"}", target);
	} else {
		return usage_err("unknown command ", cmd);
	}
	char *owned = NULL;
	if (conf != NULL && (owned = socket_of_config(conf)) == NULL)
		return 1;
	if (sock == NULL)
		sock = owned != NULL ? owned : BST_ADMIN_DEFAULT_SOCKET;
	char *resp = NULL;
	int st = api_call(sock, method, path, body[0] ? body : NULL, &resp);
	free(owned);
	if (st < 0)
		return 1;
	print_answer(st, resp, json || strcmp(cmd, "status") == 0 || strcmp(cmd, "blocks") == 0 ||
				       strcmp(cmd, "config") == 0 || strcmp(cmd, "upstreams") == 0);
	free(resp);
	return st >= 200 && st < 300 ? 0 : 1;
}

int bst_ctl_main(int argc, char **argv)
{
	if (argc < 2 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
		fputs(usage_text, argc < 2 ? stderr : stdout);
		return argc < 2 ? 2 : 0;
	}
	bool signals = strcmp(argv[1], "upgrade") == 0; /* Task 2's signal-driven upgrade: -p or -c */
	for (int i = 2; signals && i < argc; i++)
		if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--json") == 0)
			signals = false;
	if (signals && argc == 2)
		signals = false; /* bare `bastionctl upgrade`: through the API */
	if (!signals)
		return api_main(argc, argv);
	upgrade_opts o = {.timeout_s = 60, .settle_s = 1};
	const char *conf = NULL;
	for (int i = 2; i < argc; i += 2) { /* every option takes a value */
		const char *a = argv[i], *v = i + 1 < argc ? argv[i + 1] : NULL;
		if (strcmp(a, "-p") == 0 && v) {
			o.pidfile = v;
		} else if (strcmp(a, "-c") == 0 && v) {
			conf = v;
		} else if (strcmp(a, "--check") == 0 && v) {
			o.check = v;
		} else if (strcmp(a, "--timeout") == 0) {
			if (!seconds(v, &o.timeout_s) || o.timeout_s == 0)
				return usage_err("invalid --timeout ", v);
		} else if (strcmp(a, "--settle") == 0) {
			if (!seconds(v, &o.settle_s))
				return usage_err("invalid --settle ", v);
		} else {
			return usage_err("unknown or incomplete option ", a);
		}
	}
	if ((o.pidfile == NULL) == (conf == NULL))
		return usage_err("give exactly one of -p and -c", NULL);
	char *owned = NULL;
	if (conf != NULL) {
		owned = pid_of_config(conf);
		if (owned == NULL)
			return 1;
		o.pidfile = owned;
	}
	int rc = upgrade(&o);
	free(owned);
	return rc;
}
