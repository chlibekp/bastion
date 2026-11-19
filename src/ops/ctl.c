/* See ctl.h. */
#include "ops/ctl.h"

#include "config/compile.h"
#include "config/parser.h"
#include "config/template.h"
#include "core/arena.h"

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
	"exit status: 0 upgraded, 1 failed (old master kept or restored), 2 usage error\n";

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

int bst_ctl_main(int argc, char **argv)
{
	if (argc < 2 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
		fputs(usage_text, argc < 2 ? stderr : stdout);
		return argc < 2 ? 2 : 0;
	}
	if (strcmp(argv[1], "upgrade") != 0)
		return usage_err("unknown command ", argv[1]);
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
