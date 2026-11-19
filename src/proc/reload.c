/* Reload by re-executing master in place: see reload.h. */
#include "proc/reload.h"

#include "core/addr.h"
#include "core/log.h"
#include "core/shm.h"
#include "ops/admin.h"
#include "ops/metrics.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define INHERIT_VAR "BASTION_INHERIT"
#define VALIDATE_TIMEOUT_MS 30000

extern char **environ;

static char **g_argv;
static int g_argc;
static char g_status[256] = "none";
static bst_inherit g_inh = {.pid_fd = -1};

/* ---- arguments and status ---- */

void bst_reload_save_argv(int argc, char **argv)
{
	g_argv = calloc((size_t)argc + 2, sizeof *g_argv);
	if (g_argv == NULL)
		return;
	for (int i = 0; i < argc; i++) {
		const char *a = argv[i];
		char *abs = NULL;
		if (i > 0 && strcmp(argv[i - 1], "-c") == 0 && a[0] != '/') {
			char cwd[PATH_MAX];
			if (getcwd(cwd, sizeof cwd) != NULL) {
				size_t n = strlen(cwd) + strlen(a) + 2;
				abs = malloc(n);
				if (abs != NULL)
					snprintf(abs, n, "%s/%s", cwd, a);
			}
		}
		g_argv[i] = abs != NULL ? abs : strdup(a);
		if (g_argv[i] == NULL) {
			g_argv = NULL; /* out of memory at start: reload refused later, leak irrelevant */
			return;
		}
	}
	g_argc = argc;
}

const char *bst_reload_status(void)
{
	return g_status;
}

void bst_reload_set_status(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(g_status, sizeof g_status, fmt, ap);
	va_end(ap);
}

static uint64_t mono_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* ---- validation ---- */

/* One line: newlines become "; ", trailing whitespace dropped. */
static void flatten(char *s)
{
	size_t n = strlen(s);
	while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == ' ' || s[n - 1] == '\r'))
		s[--n] = 0;
	for (size_t i = 0; i < n; i++)
		if (s[i] == '\n' || s[i] == '\r')
			s[i] = ' ';
}

int bst_reload_validate(int exe_fd, char *why, size_t cap)
{
	why[0] = 0;
	if (g_argv == NULL) {
		snprintf(why, cap, "the start arguments were not saved");
		return -1;
	}
	int p[2];
	if (pipe2(p, O_CLOEXEC) != 0) {
		snprintf(why, cap, "pipe: %s", strerror(errno));
		return -1;
	}
	g_argv[g_argc] = "-t";
	g_argv[g_argc + 1] = NULL;
	pid_t pid = fork();
	if (pid == 0) {
		sigset_t none;
		sigemptyset(&none);
		sigprocmask(SIG_SETMASK, &none, NULL);
		dup2(p[1], 1);
		dup2(p[1], 2);
		int dn = open("/dev/null", O_RDONLY | O_CLOEXEC);
		if (dn >= 0)
			dup2(dn, 0);
		/* The child must not think it inherits anything. */
		unsetenv(INHERIT_VAR);
		if (exe_fd >= 0) {
			(void)fcntl(exe_fd, F_SETFD, 0); /* a script's interpreter opens it by /dev/fd */
			fexecve(exe_fd, g_argv, environ);
		} else {
			execv("/proc/self/exe", g_argv);
		}
		_exit(127);
	}
	g_argv[g_argc] = NULL;
	close(p[1]);
	if (pid < 0) {
		close(p[0]);
		snprintf(why, cap, "fork: %s", strerror(errno));
		return -1;
	}
	char out[1024];
	size_t len = 0;
	uint64_t deadline = mono_ms() + VALIDATE_TIMEOUT_MS;
	for (;;) {
		uint64_t now = mono_ms();
		if (now >= deadline) {
			kill(pid, SIGKILL);
			break;
		}
		struct pollfd pf = {.fd = p[0], .events = POLLIN};
		int rc = poll(&pf, 1, (int)(deadline - now));
		if (rc < 0 && errno == EINTR)
			continue;
		if (rc <= 0)
			continue;
		char buf[512];
		ssize_t n = read(p[0], buf, sizeof buf);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			break;
		size_t take = (size_t)n < sizeof out - 1 - len ? (size_t)n : sizeof out - 1 - len;
		memcpy(out + len, buf, take);
		len += take;
	}
	close(p[0]);
	out[len] = 0;
	int st = 0;
	while (waitpid(pid, &st, 0) < 0 && errno == EINTR)
		;
	if (WIFEXITED(st) && WEXITSTATUS(st) == 0)
		return 0;
	flatten(out);
	if (out[0] == 0)
		snprintf(why, cap, "config check %s %d", WIFEXITED(st) ? "exited with status" : "killed by signal",
			 WIFEXITED(st) ? WEXITSTATUS(st) : WTERMSIG(st));
	else
		snprintf(why, cap, "%s", out);
	return -1;
}

/* ---- the hand-over: decoding ---- */

void bst_inherit_key(const bst_cfg_listen *l, char *buf, size_t cap)
{
	char ip[BST_ADDR_STRLEN];
	bst_addr_format(&l->addr.ip, ip, sizeof ip);
	snprintf(buf, cap, "%s %s %u", l->http3 ? "udp" : "tcp", ip, (unsigned)l->addr.port);
}

static bool parse_int(const char *s, const char **end, long lo, long hi, long *out)
{
	char *e;
	errno = 0;
	long v = strtol(s, &e, 10);
	if (e == s || errno != 0 || v < lo || v > hi)
		return false;
	*out = v;
	*end = e;
	return true;
}

/* Every fd named must be open, or the value is not ours. */
static bool fd_ok(long fd)
{
	return fd > 2 && fcntl((int)fd, F_GETFD) >= 0;
}

static bool decode_listener(char *v)
{
	char *bar = strchr(v, '|');
	if (bar == NULL || (size_t)(bar - v) >= sizeof g_inh.listeners[0].key)
		return false;
	bst_inherit_listener *nl = realloc(g_inh.listeners, (g_inh.nlisteners + 1) * sizeof *nl);
	if (nl == NULL)
		return false;
	g_inh.listeners = nl;
	bst_inherit_listener *l = &nl[g_inh.nlisteners];
	memset(l, 0, sizeof *l);
	memcpy(l->key, v, (size_t)(bar - v));
	const char *p = bar + 1;
	long n;
	if (!parse_int(p, &p, 1, 4096, &n) || *p != '|')
		return false;
	l->fds = calloc((size_t)n, sizeof *l->fds);
	if (l->fds == NULL)
		return false;
	l->nslots = (int)n;
	g_inh.nlisteners++;
	p++;
	for (long i = 0; i < n; i++) {
		long fd;
		if (!parse_int(p, &p, 3, INT_MAX, &fd) || !fd_ok(fd))
			return false;
		l->fds[i] = (int)fd;
		if (*p == ',')
			p++;
	}
	return *p == 0;
}

static bool decode_shm(char *v)
{
	char *bar = strchr(v, '|');
	long fd;
	const char *end;
	if (bar == NULL)
		return false;
	*bar = 0;
	if (!parse_int(bar + 1, &end, 3, INT_MAX, &fd) || *end != 0 || !fd_ok(fd))
		return false;
	bst_shm_inherited_add(v, (int)fd);
	return true;
}

static bool decode_child(const char *v)
{
	long pid, chan, slot;
	const char *p = v;
	if (!parse_int(p, &p, 1, INT_MAX, &pid) || *p++ != '|' ||
	    !parse_int(p, &p, -1, INT_MAX, &chan) || *p++ != '|' ||
	    !parse_int(p, &p, -1, 65535, &slot) || *p != 0)
		return false;
	if (g_inh.nolds == BST_RELOAD_MAX_OLD)
		return true; /* the encoder never sends more */
	bst_inherit_child *no = realloc(g_inh.olds, (g_inh.nolds + 1) * sizeof *no);
	if (no == NULL)
		return false;
	g_inh.olds = no;
	no[g_inh.nolds++] = (bst_inherit_child){.pid = (pid_t)pid,
						.chan = chan >= 0 && fd_ok(chan) ? (int)chan : -1,
						.slot = (int)slot};
	return true;
}

static bool decode_route(char *v);

const bst_inherit *bst_inherit_load(void)
{
	const char *raw = getenv(INHERIT_VAR);
	if (raw == NULL)
		return &g_inh;
	/* The format version comes first and is checked before anything else is read: a value of
	 * another version is refused whole, never half understood. */
	long want = BST_INHERIT_VERSION, ver = -1;
#ifdef BST_TEST
	const char *tv = getenv("BST_TEST_INHERIT_VERSION"); /* plays a binary of another format */
	if (tv != NULL)
		want = strtol(tv, NULL, 10);
#endif
	const char *vend = raw;
	size_t rawlen = strnlen(raw, BST_INHERIT_MAX_LEN + 1);
	if (rawlen > BST_INHERIT_MAX_LEN) {
		snprintf(g_inh.why, sizeof g_inh.why, "the handed-over state is too long");
		g_inh.refused = true;
	} else if (strncmp(raw, "v=", 2) != 0 || !parse_int(raw + 2, &vend, 0, INT_MAX, &ver) ||
		   (*vend != ';' && *vend != 0)) {
		snprintf(g_inh.why, sizeof g_inh.why, "the handed-over state has no format version");
		g_inh.refused = true;
	} else if (ver != want) {
		snprintf(g_inh.why, sizeof g_inh.why, "state format version %ld, this binary reads %ld",
			 ver, want);
		g_inh.refused = true;
	}
	if (g_inh.refused) {
		unsetenv(INHERIT_VAR);
		return &g_inh;
	}
	char *s = strdup(*vend == ';' ? vend + 1 : vend);
	unsetenv(INHERIT_VAR); /* children and hooks must not see it */
	if (s == NULL)
		return &g_inh;
	bool ok = true;
	char *save = NULL;
	for (char *tok = strtok_r(s, ";", &save); ok && tok != NULL; tok = strtok_r(NULL, ";", &save)) {
		if (tok[0] == 0 || tok[1] != '=') {
			ok = false;
			break;
		}
		char *v = tok + 2;
		long n;
		const char *end;
		switch (tok[0]) {
		case 'g':
			ok = parse_int(v, &end, 0, INT_MAX, &n) && *end == 0;
			if (ok)
				g_inh.generation = (unsigned)n;
			break;
		case 'p':
			ok = parse_int(v, &end, 3, INT_MAX, &n) && *end == 0 && fd_ok(n);
			if (ok)
				g_inh.pid_fd = (int)n;
			break;
		case 'l':
			ok = decode_listener(v);
			break;
		case 's':
			ok = decode_shm(v);
			break;
		case 'c':
			ok = decode_child(v);
			break;
		case 'r':
			ok = decode_route(v);
			break;
		case 'u':
			ok = parse_int(v, &end, 2, INT_MAX, &n) && *end == 0;
			/* Only our parent: a stale value (it has exited since) names no process of ours. */
			if (ok && (pid_t)n == getppid())
				g_inh.upgrade_parent = (pid_t)n;
			break;
		default:
			ok = false;
		}
	}
	free(s);
	if (!ok) {
		bst_log(BST_LOG_WARN, "reload: %s is malformed: starting fresh", INHERIT_VAR);
		return &g_inh; /* what was decoded is still usable; the rest starts fresh */
	}
	g_inh.present = true;
	/* Every inherited fd goes back to close-on-exec until the next hand-over. */
	if (g_inh.pid_fd >= 0)
		(void)fcntl(g_inh.pid_fd, F_SETFD, FD_CLOEXEC);
	for (size_t i = 0; i < g_inh.nlisteners; i++)
		for (int k = 0; k < g_inh.listeners[i].nslots; k++)
			(void)fcntl(g_inh.listeners[i].fds[k], F_SETFD, FD_CLOEXEC);
	for (size_t i = 0; i < g_inh.nolds; i++)
		if (g_inh.olds[i].chan >= 0)
			(void)fcntl(g_inh.olds[i].chan, F_SETFD, FD_CLOEXEC);
	for (size_t i = 0; i < g_inh.nroutes; i++)
		for (int k = 0; k < 3; k++)
			(void)fcntl(g_inh.routes[i].fd[k], F_SETFD, FD_CLOEXEC);
	return &g_inh;
}

bool bst_inherit_take_listener(const bst_cfg_listen *l, int nslots, int *fds)
{
	if (l->http3)
		return false; /* each generation binds its own: see bst_inherit_old_udp */
	char key[64];
	bst_inherit_key(l, key, sizeof key);
	for (size_t i = 0; i < g_inh.nlisteners; i++) {
		bst_inherit_listener *il = &g_inh.listeners[i];
		if (il->taken || strcmp(il->key, key) != 0 || il->nslots != nslots)
			continue;
		memcpy(fds, il->fds, (size_t)nslots * sizeof *fds);
		il->taken = true;
		return true;
	}
	return false;
}

bool bst_inherit_take_route(const bst_cfg_listen *l, int fds[3])
{
	char key[64];
	bst_inherit_key(l, key, sizeof key);
	for (size_t i = 0; i < g_inh.nroutes; i++) {
		bst_inherit_route *r = &g_inh.routes[i];
		if (r->fd[0] < 0 || strcmp(r->key, key) != 0)
			continue;
		memcpy(fds, r->fd, sizeof r->fd);
		r->fd[0] = r->fd[1] = r->fd[2] = -1; /* the caller owns them now */
		return true;
	}
	return false;
}

static bool decode_route(char *v)
{
	char *bar = strchr(v, '|');
	if (bar == NULL || (size_t)(bar - v) >= sizeof g_inh.routes[0].key)
		return false;
	bst_inherit_route *nr = realloc(g_inh.routes, (g_inh.nroutes + 1) * sizeof *nr);
	if (nr == NULL)
		return false;
	g_inh.routes = nr;
	bst_inherit_route *r = &nr[g_inh.nroutes];
	memset(r, 0, sizeof *r);
	memcpy(r->key, v, (size_t)(bar - v));
	const char *p = bar + 1;
	for (int k = 0; k < 3; k++) {
		long fd;
		if (!parse_int(p, &p, 3, INT_MAX, &fd) || !fd_ok(fd) || *p != (k < 2 ? ',' : 0))
			return false;
		r->fd[k] = (int)fd;
		p++;
	}
	g_inh.nroutes++;
	return true;
}

void bst_inherit_close_untaken(void)
{
	for (size_t i = 0; i < g_inh.nlisteners; i++) {
		bst_inherit_listener *il = &g_inh.listeners[i];
		if (!il->taken) {
			for (int k = 0; k < il->nslots; k++)
				close(il->fds[k]);
			/* A UDP listener is never taken: the draining workers keep their own copies. */
			if (strncmp(il->key, "udp ", 4) != 0)
				bst_log(BST_LOG_INFO, "reload: listener %s closed (%s)", il->key,
					"removed, or its slot count changed");
		}
		free(il->fds);
	}
	free(g_inh.listeners);
	g_inh.listeners = NULL;
	g_inh.nlisteners = 0;
	for (size_t i = 0; i < g_inh.nroutes; i++) /* a QUIC listener that is gone */
		for (int k = 0; k < 3; k++)
			if (g_inh.routes[i].fd[k] >= 0)
				close(g_inh.routes[i].fd[k]);
	free(g_inh.routes);
	g_inh.routes = NULL;
	g_inh.nroutes = 0;
	bst_shm_inherited_close_untaken();
}

/* ---- the hand-over: encoding ---- */

typedef struct sbuf {
	char *p;
	size_t len, cap;
	bool oom;
} sbuf;

static void put(sbuf *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void put(sbuf *b, const char *fmt, ...)
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
		size_t nc = b->cap * 2 + (size_t)n;
		char *np = realloc(b->p, nc);
		if (np == NULL) {
			b->oom = true;
			return;
		}
		b->p = np;
		b->cap = nc;
	}
}

static void inheritable(int fd)
{
	int fl = fcntl(fd, F_GETFD);
	if (fl >= 0)
		(void)fcntl(fd, F_SETFD, fl & ~FD_CLOEXEC);
}

char *bst_inherit_encode(const bst_inherit_out *o)
{
	sbuf b = {.p = malloc(256), .cap = 256};
	if (b.p == NULL)
		return NULL;
	b.p[0] = 0;
	put(&b, "v=%d;g=%u", BST_INHERIT_VERSION, o->generation);
	if (o->upgrade_parent > 0)
		put(&b, ";u=%ld", (long)o->upgrade_parent);
	if (o->pid_fd >= 0) {
		inheritable(o->pid_fd);
		put(&b, ";p=%d", o->pid_fd);
	}
	for (size_t i = 0; i < o->nlisteners; i++) {
		char key[64];
		bst_inherit_key(o->lcfg[i], key, sizeof key);
		put(&b, ";l=%s|%d|", key, o->nslots);
		for (int k = 0; k < o->nslots; k++) {
			inheritable(o->lfds[i][k]);
			put(&b, "%s%d", k ? "," : "", o->lfds[i][k]);
		}
	}
	for (size_t i = 0; i < o->nroutes; i++) {
		const bst_inherit_route *r = &o->routes[i];
		for (int k = 0; k < 3; k++)
			inheritable(r->fd[k]);
		put(&b, ";r=%s|%d,%d,%d", r->key, r->fd[0], r->fd[1], r->fd[2]);
	}
	const char *name;
	int fd;
	for (size_t i = 0; bst_shm_kept_get(i, &name, &fd); i++) {
		inheritable(fd);
		put(&b, ";s=%s|%d", name, fd);
	}
	for (size_t i = 0; i < o->nkids && i < BST_RELOAD_MAX_OLD; i++) {
		const bst_inherit_child *c = &o->kids[i];
		if (c->chan >= 0)
			inheritable(c->chan);
		put(&b, ";c=%ld|%d|%d", (long)c->pid, c->chan, c->slot);
	}
	if (b.oom || b.len > BST_INHERIT_MAX_LEN) {
		free(b.p);
		return NULL;
	}
	return b.p;
}

static void cloexec(int fd)
{
	if (fd >= 0)
		(void)fcntl(fd, F_SETFD, FD_CLOEXEC);
}

void bst_inherit_encoded_cloexec(const bst_inherit_out *o)
{
	cloexec(o->pid_fd);
	for (size_t i = 0; i < o->nlisteners; i++)
		for (int k = 0; k < o->nslots; k++)
			cloexec(o->lfds[i][k]);
	for (size_t i = 0; i < o->nroutes; i++)
		for (int k = 0; k < 3; k++)
			cloexec(o->routes[i].fd[k]);
	const char *name;
	int fd;
	for (size_t i = 0; bst_shm_kept_get(i, &name, &fd); i++)
		cloexec(fd);
	for (size_t i = 0; i < o->nkids; i++)
		cloexec(o->kids[i].chan);
}

int bst_reload_exec(int exe_fd, const char *value)
{
	if (g_argv == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (setenv(INHERIT_VAR, value, 1) != 0)
		return -1;
	bst_metrics_before_exec();
	bst_admin_before_exec();
	g_argv[g_argc] = NULL;
	if (exe_fd >= 0) {
		(void)fcntl(exe_fd, F_SETFD, 0);
		fexecve(exe_fd, g_argv, environ);
	} else {
		execve("/proc/self/exe", g_argv, environ);
	}
	int e = errno;
	bst_metrics_exec_failed();
	bst_admin_exec_failed();
	unsetenv(INHERIT_VAR);
	errno = e;
	return -1;
}
