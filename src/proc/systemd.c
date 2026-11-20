/* See systemd.h. */
#include "proc/systemd.h"

#include "core/log.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int bst_sd_notify(const char *state)
{
	const char *path = getenv("NOTIFY_SOCKET");
	if (path == NULL || path[0] == 0)
		return 0;
	struct sockaddr_un sa = { .sun_family = AF_UNIX };
	size_t len = strlen(path);
	if ((path[0] != '/' && path[0] != '@') || len < 2 || len >= sizeof sa.sun_path) {
		bst_log(BST_LOG_WARN, "sd_notify: NOTIFY_SOCKET is not a usable socket address");
		return -1;
	}
	memcpy(sa.sun_path, path, len);
	if (path[0] == '@')
		sa.sun_path[0] = 0; /* abstract namespace */
	int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		bst_log(BST_LOG_WARN, "sd_notify: socket: %s", strerror(errno));
		return -1;
	}
	socklen_t sl = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + len);
	ssize_t n = sendto(fd, state, strlen(state), MSG_NOSIGNAL, (struct sockaddr *)&sa, sl);
	int e = errno;
	close(fd);
	if (n < 0) {
		bst_log(BST_LOG_WARN, "sd_notify: %s", strerror(e));
		return -1;
	}
	return 0;
}

int bst_sd_notifyf(const char *fmt, ...)
{
	char buf[512];
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(buf, sizeof buf, fmt, ap);
	va_end(ap);
	if (n < 0 || (size_t)n >= sizeof buf) {
		bst_log(BST_LOG_WARN, "sd_notify: message too long");
		return -1;
	}
	return bst_sd_notify(buf);
}

/* A decimal number that is all of s, or false. */
static bool parse_u64(const char *s, uint64_t *out)
{
	if (s == NULL || *s < '0' || *s > '9')
		return false;
	char *end;
	errno = 0;
	unsigned long long v = strtoull(s, &end, 10);
	if (errno != 0 || *end != '\0')
		return false;
	*out = v;
	return true;
}

uint64_t bst_sd_watchdog_usec(void)
{
	uint64_t usec, pid;
	if (!parse_u64(getenv("WATCHDOG_USEC"), &usec) || usec == 0)
		return 0;
	const char *p = getenv("WATCHDOG_PID");
	if (p != NULL && p[0] != '\0') {
		if (!parse_u64(p, &pid))
			return 0;
		/* ours, or our parent's: a live upgrade's new master takes over the old one's pings */
		if (pid != (uint64_t)getpid() && pid != (uint64_t)getppid())
			return 0;
	}
	return usec;
}

/* ---- socket activation ---- */

#define MAX_PASSED 64

static struct {
	bool read;
	int first, n;
	bool taken[MAX_PASSED];
} act;

void bst_sd_listen_adopt_(int first, int n)
{
	if (first < 0) { /* forget: the next call reads the environment */
		memset(&act, 0, sizeof act);
		return;
	}
	act.read = true;
	act.first = first;
	act.n = n < 0 ? 0 : n > MAX_PASSED ? MAX_PASSED : n;
	memset(act.taken, 0, sizeof act.taken);
	for (int i = 0; i < act.n; i++)
		(void)fcntl(first + i, F_SETFD, FD_CLOEXEC); /* never leaked to a hook or a re-exec */
}

int bst_sd_listen_fds(void)
{
	if (act.read)
		return act.n;
	uint64_t pid, n;
	bool mine = parse_u64(getenv("LISTEN_PID"), &pid) && pid == (uint64_t)getpid() &&
		    parse_u64(getenv("LISTEN_FDS"), &n) && n > 0;
	unsetenv("LISTEN_PID");
	unsetenv("LISTEN_FDS");
	unsetenv("LISTEN_FDNAMES");
	if (!mine) {
		act.read = true;
		return 0;
	}
	if (n > MAX_PASSED) {
		bst_log(BST_LOG_WARN, "socket activation: %llu sockets passed, using the first %d",
			(unsigned long long)n, MAX_PASSED);
		n = MAX_PASSED;
	}
	bst_sd_listen_adopt_(BST_SD_LISTEN_FDS_START, (int)n);
	return act.n;
}

static bool same_addr(int fd, const bst_cfg_listen *l)
{
	int type = 0, acc = 0;
	socklen_t tl = sizeof type, al = sizeof acc;
	if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &tl) != 0 || type != SOCK_STREAM ||
	    getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &acc, &al) != 0 || !acc)
		return false;
	struct sockaddr_storage ss;
	socklen_t sl = sizeof ss;
	if (getsockname(fd, (struct sockaddr *)&ss, &sl) != 0)
		return false;
	if (l->addr.ip.family == BST_IP_V6) {
		const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)&ss;
		return ss.ss_family == AF_INET6 && ntohs(s6->sin6_port) == l->addr.port &&
		       memcmp(&s6->sin6_addr, l->addr.ip.b, 16) == 0;
	}
	const struct sockaddr_in *s4 = (const struct sockaddr_in *)&ss;
	return ss.ss_family == AF_INET && ntohs(s4->sin_port) == l->addr.port &&
	       memcmp(&s4->sin_addr, l->addr.ip.b, 4) == 0;
}

bool bst_sd_take_listener(const bst_cfg_listen *l, int slots, int *fds)
{
	if (l->http3 || bst_sd_listen_fds() == 0)
		return false;
	for (int i = 0; i < act.n; i++) {
		int fd = act.first + i;
		if (act.taken[i] || !same_addr(fd, l))
			continue;
		int fl = fcntl(fd, F_GETFL);
		if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) != 0)
			continue;
		int s;
		for (s = 0; s < slots; s++) {
			fds[s] = fcntl(fd, F_DUPFD_CLOEXEC, 0);
			if (fds[s] < 0)
				break;
		}
		if (s < slots) {
			bst_log(BST_LOG_WARN, "socket activation: dup of fd %d: %s", fd, strerror(errno));
			while (s-- > 0)
				close(fds[s]);
			continue;
		}
		act.taken[i] = true;
		close(fd); /* the duplicates carry it from here, through reloads too */
		bst_log(BST_LOG_INFO, "socket activation: listen %u uses the socket systemd passed as fd %d",
			(unsigned)l->addr.port, fd);
		return true;
	}
	return false;
}

void bst_sd_close_untaken(void)
{
	for (int i = 0; i < act.n; i++)
		if (!act.taken[i]) {
			bst_log(BST_LOG_WARN,
				"socket activation: fd %d matches no TCP listen in the configuration: closed",
				act.first + i);
			close(act.first + i);
			act.taken[i] = true;
		}
}
