/* Listeners and TCP socket options: creation, failure paths, refused options (warn or
 * fail), and the per-connection options applied after accept. */
#include "config/compile.h"
#include "core/log.h"
#include "io/listener.h"
#include "io/tcp_profile.h"
#include "tap.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

static uint16_t free_port(void)
{
	int s = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	socklen_t len = sizeof a;
	if (s < 0 || bind(s, (struct sockaddr *)&a, sizeof a) != 0 ||
	    getsockname(s, (struct sockaddr *)&a, &len) != 0)
		abort();
	close(s);
	return ntohs(a.sin_port);
}

static bst_cfg_listen v4(uint16_t port, const bst_tcp_profile *p)
{
	bst_cfg_listen l;
	memset(&l, 0, sizeof l);
	l.addr.ip.family = BST_IP_V4;
	l.addr.ip.b[0] = 127;
	l.addr.ip.b[3] = 1;
	l.addr.port = port;
	l.tcp = p;
	return l;
}

static bst_cfg_listen v6any(uint16_t port)
{
	bst_cfg_listen l;
	memset(&l, 0, sizeof l);
	l.addr.ip.family = BST_IP_V6;
	l.addr.port = port;
	return l;
}

static void closeall(int *fds, int n)
{
	for (int i = 0; i < n; i++)
		if (fds[i] >= 0)
			close(fds[i]);
}

static int geti(int fd, int lvl, int opt)
{
	int v = -12345;
	socklen_t len = sizeof v;
	if (getsockopt(fd, lvl, opt, &v, &len) != 0)
		return -12345;
	return v;
}

static bool fd_open(int fd)
{
	return fcntl(fd, F_GETFD) != -1;
}

static void set(bst_tcp_profile *p, bst_tcp_opt o, bool require)
{
	p->set |= 1u << o;
	if (require)
		p->require |= 1u << o;
}

/* ---- log capture ---- */

static char logpath[64];
static int logfd = -1;
static void log_begin(void)
{
	snprintf(logpath, sizeof logpath, "/tmp/bst_sockopts_log.%d", (int)getpid());
	logfd = open(logpath, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	bst_log_init(logfd, BST_LOG_DEBUG);
}
static void log_end(char *buf, size_t cap)
{
	bst_log_init(2, BST_LOG_WARN);
	ssize_t n = pread(logfd, buf, cap - 1, 0);
	buf[n < 0 ? 0 : n] = 0;
	close(logfd);
	unlink(logpath);
}
static unsigned count_of(const char *hay, const char *needle)
{
	unsigned n = 0;
	for (const char *p = hay; (p = strstr(p, needle)) != NULL; p += strlen(needle))
		n++;
	return n;
}

/* ---- creation ---- */

TEST(slots_are_reuseport_nonblocking_cloexec_listening)
{
	uint16_t port = free_port();
	bst_cfg_listen l = v4(port, NULL);
	int fds[4];
	bst_err e = { .msg = "" };
	ASSERT_EQ(bst_listener_create(&l, 4, fds, &e), 0);
	for (int i = 0; i < 4; i++) {
		ASSERT(fds[i] >= 0);
		ASSERT_EQ(geti(fds[i], SOL_SOCKET, SO_REUSEPORT), 1);
		ASSERT_EQ(geti(fds[i], SOL_SOCKET, SO_ACCEPTCONN), 1);
		ASSERT(fcntl(fds[i], F_GETFL) & O_NONBLOCK);
		ASSERT(fcntl(fds[i], F_GETFD) & FD_CLOEXEC);
		ASSERT_EQ(geti(fds[i], IPPROTO_TCP, TCP_NODELAY), 1); /* the default profile */
	}
	closeall(fds, 4);
}

TEST(connections_spread_over_slots)
{
	uint16_t port = free_port();
	bst_cfg_listen l = v4(port, NULL);
	int fds[4], hit[4] = { 0 };
	bst_err e = { .msg = "" };
	ASSERT_EQ(bst_listener_create(&l, 4, fds, &e), 0);
	struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port),
				 .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	int cl[64];
	for (int i = 0; i < 64; i++) {
		cl[i] = socket(AF_INET, SOCK_STREAM, 0);
		ASSERT_EQ(connect(cl[i], (struct sockaddr *)&a, sizeof a), 0);
	}
	for (int s = 0; s < 4; s++)
		for (;;) {
			int c = accept4(fds[s], NULL, NULL, SOCK_NONBLOCK);
			if (c < 0)
				break;
			hit[s]++;
			close(c);
		}
	int total = 0, used = 0;
	for (int s = 0; s < 4; s++) {
		total += hit[s];
		used += hit[s] > 0;
	}
	ASSERT_EQ(total, 64);
	ASSERT(used >= 2);
	for (int i = 0; i < 64; i++)
		close(cl[i]);
	closeall(fds, 4);
}

TEST(v6_any_is_v6only_and_coexists_with_v4_any)
{
	int probe = socket(AF_INET6, SOCK_STREAM, 0);
	if (probe < 0) {
		printf("# skip: no IPv6 here\n");
		return;
	}
	close(probe);
	uint16_t port = free_port();
	bst_cfg_listen l4 = v4(port, NULL), l6 = v6any(port);
	memset(l4.addr.ip.b, 0, 4); /* 0.0.0.0 */
	int f4[2], f6[2];
	bst_err e = { .msg = "" };
	ASSERT_EQ(bst_listener_create(&l4, 2, f4, &e), 0);
	ASSERT_EQ(bst_listener_create(&l6, 2, f6, &e), 0); /* no EADDRINUSE: V6ONLY is on */
	for (int i = 0; i < 2; i++)
		ASSERT_EQ(geti(f6[i], IPPROTO_IPV6, IPV6_V6ONLY), 1);
	closeall(f4, 2);
	closeall(f6, 2);
}

TEST(bind_failure_reports_address_and_errno_and_closes_all)
{
	uint16_t port = free_port();
	int blocker = socket(AF_INET, SOCK_STREAM, 0); /* no SO_REUSEPORT: blocks every bind */
	struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port),
				 .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	ASSERT_EQ(bind(blocker, (struct sockaddr *)&a, sizeof a), 0);
	ASSERT_EQ(listen(blocker, 1), 0);
	bst_cfg_listen l = v4(port, NULL);
	int fds[3] = { 77, 77, 77 };
	bst_err e = { .msg = "" };
	ASSERT_EQ(bst_listener_create(&l, 3, fds, &e), -1);
	char want[40];
	snprintf(want, sizeof want, "127.0.0.1:%u", (unsigned)port);
	ASSERT(strstr(e.msg, "bind") != NULL);
	ASSERT(strstr(e.msg, want) != NULL);
	ASSERT(strstr(e.msg, strerror(EADDRINUSE)) != NULL);
	for (int i = 0; i < 3; i++)
		ASSERT_EQ(fds[i], -1);
	close(blocker);
}

TEST(partial_failure_closes_every_socket_already_created)
{
	uint16_t port = free_port();
	bst_cfg_listen l = v4(port, NULL);
	int lowest = open("/dev/null", O_RDONLY);
	close(lowest);
	struct rlimit old, lim;
	getrlimit(RLIMIT_NOFILE, &old);
	lim = old;
	lim.rlim_cur = (rlim_t)lowest + 2; /* two sockets fit, the third socket() fails */
	ASSERT_EQ(setrlimit(RLIMIT_NOFILE, &lim), 0);
	int fds[4];
	bst_err e = { .msg = "" };
	int rc = bst_listener_create(&l, 4, fds, &e);
	setrlimit(RLIMIT_NOFILE, &old);
	ASSERT_EQ(rc, -1);
	ASSERT(strstr(e.msg, strerror(EMFILE)) != NULL);
	ASSERT(!fd_open(lowest) && !fd_open(lowest + 1)); /* the two created sockets are closed */
	for (int i = 0; i < 4; i++)
		ASSERT_EQ(fds[i], -1);
	/* and the port is free again */
	ASSERT_EQ(bst_listener_create(&l, 1, fds, &e), 0);
	closeall(fds, 1);
}

TEST(bad_slot_counts_are_errors)
{
	bst_cfg_listen l = v4(free_port(), NULL);
	int fds[1];
	bst_err e = { .msg = "" };
	ASSERT_EQ(bst_listener_create(&l, 0, fds, &e), -1);
	ASSERT_EQ(bst_listener_create(&l, -3, fds, &e), -1);
	ASSERT_EQ(bst_listener_create(&l, BST_LISTENER_MAX_SLOTS + 1, fds, &e), -1);
}

/* ---- refused options ---- */

TEST(refused_option_warns_once_and_the_listener_starts)
{
	bst_tcp_profile p;
	bst_tcp_profile_defaults(&p, "edge");
	snprintf(p.congestion, sizeof p.congestion, "nosuchcc");
	set(&p, BST_TCP_CONGESTION, false);
	bst_cfg_listen l = v4(free_port(), &p);
	int fds[3];
	bst_err e = { .msg = "" };
	char log[4096];
	log_begin();
	int rc = bst_listener_create(&l, 3, fds, &e);
	log_end(log, sizeof log);
	ASSERT_EQ(rc, 0);
	ASSERT_EQ(count_of(log, "congestion"), 1); /* once per listener, not per slot */
	ASSERT(strstr(log, "WARN") != NULL);
	ASSERT(strstr(log, "edge") != NULL);
	ASSERT(strstr(log, strerror(ENOENT)) != NULL);
	ASSERT_EQ(geti(fds[0], SOL_SOCKET, SO_ACCEPTCONN), 1);
	closeall(fds, 3);
}

TEST(refused_option_with_require_fails_startup_and_closes_all)
{
	bst_tcp_profile p;
	bst_tcp_profile_defaults(&p, "strict");
	snprintf(p.congestion, sizeof p.congestion, "nosuchcc");
	set(&p, BST_TCP_CONGESTION, true);
	uint16_t port = free_port();
	bst_cfg_listen l = v4(port, &p);
	int fds[3];
	bst_err e = { .msg = "" };
	char log[4096];
	log_begin();
	int rc = bst_listener_create(&l, 3, fds, &e);
	log_end(log, sizeof log);
	ASSERT_EQ(rc, -1);
	ASSERT(strstr(e.msg, "congestion") != NULL);
	ASSERT(strstr(e.msg, "nosuchcc") != NULL);
	ASSERT(strstr(e.msg, strerror(ENOENT)) != NULL);
	ASSERT(strstr(e.msg, "strict") != NULL);
	for (int i = 0; i < 3; i++)
		ASSERT_EQ(fds[i], -1);
	ASSERT_EQ(count_of(log, "WARN"), 0); /* a failure, not a warning */
	ASSERT_EQ(bst_listener_create(&l, 1, fds, &e), -1); /* still refused, port not leaked */
	bst_tcp_profile q;
	bst_tcp_profile_defaults(&q, "ok");
	l.tcp = &q;
	ASSERT_EQ(bst_listener_create(&l, 1, fds, &e), 0);
	closeall(fds, 1);
}

TEST(clamped_buffer_is_not_silent)
{
	bst_tcp_profile p;
	bst_tcp_profile_defaults(&p, "big");
	p.rcvbuf = 1u << 30; /* far above net.core.rmem_max on any default kernel */
	set(&p, BST_TCP_RCVBUF, false);
	bst_cfg_listen l = v4(free_port(), &p);
	int fds[1];
	bst_err e = { .msg = "" };
	char log[4096];
	log_begin();
	ASSERT_EQ(bst_listener_create(&l, 1, fds, &e), 0);
	log_end(log, sizeof log);
	ASSERT(strstr(log, "rcvbuf") != NULL);
	ASSERT(strstr(log, "rmem_max") != NULL);
	closeall(fds, 1);
	set(&p, BST_TCP_RCVBUF, true);
	ASSERT_EQ(bst_listener_create(&l, 1, fds, &e), -1);
	ASSERT(strstr(e.msg, "rcvbuf") != NULL);
}

TEST(backlog_above_somaxconn_is_not_silent)
{
	int somax = 0;
	FILE *f = fopen("/proc/sys/net/core/somaxconn", "r");
	if (f != NULL) {
		if (fscanf(f, "%d", &somax) != 1)
			somax = 0;
		fclose(f);
	}
	if (somax <= 0 || somax >= 65535) {
		printf("# skip: somaxconn is %d\n", somax);
		return;
	}
	bst_tcp_profile p;
	bst_tcp_profile_defaults(&p, "bl");
	p.backlog = 65535;
	bst_cfg_listen l = v4(free_port(), &p);
	int fds[1];
	bst_err e = { .msg = "" };
	char log[4096];
	log_begin();
	ASSERT_EQ(bst_listener_create(&l, 1, fds, &e), 0);
	log_end(log, sizeof log);
	ASSERT(strstr(log, "backlog") != NULL);
	ASSERT(strstr(log, "somaxconn") != NULL);
	closeall(fds, 1);
	p.require |= 1u << BST_TCP_BACKLOG;
	ASSERT_EQ(bst_listener_create(&l, 1, fds, &e), -1);
	ASSERT(strstr(e.msg, "somaxconn") != NULL);
}

TEST(fastopen_without_the_server_sysctl_is_not_silent)
{
	int v = -1;
	FILE *f = fopen("/proc/sys/net/ipv4/tcp_fastopen", "r");
	if (f != NULL) {
		if (fscanf(f, "%d", &v) != 1)
			v = -1;
		fclose(f);
	}
	if (v < 0) {
		printf("# skip: no tcp_fastopen sysctl\n");
		return;
	}
	bst_tcp_profile p;
	bst_tcp_profile_defaults(&p, "tfo");
	p.fastopen = 256;
	set(&p, BST_TCP_FASTOPEN, false);
	bst_cfg_listen l = v4(free_port(), &p);
	int fds[1];
	bst_err e = { .msg = "" };
	char log[4096];
	log_begin();
	ASSERT_EQ(bst_listener_create(&l, 1, fds, &e), 0);
	log_end(log, sizeof log);
	ASSERT_EQ(geti(fds[0], IPPROTO_TCP, TCP_FASTOPEN), 256);
	ASSERT_EQ(strstr(log, "net.ipv4.tcp_fastopen") != NULL, (v & 2) == 0);
	closeall(fds, 1);
}

TEST(incoming_cpu_steering_assigns_a_cpu_per_slot)
{
	bst_tcp_profile p;
	bst_tcp_profile_defaults(&p, "steer");
	p.steering = BST_STEER_INCOMING_CPU;
	set(&p, BST_TCP_STEERING, false);
	bst_cfg_listen l = v4(free_port(), &p);
	int fds[3];
	bst_err e = { .msg = "" };
	ASSERT_EQ(bst_listener_create(&l, 3, fds, &e), 0);
	long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
	for (int i = 0; i < 3; i++)
		ASSERT_EQ(geti(fds[i], SOL_SOCKET, SO_INCOMING_CPU), (int)(i % ncpu));
	closeall(fds, 3);
}

/* ---- options applied per connection ---- */

static int accepted_pair(int lfd, uint16_t port, int *client)
{
	struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port),
				 .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	*client = socket(AF_INET, SOCK_STREAM, 0);
	if (connect(*client, (struct sockaddr *)&a, sizeof a) != 0)
		return -1;
	return accept4(lfd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
}

TEST(accepted_options_touch_only_what_is_not_inherited)
{
	/* Everything but quickack is inherited from the listener, so a profile without a
	 * quickack setting costs no syscall on the accept path. */
	bst_tcp_profile p;
	bst_tcp_profile_defaults(&p, "acc");
	p.fastopen = 1;
	set(&p, BST_TCP_FASTOPEN, false);
	p.notsent_lowat = 4096;
	set(&p, BST_TCP_NOTSENT_LOWAT, false);
	uint16_t port = free_port();
	bst_cfg_listen l = v4(port, &p);
	int fds[1], cl;
	bst_err e = { .msg = "" };
	char log[2048];
	log_begin();
	ASSERT_EQ(bst_listener_create(&l, 1, fds, &e), 0); /* may warn about the Fast Open sysctl */
	log_end(log, sizeof log);
	int a = accepted_pair(fds[0], port, &cl);
	ASSERT(a >= 0);
	ASSERT_EQ(geti(a, IPPROTO_TCP, TCP_NODELAY), 1); /* inherited */
	ASSERT_EQ(geti(a, IPPROTO_TCP, TCP_NOTSENT_LOWAT), 4096);
	unsigned before = bst_test_sockopt_calls;
	ASSERT_EQ(bst_sock_apply_accepted(a, &p), 0);
	ASSERT_EQ(bst_test_sockopt_calls - before, 0);
	/* quickack on is the kernel default for a new connection: skipped as well */
	p.quickack = true;
	set(&p, BST_TCP_QUICKACK, false);
	ASSERT_EQ(bst_sock_apply_accepted(a, &p), 0);
	ASSERT_EQ(bst_test_sockopt_calls - before, 0);
	ASSERT_EQ(geti(a, IPPROTO_TCP, TCP_QUICKACK), 1);
	/* quickack off differs from the default: exactly one call */
	p.quickack = false;
	ASSERT_EQ(bst_sock_apply_accepted(a, &p), 0);
	ASSERT_EQ(bst_test_sockopt_calls - before, 1);
	ASSERT_EQ(geti(a, IPPROTO_TCP, TCP_QUICKACK), 0);
	close(a);
	close(cl);
	closeall(fds, 1);
}

TEST(accepted_apply_reports_refusal_without_closing)
{
	bst_tcp_profile p;
	bst_tcp_profile_defaults(&p, "x");
	p.quickack = false;
	set(&p, BST_TCP_QUICKACK, false);
	char log[1024];
	log_begin();
	ASSERT_EQ(bst_sock_apply_accepted(-1, &p), -EBADF);
	ASSERT_EQ(bst_sock_apply_accepted(-1, &p), -EBADF); /* reported again, logged only once */
	log_end(log, sizeof log);
	ASSERT_EQ(count_of(log, "quickack"), 1);
	ASSERT(strstr(log, strerror(EBADF)) != NULL);
	ASSERT_EQ(bst_sock_apply_accepted(-1, NULL), 0); /* no profile, nothing to do */
}

TAP_MAIN()
