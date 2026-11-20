/* systemd integration without libsystemd (src/proc/systemd.c): notify datagrams, the watchdog
 * interval, and socket activation. The end to end runs under systemd are tests/vm/test_systemd.py. */
#include "proc/systemd.h"
#include "tap.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/* A datagram socket bound in the abstract namespace; its name goes in NOTIFY_SOCKET. */
static int notify_sink(char *env, size_t cap)
{
	int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	struct sockaddr_un sa = { .sun_family = AF_UNIX };
	int n = snprintf(sa.sun_path + 1, sizeof sa.sun_path - 1, "bst-sd-test-%ld", (long)getpid());
	if (fd < 0 || bind(fd, (struct sockaddr *)&sa, (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + (size_t)n)) != 0)
		return -1;
	snprintf(env, cap, "@%s", sa.sun_path + 1);
	return fd;
}

static const char *recv_msg(int fd)
{
	static char buf[600];
	ssize_t n = recv(fd, buf, sizeof buf - 1, MSG_DONTWAIT);
	buf[n > 0 ? n : 0] = '\0';
	return buf;
}

TEST(notify_sends_one_datagram_to_an_abstract_socket)
{
	char env[128];
	int fd = notify_sink(env, sizeof env);
	ASSERT(fd >= 0);
	setenv("NOTIFY_SOCKET", env, 1);
	ASSERT_EQ(bst_sd_notify("READY=1"), 0);
	ASSERT_STR(recv_msg(fd), "READY=1");
	ASSERT_EQ(bst_sd_notifyf("RELOADING=1\nMONOTONIC_USEC=%u", 42u), 0);
	ASSERT_STR(recv_msg(fd), "RELOADING=1\nMONOTONIC_USEC=42");
	unsetenv("NOTIFY_SOCKET");
	close(fd);
}

TEST(notify_without_a_socket_does_nothing)
{
	unsetenv("NOTIFY_SOCKET");
	ASSERT_EQ(bst_sd_notify("READY=1"), 0);
	setenv("NOTIFY_SOCKET", "", 1);
	ASSERT_EQ(bst_sd_notify("READY=1"), 0);
	unsetenv("NOTIFY_SOCKET");
}

TEST(notify_refuses_a_relative_or_missing_address)
{
	setenv("NOTIFY_SOCKET", "relative/path", 1);
	ASSERT_EQ(bst_sd_notify("READY=1"), -1);
	setenv("NOTIFY_SOCKET", "/nonexistent/bst-notify", 1);
	ASSERT_EQ(bst_sd_notify("READY=1"), -1);
	setenv("NOTIFY_SOCKET", "@", 1);
	ASSERT_EQ(bst_sd_notify("READY=1"), -1);
	unsetenv("NOTIFY_SOCKET");
}

TEST(watchdog_is_ours_or_our_parents)
{
	char pid[32];
	unsetenv("WATCHDOG_USEC");
	unsetenv("WATCHDOG_PID");
	ASSERT_EQ(bst_sd_watchdog_usec(), 0u);
	setenv("WATCHDOG_USEC", "3000000", 1);
	ASSERT_EQ(bst_sd_watchdog_usec(), 3000000u); /* no WATCHDOG_PID: ours */
	snprintf(pid, sizeof pid, "%ld", (long)getpid());
	setenv("WATCHDOG_PID", pid, 1);
	ASSERT_EQ(bst_sd_watchdog_usec(), 3000000u);
	snprintf(pid, sizeof pid, "%ld", (long)getppid()); /* a live upgrade's old master */
	setenv("WATCHDOG_PID", pid, 1);
	ASSERT_EQ(bst_sd_watchdog_usec(), 3000000u);
	setenv("WATCHDOG_PID", "1", 1);
	if (getppid() != 1)
		ASSERT_EQ(bst_sd_watchdog_usec(), 0u); /* another process's */
	setenv("WATCHDOG_PID", "12x", 1);
	ASSERT_EQ(bst_sd_watchdog_usec(), 0u);
	unsetenv("WATCHDOG_PID");
	setenv("WATCHDOG_USEC", "-5", 1);
	ASSERT_EQ(bst_sd_watchdog_usec(), 0u);
	setenv("WATCHDOG_USEC", "0", 1);
	ASSERT_EQ(bst_sd_watchdog_usec(), 0u);
	unsetenv("WATCHDOG_USEC");
}

static int listening(uint16_t *port)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in sa = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	socklen_t sl = sizeof sa;
	if (fd < 0 || bind(fd, (struct sockaddr *)&sa, sizeof sa) != 0 || listen(fd, 8) != 0 ||
	    getsockname(fd, (struct sockaddr *)&sa, &sl) != 0)
		return -1;
	*port = ntohs(sa.sin_port);
	return fd;
}

static bst_cfg_listen loopback(uint16_t port)
{
	bst_cfg_listen l;
	memset(&l, 0, sizeof l);
	l.addr.ip.family = BST_IP_V4;
	l.addr.ip.b[0] = 127;
	l.addr.ip.b[3] = 1;
	l.addr.port = port;
	return l;
}

TEST(socket_activation_uses_the_matching_socket_for_every_slot)
{
	uint16_t pa, pb;
	int a = listening(&pa), b = listening(&pb);
	ASSERT(a >= 0 && b == a + 1); /* consecutive, as systemd passes them */
	bst_sd_listen_adopt_(a, 2);
	ASSERT_EQ(bst_sd_listen_fds(), 2);
	bst_cfg_listen other = loopback((uint16_t)(pb + 1 == pa ? pb + 2 : pb + 1));
	int fds[3] = { -1, -1, -1 };
	ASSERT(!bst_sd_take_listener(&other, 3, fds));
	bst_cfg_listen lb = loopback(pb);
	ASSERT(bst_sd_take_listener(&lb, 3, fds));
	for (int i = 0; i < 3; i++) {
		struct sockaddr_in sa;
		socklen_t sl = sizeof sa;
		ASSERT(fds[i] >= 0);
		ASSERT_EQ(getsockname(fds[i], (struct sockaddr *)&sa, &sl), 0);
		ASSERT_EQ(ntohs(sa.sin_port), pb);
		ASSERT(fcntl(fds[i], F_GETFL) & O_NONBLOCK);
		ASSERT(fcntl(fds[i], F_GETFD) & FD_CLOEXEC);
	}
	ASSERT_EQ(fcntl(b, F_GETFD), -1); /* the passed fd itself is closed once duplicated */
	int again[1] = { -1 };
	ASSERT(!bst_sd_take_listener(&lb, 1, again)); /* taken once */
	bst_sd_close_untaken();
	ASSERT_EQ(fcntl(a, F_GETFD), -1); /* nothing matched it: closed */
	for (int i = 0; i < 3; i++)
		close(fds[i]);
}

TEST(socket_activation_needs_this_pid)
{
	char pid[32];
	snprintf(pid, sizeof pid, "%ld", (long)getpid() + 1);
	bst_sd_listen_adopt_(-1, 0); /* read the environment again */
	setenv("LISTEN_PID", pid, 1); /* meant for another process */
	setenv("LISTEN_FDS", "1", 1);
	ASSERT_EQ(bst_sd_listen_fds(), 0);
	ASSERT(getenv("LISTEN_FDS") == NULL && getenv("LISTEN_PID") == NULL); /* removed once read */
	bst_sd_listen_adopt_(-1, 0);
	snprintf(pid, sizeof pid, "%ld", (long)getpid());
	setenv("LISTEN_PID", pid, 1);
	setenv("LISTEN_FDS", "zero", 1);
	ASSERT_EQ(bst_sd_listen_fds(), 0);
	bst_cfg_listen l = loopback(80);
	int fds[1] = { -1 };
	ASSERT(!bst_sd_take_listener(&l, 1, fds));
}

TAP_MAIN()
