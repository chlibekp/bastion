#include "tap.h"

#include "core/counters.h"
#include "core/log.h"

#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int pfd[2];

static void pipe_open(bool nonblock, int level)
{
	bst_counters_reset_for_test();
	ASSERT_EQ(pipe(pfd), 0);
	if (nonblock) {
		fcntl(pfd[0], F_SETFL, O_NONBLOCK);
		fcntl(pfd[1], F_SETFL, O_NONBLOCK);
	}
	bst_log_init(pfd[1], level);
}

/* Closes the write end and returns everything the reader got. */
static size_t pipe_drain(char *buf, size_t cap)
{
	close(pfd[1]);
	fcntl(pfd[0], F_SETFL, O_NONBLOCK);
	size_t n = 0;
	ssize_t r;
	while (n < cap - 1 && (r = read(pfd[0], buf + n, cap - 1 - n)) > 0)
		n += (size_t)r;
	buf[n] = '\0';
	close(pfd[0]);
	return n;
}

static int count_nl(const char *s)
{
	int c = 0;
	for (; *s; s++)
		c += *s == '\n';
	return c;
}

/* Removes "<time> <pid> <tag> " from the start of every line, in place, so tests can
 * compare "LEVEL message". The prefix has its own test. */
static void strip_prefixes(char *buf)
{
	char *out = buf;
	for (char *s = buf; *s;) {
		char *e = strchr(s, '\n');
		size_t len = e ? (size_t)(e - s) + 1 : strlen(s);
		char *p = s;
		for (int sp = 0; sp < 3 && p < s + len; p++)
			sp += *p == ' ';
		memmove(out, p, len - (size_t)(p - s));
		out += len - (size_t)(p - s);
		s += len;
	}
	*out = '\0';
}

static uint64_t dropped(void)
{
	return bst_log_dropped();
}

/* Fresh "before init" state needs a fresh process, and fork would inherit state from
 * earlier tests. So the test re-execs this binary with an env var; the constructor
 * below sees it before main and the tap tests, logs without init, and exits. */
#define PREINIT_ENV "BST_LOG_PREINIT_CHILD"
static void __attribute__((constructor)) preinit_child(void)
{
	if (getenv(PREINIT_ENV) == NULL)
		return;
	bst_log(BST_LOG_INFO, "hidden");
	bst_log(BST_LOG_WARN, "shown \x01");
	_exit(0);
}

TEST(log_before_init_defaults)
{
	int fds[2];
	ASSERT_EQ(pipe(fds), 0);
	pid_t p = fork();
	ASSERT(p >= 0);
	if (p == 0) {
		dup2(fds[1], 2);
		setenv(PREINIT_ENV, "1", 1);
		execl("/proc/self/exe", "test_log", (char *)NULL);
		_exit(127);
	}
	close(fds[1]);
	char buf[64] = { 0 };
	ssize_t n = read(fds[0], buf, sizeof buf - 1);
	close(fds[0]);
	int st;
	waitpid(p, &st, 0);
	ASSERT(WIFEXITED(st) && WEXITSTATUS(st) == 0);
	ASSERT(n > 0);
	strip_prefixes(buf);
	ASSERT_STR(buf, "WARN shown \\x01\n");
}

TEST(log_drop_counted_with_full_table)
{
	bst_counters_reset_for_test();
	char name[32];
	for (int i = 0; i < BST_COUNTER_MAX; i++) {
		snprintf(name, sizeof name, "f%d", i);
		bst_counter_register(name, "", NULL);
	}
	ASSERT_EQ(bst_counter_register("x", "", NULL), BST_COUNTER_INVALID);
	int fds[2];
	ASSERT_EQ(pipe(fds), 0);
	close(fds[0]);
	bst_log_init(fds[1], BST_LOG_DEBUG); /* cannot register the drop counter */
	uint64_t before = bst_log_dropped();
	bst_log(BST_LOG_ERROR, "gone");
	bst_log(BST_LOG_ERROR, "gone");
	ASSERT_EQ(bst_log_dropped(), before + 2);
	close(fds[1]);
}

TEST(log_drops_before_init_move_into_counter)
{
	/* Drops that happened while the table was full are kept once a slot exists. */
	bst_counters_reset_for_test();
	char name[32];
	for (int i = 0; i < BST_COUNTER_MAX; i++) {
		snprintf(name, sizeof name, "g%d", i);
		bst_counter_register(name, "", NULL);
	}
	int fds[2];
	ASSERT_EQ(pipe(fds), 0);
	close(fds[0]);
	bst_log_init(fds[1], BST_LOG_DEBUG);
	uint64_t base = bst_log_dropped();
	bst_log(BST_LOG_ERROR, "gone");
	bst_counters_reset_for_test();
	bst_log_init(fds[1], BST_LOG_DEBUG); /* now it registers and absorbs the private count */
	ASSERT_EQ(bst_log_dropped(), base + 1);
	ASSERT_EQ(bst_counter_get(bst_counter_register(BST_LOG_DROP_COUNTER, "", NULL)), base + 1);
	close(fds[1]);
}

TEST(log_line_has_timestamp_pid_tag)
{
	pipe_open(false, BST_LOG_DEBUG);
	time_t before = time(NULL);
	bst_log(BST_LOG_WARN, "hello %d", 7);
	time_t after = time(NULL);
	char buf[256];
	pipe_drain(buf, sizeof buf);
	int y, mo, d, h, mi, sec, ms, pid, used = 0;
	char tag[8], lvl[8];
	ASSERT(sscanf(buf, "%4d-%2d-%2dT%2d:%2d:%2d.%3dZ %d %7s %7s %n", &y, &mo, &d, &h, &mi, &sec,
		      &ms, &pid, tag, lvl, &used) == 10);
	ASSERT_STR(tag, "-");
	ASSERT_STR(lvl, "WARN");
	ASSERT_EQ(pid, getpid());
	ASSERT_STR(buf + used, "hello 7\n");
	ASSERT(buf[4] == '-' && buf[10] == 'T' && buf[19] == '.' && buf[23] == 'Z');
	struct tm tm = { .tm_year = y - 1900, .tm_mon = mo - 1, .tm_mday = d, .tm_hour = h,
			 .tm_min = mi, .tm_sec = sec };
	time_t got = timegm(&tm);
	ASSERT(got >= before && got <= after);
	ASSERT(ms >= 0 && ms <= 999);
}

TEST(log_pid_is_read_per_line_after_fork)
{
	pipe_open(false, BST_LOG_DEBUG);
	bst_log(BST_LOG_ERROR, "parent");
	pid_t p = fork();
	ASSERT(p >= 0);
	if (p == 0) {
		bst_log(BST_LOG_ERROR, "child");
		_exit(0);
	}
	int st;
	waitpid(p, &st, 0);
	char buf[512];
	pipe_drain(buf, sizeof buf);
	char want_parent[32], want_child[32];
	snprintf(want_parent, sizeof want_parent, "Z %d - ERROR parent", getpid());
	snprintf(want_child, sizeof want_child, "Z %d - ERROR child", p);
	ASSERT(strstr(buf, want_parent) != NULL);
	ASSERT(strstr(buf, want_child) != NULL);
}

TEST(log_tag_is_copied_and_escaped)
{
	char tag[] = "worker3";
	bst_log_set_tag(tag);
	tag[0] = 'X'; /* the log must have its own copy */
	pipe_open(false, BST_LOG_DEBUG);
	bst_log(BST_LOG_ERROR, "a");
	bst_log_set_tag("bad\ntag \x01");
	bst_log(BST_LOG_ERROR, "b");
	bst_log_set_tag("0123456789012345678901234567890123456789"); /* longer than the buffer */
	bst_log(BST_LOG_ERROR, "c");
	bst_log_set_tag("\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"); /* 4 bytes each: cut on a unit */
	bst_log(BST_LOG_ERROR, "d");
	bst_log_set_tag(NULL);
	bst_log(BST_LOG_ERROR, "e");
	bst_log_set_tag("");
	bst_log(BST_LOG_ERROR, "f");
	char buf[1024];
	pipe_drain(buf, sizeof buf);
	ASSERT_EQ(count_nl(buf), 6);
	ASSERT(strstr(buf, " worker3 ERROR a\n") != NULL);
	ASSERT(strstr(buf, " bad\\ntag \\x01 ERROR b\n") != NULL);
	ASSERT(strstr(buf, " 0123456789012345678901234567890 ERROR c\n") != NULL); /* 31 bytes */
	ASSERT(strstr(buf, " \\x01\\x01\\x01\\x01\\x01\\x01\\x01 ERROR d\n") != NULL); /* 28 bytes */
	ASSERT(strstr(buf, " - ERROR e\n") != NULL);
	ASSERT(strstr(buf, " - ERROR f\n") != NULL);
}

static void check_time(int64_t sec)
{
	char got[40], want[40];
	time_t t = (time_t)sec;
	struct tm tm;
	gmtime_r(&t, &tm);
	strftime(want, sizeof want, "%Y-%m-%dT%H:%M:%S.123Z", &tm);
	size_t n = bst_log_format_time_(got, sizeof got, sec, 123);
	if (n != 24 || strcmp(got, want) != 0) {
		printf("# time %lld: got %s want %s\n", (long long)sec, got, want);
		tap_state.current_failed = 1;
	}
}

TEST(log_time_matches_gmtime_r)
{
	/* A sweep of every 7h13m from 1970 through 9999-12-31, plus edge days. */
	for (int64_t s = 0; s <= 253402300799LL; s += 7 * 3600 + 13 * 60 + 1)
		check_time(s);
	static const int64_t edges[] = {
		0, 86399, 86400, 951782400 /* 2000-02-29 */, 951868800, 4107542400LL /* 2100-03-01 */,
		4107456000LL /* 2100-02-28 */, 78796800 /* 1972-02-29 */, 2147483647 /* 2038 */,
		2147483648LL, 4294967295LL, 253402300799LL, 1709164800 /* 2024-02-29 */,
		-1 /* 1969-12-31 23:59:59 */, -86400, -2208988800LL /* 1900-01-01 */,
	};
	for (size_t i = 0; i < sizeof edges / sizeof *edges; i++)
		check_time(edges[i]);
	/* every second around leap days and century boundaries */
	for (int64_t base = 951782400 - 3; base < 951782400 + 3; base++)
		check_time(base);
	for (int64_t s = 2147483647LL - 5; s < 2147483647LL + 5; s++)
		check_time(s);
	ASSERT(!tap_state.current_failed);
}

/* First log line after a seccomp filter that kills every file-opening syscall, with a
 * hostile TZ: glibc's gmtime_r would open the zone file here and die with SIGSYS. */
#if defined(__x86_64__)
#define BST_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define BST_AUDIT_ARCH AUDIT_ARCH_AARCH64
#endif
#ifdef BST_AUDIT_ARCH
static void install_open_killer(void)
{
	struct sock_filter f[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, BST_AUDIT_ARCH, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_openat, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_openat2, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
#ifdef SYS_open
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_open, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
#endif
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = { .len = (unsigned short)(sizeof f / sizeof f[0]), .filter = f };
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
	    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0)
		_exit(10);
}

/* Needs a process whose time-zone state was never initialised (an earlier gmtime_r in
 * this binary would hide the bug), so the child is a fresh exec of this binary; the
 * constructor below runs before main. */
#define SECCOMP_ENV "BST_LOG_SECCOMP_CHILD"
static void __attribute__((constructor)) seccomp_child(void)
{
	if (getenv(SECCOMP_ENV) == NULL)
		return;
	setenv("TZ", ":/etc/passwd", 1);
	bst_log_init(2, BST_LOG_DEBUG);
	bst_log_set_tag("sandboxed");
	install_open_killer();
	bst_log(BST_LOG_ERROR, "first line %d", 1);
	_exit(0);
}

TEST(log_first_line_opens_no_files)
{
	int fds[2];
	ASSERT_EQ(pipe(fds), 0);
	pid_t p = fork();
	ASSERT(p >= 0);
	if (p == 0) {
		dup2(fds[1], 2);
		setenv(SECCOMP_ENV, "1", 1);
		execl("/proc/self/exe", "test_log", (char *)NULL);
		_exit(127);
	}
	close(fds[1]);
	char buf[256] = { 0 };
	ssize_t n = read(fds[0], buf, sizeof buf - 1);
	close(fds[0]);
	int st;
	waitpid(p, &st, 0);
	ASSERT(WIFEXITED(st));
	ASSERT_EQ(WEXITSTATUS(st), 0);
	ASSERT(n > 0);
	ASSERT(strstr(buf, " sandboxed ERROR first line 1\n") != NULL);
}
#endif

TEST(log_escapes_control)
{
	pipe_open(false, BST_LOG_DEBUG);
	const char *evil = "a\nb\r\x1b[31mred\x01\x7f\\";
	bst_log(BST_LOG_ERROR, "msg \n %s end", evil);
	char buf[512];
	pipe_drain(buf, sizeof buf);
	strip_prefixes(buf);
	ASSERT_STR(buf, "ERROR msg \\n a\\nb\\r\\x1b[31mred\\x01\\x7f\\\\ end\n");
	ASSERT_EQ(count_nl(buf), 1);
}

TEST(log_escapes_invalid_utf8_and_c1)
{
	pipe_open(false, BST_LOG_DEBUG);
	/* valid e-acute and euro pass; lone 0xff, overlong C0 80, surrogate ED A0 80,
	 * C1 NEL (C2 85), U+2028, truncated E2 82 at the end are all escaped. */
	bst_log(BST_LOG_INFO, "%s", "\xc3\xa9\xe2\x82\xac|\xff|\xc0\x80|\xed\xa0\x80|\xc2\x85|\xe2\x80\xa8|\xe2\x82");
	char buf[512];
	pipe_drain(buf, sizeof buf);
	strip_prefixes(buf);
	ASSERT_STR(buf, "INFO \xc3\xa9\xe2\x82\xac|\\xff|\\xc0\\x80|\\xed\\xa0\\x80|\\xc2\\x85|"
			"\\xe2\\x80\\xa8|\\xe2\\x82\n");
	ASSERT_EQ(count_nl(buf), 1);
}

TEST(log_all_bytes_single_line)
{
	pipe_open(false, BST_LOG_DEBUG);
	char s[256];
	for (int i = 0; i < 255; i++)
		s[i] = (char)(i + 1);
	s[255] = '\0';
	bst_log(BST_LOG_WARN, "%s", s);
	char buf[2048];
	size_t n = pipe_drain(buf, sizeof buf);
	ASSERT_EQ(count_nl(buf), 1);
	ASSERT(buf[n - 1] == '\n');
	for (size_t i = 0; i + 1 < n; i++) {
		unsigned char c = (unsigned char)buf[i];
		ASSERT(c >= 0x20 && c != 0x7f);
	}
}

TEST(log_truncates_at_boundary)
{
	/* Every byte expands 4x, so the line must cut inside the escape stream. */
	for (int pad = 0; pad < 4; pad++) {
		pipe_open(false, BST_LOG_DEBUG);
		char s[BST_LOG_RAW_MAX + 100];
		memset(s, 0x01, sizeof s);
		memset(s, 'x', (size_t)pad);
		s[sizeof s - 1] = '\0';
		bst_log(BST_LOG_ERROR, "%s", s);
		char buf[BST_LOG_LINE_MAX + 64];
		size_t n = pipe_drain(buf, sizeof buf);
		ASSERT(n <= BST_LOG_LINE_MAX);
		ASSERT(n > BST_LOG_LINE_MAX - 8);
		ASSERT_EQ(count_nl(buf), 1);
		ASSERT(buf[n - 1] == '\n');
		size_t m = strlen(BST_LOG_TRUNC_MARK);
		ASSERT(memcmp(buf + n - 1 - m, BST_LOG_TRUNC_MARK, m) == 0);
		/* What precedes the marker is whole \x01 escapes only. */
		const char *p = strstr(buf, "ERROR ");
		ASSERT(p != NULL);
		p += 6 + pad;
		const char *end = buf + n - 1 - m;
		ASSERT(((size_t)(end - p)) % 4 == 0);
		for (; p < end; p += 4)
			ASSERT(memcmp(p, "\\x01", 4) == 0);
	}
}

TEST(log_short_message_not_marked)
{
	pipe_open(false, BST_LOG_DEBUG);
	char buf[BST_LOG_LINE_MAX + 64];
	bst_log(BST_LOG_ERROR, "%s", "");
	close(pfd[1]);
	ssize_t pl = read(pfd[0], buf, sizeof buf); /* prefix + "ERROR " + "\n" */
	close(pfd[0]);
	ASSERT(pl > 8);
	pipe_open(false, BST_LOG_DEBUG);
	char s[BST_LOG_LINE_MAX];
	memset(s, 'a', sizeof s);
	s[BST_LOG_LINE_MAX - (size_t)pl] = '\0'; /* prefix + body + "\n" == LINE_MAX exactly */
	bst_log(BST_LOG_ERROR, "%s", s);
	size_t n = pipe_drain(buf, sizeof buf);
	ASSERT_EQ(n, BST_LOG_LINE_MAX);
	ASSERT(strstr(buf, "truncated") == NULL);
}

static int side_effects;
static int bump(void)
{
	return ++side_effects;
}

TEST(log_level_filter)
{
	pipe_open(false, BST_LOG_WARN);
	side_effects = 0;
	bst_log(BST_LOG_DEBUG, "d %d", bump());
	bst_log(BST_LOG_INFO, "i %d", bump());
	ASSERT_EQ(side_effects, 0);
	bst_log(BST_LOG_WARN, "w %d", bump());
	ASSERT_EQ(side_effects, 1);
	bst_log_init(pfd[1], BST_LOG_ERROR); /* reconfigure */
	bst_log(BST_LOG_WARN, "w2 %d", bump());
	ASSERT_EQ(side_effects, 1);
	bst_log(BST_LOG_ERROR, "e %d", bump());
	char buf[256];
	pipe_drain(buf, sizeof buf);
	strip_prefixes(buf);
	ASSERT_STR(buf, "WARN w 1\nERROR e 2\n");
}

TEST(log_errno_preserved)
{
	pipe_open(false, BST_LOG_DEBUG);
	errno = ENOENT;
	bst_log(BST_LOG_ERROR, "x");
	ASSERT_EQ(errno, ENOENT);
	close(pfd[0]); /* reader gone: the failure path must preserve it too */
	errno = EACCES;
	bst_log(BST_LOG_ERROR, "y");
	ASSERT_EQ(errno, EACCES);
	close(pfd[1]);
}

TEST(log_fd_gone)
{
	pipe_open(false, BST_LOG_DEBUG);
	close(pfd[0]);
	struct sigaction before, after;
	sigaction(SIGPIPE, NULL, &before);
	sigset_t m0, m1, pend;
	sigprocmask(SIG_SETMASK, NULL, &m0);
	bst_log(BST_LOG_ERROR, "reader is gone");
	ASSERT_EQ(dropped(), 1);
	bst_log(BST_LOG_ERROR, "again");
	ASSERT_EQ(dropped(), 2);
	sigaction(SIGPIPE, NULL, &after);
	ASSERT(before.sa_handler == after.sa_handler);
	sigprocmask(SIG_SETMASK, NULL, &m1);
	ASSERT_EQ(sigismember(&m0, SIGPIPE), sigismember(&m1, SIGPIPE));
	sigpending(&pend);
	ASSERT_EQ(sigismember(&pend, SIGPIPE), 0);
	close(pfd[1]);

	/* A closed (EBADF) fd also drops quietly. */
	bst_log_init(pfd[1], BST_LOG_DEBUG);
	bst_log(BST_LOG_ERROR, "bad fd");
	ASSERT_EQ(dropped(), 3);
}

TEST(log_nonblocking_full_pipe_drops)
{
	pipe_open(true, BST_LOG_DEBUG);
	for (int i = 0; i < 4000; i++) /* ~64 KiB pipe, 100+ byte lines: must fill */
		bst_log(BST_LOG_ERROR, "fill %d ................................................"
				       "......................................", i);
	ASSERT(dropped() > 0);
	char buf[1 << 17];
	size_t n = pipe_drain(buf, sizeof buf);
	ASSERT(n > 0 && buf[n - 1] == '\n'); /* nothing partial was left behind */
	ASSERT(strstr(buf, "ERROR fill 0 ") != NULL);
}

static void short_write_child(void)
{
	char path[] = "/tmp/bst_log_XXXXXX";
	int fd = mkstemp(path);
	if (fd < 0)
		_exit(10);
	unlink(path);
	signal(SIGXFSZ, SIG_IGN);
	struct rlimit rl = { 5, 5 };
	setrlimit(RLIMIT_FSIZE, &rl);
	bst_counters_reset_for_test();
	bst_log_init(fd, BST_LOG_DEBUG);
	bst_log(BST_LOG_ERROR, "this line is longer than five bytes");
	if (dropped() != 1)
		_exit(11);
	_exit(0);
}

TEST(log_short_write_is_drop)
{
	pid_t p = fork();
	ASSERT(p >= 0);
	if (p == 0)
		short_write_child();
	int st;
	waitpid(p, &st, 0);
	ASSERT(WIFEXITED(st));
	ASSERT_EQ(WEXITSTATUS(st), 0);
}

TEST(log_concurrent_writers_whole_lines)
{
	enum { W = 6, N = 300 };
	pipe_open(false, BST_LOG_DEBUG);
	for (int w = 0; w < W; w++) {
		pid_t p = fork();
		ASSERT(p >= 0);
		if (p == 0) {
			close(pfd[0]);
			for (int i = 0; i < N; i++)
				bst_log(BST_LOG_ERROR, "w%d i%d %.*s|", w, i, 100 + w * 90,
					"0123456789012345678901234567890123456789012345678901234567890123456789"
					"0123456789012345678901234567890123456789012345678901234567890123456789"
					"0123456789012345678901234567890123456789012345678901234567890123456789"
					"0123456789012345678901234567890123456789012345678901234567890123456789"
					"0123456789012345678901234567890123456789012345678901234567890123456789"
					"0123456789012345678901234567890123456789012345678901234567890123456789"
					"0123456789012345678901234567890123456789012345678901234567890123456789"
					"0123456789012345678901234567890123456789012345678901234567890123456789");
			_exit(0);
		}
	}
	close(pfd[1]);
	static char all[W * N * 1100];
	size_t n = 0;
	ssize_t r;
	while ((r = read(pfd[0], all + n, sizeof all - 1 - n)) > 0)
		n += (size_t)r;
	all[n] = '\0';
	close(pfd[0]);
	for (int w = 0; w < W; w++)
		wait(NULL);
	int lines = 0, seen[W] = { 0 };
	for (char *s = all; *s;) {
		char *e = strchr(s, '\n');
		ASSERT(e != NULL);
		*e = '\0';
		int cw, ci, used;
		ASSERT(sscanf(s, "%*s %*d %*s ERROR w%d i%d %n", &cw, &ci, &used) == 2);
		size_t len = strlen(s + used);
		ASSERT_EQ(len, (size_t)(100 + cw * 90) + 1);
		ASSERT(s[strlen(s) - 1] == '|');
		seen[cw]++;
		lines++;
		s = e + 1;
	}
	ASSERT_EQ(lines, W * N);
	for (int w = 0; w < W; w++)
		ASSERT_EQ(seen[w], N);
}

TEST(histogram_buckets)
{
	ASSERT_EQ(bst_histogram_bucket_index(0), 0);
	ASSERT_EQ(bst_histogram_bucket_index(1), 1);
	ASSERT_EQ(bst_histogram_bucket_index(3), 3);
	ASSERT_EQ(bst_histogram_bucket_index(4), 4);
	ASSERT_EQ(bst_histogram_bucket_index(7), 7);
	ASSERT_EQ(bst_histogram_bucket_index(8), 8);
	ASSERT_EQ(bst_histogram_bucket_index(9), 8);
	ASSERT_EQ(bst_histogram_bucket_index(10), 9);
	ASSERT_EQ(bst_histogram_bucket_index(15), 11);
	ASSERT_EQ(bst_histogram_bucket_index(16), 12);
	ASSERT_EQ(bst_histogram_bucket_index(UINT64_MAX), BST_HIST_BUCKETS - 1);
	ASSERT_EQ(bst_histogram_bucket_index((uint64_t)1 << 63), BST_HIST_BUCKETS - 4);
	ASSERT_EQ(bst_histogram_bucket_index(((uint64_t)1 << 63) - 1), BST_HIST_BUCKETS - 5);
	/* Every bucket's upper bound is its own last value, and the next value moves up. */
	for (unsigned b = 0; b < BST_HIST_BUCKETS; b++) {
		uint64_t up = bst_histogram_bucket_upper(b);
		ASSERT_EQ(bst_histogram_bucket_index(up), b);
		if (b + 1 < BST_HIST_BUCKETS)
			ASSERT_EQ(bst_histogram_bucket_index(up + 1), b + 1);
	}
	ASSERT(bst_histogram_bucket_upper(BST_HIST_BUCKETS - 1) == UINT64_MAX);

	bst_counters_reset_for_test();
	bst_counter_id h = bst_histogram_register("lat", "latency", "route=a");
	bst_histogram_observe(h, 0);
	bst_histogram_observe(h, 9);
	bst_histogram_observe(h, 10);
	bst_histogram_observe(h, UINT64_MAX);
	ASSERT_EQ(bst_histogram_count(h), 4);
	ASSERT_EQ(bst_histogram_bucket(h, 0), 1);
	ASSERT_EQ(bst_histogram_bucket(h, 8), 1);
	ASSERT_EQ(bst_histogram_bucket(h, 9), 1);
	ASSERT_EQ(bst_histogram_bucket(h, BST_HIST_BUCKETS - 1), 1);
	ASSERT_EQ(bst_histogram_bucket(h, BST_HIST_BUCKETS), 0);
	ASSERT(bst_histogram_sum(h) == 18); /* 0+9+10+MAX wraps to 18 */
}

TEST(counters_basic_and_duplicates)
{
	bst_counters_reset_for_test();
	bst_counter_id a = bst_counter_register("reqs", "requests", "code=200");
	bst_counter_id b = bst_counter_register("reqs", "requests", "code=404");
	bst_counter_id c = bst_counter_register("reqs", "other help", "code=200");
	ASSERT(a != BST_COUNTER_INVALID && b != a);
	ASSERT_EQ(c, a);
	bst_counter_add(a, 5);
	bst_counter_add(a, 2);
	ASSERT_EQ(bst_counter_get(a), 7);
	ASSERT_EQ(bst_counter_get(b), 0);
	/* Same name+labels, different kind: refused rather than aliased. */
	ASSERT_EQ(bst_histogram_register("reqs", "", "code=200"), BST_COUNTER_INVALID);
	/* Wrong-kind updates are no-ops. */
	bst_histogram_observe(a, 5);
	ASSERT_EQ(bst_counter_get(a), 7);
	ASSERT_EQ(bst_counter_register(NULL, "", NULL), BST_COUNTER_INVALID);
	char longname[BST_COUNTER_NAME_MAX + 1];
	memset(longname, 'n', sizeof longname);
	longname[sizeof longname - 1] = '\0';
	ASSERT_EQ(bst_counter_register(longname, "", NULL), BST_COUNTER_INVALID);
	bst_counter_add(12345, 1); /* out of range id */
}

TEST(counters_capacity)
{
	bst_counters_reset_for_test();
	char name[32];
	for (int i = 0; i < BST_COUNTER_MAX; i++) {
		snprintf(name, sizeof name, "c%d", i);
		ASSERT(bst_counter_register(name, "", NULL) != BST_COUNTER_INVALID);
	}
	bst_counter_id over = bst_counter_register("one_too_many", "", NULL);
	ASSERT_EQ(over, BST_COUNTER_INVALID);
	bst_counter_add(over, 1);
	bst_counter_add(BST_COUNTER_MAX, 1);
	ASSERT_EQ(bst_counter_get(over), 0);
	ASSERT_EQ(bst_counter_count(), BST_COUNTER_MAX);
	/* Existing names still resolve when full. */
	ASSERT_EQ(bst_counter_register("c7", "", NULL), 7);
	/* A full table still logs: the drop counter simply cannot register. */
	pipe_open(false, BST_LOG_DEBUG);
	bst_counters_reset_for_test();
	bst_histogram_register("h0", "", NULL);
	for (int i = 1; i <= BST_HIST_MAX; i++) {
		snprintf(name, sizeof name, "h%d", i);
		bst_counter_id h = bst_histogram_register(name, "", NULL);
		ASSERT_EQ(h == BST_COUNTER_INVALID, i == BST_HIST_MAX);
	}
	close(pfd[0]);
	close(pfd[1]);
}

static volatile sig_atomic_t handler_ran;
static bst_counter_id sig_id;
static void on_usr1(int s)
{
	(void)s;
	bst_counter_add(sig_id, 3);
	handler_ran = 1;
}

TEST(counter_add_from_signal_handler)
{
	bst_counters_reset_for_test();
	sig_id = bst_counter_register("sig", "", NULL);
	struct sigaction sa = { .sa_handler = on_usr1 };
	sigaction(SIGUSR1, &sa, NULL);
	raise(SIGUSR1);
	ASSERT(handler_ran);
	ASSERT_EQ(bst_counter_get(sig_id), 3);
	signal(SIGUSR1, SIG_DFL);
}

/* The crash handler's line: same prefix as bst_log, built with no libc formatting. */
TEST(safe_line_has_the_log_format)
{
	char buf[256], norm[256];
	pipe_open(false, BST_LOG_DEBUG);
	bst_log_set_tag("worker/3");
	bst_log(BST_LOG_ERROR, "normal");
	bst_log_safe_line(BST_LOG_ERROR, "crash: x", 8);
	bst_log_set_tag(NULL);
	pipe_drain(buf, sizeof buf);
	char *nl = strchr(buf, '\n');
	ASSERT(nl != NULL);
	memcpy(norm, buf, (size_t)(nl - buf));
	norm[nl - buf] = 0;
	/* 24 bytes of time, then "<pid> worker/3 ERROR ": identical up to the message. */
	char pid[32];
	snprintf(pid, sizeof pid, " %ld worker/3 ERROR ", (long)getpid());
	ASSERT(strstr(norm, pid) == norm + 24);
	ASSERT(strstr(nl + 1, pid) == nl + 1 + 24);
	ASSERT(strcmp(nl + 1 + 24 + strlen(pid), "crash: x\n") == 0);
	ASSERT(nl[1 + 10] == 'T' && nl[1 + 23] == 'Z');
}

/* A socket's description is shared with whoever holds it, so O_NONBLOCK is not an option:
 * send(MSG_DONTWAIT) gives the same promise per call. */
TEST(socket_sink_never_blocks)
{
	int sv[2];
	ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
	bst_log_init(sv[1], BST_LOG_INFO);
	bst_log_set_socket(true);
	uint64_t d0 = bst_log_dropped();
	for (int i = 0; i < 100000 && bst_log_dropped() == d0; i++)
		bst_log(BST_LOG_INFO, "%0900d", i);
	ASSERT(bst_log_dropped() > d0); /* full, and still here */
	ASSERT_EQ(fcntl(sv[1], F_GETFL) & O_NONBLOCK, 0);
	bst_log_set_socket(false);
	bst_log_init(2, BST_LOG_WARN);
	close(sv[0]);
	close(sv[1]);
}

TAP_MAIN()
