#include "tap.h"

#include "core/counters.h"
#include "core/log.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/wait.h>
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

TEST(log_escapes_control)
{
	pipe_open(false, BST_LOG_DEBUG);
	const char *evil = "a\nb\r\x1b[31mred\x01\x7f\\";
	bst_log(BST_LOG_ERROR, "msg \n %s end", evil);
	char buf[512];
	pipe_drain(buf, sizeof buf);
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
		const char *p = buf + 6 + (size_t)pad;
		const char *end = buf + n - 1 - m;
		ASSERT(((size_t)(end - p)) % 4 == 0);
		for (; p < end; p += 4)
			ASSERT(memcmp(p, "\\x01", 4) == 0);
	}
}

TEST(log_short_message_not_marked)
{
	pipe_open(false, BST_LOG_DEBUG);
	char s[BST_LOG_LINE_MAX];
	memset(s, 'a', sizeof s);
	s[BST_LOG_LINE_MAX - 1 - 6] = '\0'; /* "ERROR " + body + "\n" == LINE_MAX exactly */
	bst_log(BST_LOG_ERROR, "%s", s);
	char buf[BST_LOG_LINE_MAX + 64];
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
	ASSERT(memcmp(buf, "ERROR fill 0 ", 13) == 0);
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
		ASSERT(sscanf(s, "ERROR w%d i%d %n", &cw, &ci, &used) == 2);
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

TAP_MAIN()
