#include "core/log.h"

#include "core/counters.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

int bst_log_min_level_ = BST_LOG_WARN;
static int log_fd = 2;

/* Drop accounting never scans or allocates: bst_log_init registers the counter once
 * and caches its id (bst_counters_reset_for_test invalidates it). Until then, or when
 * the table was full, drops go to a private count that init folds into the counter. */
static bst_counter_id drop_id = BST_COUNTER_INVALID;
static uint64_t private_drops;

static const char *const level_name[] = { "DEBUG ", "INFO ", "WARN ", "ERROR " };

/* Already escaped; set once at startup, before threads or forks that log. */
static char log_tag[BST_LOG_TAG_MAX] = "-";

void bst_log_init(int fd, int level)
{
	if (level < BST_LOG_DEBUG)
		level = BST_LOG_DEBUG;
	if (level > BST_LOG_ERROR)
		level = BST_LOG_ERROR;
	log_fd = fd;
	bst_log_min_level_ = level;
	drop_id = bst_counter_register(BST_LOG_DROP_COUNTER, "Log lines dropped", NULL);
	if (drop_id != BST_COUNTER_INVALID)
		bst_counter_add(drop_id,
				__atomic_exchange_n(&private_drops, 0, __ATOMIC_RELAXED));
}

uint64_t bst_log_dropped(void)
{
	return __atomic_load_n(&private_drops, __ATOMIC_RELAXED) + bst_counter_get(drop_id);
}

static void count_drop(void)
{
	if (drop_id != BST_COUNTER_INVALID)
		bst_counter_add(drop_id, 1);
	else
		__atomic_fetch_add(&private_drops, 1, __ATOMIC_RELAXED);
}

/* Length of the valid, strictly encoded UTF-8 sequence at p (NUL terminated), or 0. */
static size_t utf8_len(const unsigned char *p)
{
	unsigned char b0 = p[0];
	#define CONT(x) (((x) & 0xC0) == 0x80)
	if (b0 >= 0xC2 && b0 <= 0xDF)
		return CONT(p[1]) ? 2 : 0;
	if (b0 >= 0xE0 && b0 <= 0xEF) {
		unsigned char lo = b0 == 0xE0 ? 0xA0 : 0x80;
		unsigned char hi = b0 == 0xED ? 0x9F : 0xBF;
		return (p[1] >= lo && p[1] <= hi && CONT(p[2])) ? 3 : 0;
	}
	if (b0 >= 0xF0 && b0 <= 0xF4) {
		unsigned char lo = b0 == 0xF0 ? 0x90 : 0x80;
		unsigned char hi = b0 == 0xF4 ? 0x8F : 0xBF;
		return (p[1] >= lo && p[1] <= hi && CONT(p[2]) && CONT(p[3])) ? 4 : 0;
	}
	#undef CONT
	return 0;
}

static size_t emit_hex(char *out, unsigned char c)
{
	static const char hex[] = "0123456789abcdef";
	out[0] = '\\';
	out[1] = 'x';
	out[2] = hex[c >> 4];
	out[3] = hex[c & 15];
	return 4;
}

/* Escape one unit at s into out (room for at least 4 bytes). Returns bytes written and
 * sets *used to input bytes consumed. */
static size_t escape_unit(const unsigned char *s, char *out, size_t *used)
{
	unsigned char c = s[0];
	*used = 1;
	switch (c) {
	case '\n': out[0] = '\\'; out[1] = 'n'; return 2;
	case '\r': out[0] = '\\'; out[1] = 'r'; return 2;
	case '\t': out[0] = '\\'; out[1] = 't'; return 2;
	case '\\': out[0] = '\\'; out[1] = '\\'; return 2;
	default: break;
	}
	if (c < 0x20 || c == 0x7F)
		return emit_hex(out, c);
	if (c < 0x80) {
		out[0] = (char)c;
		return 1;
	}
	size_t n = utf8_len(s);
	if (n == 0)
		return emit_hex(out, c);
	bool c1 = c == 0xC2 && s[1] >= 0x80 && s[1] <= 0x9F;
	bool lsep = c == 0xE2 && s[1] == 0x80 && (s[2] == 0xA8 || s[2] == 0xA9);
	if (c1 || lsep) {
		/* Escape the whole sequence so the visible text stays one unit. */
		size_t w = 0;
		for (size_t i = 0; i < n; i++)
			w += emit_hex(out + w, s[i]);
		*used = n;
		return w; /* at most 12 */
	}
	memcpy(out, s, n);
	*used = n;
	return n;
}

#define UNIT_MAX 12

void bst_log_set_tag(const char *tag)
{
	char out[BST_LOG_TAG_MAX];
	size_t pos = 0;
	for (size_t i = 0; tag != NULL && tag[i] != '\0';) {
		char unit[UNIT_MAX];
		size_t used;
		size_t w = escape_unit((const unsigned char *)tag + i, unit, &used);
		if (pos + w > sizeof out - 1)
			break;
		memcpy(out + pos, unit, w);
		pos += w;
		i += used;
	}
	if (pos == 0) {
		out[0] = '-';
		pos = 1;
	}
	out[pos] = '\0';
	memcpy(log_tag, out, pos + 1);
}

/* Civil date from days since 1970-01-01 (proleptic Gregorian; Howard Hinnant's
 * days_from_civil inverse). Pure arithmetic: glibc's gmtime_r reads TZ and may open
 * zoneinfo files and allocate, which a sandboxed worker's first log line cannot do. */
static void civil_from_days(int64_t z, int *y, int *m, int *d)
{
	z += 719468;
	int64_t era = (z >= 0 ? z : z - 146096) / 146097;
	int64_t doe = z - era * 146097;
	int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
	int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	int64_t mp = (5 * doy + 2) / 153;
	*d = (int)(doy - (153 * mp + 2) / 5 + 1);
	*m = (int)(mp < 10 ? mp + 3 : mp - 9);
	*y = (int)(yoe + era * 400 + (*m <= 2));
}

/* "YYYY-MM-DDTHH:MM:SS.mmmZ" (24 bytes plus NUL) for sec since the epoch, UTC. Years are
 * clamped to 0..9999 so the width is fixed. */
size_t bst_log_format_time_(char *out, size_t cap, int64_t sec, int ms)
{
	int64_t days = sec / 86400, rem = sec % 86400;
	if (rem < 0) {
		rem += 86400;
		days--;
	}
	int y, m, d;
	civil_from_days(days, &y, &m, &d);
	if (y < 0)
		y = 0;
	if (y > 9999)
		y = 9999;
	int n = snprintf(out, cap, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", y, m, d,
			 (int)(rem / 3600), (int)(rem % 3600 / 60), (int)(rem % 60), ms % 1000);
	return n < 0 ? 0 : (size_t)n;
}

/* "2026-11-05T12:34:56.789Z <pid> <tag> LEVEL ": UTC from CLOCK_REALTIME and plain
 * arithmetic (no time-zone call, no file access, no allocation), pid read on every line
 * so a forked child never logs its parent's pid. Returns bytes written. */
static size_t line_prefix(char *line, size_t cap, int level)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
		ts = (struct timespec){ 0, 0 };
	size_t n = bst_log_format_time_(line, cap, (int64_t)ts.tv_sec, (int)(ts.tv_nsec / 1000000));
	if (n == 0 || n >= cap)
		return n;
	int k = snprintf(line + n, cap - n, " %ld %s %s", (long)getpid(), log_tag, level_name[level]);
	return k < 0 ? n : n + (size_t)k;
}

/* Write line once (EINTR retried), never spinning and never raising SIGPIPE. On a
 * non-blocking fd it cannot block; regular files and blocking fds can still stall. */
static bool write_line(const char *line, size_t len)
{
	sigset_t pipe_set, old, pending;
	sigemptyset(&pipe_set);
	sigaddset(&pipe_set, SIGPIPE);
	/* Block SIGPIPE for this thread; remember whether one was already pending so we
	 * only consume the one our own write raised. */
	pthread_sigmask(SIG_BLOCK, &pipe_set, &old);
	sigpending(&pending);
	bool was_pending = sigismember(&pending, SIGPIPE) == 1;

	ssize_t w;
	do
		w = write(log_fd, line, len);
	while (w < 0 && errno == EINTR);
	bool epipe = w < 0 && errno == EPIPE;

	if (epipe && !was_pending) {
		struct timespec zero = { 0, 0 };
		while (sigtimedwait(&pipe_set, NULL, &zero) < 0 && errno == EINTR)
			;
	}
	pthread_sigmask(SIG_SETMASK, &old, NULL);
	return w >= 0 && (size_t)w == len;
}

void bst_log_write_(int level, const char *fmt, ...)
{
	int saved_errno = errno;
	if (level < BST_LOG_DEBUG)
		level = BST_LOG_DEBUG;
	if (level > BST_LOG_ERROR)
		level = BST_LOG_ERROR;

	char raw[BST_LOG_RAW_MAX];
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(raw, sizeof raw, fmt, ap);
	va_end(ap);
	size_t rawlen;
	bool truncated = false;
	if (n < 0) {
		rawlen = (size_t)snprintf(raw, sizeof raw, "(log format error)");
	} else if ((size_t)n >= sizeof raw) {
		rawlen = sizeof raw - 1;
		truncated = true;
	} else {
		rawlen = (size_t)n;
	}

	char line[BST_LOG_LINE_MAX];
	const size_t body_max = sizeof line - 1; /* room for the newline */
	const size_t mark_len = sizeof BST_LOG_TRUNC_MARK - 1;
	size_t pos = line_prefix(line, sizeof line, level);
	size_t mark_pos = pos; /* last unit boundary where the marker still fits */
	size_t i = 0;
	while (i < rawlen) {
		char unit[UNIT_MAX];
		size_t used;
		size_t w = escape_unit((const unsigned char *)raw + i, unit, &used);
		if (i + used > rawlen) { /* sequence straddles the raw cut: escape one byte */
			w = emit_hex(unit, (unsigned char)raw[i]);
			used = 1;
		}
		if (pos + w > body_max) {
			truncated = true;
			break;
		}
		memcpy(line + pos, unit, w);
		pos += w;
		i += used;
		if (pos + mark_len <= body_max)
			mark_pos = pos;
	}
	if (truncated) {
		if (pos + mark_len > body_max)
			pos = mark_pos;
		memcpy(line + pos, BST_LOG_TRUNC_MARK, mark_len);
		pos += mark_len;
	}
	line[pos++] = '\n';

	if (!write_line(line, pos))
		count_drop();
	errno = saved_errno;
}
