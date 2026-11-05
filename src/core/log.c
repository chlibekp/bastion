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

/* Write line without ever blocking, spinning, or raising SIGPIPE. */
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
	size_t pos = (size_t)snprintf(line, sizeof line, "%s", level_name[level]);
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
