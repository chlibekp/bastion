/* Error log. One call is exactly one line, written with a single write(2).
 *
 * The whole formatted message, %s arguments included, is escaped: backslash, control
 * bytes, DEL, C1 controls, U+2028/2029 and any byte that is not part of a valid UTF-8
 * sequence appear as \n \r \t \\ or \xHH text. Valid UTF-8 passes through.
 *
 * Line format: "2026-11-05T12:34:56.789Z <pid> <tag> LEVEL message\n". The time is UTC
 * (CLOCK_REALTIME), the pid is read on every line so it is right after fork, and the tag
 * is set by bst_log_set_tag (default "-"). The timestamp, pid and tag count toward
 * BST_LOG_LINE_MAX; a message that does not fit is cut at an escape boundary and ends
 * with BST_LOG_TRUNC_MARK.
 *
 * Blocking: the single write(2) is retried only on EINTR, never spun on. On a
 * non-blocking fd it never blocks: EAGAIN, a short write or any other error drops the
 * line and bumps the bst_log_dropped_total counter. On a blocking fd (including a
 * regular file or a full blocking pipe) write(2) itself can stall, and that is the
 * caller's to avoid: pass a non-blocking fd to bst_log_init. A regular file is always
 * "ready", so non-blocking mode does not help there: a write to a file can still stall
 * (slow or full disk) and the line then waits. SIGPIPE is absorbed
 * without touching the process's signal disposition. errno is preserved.
 *
 * Error paths only; request-rate events go through the Phase 14 ring. */
#ifndef BST_CORE_LOG_H
#define BST_CORE_LOG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum bst_log_level {
	BST_LOG_DEBUG = 0,
	BST_LOG_INFO = 1,
	BST_LOG_WARN = 2,
	BST_LOG_ERROR = 3,
};

#define BST_LOG_LINE_MAX 1024 /* bytes written per line, newline included */
#define BST_LOG_RAW_MAX 1024  /* bytes of formatted message considered, before escaping */
#define BST_LOG_TRUNC_MARK "...[truncated]"
#define BST_LOG_DROP_COUNTER "bst_log_dropped_total"

#define BST_LOG_TAG_MAX 32 /* bytes kept for the tag after escaping, NUL included */

/* Name of this process in every line ("master", "worker/3", "helper"). Copied, escaped
 * like message text and cut at an escape boundary to fit. NULL or empty gives "-".
 * Call it at startup, before other threads log. */
void bst_log_set_tag(const char *tag);

/* Set the destination and minimum level. May be called again. Before the first call,
 * logs go to stderr at BST_LOG_WARN. fd ownership stays with the caller. */
void bst_log_init(int fd, int level);

/* The fd is a socket: write with send(MSG_DONTWAIT), so a full socket drops the line. A socket's
 * description is shared with whoever else holds it and cannot be reopened, so O_NONBLOCK is
 * not an option there; the flag makes the promise per call instead. Set it with the fd. */
void bst_log_set_socket(bool on);
/* The destination set by bst_log_init (2 before it). */
int bst_log_fd(void);

/* One line in the same format, for the crash handler: async-signal-safe (no stdio, no locale,
 * no allocation, no libc formatting). msg is written as given, so it must be plain ASCII without
 * a newline; a line that does not fit in 256 bytes is cut. No drop accounting. */
void bst_log_safe_line(int level, const char *msg, size_t len);

/* Lines dropped so far. Counts drops from before init and while the counter table was
 * full too. */
uint64_t bst_log_dropped(void);

#ifdef BST_TEST
/* Test builds: the timestamp formatter ("YYYY-MM-DDTHH:MM:SS.mmmZ"), for sweeps. */
size_t bst_log_format_time_(char *out, size_t cap, int64_t sec, int ms);
#endif

extern int bst_log_min_level_; /* read by the bst_log macro; use bst_log_init to set */

void bst_log_write_(int level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

/* Disabled levels evaluate none of the format arguments. */
#define bst_log(level, ...)                                                             \
	do {                                                                            \
		if ((int)(level) >= bst_log_min_level_)                                 \
			bst_log_write_((int)(level), __VA_ARGS__);                      \
	} while (0)

#endif
