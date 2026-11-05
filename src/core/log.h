/* Error log. One call is exactly one line, written with a single write(2).
 *
 * The whole formatted message, %s arguments included, is escaped: backslash, control
 * bytes, DEL, C1 controls, U+2028/2029 and any byte that is not part of a valid UTF-8
 * sequence appear as \n \r \t \\ or \xHH text. Valid UTF-8 passes through. Output is
 * "LEVEL message\n"; a message that does not fit BST_LOG_LINE_MAX is cut at an escape
 * boundary and ends with BST_LOG_TRUNC_MARK. Never blocks: EAGAIN, a short write or
 * any other error drops the line and bumps the bst_log_dropped_total counter. SIGPIPE
 * is absorbed without touching the process's signal disposition. errno is preserved.
 *
 * Error paths only; request-rate events go through the Phase 14 ring. */
#ifndef BST_CORE_LOG_H
#define BST_CORE_LOG_H

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

/* Set the destination and minimum level. May be called again. Before the first call,
 * logs go to stderr at BST_LOG_WARN. fd ownership stays with the caller. */
void bst_log_init(int fd, int level);

/* Lines dropped so far. Counts drops from before init and while the counter table was
 * full too. */
uint64_t bst_log_dropped(void);

extern int bst_log_min_level_; /* read by the bst_log macro; use bst_log_init to set */

void bst_log_write_(int level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

/* Disabled levels evaluate none of the format arguments. */
#define bst_log(level, ...)                                                             \
	do {                                                                            \
		if ((int)(level) >= bst_log_min_level_)                                 \
			bst_log_write_((int)(level), __VA_ARGS__);                      \
	} while (0)

#endif
