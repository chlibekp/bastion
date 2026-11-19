/* Access logs (Phase 14, Task 3): non-blocking, structured, one line per request.
 *
 *   worker  bst_access_log runs when an HTTP/1.1, HTTP/2 or HTTP/3 stream is released (the
 *           cache's internal sink streams are not requests and are never logged). Each
 *           `access_log` of the stream's scope that passes its filters (errors_only=, sample=,
 *           if=) renders one line (ops/log_format.h) and pushes it into this worker's ring in
 *           shared memory. A full ring drops the line and counts it: a worker never waits for
 *           the disk.
 *   helper  drains every ring on a timer (log_flush_interval) and whenever a file's batch
 *           buffer fills, and writes each file's batch with one write(). A failed or short
 *           write (disk full, a deleted directory) drops the lines and counts them. It never
 *           opens a path: master opens every file before fork and hands reopened ones over the
 *           channel (BST_MSG_LOG_REOPEN). On STOP it drains what is left first; a graceful STOP
 *           (a reload's old generation) keeps draining until its workers have exited.
 *   master  opens the files (append, created 0640) and maps the rings before any fork. USR1
 *           reopens every file by path (logrotate) and passes the new descriptors to the helper.
 *
 * Ring records are one byte of file index then the line, newline included. Batches use write()
 * per file, not writev: each file's lines are copied into one contiguous buffer as they are
 * drained, so a single write() covers the batch (the plan's Step 3 says writev; see the commit).
 *
 * Dropped lines: bastion_log_dropped_total, and one warning a second at most in the helper's
 * error log with the running total. Workers add theirs to a shared counter in the ring region,
 * so the helper reports drops of every process. */
#ifndef BST_OPS_LOGGER_H
#define BST_OPS_LOGGER_H

#include "config/compile.h"
#include "io/loop.h"
#include "ops/log_format.h"
#include "route/vars.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BST_LOG_FILES_MAX 255 /* one index byte per record */
#define BST_LOG_STDOUT "stdout"

/* One `access_log` statement. file < 0 is `access_log off`. */
typedef struct bst_access_log {
	const char *path; /* NULL for off */
	const char *format_name;
	bst_cfg_loc loc;
	double sample;	  /* 1 logs every request */
	bool errors_only; /* status >= 400 only */
	const bst_tpl *cond; /* if=: logged when not empty and not "0", NULL when absent */
	const bst_logfmt *fmt; /* resolved by the post hook */
	int file;	       /* index into bst_cfg_logs.paths, -1 for off */
} bst_alog;

typedef struct bst_cfg_logs {
	bst_logfmt **formats;
	size_t nformats, formats_cap_;
	bst_alog **entries; /* every statement, for the post hook */
	size_t nentries, entries_cap_;
	const char **paths; /* unique files, in first-use order */
	size_t npaths, paths_cap_;
	uint64_t buffer;	    /* log_buffer: bytes of each worker's ring */
	uint64_t flush_ms;	    /* log_flush_interval */
	const char **headers;	    /* redacted headers: defaults, then log_redact_headers */
	size_t nheaders, headers_cap_;
	const char **params;	    /* log_redact_query_params */
	size_t nparams, params_cap_;
	bst_var_redact redact;
} bst_cfg_logs;

/* ---- master ---- */

/* Before any fork: opens every file and maps the rings for nworkers. 0 (also with no access
 * log configured), or -1 with e set. */
int bst_logger_setup(const bst_config *cfg, int nworkers, bst_err *e);
/* USR1: reopens every file by path. helper_chan is the helper's channel (-1: none running);
 * each new descriptor is passed to it. A file that fails to reopen keeps its old descriptor. */
void bst_logger_reopen(int helper_chan);
/* A worker of this generation exited (crashed or not): its ring gets nothing more. */
void bst_logger_worker_exited(int slot);
/* Releases master's descriptors and mappings at exit. */
void bst_logger_teardown(void);

/* ---- worker ---- */

/* In a forked worker: closes the files (the helper writes them) and attaches slot's ring. */
void bst_logger_worker_start(int slot);
/* Logs a finished request (no-op when nothing is configured or no response was sent). */
void bst_access_log(bst_stream *s);
/* The worker is about to exit: tells the helper its ring gets nothing more. */
void bst_logger_worker_exit(void);

/* ---- helper ---- */

void bst_logger_helper_start(bst_loop *l);
/* A descriptor passed with BST_MSG_LOG_REOPEN; takes ownership. */
void bst_logger_helper_reopened(unsigned file, int fd);
/* STOP: drains and returns true when the helper may exit now; false means it keeps draining
 * (graceful, workers still running) and exits by itself once they are done. */
bool bst_logger_helper_stop(bool graceful);

#endif
