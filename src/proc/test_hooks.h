/* Test-build seams of the process model, all driven by BST_TEST_* environment variables and all
 * absent from a release binary (make check-release proves it). */
#ifndef BST_PROC_TEST_HOOKS_H
#define BST_PROC_TEST_HOOKS_H

#ifdef BST_TEST
#include "proc/worker.h"

#include <stdbool.h>
#include <stdint.h>

/* BST_TEST_WORKER_URING_FAIL=<slot>:<spec>: BST_TEST_URING_FAIL=<spec> for that worker's loop
 * only, after master's probe saw no failure. BST_TEST_HELPER_DELAY_MS holds the helper back
 * first, so its failure comes after every worker is ready. */
void bst_test_child_loop(int slot);
/* BST_TEST_WORKER_WATCH_DELAY_MS sleeps first, to open the window before the prctl. Returns
 * false under BST_TEST_NO_PDEATHSIG, which leaves the channel as the only watch. */
bool bst_test_child_watch(void);
/* BST_TEST_WORKER_CRASH=<slot|helper>:<segv|abort|stack|frames|heap> dies here, at start (heap: an ASan overflow report). */
void bst_test_child_crash(int slot);
/* BST_TEST_WORKER_EXIT78=<path>: when path exists, removes it and exits 78, as a child that
 * cannot start. Call as early as a crash would come. */
void bst_test_child_exit78(void);
/* BST_TEST_WORKER_REPORT=1 logs what the allocator, drop-order and tty tests read.
 * BST_TEST_WORKER_SQ_CONNECT=<path>[,<path>] also connects a unix socket to each path through the
 * loop's SQ ring and logs the result: CONNECT is an opcode restrictions leave open, and a socket
 * file's mode is checked against the credentials of whoever runs the request. */
void bst_test_child_report(bst_loop *l);
/* BST_TEST_AIO_CRASH=<slot>:<segv|abort|stack> runs that fault on a pool thread. */
void bst_test_child_aio_crash(int slot, bst_loop *l);
/* BST_TEST_DROP_FAIL=<setgroups|setgid|setuid|regain>: that step of the drop fails. */
bool bst_test_drop_fails(const char *step);
/* BST_TEST_DROPPED_URING_FAIL=<spec>: BST_TEST_URING_FAIL=<spec> from the privilege drop on, the
 * way kernel.io_uring_disabled=1 refuses rings to an unprivileged process only. */
void bst_test_child_dropped(void);
/* BST_TEST_CHANNEL_GARBAGE=<slot>:<kind> writes a bad message to master after READY. True for
 * kind `close`, which shuts the channel down: the caller stops reading it. Kind `ready_on_stop`
 * sends nothing yet: bst_test_channel_on_stop writes a READY when the STOP arrives. */
bool bst_test_channel_garbage(int slot, int fd);
void bst_test_channel_on_stop(int slot, int fd);
/* BST_TEST_NO_CHANNEL_EOF: a worker ignores master's channel closing, which leaves
 * PR_SET_PDEATHSIG as the only watch. */
bool bst_test_ignore_channel_eof(void);
/* BST_TEST_RESPAWN_SCALE divides real respawn delays (default 1).
 * BST_TEST_RESPAWN_STABLE_MS replaces the stable-run time when set. */
uint64_t bst_test_respawn_delay(uint64_t ms);
uint64_t bst_test_stable_ms(uint64_t ms);
/* BST_TEST_STARTUP_DEADLINE_MS replaces the startup deadline when set. */
uint64_t bst_test_startup_deadline(uint64_t ms);

/* BST_TEST_SANDBOX_FAIL=<step>:<n>: n for this step of the sandbox (a nonzero errno, for tsync a
 * thread id), else 0. Steps: tsync, seccomp, landlock, namespaces. */
int bst_test_sandbox_fail(const char *step);
/* BST_TEST_MASTER_LEAK: loses a block on master's way out, for its leak check to find. */
void bst_test_master_leak(void);
/* tests/fixtures/sandbox_probe.c, which says what they do. claim runs first thing in a child,
 * prepare before the sandbox, probe_ring before the loop has anything armed, probe after READY. */
void bst_test_sandbox_claim(int slot);
void bst_test_sandbox_prepare(bst_loop *l);
void bst_test_sandbox_probe_ring(void);
void bst_test_sandbox_probe(void);

/* test_raw.c. BST_TEST_RAW_MODE=echo|slow|respond|budget sets bst_worker_on_conn to a small
 * protocol on the real accept path, until Phase 4 has a handler.
 *   echo      writes back what it reads
 *   slow      sends BST_TEST_RAW_SLOW=<total>:<chunk>:<interval_ms> bytes of (offset % 251),
 *             default 4194304:65536:10
 *   respond   writes one fixed line and closes
 *   budget    overload protection (limits { }): holds BST_TEST_RAW_MEM=<bytes> of touched memory
 *             per connection against worker_memory and answers with the fixed line, then keeps
 *             the connection until the peer closes. Over budget (bst_overloaded, or a refused
 *             charge) it answers `HTTP/1.1 <overload_status>` with Retry-After and closes.
 * BST_TEST_RAW_LOG_LINES=n also logs n long lines at warn level for each connection. */
void bst_test_raw_install(void);
#endif

#endif
