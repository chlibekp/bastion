/* Test-build seams of the process model, all driven by BST_TEST_* environment variables and all
 * absent from a release binary (make check-release proves it). */
#ifndef BST_PROC_TEST_HOOKS_H
#define BST_PROC_TEST_HOOKS_H

#ifdef BST_TEST
#include "proc/worker.h"

#include <stdbool.h>
#include <stdint.h>

/* BST_TEST_WORKER_URING_FAIL=<slot>:<spec>: BST_TEST_URING_FAIL=<spec> for that worker's loop
 * only, after master's probe saw no failure. */
void bst_test_child_loop(int slot);
/* BST_TEST_WORKER_WATCH_DELAY_MS sleeps first, to open the window before the prctl. Returns
 * false under BST_TEST_NO_PDEATHSIG, which leaves the channel as the only watch. */
bool bst_test_child_watch(void);
/* BST_TEST_WORKER_CRASH=<slot|helper>:<segv|abort|stack|frames> dies here, at start. */
void bst_test_child_crash(int slot);
/* BST_TEST_WORKER_REPORT=1 logs what the allocator tests read. */
void bst_test_child_report(void);
/* BST_TEST_CHANNEL_GARBAGE=<slot>:<kind> writes a bad message to master after READY. True for
 * kind `close`, which shuts the channel down: the caller stops reading it. */
bool bst_test_channel_garbage(int slot, int fd);
/* BST_TEST_NO_CHANNEL_EOF: a worker ignores master's channel closing, which leaves
 * PR_SET_PDEATHSIG as the only watch. */
bool bst_test_ignore_channel_eof(void);
/* BST_TEST_RESPAWN_SCALE divides real respawn delays (default 1).
 * BST_TEST_RESPAWN_STABLE_MS replaces the stable-run time when set. */
uint64_t bst_test_respawn_delay(uint64_t ms);
uint64_t bst_test_stable_ms(uint64_t ms);

/* test_raw.c. BST_TEST_RAW_MODE=echo|slow|respond sets bst_worker_on_conn to a small protocol on
 * the real accept path, until Phase 4 has a handler. Task 9 reuses it.
 *   echo      writes back what it reads
 *   slow      sends BST_TEST_RAW_SLOW=<total>:<chunk>:<interval_ms> bytes of (offset % 251),
 *             default 4194304:65536:10
 *   respond   writes one fixed line and closes
 * BST_TEST_RAW_LOG_LINES=n also logs n long lines at warn level for each connection. */
void bst_test_raw_install(void);
#endif

#endif
