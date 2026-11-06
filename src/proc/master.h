/* The master process: owns listeners, supervises children, never touches client bytes.
 *
 * Master stays in a small poll(2) loop over a signalfd and one channel per child. It forks one
 * helper and one worker per slot. TERM and INT stop fast, QUIT stops gracefully within
 * shutdown_timeout, and HUP and USR2 are logged and ignored until Phase 14 gives them reload and
 * upgrade. A child's death is seen through SIGCHLD and every child is reaped with
 * waitpid(-1, WNOHANG) in a loop, since signals coalesce.
 *
 * Slots. Master keeps a copy of every listening socket, so a slot with no worker keeps queueing:
 * respawn loses nothing and the queue is not drained on a worker's death. The first crash
 * respawns at once; further crashes back off exponentially to BST_RESPAWN_MAX_MS, and a child
 * that ran for BST_RESPAWN_STABLE_MS starts counting from one again. While a slot is in backoff
 * the connections the kernel hashes to it WAIT in its accept queue. Master logs that at error
 * level with the slot and the backoff. Phase 13's reuseport program can route around dead slots.
 *
 * Startup. A child exiting BST_EXIT_STARTUP before every worker first reported ready ends the
 * server with status 1. Every worker must run the same backend: a worker that falls back under
 * `backend auto` moves all of them to epoll, by a graceful replacement that does not count as a
 * crash.
 *
 * The channel. Messages are typed and length-checked (channel.h). A malformed or out-of-place
 * message gets its sender killed, and master carries on: a compromised worker wrote it. */
#ifndef BST_PROC_MASTER_H
#define BST_PROC_MASTER_H

#include "config/compile.h"

#include <stdint.h>

#define BST_RESPAWN_BASE_MS 250u     /* delay after the second crash in a row; the first has none */
#define BST_RESPAWN_MAX_MS 30000u
#define BST_RESPAWN_STABLE_MS 60000u /* a child that ran this long is no longer crash looping */
#define BST_FAST_STOP_MS 2000u       /* after a fast stop, children still here are killed */
#define BST_CHAN_EOF_GRACE_MS 1000u  /* a child alive this long after closing its channel is killed */
#define BST_CHAN_BUDGET 16u          /* messages per child per wakeup: a flood cannot starve master */

/* Runs the server in the foreground. Returns the exit status: 0 after a requested stop, 1 when
 * startup failed (the reason is on stderr and in the error log). */
int bst_master_run(bst_config *cfg);

/* The delay before respawning a child on its crashes-th crash in a row. */
uint64_t bst_respawn_backoff_ms(unsigned crashes);

#endif
