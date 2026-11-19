/* Live binary upgrade (SIGUSR2), with rollback. Unlike a reload (proc/reload.h), which replaces
 * master's image in place, an upgrade keeps the old master running beside the new one until the
 * operator commits, so that a bad binary can be rolled back with nothing lost:
 *
 *   USR2   the old master opens the binary at the path it was started from (saved at start: the
 *          signal carries no path, so whoever may signal master can only run what an
 *          administrator installed there), refuses it unless it is a regular executable file
 *          owned by root or master's user and writable by nobody else (nor its directory, unless
 *          sticky), runs it with `-t` on the configuration, renames the PID file to
 *          <pid>.oldbin and forks it as a child, handing over in BASTION_INHERIT (format
 *          version first: BST_INHERIT_VERSION) the listening sockets, the kept shared memory
 *          (ticket keys, block table) and the QUIC routing maps. XDP is handed over through its
 *          bpffs pins (xdp/loader.h). The new master starts its own workers on the same sockets
 *          and, once every one is ready, writes its PID into the PID file. Both generations
 *          serve meanwhile.
 *   WINCH  the old master drains its workers (graceful stop) and does not respawn them. Its
 *          helper stays.
 *   QUIT   the old master stops gracefully and exits: the upgrade is committed. It tells a
 *          supervisor the new MAINPID (sd_notify) first, and leaves the shared state, XDP pins
 *          and links, and ticket keys to the new master.
 *   HUP    (before QUIT) rolls back: the old master starts its workers again, takes the XDP
 *          program and the QUIC routing back, renames <pid>.oldbin back and stops the new master
 *          (QUIT). A HUP with no upgrade in progress is a reload.
 *
 * A new master that fails (bad config, crash at start, a state format it does not read, which
 * exits with BST_EXIT_STATE) is reaped by the old one, which reports why, restores the PID file
 * and, if WINCH had drained them, its workers: it keeps serving. `bastionctl upgrade`
 * (ops/ctl.h) runs the sequence and rolls back by itself on failure.
 *
 * Limits: the XDP filter hands over without a gap only when pinned (the default pin_path on
 * bpffs). Rate limit zones, the cache index, counters and upstream health start fresh in the
 * new master, as on a reload. A slot whose worker was still draining when a rollback came waits
 * for it to exit (shutdown_timeout at most) before its new worker starts. */
#ifndef BST_PROC_UPGRADE_H
#define BST_PROC_UPGRADE_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

/* Records the absolute path of the running binary. Called once at start, before any chdir. */
void bst_upgrade_save_exe(void);
const char *bst_upgrade_exe(void);

/* Opens the binary at the saved path and checks that it may be run (see above). An fd
 * (close-on-exec), or -1 with the reason in why. */
int bst_upgrade_open_binary(char *why, size_t cap);
/* The ownership and mode checks on an open binary at path, for bst_upgrade_open_binary and the
 * unit tests. 0, or -1 with the reason in why. */
int bst_upgrade_check(int fd, const char *path, char *why, size_t cap);

/* Writes pid as the content of the open PID file. 0 or -1 (errno). */
int bst_pidfile_write(int fd, pid_t pid);
/* Whether path still names the file open as fd (a PID file that was renamed or replaced is not
 * ours to unlink). */
bool bst_pidfile_is(int fd, const char *path);

/* One datagram to $NOTIFY_SOCKET (path or abstract "@name"), nothing when it is unset. A
 * minimal sd_notify for the upgrade's MAINPID hand-over; Phase 14 Task 9 extends it. 0, or -1
 * (logged). */
int bst_upgrade_notify(const char *state);

#endif
