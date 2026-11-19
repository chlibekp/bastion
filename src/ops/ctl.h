/* bastionctl: the operator's command line, the same binary run under that name (argv[0]).
 *
 * Phase 14 Task 2 provides `bastionctl upgrade`, which drives a live binary upgrade through
 * master's signals (proc/upgrade.h) and its PID file:
 *
 *   bastionctl upgrade (-p pidfile | -c config) [--timeout s] [--settle s] [--check host:port]
 *
 * USR2 to the master named by the PID file; waits for <pid>.oldbin (the new binary passed its
 * check and was started), then for the PID file to name the new master (every new worker is
 * ready); optionally checks that host:port accepts a TCP connection; WINCH (the old workers
 * drain); watches the new master for --settle seconds; then QUIT (the old master exits). When the
 * new master fails or the check fails, it sends HUP (rollback: the old master serves alone again)
 * and exits 1. Signals reach only what the caller may signal; the binary that runs is the one at
 * master's own path, never one named here. Task 6 adds the admin API and the other commands. */
#ifndef BST_OPS_CTL_H
#define BST_OPS_CTL_H

/* argv[0] is "bastionctl" (or a path ending in it). Exit status: 0 done, 1 failed (rolled back
 * or refused), 2 usage error. */
int bst_ctl_main(int argc, char **argv);

#endif
