/* systemd integration without libsystemd (packaging/bastion.service).
 *
 * Notify. bst_sd_notify sends one datagram to $NOTIFY_SOCKET (a path, or "@name" in the abstract
 * namespace); nothing happens when it is unset. Master sends READY=1 once a generation serves,
 * RELOADING=1 with MONOTONIC_USEC when a reload starts (READY=1 again when it ends, failed or
 * not), STOPPING=1 when it stops, STATUS= lines, and during a live upgrade the old master sends
 * MAINPID=<new> on commit (or MAINPID=<self> on rollback): with NotifyAccess=main only the main
 * process is heard, so the new master's own messages count from that moment.
 *
 * Watchdog. With WatchdogSec= systemd sets WATCHDOG_USEC (and WATCHDOG_PID). Master sends
 * WATCHDOG=1 at half the interval from its event loop, so a master that stops turning its loop
 * is restarted. WATCHDOG_PID may name the old master of a live upgrade, which is the new
 * master's parent: that counts as ours, so the pings continue after the MAINPID hand-over.
 *
 * Socket activation. With a .socket unit (packaging/bastion.socket.example) systemd passes
 * listening sockets from fd 3 (LISTEN_FDS, LISTEN_PID). At startup a TCP `listen` whose address
 * matches one of them uses it, duplicated for every worker slot, instead of binding its own;
 * a reload or an upgrade then carries it like any other listener. Sockets nothing matched are
 * closed with a warning. The variables are removed from the environment once read. */
#ifndef BST_PROC_SYSTEMD_H
#define BST_PROC_SYSTEMD_H

#include "config/compile.h"

#include <stdbool.h>
#include <stdint.h>

#define BST_SD_LISTEN_FDS_START 3

/* One notify datagram. 0 (sent, or no NOTIFY_SOCKET), or -1 (logged). */
int bst_sd_notify(const char *state);
/* The same with printf formatting. */
int bst_sd_notifyf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* The watchdog interval systemd expects pings within, in microseconds, or 0 when there is no
 * watchdog for this process. */
uint64_t bst_sd_watchdog_usec(void);

/* Reads LISTEN_FDS for this process once and removes it from the environment: the number of
 * sockets passed (0 without socket activation). */
int bst_sd_listen_fds(void);
/* Tests: adopt n sockets from fd first instead of reading the environment; first < 0 forgets,
 * so the next call reads the environment again. */
void bst_sd_listen_adopt_(int first, int n);
/* Fills fds[0..slots) from a passed socket with the listener's address and type: true when one
 * was used. */
bool bst_sd_take_listener(const bst_cfg_listen *l, int slots, int *fds);
/* Closes every passed socket no listener took. */
void bst_sd_close_untaken(void);

#endif
