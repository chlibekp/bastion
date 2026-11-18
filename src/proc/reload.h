/* Zero-downtime reload (SIGHUP) by re-executing master in place.
 *
 * Master's subsystems (limits, cache, OCSP, upstream state, counters, XDP) are set up once,
 * before any fork, from one compiled config. Rather than teach every one of them to rebuild in a
 * running process, a reload runs the whole startup again in a fresh image of the same binary,
 * with the same PID, handing over what must not be lost:
 *
 *   1. Validate: the running binary checks the new config with `-t` in a child (parse, compile,
 *      backend probe). Failure is logged with the parse error, nothing changes, and the old
 *      generation keeps serving. The result is kept for the admin API (bst_reload_status).
 *   2. Hand over in BASTION_INHERIT: every listening socket (keyed by protocol, address and
 *      slot), the PID file and its lock, the shared memory regions whose contents must survive
 *      (session ticket keys, the block table), and every running child with its channel.
 *   3. execve(/proc/self/exe) with the original arguments. The PID stays, so a process manager,
 *      a container's PID 1 and the PID file are not disturbed, and the children stay ours.
 *   4. The new image starts its own generation on the inherited sockets (an unchanged address
 *      never stops accepting: it is the same socket), and only when every new child is ready
 *      tells the old generation to drain (graceful STOP: stop accepting, finish in-flight work)
 *      within shutdown_timeout, after which stragglers are killed.
 *
 * Documented limits. A listener whose slot count changed (a different `workers`) gets new
 * sockets, and connections queued in the removed sockets are reset. Rate limit zones, the cache
 * index, counters and upstream health start fresh: their layout follows the config. An XDP
 * filter without a bpffs pin is detached for the moment between exec and re-attach; with a pin
 * (the default) the new image adopts it with no gap. A failure after validation (a new port
 * already taken by another program) ends the server as it would at first start.
 * A cache_store keeps its disk files but its shared index starts fresh (whatever its size, so a
 * size change is no special case). The XDP lists of the new config replace the pinned ones in
 * place: the new image starts from their generation value and sweeps what was dropped.
 *
 * Draining: HTTP/1.1 connections finish their request with Connection: close, HTTP/2 ones get a
 * two-phase GOAWAY, and every open tunnel (WebSocket) gets its tunnel_drain_timeout, then closes.
 *
 * QUIC limits. Connections hand over only with `quic_routing ebpf`: under `quic_routing hash`
 * (no eBPF) the new generation's sockets take the old one's packets, and its connections fail.
 * Routing keys alternate between two halves of the socket map, so only the previous generation
 * keeps routing: a connection on a generation two reloads old loses its packets. With more than
 * 4096 workers both generations share the first half and the handoff is off. A new connection
 * whose Initial DCID happens to hash to a key of the draining generation (about
 * nworkers/65536 of them) is dropped while that generation drains.
 *
 * HUPs that arrive while a generation is still starting are coalesced into one more reload once
 * it is ready, and at most BST_RELOAD_MAX_OLD old processes are kept draining: beyond that the
 * oldest are killed, so rapid reloads cannot pile up generations. */
#ifndef BST_PROC_RELOAD_H
#define BST_PROC_RELOAD_H

#include "config/compile.h"

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#define BST_RELOAD_MAX_OLD 256

/* The arguments master was started with, saved by the CLI before anything can chdir (a relative
 * -c becomes absolute). Without them a reload is refused. */
void bst_reload_save_argv(int argc, char **argv);

/* The last reload's outcome: "none", "ok" or "failed: <reason>". */
const char *bst_reload_status(void);
void bst_reload_set_status(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* Runs `<exe> <args> -t` and reports whether the config is valid. 0, or -1 with the first lines
 * of its output in why. */
int bst_reload_validate(char *why, size_t cap);

/* ---- the hand-over ---- */

typedef struct bst_inherit_child {
	pid_t pid;
	int chan;
	int slot; /* -1: a helper */
} bst_inherit_child;

typedef struct bst_inherit_listener {
	char key[64]; /* "tcp 127.0.0.1 8080" */
	int nslots;
	int *fds;
	bool taken;
} bst_inherit_listener;

typedef struct bst_inherit_route {
	char key[64]; /* the `http3` listener's key */
	int fd[3];    /* socket map, active slots, stats (xdp/reuseport.h) */
} bst_inherit_route;

typedef struct bst_inherit {
	bool present;
	unsigned generation; /* 0 at first start */
	int pid_fd;
	bst_inherit_listener *listeners;
	size_t nlisteners;
	bst_inherit_child *olds;
	size_t nolds;
	bst_inherit_route *routes;
	size_t nroutes;
} bst_inherit;

/* Reads and removes BASTION_INHERIT, registering inherited shared memory with core/shm.c.
 * Called once at master start. A malformed value is ignored with a warning (a fresh start). */
const bst_inherit *bst_inherit_load(void);
/* The key of a listen address, as used in the hand-over. */
void bst_inherit_key(const bst_cfg_listen *l, char *buf, size_t cap);
/* Copies the inherited sockets for this listener into fds when the slot count matches and marks
 * them taken. true when it did. */
bool bst_inherit_take_listener(const bst_cfg_listen *l, int nslots, int *fds);
/* An `http3` listener is never taken: each generation binds fresh UDP sockets in the same
 * SO_REUSEPORT group at its own half of the routing keys (xdp/reuseport.h). The QUIC routing
 * maps (socket map, active slots, stats) are handed over instead, because a socket can be in one
 * socket map only and the draining generation's sockets are in the attached one: the new image
 * adds its sockets to that map and moves the active slots. true with the three fds (now the
 * caller's) when the previous image had them for this address. */
bool bst_inherit_take_route(const bst_cfg_listen *l, int fds[3]);
/* Closes inherited sockets no listener took (removed addresses, changed slot counts). */
void bst_inherit_close_untaken(void);

/* Builds the value of BASTION_INHERIT. Every fd named is made inheritable. Returns a malloc'd
 * string, or NULL when out of memory. */
typedef struct bst_inherit_out {
	unsigned generation;
	int pid_fd;
	const bst_cfg_listen **lcfg;
	int **lfds;
	size_t nlisteners;
	int nslots;
	const bst_inherit_child *kids;
	size_t nkids;
	const bst_inherit_route *routes;
	size_t nroutes;
} bst_inherit_out;
char *bst_inherit_encode(const bst_inherit_out *o);

/* execve of exe (NULL: the running binary) with the saved arguments and BASTION_INHERIT=value.
 * Returns only on failure, -1 with errno set. */
int bst_reload_exec(const char *exe, const char *value);

#endif
