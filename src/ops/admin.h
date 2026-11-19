/* The local admin API (Phase 14, Task 6), and the mailbox between the helper and master.
 *
 *   off      without an `admin {}` block nothing listens. There is never a network listener:
 *            the API is HTTP/1.1 over a Unix socket only.
 *   access   master (root) binds the socket before any fork, under a umask that leaves it
 *            unreachable until it is chmod'ed to `mode` (default 0600) and chown'ed to
 *            root:`group`. A mode that gives other users any access is refused at load. The
 *            kernel enforces the mode at connect; the helper also reads SO_PEERCRED, accepts
 *            uid 0, the socket's owner, or (with `group`) whoever the mode let in, and logs the
 *            peer's pid, uid and gid for every write action. No password or token exists, so none
 *            can leak or be hard-coded: the file mode is the credential, as for the Docker or
 *            containerd sockets.
 *   serving  the helper accepts and parses requests (sandboxed, it holds no master state); what
 *            needs master (status, reload, upgrade, the block list) goes into a shared mailbox
 *            and master is told over the helper's channel (BST_MSG_ADMIN). Master copies the
 *            request out before it reads it and validates every field (the helper is less
 *            trusted than master), acts, writes the answer and replies BST_MSG_ADMIN_DONE. One
 *            request is in flight at a time; another client meanwhile gets 503.
 *   reload   the listener is handed to the next image in BASTION_ADMIN_FD, like the metrics
 *            listener, so the socket file and its queue survive reload and live upgrade.
 *
 * Endpoints: GET /status, POST /reload, POST /upgrade, GET|POST|DELETE /blocks. The rest of the
 * spec's list (/config, /upstreams, /cache/purge, /maintenance, /challenge) answers 501 for now
 * (TODO: Phase 14 Task 6 follow-up; each needs a runtime override in shared state that the
 * workers read, which does not exist yet).
 * Runtime changes (blocks) are not written to the configuration: a block lives in master's list
 * (and the XDP maps) until its TTL ends or a reload resets the list (docs/admin-api.md). */
#ifndef BST_OPS_ADMIN_H
#define BST_OPS_ADMIN_H

#include "core/err.h"
#include "io/loop.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

struct bst_config;
struct bst_runtime;

typedef struct bst_cfg_admin {
	const char *socket; /* absolute path */
	uint32_t mode;	    /* 0600 */
	const char *group;  /* NULL: root's */
} bst_cfg_admin;

#define BST_ADMIN_DEFAULT_SOCKET "/run/bastion/admin.sock"
#define BST_ADMIN_BODY_MAX (1u << 20) /* an answer's body, at most */

typedef enum bst_admin_op {
	BST_ADMIN_STATUS = 1,
	BST_ADMIN_RELOAD,
	BST_ADMIN_UPGRADE,
	BST_ADMIN_BLOCKS,
	BST_ADMIN_BLOCK,
	BST_ADMIN_UNBLOCK,
	BST_ADMIN_OP_MAX_,
} bst_admin_op;

/* What the helper writes into the mailbox. Master treats it as hostile. */
typedef struct bst_admin_req {
	uint32_t op;	 /* bst_admin_op */
	uint32_t prefix; /* BLOCK, UNBLOCK */
	uint8_t family;	 /* 4 or 6 */
	uint8_t addr[16];
	uint64_t ttl_us; /* BLOCK */
	int32_t peer_pid; /* SO_PEERCRED, for master's log */
	uint32_t peer_uid, peer_gid;
} bst_admin_req;

/* ---- master ---- */

/* Before any fork: with an `admin {}` block, creates the mailbox and binds (or takes over) the
 * socket. 0, or -1 with e set. */
int bst_admin_setup(const struct bst_config *cfg, bst_err *e);
/* Around master's exec of the next image (proc/reload.c), as bst_metrics_before_exec. */
void bst_admin_before_exec(void);
void bst_admin_exec_failed(void);
void bst_admin_teardown(void);
/* A BST_MSG_ADMIN from the helper: copies the request of sequence seq out of the mailbox and
 * validates it. False for a stale sequence or a malformed request (logged). */
bool bst_admin_take(unsigned seq, bst_admin_req *out);
/* Writes the answer of sequence seq (body truncated to BST_ADMIN_BODY_MAX). The caller sends
 * BST_MSG_ADMIN_DONE. */
void bst_admin_answer(unsigned seq, int status, const char *body, size_t len);

/* ---- children ---- */

/* First thing in a forked child: a worker closes the admin listener. */
void bst_admin_child_start(int slot);

/* ---- helper ---- */

void bst_admin_helper_start(bst_loop *l, const struct bst_runtime *rt);
/* BST_MSG_ADMIN_DONE: answers the waiting client. */
void bst_admin_helper_done(unsigned seq);
/* STOP: closes the listener (the next generation's helper takes new clients). */
void bst_admin_helper_stop(void);
bool bst_admin_helper_idle(void);

#endif
