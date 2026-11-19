/* Prometheus metrics (Phase 14, Task 4).
 *
 *   storage  every bst_counter_* lives in the `metrics` shared region (core/counters.h): one
 *            cache-line-aligned slot of values per process, kept across reload and live
 *            upgrade, so totals never go down (a crashed worker's slot is reused by its
 *            respawn, a reload's new image attaches the same region).
 *   workers  bst_metrics_request counts each finished client request with relaxed atomic adds
 *            into ids registered by master before fork: no lock, no allocation, no syscall.
 *   helper   serves the scrape: master creates and binds the `metrics { listen }` socket
 *            (handed to the next image across a reload or upgrade exec, so it never closes) and
 *            the helper accepts on it, renders the text exposition format 0.0.4 by summing
 *            every slot, and answers. Workers never take part in a scrape.
 *
 * Off by default: without a `metrics {}` block nothing listens. The listener defaults to
 * 127.0.0.1:9145 and is never one of the public `server` listeners; a listen address that is
 * not loopback draws a warning at load (and in `-t`). `allow` restricts the peers, `auth_basic`
 * asks for a user of an auth_basic_file style list.
 *
 * Cardinality is bounded by the configuration: the `server` label takes the first name of a
 * configured server only when the request's Host matched one of its names, else `_other`;
 * `location` (per_location on) takes the location's pattern. Names a client sends never
 * become label values. Label values are reduced to [A-Za-z0-9._*~/-]; anything else is `_`. */
#ifndef BST_OPS_METRICS_H
#define BST_OPS_METRICS_H

#include "config/compile.h"
#include "core/addr.h"
#include "core/cidr.h"
#include "io/loop.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BST_METRICS_DEFAULT_PORT 9145
#define BST_METRICS_ALLOW_MAX 64

typedef struct bst_cfg_metrics {
	bst_sockaddr listen;
	const char *path; /* "/metrics" */
	bst_cidr allow[BST_METRICS_ALLOW_MAX];
	size_t nallow;	  /* 0: every peer that reaches the listener */
	const char *auth_file; /* NULL: no authentication */
	bool per_location;
} bst_cfg_metrics;

struct bst_stream;
struct bst_runtime;

/* ---- master ---- */

/* Before any fork, after the inherited state is loaded: moves the counters to the kept shared
 * region, registers the request series of cfg, and with a `metrics {}` block binds its
 * listener and loads the users. 0, or -1 with e set. */
int bst_metrics_setup(const bst_config *cfg, bst_err *e);
/* Master's own gauges. */
void bst_metrics_reload_result(bool ok);
void bst_metrics_worker_restart(void);
void bst_metrics_teardown(void);
/* Around master's exec of the next image (proc/reload.c): the listener is handed over in
 * BASTION_METRICS_FD, so the socket and its queue live on; undone when exec fails. */
void bst_metrics_before_exec(void);
void bst_metrics_exec_failed(void);

/* ---- children ---- */

/* First thing in a forked child: picks its counter slot (slot < 0: the helper); a worker
 * closes the metrics listener. */
void bst_metrics_child_start(int slot);
/* A worker: counts a finished client request. */
void bst_metrics_request(const struct bst_stream *s);

/* ---- helper ---- */

void bst_metrics_helper_start(bst_loop *l, const struct bst_runtime *rt);
/* STOP: closes the listener, so a reload's new helper takes every new scrape. */
void bst_metrics_helper_stop(void);
/* No scrape in flight. When the helper may exit but one is, it asks to exit once they are done
 * (bounded by the 10 s connection timeout). */
bool bst_metrics_helper_idle(void);
void bst_metrics_helper_exit_when_idle(void);

/* ---- exposition (also for tests) ---- */

/* Renders every registered series into a malloc'd buffer (*len bytes, NUL-terminated). NULL
 * on allocation failure. conns < 0 leaves out bastion_connections; attack < 0 leaves out
 * bastion_under_attack. */
char *bst_metrics_render(size_t *len, int64_t conns, int attack);
/* Reduces s to the label-value alphabet into out (cap > 0), NUL-terminated. */
void bst_metrics_label_value(const char *s, char *out, size_t cap);

#endif
