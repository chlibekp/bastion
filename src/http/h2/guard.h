/* HTTP/2 abuse budgets (RFC 9113 section 10.5; the attacks of CVE-2019-9511 to -9518, CVE-2023-44487
 * Rapid Reset, CVE-2024-27983 and the CONTINUATION family, CVE-2025-8671 MadeYouReset).
 *
 * Every attack of the family makes the server do work (or hold memory) that costs the client next
 * to nothing, so each kind of cheap client action has a budget: a leaky bucket that holds `rate`
 * events and drains `rate` events per second (http2_abuse { }). A well-behaved client stays far
 * inside it (a browser cancelling a page of streams is a burst, then silence); an attacker's
 * sustained flood empties it in about a second, and the connection is closed with
 * GOAWAY(ENHANCE_YOUR_CALM). Nothing here allocates. */
#ifndef BST_HTTP_H2_GUARD_H
#define BST_HTTP_H2_GUARD_H

#include "config/compile.h"

#include <stdbool.h>
#include <stdint.h>

typedef enum bst_h2_guard_kind {
	BST_H2G_RST = 0,	/* RST_STREAM from the client */
	BST_H2G_SERVER_RST,	/* a reset we sent because of what the client did */
	BST_H2G_SETTINGS,
	BST_H2G_PING,
	BST_H2G_EMPTY,		/* DATA, HEADERS or CONTINUATION without payload or END flag */
	BST_H2G_PRIORITY,
	BST_H2G_WINDOW_UPDATE,
	BST_H2G_KINDS
} bst_h2_guard_kind;

typedef struct bst_h2_guard {
	uint64_t level[BST_H2G_KINDS]; /* thousandths of an event */
	uint64_t last_ms[BST_H2G_KINDS];
	uint64_t hits[BST_H2G_KINDS];  /* times a budget ran out on this connection */
} bst_h2_guard;

/* The metric label of a kind: "rst", "server_reset", "settings", "ping", "empty", "priority",
 * "window_update", and for the two limits that are not buckets "continuation" and "control_queue". */
const char *bst_h2_guard_name(unsigned kind);

/* Charges one event of kind at time now_ms. True when the budget is exhausted: the caller
 * closes the connection with ENHANCE_YOUR_CALM. */
bool bst_h2_guard_charge(bst_h2_guard *g, const bst_cfg_h2_abuse *cfg, bst_h2_guard_kind kind,
			 uint64_t now_ms);

/* Counts a guard hit (the metric bastion_h2_abuse_total{kind}) and tells the Phase 12 escalation
 * hook, a no-op until it exists. kind is a bst_h2_guard_kind, or one of the extra kinds: the two
 * HTTP/2 limits that are not buckets, and the HTTP/3 ones (http/h3/h3_bridge.c), which charge the
 * same http2_abuse buckets: "stream_reset" (client RESET_STREAM or STOP_SENDING on requests, the
 * HTTP/3 Rapid Reset; budget rst_rate), "qpack" (a QPACK stream error) and "control_stream" (a
 * control-stream error, including closing it). */
enum {
	BST_H2G_CONTINUATION = BST_H2G_KINDS,
	BST_H2G_CONTROL_QUEUE,
	BST_H3G_STREAM_RESET,
	BST_H3G_QPACK,
	BST_H3G_CONTROL_STREAM,
	BST_H2G_ALL_KINDS
};
void bst_h2_guard_hit(unsigned kind);

/* Registers the counters. Master, before any fork. */
void bst_h2_guard_init(void);

#endif
