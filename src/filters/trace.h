/* W3C Trace Context (https://www.w3.org/TR/trace-context/), Phase 14 Task 5.
 *
 * With trace_context on, every request carries a valid traceparent upstream. An incoming
 * traceparent is kept (its trace ID, flags and tracestate) only when it is valid and the peer is
 * in trace_trust; otherwise a new trace ID is made and the client's traceparent and tracestate
 * are dropped. Either way the request gets a new span ID, the parent ID the upstream sees.
 * $trace_id and $span_id expose them to logs and header templates. No spans are exported. */
#ifndef BST_FILTERS_TRACE_H
#define BST_FILTERS_TRACE_H

#include "core/str.h"

#include <stdbool.h>
#include <stdint.h>

struct bst_stream;

typedef struct bst_traceparent {
	uint8_t version;
	uint8_t trace_id[16];
	uint8_t parent_id[8];
	uint8_t flags;
} bst_traceparent;

#define BST_TRACEPARENT_LEN 55 /* version 00: 2+1+32+1+16+1+2 */

/* Parses a traceparent field value. False (tp untouched) for anything the spec says to discard:
 * a wrong length, upper-case or non-hex digits, version ff, an all-zero trace or parent ID, or a
 * version 00 value with anything after the flags. A higher version is accepted when its first
 * four fields have the version 00 shape and anything after them starts with '-'. */
bool bst_traceparent_parse(bst_str v, bst_traceparent *tp);

/* Writes "00-<trace>-<parent>-<flags>" and a NUL into out (BST_TRACEPARENT_LEN + 1 bytes). The
 * version written is always 00, the only one this code knows. */
void bst_traceparent_format(const bst_traceparent *tp, char *out);

/* Router, after the request ID: sets s->trace_id and s->span_id and rewrites the traceparent
 * (and tracestate) request headers. Does nothing when trace_context is off. */
void bst_trace_apply(struct bst_stream *s);

#endif
