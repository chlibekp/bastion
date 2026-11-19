/* W3C Trace Context: see trace.h. */
#include "filters/trace.h"

#include "core/log.h"
#include "http/stream.h"
#include "proxy/handler.h"
#include "route/vars.h"

#include <string.h>
#include <sys/random.h>

#define TRACESTATE_MAX 512 /* the spec's limit a vendor must propagate at least */

static const char hexd[] = "0123456789abcdef";

static int hexval(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	return -1; /* upper case is invalid in traceparent */
}

static bool hex_bytes(const char *p, uint8_t *out, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		int hi = hexval(p[2 * i]), lo = hexval(p[2 * i + 1]);
		if (hi < 0 || lo < 0)
			return false;
		out[i] = (uint8_t)(hi << 4 | lo);
	}
	return true;
}

static bool all_zero(const uint8_t *b, size_t n)
{
	for (size_t i = 0; i < n; i++)
		if (b[i] != 0)
			return false;
	return true;
}

bool bst_traceparent_parse(bst_str v, bst_traceparent *tp)
{
	if (v.p == NULL || v.len < BST_TRACEPARENT_LEN)
		return false;
	const char *p = v.p;
	if (p[2] != '-' || p[35] != '-' || p[52] != '-')
		return false;
	bst_traceparent t;
	if (!hex_bytes(p, &t.version, 1) || t.version == 0xff)
		return false;
	if (t.version == 0 && v.len != BST_TRACEPARENT_LEN)
		return false;
	if (t.version != 0 && v.len > BST_TRACEPARENT_LEN && p[BST_TRACEPARENT_LEN] != '-')
		return false;
	if (!hex_bytes(p + 3, t.trace_id, 16) || !hex_bytes(p + 36, t.parent_id, 8) ||
	    !hex_bytes(p + 53, &t.flags, 1))
		return false;
	if (all_zero(t.trace_id, 16) || all_zero(t.parent_id, 8))
		return false;
	*tp = t;
	return true;
}

static char *put_hex(char *o, const uint8_t *b, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		*o++ = hexd[b[i] >> 4];
		*o++ = hexd[b[i] & 15];
	}
	return o;
}

void bst_traceparent_format(const bst_traceparent *tp, char *out)
{
	char *o = out;
	*o++ = '0';
	*o++ = '0';
	*o++ = '-';
	o = put_hex(o, tp->trace_id, 16);
	*o++ = '-';
	o = put_hex(o, tp->parent_id, 8);
	*o++ = '-';
	o = put_hex(o, &tp->flags, 1);
	*o = '\0';
}

/* Random non-zero bytes (the spec forbids an all-zero ID). False when getrandom fails. */
static bool random_id(uint8_t *b, size_t n)
{
	for (int tries = 0; tries < 4; tries++) {
		if (getrandom(b, n, 0) != (ssize_t)n)
			return false;
		if (!all_zero(b, n))
			return true;
	}
	return false;
}

static bool tracestate_ok(bst_str v)
{
	if (v.len == 0 || v.len > TRACESTATE_MAX)
		return false;
	for (uint32_t i = 0; i < v.len; i++) {
		unsigned char c = (unsigned char)v.p[i];
		if (c < 0x20 || c > 0x7e)
			return false;
	}
	return true;
}

static bst_str arena_hex(bst_stream *s, const uint8_t *b, size_t n)
{
	char *o = bst_arena_alloc(s->arena, 2 * n + 1);
	if (o == NULL)
		return (bst_str){ NULL, 0 };
	*put_hex(o, b, n) = '\0';
	return (bst_str){ o, (uint32_t)(2 * n) };
}

void bst_trace_apply(bst_stream *s)
{
	const bst_cfg_extras *x = &s->cfg->extras;
	if (!x->trace_context)
		return;
	static const bst_str tp_name = BST_S("traceparent"), ts_name = BST_S("tracestate");
	bst_headers *rq = &s->req.head.headers;
	bst_traceparent tp;
	bst_str state = { NULL, 0 };
	if (s->trace_id.p == NULL) {
		const bst_header *in = bst_headers_get_name(rq, tp_name);
		bool trusted = in != NULL && s->has_peer &&
			       bst_proxy_cidr_match(&x->trace_trust, &s->peer.ip);
		bool single = in != NULL && bst_headers_next_name(rq, in, tp_name) == NULL;
		bool keep = trusted && single && bst_traceparent_parse(in->value, &tp);
		if (keep) {
			const bst_header *st = bst_headers_get_name(rq, ts_name);
			if (st != NULL && bst_headers_next_name(rq, st, ts_name) == NULL &&
			    tracestate_ok(st->value))
				state = st->value;
		} else {
			memset(&tp, 0, sizeof tp);
			if (!random_id(tp.trace_id, sizeof tp.trace_id)) {
				bst_log(BST_LOG_WARN, "trace: getrandom failed, no trace context");
				(void)bst_headers_remove_name(rq, tp_name);
				(void)bst_headers_remove_name(rq, ts_name);
				return;
			}
		}
		if (!random_id(tp.parent_id, sizeof tp.parent_id)) {
			bst_log(BST_LOG_WARN, "trace: getrandom failed, no trace context");
			(void)bst_headers_remove_name(rq, tp_name);
			(void)bst_headers_remove_name(rq, ts_name);
			return;
		}
		s->trace_id = arena_hex(s, tp.trace_id, 16);
		s->span_id = arena_hex(s, tp.parent_id, 8);
		if (s->trace_id.p == NULL || s->span_id.p == NULL) {
			s->trace_id = s->span_id = (bst_str){ NULL, 0 };
			(void)bst_headers_remove_name(rq, tp_name);
			(void)bst_headers_remove_name(rq, ts_name);
			return;
		}
		s->trace_flags = tp.flags;
		if (state.p != NULL) {
			char *c = bst_arena_alloc(s->arena, state.len);
			s->tracestate = c != NULL ? (bst_str){ memcpy(c, state.p, state.len), state.len }
						  : (bst_str){ NULL, 0 };
		}
	} else { /* a re-route keeps the context it already has */
		(void)hex_bytes(s->trace_id.p, tp.trace_id, 16);
		(void)hex_bytes(s->span_id.p, tp.parent_id, 8);
		tp.flags = s->trace_flags;
	}
	(void)bst_headers_remove_name(rq, tp_name);
	(void)bst_headers_remove_name(rq, ts_name);
	char *out = bst_arena_alloc(s->arena, BST_TRACEPARENT_LEN + 1);
	if (out == NULL)
		return;
	bst_traceparent_format(&tp, out);
	(void)bst_headers_add(rq, tp_name, (bst_str){ out, BST_TRACEPARENT_LEN });
	if (s->tracestate.p != NULL)
		(void)bst_headers_add(rq, ts_name, s->tracestate);
}

static bst_str var_trace_id(const bst_var_ctx *c, bst_str sfx)
{
	(void)sfx;
	return c->s->trace_id.p != NULL ? c->s->trace_id : (bst_str){ "", 0 };
}

static bst_str var_span_id(const bst_var_ctx *c, bst_str sfx)
{
	(void)sfx;
	return c->s->span_id.p != NULL ? c->s->span_id : (bst_str){ "", 0 };
}

static const bst_var_def trace_vars[] = {
	{ "trace_id", var_trace_id, false },
	{ "span_id", var_span_id, false },
};
BST_VARS(trace_vars);
