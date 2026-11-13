/* Where an HTTP/2 stream meets the HTTP semantics layer: a request header block becomes a bst_req
 * and a handler, and what the handler sends becomes HEADERS, DATA and trailers. Everything that
 * decides whether a request is acceptable is shared with the other protocols
 * (validate_pseudo.c, semantics.c, the router); this file adds only what HTTP/2 itself needs:
 * the connection policies (virtual host, 0-RTT, memory budget) and the mapping of responses. */
#include "http/h2/conn_priv.h"
#include "http/h3/altsvc.h"

#include "http/token.h"
#include "http/validate_pseudo.h"
#include "tls/conn.h"

#include <stdio.h>
#include <string.h>

#ifndef BST_VERSION
#define BST_VERSION "0.0.0"
#endif

#define S(bs) ((h2s *)(bs))
#define LIVE(s) (!(s)->c->closed && !(s)->dead && (!(s)->detached || (s)->own))

/* ---- responses ---- */

static bool conn_specific(bst_hdr_id id)
{
	return id == BST_H_CONNECTION || id == BST_H_KEEP_ALIVE || id == BST_H_PROXY_CONNECTION ||
	       id == BST_H_TRANSFER_ENCODING || id == BST_H_UPGRADE;
}

/* Encodes hs (HPACK state is shared by the whole connection, so the block goes into the output
 * queue at once, in wire order). */
static bool queue_block(h2c *c, uint32_t id, const bst_headers *hs, bool end)
{
	bst_h2_wr blk = { 0 };
	size_t before = c->ctl.len;
	int rc = bst_hpack_encode(&c->enc, hs, &blk);
	if (rc == 0)
		rc = bst_h2_write_headers(&c->ctl, id, blk.p, blk.len, end, c->peer_max_frame);
	bst_h2_wr_free(&blk);
	if (rc != 0) {
		c->ctl.len = before;
		h2c_conn_error(c, BST_H2_INTERNAL_ERROR);
		return false;
	}
	return h2c_queue_ok(c, 0);
}

static int h2_send_head(bst_stream *bs, const bst_resp_head *hin, bool end)
{
	h2s *s = S(bs);
	h2c *c = s->c;
	if (!LIVE(s) || s->head_sent || s->resp_done || hin->status < 200 || hin->status > 599)
		return -1;
	h2c_enter(c);
	int st = hin->status;
	s->no_body = s->is_head || st == 204 || st == 304;
	bst_headers hs;
	bst_headers_init(&hs, s->s.arena);
	char *sv = bst_arena_alloc(s->s.arena, 8);
	int rc = -1;
	if (sv == NULL)
		goto out;
	snprintf(sv, 8, "%d", st);
	bool ok = bst_headers_add(&hs, BST_S(":status"), (bst_str){ sv, 3 }) == 0;
	bool has_date = false, has_server = false;
	for (uint32_t i = 0; ok && i < hin->headers.n; i++) {
		const bst_header *h = &hin->headers.v[i];
		if (conn_specific(h->id) || h->id == BST_H_CONTENT_LENGTH || (h->name.len > 0 && h->name.p[0] == ':'))
			continue;
		has_date |= h->id == BST_H_DATE;
		has_server |= h->id == BST_H_SERVER;
		ok = bst_headers_add(&hs, h->name, h->value) == 0;
	}
	if (ok && !has_date) {
		bst_str d = bst_http_date(); /* valid until the next call: encoded below, before any other */
		ok = bst_headers_add(&hs, BST_S("date"), d) == 0;
	}
	if (ok && !has_server)
		ok = bst_headers_add(&hs, BST_S("server"),
				     s->s.cfg->http.server_tokens ? BST_S("bastion/" BST_VERSION) : BST_S("bastion")) == 0;
	char alt[BST_ALT_SVC_MAX];
	if (ok && s->s.server != NULL && bst_headers_get_name(&hs, BST_S("alt-svc")) == NULL) {
		bst_str av = bst_alt_svc(s->s.server, alt);
		if (av.len > 0)
			ok = bst_headers_add(&hs, BST_S("alt-svc"), av) == 0;
	}
	if (ok && st != 204 && st != 304) {
		int64_t cl = hin->content_length;
		if (cl < 0 && end && !s->is_head)
			cl = 0;
		if (cl >= 0) {
			char *lv = bst_arena_alloc(s->s.arena, 24);
			int n = lv != NULL ? snprintf(lv, 24, "%lld", (long long)cl) : 0;
			ok = n > 0 && bst_headers_add(&hs, BST_S("content-length"), (bst_str){ lv, (uint32_t)n }) == 0;
			if (!s->no_body)
				s->cl_left = cl;
		}
	}
	if (!ok || !queue_block(c, s->id, &hs, end))
		goto out;
	s->head_sent = true;
	rc = 0;
	if (end) {
		s->resp_done = s->end_queued = s->local_closed = true;
		s->in_batch = true; /* finished once the write that carries it completes */
		s->wnext = c->batch;
		c->batch = s;
	} else {
		h2_sched_update(s);
	}
	h2c_pump(c);
out:
	if (rc != 0 && !c->closed)
		h2c_conn_error(c, BST_H2_INTERNAL_ERROR);
	h2c_leave(c);
	return rc;
}

static int h2_send_interim(bst_stream *bs, int status, const bst_headers *extra)
{
	h2s *s = S(bs);
	h2c *c = s->c;
	if (!LIVE(s) || s->head_sent || status < 100 || status > 199 || status == 101)
		return -1;
	h2c_enter(c);
	bst_headers hs;
	bst_headers_init(&hs, s->s.arena);
	char *sv = bst_arena_alloc(s->s.arena, 8);
	bool ok = sv != NULL;
	if (ok) {
		snprintf(sv, 8, "%d", status);
		ok = bst_headers_add(&hs, BST_S(":status"), (bst_str){ sv, 3 }) == 0;
	}
	for (uint32_t i = 0; ok && extra != NULL && i < extra->n; i++)
		if (!conn_specific(extra->v[i].id) && extra->v[i].id != BST_H_CONTENT_LENGTH)
			ok = bst_headers_add(&hs, extra->v[i].name, extra->v[i].value) == 0;
	int rc = ok && queue_block(c, s->id, &hs, false) ? 0 : -1;
	if (rc == 0)
		h2c_pump(c);
	h2c_leave(c);
	return rc;
}

static int h2_send_body(bst_stream *bs, bst_chain *data, bool end, bst_done_cb cb, void *ud)
{
	h2s *s = S(bs);
	h2c *c = s->c;
	if (!LIVE(s) || !s->head_sent || s->resp_done || s->cb != NULL)
		return -1;
	uint64_t len = bst_chain_len(data);
	h2c_enter(c);
	bool ok = true;
	if (s->no_body) {
		bst_chain_clear(data);
	} else if (s->cl_left >= 0 && len > (uint64_t)s->cl_left) {
		ok = false; /* more than the Content-Length said */
	} else {
		if (s->cl_left >= 0)
			s->cl_left -= (int64_t)len;
		if (end && s->cl_left > 0)
			ok = false; /* fewer: the peer would wait for bytes that never come */
		else
			ok = bst_chain_move(&s->out, data) == 0;
	}
	if (!ok) {
		h2s_reset(s, BST_H2_INTERNAL_ERROR, BST_STREAM_ERR_INTERNAL);
		h2c_leave(c);
		return -1;
	}
	if (end)
		s->resp_done = true;
	s->cb = cb;
	s->cb_ud = ud;
	if (s->out.len == 0 && cb != NULL && !s->in_batch && !end)
		h2c_cbq_push(s);
	h2_sched_update(s);
	h2c_pump(c);
	h2c_leave(c);
	return 0;
}

static int h2_send_trailers(bst_stream *bs, const bst_headers *t)
{
	h2s *s = S(bs);
	h2c *c = s->c;
	if (!LIVE(s) || !s->head_sent || s->resp_done || s->trailers_due || s->no_body)
		return -1;
	for (uint32_t i = 0; i < t->n; i++) {
		const bst_header *h = &t->v[i];
		if (!bst_is_token(h->name) || h->name.p[0] == ':' || conn_specific(h->id) ||
		    h->id == BST_H_CONTENT_LENGTH || !bst_is_field_value_clean(h->value))
			return -1;
		if (bst_headers_add(&s->resp_trailers, h->name, h->value) != 0)
			return -1;
	}
	if (t->n == 0) /* an empty section would be a HEADERS frame without fields: send END_STREAM instead */
		return -1;
	s->trailers_due = true;
	s->resp_done = true;
	c->trailers_pending++;
	h2c_arm_flush(c);
	return 0;
}

void h2_deliver(h2s *s)
{
	h2c *c = s->c;
	while (!c->closed && !s->dead && s->reading && !s->detached && s->s.handler != NULL) {
		bool data = s->in.len > 0;
		bool end_due = s->remote_closed && !s->end_sent;
		if (!data && !end_due)
			break;
		if (data && s->credit == 0)
			break;
		size_t n = (size_t)s->in.len;
		if (data)
			s->credit = s->credit > n ? s->credit - n : 0;
		bool end = s->remote_closed;
		if (end)
			s->end_sent = true;
		h2_recv_consumed(c, s, n); /* the bytes are the handler's now: the peer may send more */
		if (end && s->trailers.n > 0 && s->s.handler->on_trailers != NULL)
			s->s.handler->on_trailers(&s->s, &s->trailers);
		if (c->closed || s->dead)
			break;
		if (s->s.handler->on_body != NULL)
			s->s.handler->on_body(&s->s, &s->in, end);
		if (c->closed || s->dead)
			break;
		bst_chain_clear(&s->in);
		if (end)
			break;
	}
}

static void h2_read_body(bst_stream *bs, size_t credit)
{
	h2s *s = S(bs);
	h2c *c = s->c;
	if (!LIVE(s))
		return;
	h2c_enter(c);
	s->reading = true;
	s->credit = credit > UINT64_MAX - s->credit ? UINT64_MAX : s->credit + credit;
	if (s->s.req.expect_continue && !s->expect_sent && !s->head_sent && !s->remote_closed) {
		s->expect_sent = true;
		(void)h2_send_interim(bs, 100, NULL);
	}
	h2_deliver(s);
	h2c_leave(c);
}

static void h2_reset_op(bst_stream *bs, bst_stream_err why)
{
	h2s *s = S(bs);
	if (!LIVE(s))
		return;
	h2c *c = s->c;
	h2c_enter(c);
	uint32_t code = why == BST_STREAM_ERR_PROTOCOL ? BST_H2_PROTOCOL_ERROR
			: why == BST_STREAM_ERR_INTERNAL ? BST_H2_INTERNAL_ERROR
							   : BST_H2_CANCEL;
	h2s_reset(s, code, why == BST_STREAM_ERR_NONE ? BST_STREAM_ERR_CANCEL : why);
	h2c_leave(c);
}

const bst_stream_ops bst_h2_ops = {
	.send_head = h2_send_head,
	.send_interim = h2_send_interim,
	.send_body = h2_send_body,
	.send_trailers = h2_send_trailers,
	.read_body = h2_read_body,
	.reset = h2_reset_op,
};

/* ---- requests ---- */

void h2_reject(h2c *c, h2s *s, int status)
{
	s->rejected = true;
	s->own = true;
	(void)bst_send_error(&s->s, status);
	s->own = false;
	(void)c;
}

static void reject_retry_after(h2c *c, h2s *s, int status)
{
	const bst_cfg_limits *lim = bst_worker_limits(c->w);
	char *v = bst_arena_alloc(s->s.arena, 16);
	int n = v != NULL ? snprintf(v, 16, "%u", lim->overload_retry_after) : 0;
	s->rejected = true;
	s->own = true;
	(void)bst_send_error_hdr(&s->s, status, BST_S("Retry-After"), (bst_str){ v, n > 0 ? (uint32_t)n : 0 });
	s->own = false;
}

void h2_request_start(h2c *c, h2s *s, const bst_headers *in, bool end_stream)
{
	bst_req *rq = &s->s.req;
	s->remote_closed = end_stream;
	bst_pseudo_opts po = { .end_stream = end_stream, .allow_protocol = c->cfg->connect_protocol };
	bst_pseudo_result pr;
	bst_pseudo_rc prc = bst_validate_pseudo_request(in, s->s.arena, &rq->head, &po, &pr);
	if (prc == BST_PSEUDO_MALFORMED) {
		/* RFC 9113 section 8.1.1: a malformed request is a stream error of type PROTOCOL_ERROR. */
		h2c_stream_error(c, s->id, BST_H2_PROTOCOL_ERROR);
		return;
	}
	if (prc == BST_PSEUDO_BAD_REQUEST) {
		h2_reject(c, s, 400);
		return;
	}
	s->has_cl = pr.has_length;
	s->cl = pr.length;
	if (pr.has_length && pr.length > 0)
		rq->framing = (bst_framing){ BST_FRAMING_LENGTH, pr.length };
	else if (!end_stream && !pr.has_length)
		rq->framing = (bst_framing){ BST_FRAMING_CHUNKED, 0 }; /* a body of unknown length */
	else
		rq->framing = (bst_framing){ BST_FRAMING_NONE, 0 };
	bool ext = rq->head.method == BST_M_CONNECT && pr.protocol.len > 0;
	if (ext && !bst_str_eq(pr.protocol, BST_S("websocket"))) {
		/* RFC 8441 extended CONNECT: only WebSocket has a handler (the proxy); anything else is
		 * refused (the setting is only advertised when http2_connect_protocol is on) */
		h2_reject(c, s, 501);
		return;
	}
	int st;
	if (ext) {
		/* the request's semantics are those of the WebSocket GET it stands for; the tunnel
		 * handler (proxy/handler.c) sees CONNECT with head.protocol set */
		rq->head.protocol = pr.protocol;
		rq->head.method = BST_M_GET;
		st = bst_validate_request_semantics(rq);
		rq->head.method = BST_M_CONNECT;
	} else {
		st = bst_validate_request_semantics(rq);
	}
	if (st != 0) {
		h2_reject(c, s, st);
		return;
	}
	if (rq->head.method == BST_M_HEAD)
		s->is_head = true;
	bool matched = true;
	s->s.server = bst_vhost_lookup(c->set, rq->host, &matched);
	s->s.cfg = &s->s.server->common;
	const bst_cfg_server *def = bst_vhost_default(c->set);
	if (!matched && def->unknown_host == BST_UNKNOWN_HOST_CLOSE) {
		h2c_conn_error(c, BST_H2_NO_ERROR);
		return;
	}
	if (!matched && def->unknown_host == BST_UNKNOWN_HOST_421) {
		h2_reject(c, s, 421);
		return;
	}
	const bst_cfg_server *sni = bst_tls_sni_server(c->t), *chosen = bst_tls_chosen_server(c->t);
	bool mtls_cross = chosen != NULL && chosen != s->s.server &&
			  (s->s.server->tls.client_auth != BST_CLIENT_AUTH_OFF ||
			   chosen->tls.client_auth != BST_CLIENT_AUTH_OFF);
	if (mtls_cross || (sni != NULL && sni != s->s.server && sni->tls.host_sni == BST_HOST_SNI_421)) {
		h2_reject(c, s, 421); /* connection coalescing across hosts (RFC 9110 section 7.4) is refused */
		return;
	}
	if (c->syn_data && !c->syn_checked) {
		c->syn_checked = true;
		if (rq->head.method != BST_M_GET && rq->head.method != BST_M_HEAD && rq->head.method != BST_M_OPTIONS) {
			h2_reject(c, s, 425);
			return;
		}
		rq->early_data = true;
	}
	if (bst_tls_early_active(c->t)) {
		const bst_cfg_server *ch = chosen != NULL ? chosen : s->s.server;
		const bst_cfg_tls_profile *pf = ch->tls.profile;
		if (pf == NULL || !pf->early_data || (pf->early_methods & (1u << rq->head.method)) == 0) {
			h2_reject(c, s, 425);
			return;
		}
		rq->early_data = true;
	}
	const bst_cfg_common *cfg = s->s.cfg;
	if (rq->framing.kind == BST_FRAMING_LENGTH && cfg->client_max_body_size != 0 &&
	    rq->framing.length > cfg->client_max_body_size) {
		h2_reject(c, s, 413);
		return;
	}
	if (c->w != NULL) {
		size_t charge = sizeof *s + H2_ARENA_CHUNK;
		if (bst_overloaded(c->w) || !bst_worker_mem_charge(c->w, charge)) {
			bst_worker_refused(c->w);
			reject_retry_after(c, s, (int)bst_worker_limits(c->w)->overload_status);
			return;
		}
		s->charged = charge;
	}
	if (c->cfg->priorities) {
		const bst_header *p = bst_headers_get_name(&rq->head.headers, BST_S("priority"));
		if (p != NULL)
			h2_set_priority(s, p->value.p, p->value.len);
	}
	c->served++;
	bst_stream_dispatch(&s->s);
}

bool h2_request_trailers(h2c *c, h2s *s, const bst_headers *in)
{
	(void)c;
	if (!bst_validate_trailer_fields(in))
		return false;
	for (uint32_t i = 0; i < in->n; i++)
		if (bst_headers_add(&s->trailers, in->v[i].name, in->v[i].value) != 0)
			return false;
	return true;
}

void h2_priority_update(h2c *c, uint32_t id, const char *v, size_t n)
{
	h2s *s = h2s_find(c, id);
	if (s != NULL && c->cfg->priorities)
		h2_set_priority(s, v, n);
}
