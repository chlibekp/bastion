#include "http/stream.h"

#include "filters/compress.h"
#include "filters/extras.h"
#include "filters/headers.h"
#include "ops/logger.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

bst_arena *bst_stream_arena(bst_stream *s)
{
	return s->arena;
}

bst_req *bst_stream_req(bst_stream *s)
{
	return &s->req;
}

void bst_stream_set_handler(bst_stream *s, const bst_handler_ops *h, void *hctx)
{
	s->handler = h;
	s->hctx = hctx;
	if (h->on_request != NULL)
		h->on_request(s);
}

int bst_stream_send_head(bst_stream *s, const bst_resp_head *h, bool end_stream)
{
	bst_resp_head out = *h; /* the header operations edit a copy of what the handler gave */
	if (s->status_override != 0 && out.status == 200)
		out.status = s->status_override; /* an error_page keeps the status it answers for */
	bst_filter_response_headers(s, &out);
	if (out.status >= 200) {
		bst_extras_response_head(s, &out);
		bst_compress_attach(s, &out, end_stream);
	}
	for (bst_filter *f = s->filters; f != NULL; f = f->next)
		if (f->ops->on_head != NULL && f->ops->on_head(f, &out, end_stream) != 0)
			return -1;
	if (out.status >= 200)
		s->log_status = out.status;
	return s->ops->send_head(s, &out, end_stream);
}

void bst_stream_log_begin(bst_stream *s, uint8_t proto)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	s->log_proto = proto;
	s->log_start_us = (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

void bst_stream_add_filter(bst_stream *s, bst_filter *f)
{
	f->s = s;
	f->next = NULL;
	bst_filter **p = &s->filters;
	while (*p != NULL)
		p = &(*p)->next;
	*p = f;
}

void bst_stream_release(bst_stream *s)
{
	if (s->log_proto != 0)
		bst_access_log(s); /* before the filters go: it reads the request, never them */
	bst_filter *f = s->filters;
	s->filters = NULL;
	while (f != NULL) {
		bst_filter *next = f->next; /* release may free f */
		if (f->ops->release != NULL)
			f->ops->release(f);
		f = next;
	}
}

int bst_stream_send_interim(bst_stream *s, int status, const bst_headers *h)
{
	return s->ops->send_interim(s, status, h);
}

int bst_stream_send_body(bst_stream *s, bst_chain *c, bool end_stream, bst_done_cb cb, void *ud)
{
	for (bst_filter *f = s->filters; f != NULL; f = f->next)
		if (f->ops->on_body != NULL && f->ops->on_body(f, c, end_stream) != 0)
			return -1;
	s->log_body_bytes += bst_chain_len(c);
	return s->ops->send_body(s, c, end_stream, cb, ud);
}

int bst_stream_send_trailers(bst_stream *s, const bst_headers *h)
{
	return s->ops->send_trailers(s, h);
}

void bst_stream_read_body(bst_stream *s, size_t credit)
{
	s->ops->read_body(s, credit);
}
