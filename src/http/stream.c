#include "http/stream.h"

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
	return s->ops->send_head(s, h, end_stream);
}

int bst_stream_send_interim(bst_stream *s, int status, const bst_headers *h)
{
	return s->ops->send_interim(s, status, h);
}

int bst_stream_send_body(bst_stream *s, bst_chain *c, bool end_stream, bst_done_cb cb, void *ud)
{
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
