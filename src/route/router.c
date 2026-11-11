/* The router: from a validated request to the handler that answers it (architecture section 5).
 * The path is normalized once (route/uri.h), the location is found on the normalized path
 * (route/location.h), and from then on the stream carries the location's configuration. */
#include "core/log.h"
#include "http/stream.h"
#include "route/uri.h"

#include <string.h>

/* Phase 5 is built up in steps; the handler table grows with it. */
static void start_handler(bst_stream *s)
{
	if (s->cfg->http.ret.set)
		bst_stream_set_handler(s, &bst_return_handler, NULL);
	else
		(void)bst_send_error(s, 404);
}

/* Normalizes the request path into the stream arena. 0, or the status to refuse with. */
static int normalize_path(bst_stream *s)
{
	const bst_req_head *h = &s->req.head;
	bst_str path = h->path;
	if (h->form == BST_TARGET_ASTERISK || path.len == 0)
		path = BST_S("/"); /* OPTIONS *: the server's own configuration answers */
	char *buf = bst_arena_alloc(s->arena, (size_t)path.len + 1);
	if (buf == NULL)
		return 500;
	size_t n = 0;
	bst_uri_flags fl = s->server->common.merge_slashes ? BST_URI_MERGE_SLASHES : 0;
	if (bst_uri_normalize(path, buf, (size_t)path.len + 1, fl, &n) != BST_URI_OK)
		return 400;
	s->uri = (bst_str){ buf, (uint32_t)n };
	return 0;
}

void bst_stream_dispatch(bst_stream *s)
{
	int st = normalize_path(s);
	if (st != 0) {
		(void)bst_send_error(s, st);
		return;
	}
	s->loc = bst_location_find(s->server, s->uri, &s->caps);
	if (s->caps.limit_hit) {
		bst_log(BST_LOG_WARN, "route: regex limit reached while matching a %u-byte path: 500",
			(unsigned)s->uri.len);
		(void)bst_send_error(s, 500);
		return;
	}
	s->cfg = bst_location_cfg(s->server, s->loc);
	start_handler(s);
}
