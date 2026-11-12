/* The router: from a validated request to the handler that answers it (architecture section 5).
 * The path is normalized once (route/uri.h), the location is found on the normalized path
 * (route/location.h), and from then on the stream carries the location's configuration. */
#include "core/log.h"
#include "http/stream.h"
#include "handlers/static.h"
#include "proc/test_hooks.h"
#include "proxy/handler.h"
#include "route/rewrite.h"
#include "route/uri.h"
#include "tls/conn.h"

#include <string.h>

static void start_handler(bst_stream *s)
{
#ifdef BST_TEST
	if (bst_test_echo_wants(s)) {
		bst_stream_set_handler(s, &bst_test_echo_handler, NULL);
		return;
	}
#endif
	if (s->cfg->redirect.set)
		bst_stream_set_handler(s, &bst_redirect_handler, NULL);
	else if (s->cfg->http.ret.set)
		bst_stream_set_handler(s, &bst_return_handler, NULL);
	else if (s->cfg->proxy.set)
		bst_stream_set_handler(s, &bst_proxy_handler, NULL);
	else if (s->cfg->files.root != NULL)
		bst_stream_set_handler(s, &bst_static_handler, NULL);
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

/* One pass of the search: the server's rewrites, the location for the resulting path, then the
 * rewrites of that location. Returns 0 to go on with the handler, 1 to search again (a `last`),
 * or the status to answer with. */
static int route_once(bst_stream *s)
{
	const bst_cfg_common *srv = &s->server->common;
	bst_rewrite_flag flag;
	int st = bst_rewrite_run(s, &srv->rewrites, &flag);
	if (st != 0)
		return st;
	s->loc = bst_location_find(s->server, s->uri, &s->caps);
	if (s->caps.limit_hit) {
		bst_log(BST_LOG_WARN, "route: regex limit reached while matching a %u-byte path: 500",
			(unsigned)s->uri.len);
		return 500;
	}
	s->cfg = bst_location_cfg(s->server, s->loc);
	if (s->cfg->files.internal && !s->internal_ok)
		return 404; /* an internal location is not for clients */
	if (s->cfg->auth_mtls && !bst_tls_client_verified(s->transport))
		return 403; /* auth_mtls: a verified client certificate or nothing */
	/* A location that writes its own rewrites replaces the server's list; one that does not has
	 * the very same list, which already ran above. */
	if (s->loc != NULL && s->cfg->rewrites.items != srv->rewrites.items) {
		st = bst_rewrite_run(s, &s->cfg->rewrites, &flag);
		if (st != 0)
			return st;
		if (flag == BST_REWRITE_LAST)
			return 1;
	}
	return 0;
}

/* The rewrite loop, the request header operations and the handler, for a path in s->uri. */
static void route_and_start(bst_stream *s)
{
	int st = 0;
	unsigned cycles = 0;
	while (st == 0 && (st = route_once(s)) == 1) {
		if (++cycles > s->server->common.rewrite_max_cycles) {
			bst_log(BST_LOG_WARN, "route: %u rewrite restarts on \"%.*s\": a loop, 500",
				cycles - 1, (int)(s->uri.len > 120 ? 120 : s->uri.len), s->uri.p);
			st = 500;
		} else {
			st = 0;
		}
	}
	if (st != 0) {
		(void)bst_send_error(s, st);
		return;
	}
	bst_apply_request_headers(s);
	start_handler(s);
}

void bst_stream_dispatch(bst_stream *s)
{
	int st = normalize_path(s);
	if (st != 0) {
		(void)bst_send_error(s, st);
		return;
	}
	route_and_start(s);
}

void bst_stream_reroute(bst_stream *s, bst_str uri, int err_status)
{
	if (++s->reroutes > s->server->common.rewrite_max_cycles) {
		bst_log(BST_LOG_WARN, "route: too many internal redirects: 500");
		s->in_error_page = true; /* the default page, not another error_page */
		(void)bst_send_error(s, 500);
		return;
	}
	char *buf = bst_arena_alloc(s->arena, (size_t)uri.len + 1);
	size_t n = 0;
	bst_uri_flags fl = s->server->common.merge_slashes ? BST_URI_MERGE_SLASHES : 0;
	if (buf == NULL || bst_uri_clean(uri, buf, (size_t)uri.len + 1, fl, &n) != BST_URI_OK) {
		s->in_error_page = true;
		(void)bst_send_error(s, err_status != 0 ? err_status : 500);
		return;
	}
	s->uri = (bst_str){ buf, (uint32_t)n };
	s->uri_changed = true;
	s->internal_ok = true;
	if (err_status != 0) {
		s->status_override = err_status;
		s->in_error_page = true;
	}
	route_and_start(s);
}
