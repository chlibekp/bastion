/* Request IDs: a random 128-bit value (32 hex digits) from getrandom, so IDs are unique across
 * workers without coordination. A client's own ID is replaced unless its peer is trusted
 * (request_id_trust), and then only a short token-like value is kept, never anything that could
 * smuggle a header or a log line. */
#include "filters/extras.h"

#include "proxy/handler.h"
#include "tls/conn.h"

#include <string.h>
#include <sys/random.h>

bool bst_stream_is_tls(const bst_stream *s)
{
	return bst_tls_var(s->transport, "protocol") != NULL;
}

static bool id_ok(bst_str v)
{
	if (v.len == 0 || v.len > 128)
		return false;
	for (uint32_t i = 0; i < v.len; i++) {
		char c = v.p[i];
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
		      c == '-' || c == '_' || c == '.'))
			return false;
	}
	return true;
}

static bst_str make_id(bst_stream *s)
{
	unsigned char r[16];
	static const char hex[] = "0123456789abcdef";
	char *b = bst_arena_alloc(s->arena, 33);
	if (b == NULL || getrandom(r, sizeof r, 0) != (ssize_t)sizeof r)
		return (bst_str){ NULL, 0 };
	for (size_t i = 0; i < sizeof r; i++) {
		b[2 * i] = hex[r[i] >> 4];
		b[2 * i + 1] = hex[r[i] & 15];
	}
	b[32] = '\0';
	return (bst_str){ b, 32 };
}

void bst_request_id_apply(bst_stream *s)
{
	const bst_cfg_extras *x = &s->cfg->extras;
	if (!x->request_id || x->request_id_header == NULL)
		return;
	bst_str name = { x->request_id_header, (uint32_t)strlen(x->request_id_header) };
	bst_headers *rq = &s->req.head.headers;
	if (s->request_id.p == NULL) { /* a re-route keeps the ID it already has */
		const bst_header *in = bst_headers_get_name(rq, name);
		bool trusted = in != NULL && s->has_peer &&
			       bst_proxy_cidr_match(&x->request_id_trust, &s->peer.ip);
		bool single = in != NULL && bst_headers_next_name(rq, in, name) == NULL;
		if (trusted && single && id_ok(in->value))
			s->request_id = in->value;
		else
			s->request_id = make_id(s);
	}
	(void)bst_headers_remove_name(rq, name); /* the client's copies: never forwarded */
	if (s->request_id.p != NULL)
		(void)bst_headers_add(rq, name, s->request_id);
}
