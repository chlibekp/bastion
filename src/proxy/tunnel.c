/* See tunnel.h. */
#include "proxy/tunnel.h"

#include <string.h>

static unsigned g_tunnels; /* per worker */

static bool b64_char(char c)
{
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
	       c == '+' || c == '/';
}

bool bst_tunnel_ws_request(const bst_stream *s)
{
	const bst_req_head *h = &s->req.head;
	if (h->method != BST_M_GET || h->version_minor < 1 ||
	    s->req.framing.kind != BST_FRAMING_NONE)
		return false;
	if (!bst_headers_list_has(&h->headers, BST_H_UPGRADE, BST_S("websocket")) ||
	    !bst_headers_list_has(&h->headers, BST_H_CONNECTION, BST_S("upgrade")))
		return false;
	if (bst_headers_count(&h->headers, BST_H_UPGRADE) != 1)
		return false;
	const bst_header *k = bst_headers_get_name(&h->headers, BST_S("sec-websocket-key"));
	const bst_header *v = bst_headers_get_name(&h->headers, BST_S("sec-websocket-version"));
	if (k == NULL || v == NULL || !bst_str_eq(v->value, BST_S("13")))
		return false;
	/* 16 bytes in base64: 22 characters and "==" */
	if (k->value.len != 24 || k->value.p[22] != '=' || k->value.p[23] != '=')
		return false;
	for (size_t i = 0; i < 22; i++)
		if (!b64_char(k->value.p[i]))
			return false;
	return true;
}

bool bst_tunnel_acquire(unsigned max)
{
	if (max != 0 && g_tunnels >= max)
		return false;
	g_tunnels++;
	return true;
}

void bst_tunnel_release(void)
{
	if (g_tunnels > 0)
		g_tunnels--;
}

unsigned bst_tunnel_count(void)
{
	return g_tunnels;
}
