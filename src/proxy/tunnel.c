/* See tunnel.h. */
#include "proxy/tunnel.h"

#include <openssl/evp.h>
#include <string.h>
#include <sys/random.h>

static unsigned g_tunnels; /* per worker */

int bst_tunnel_make_key(char out[32])
{
	unsigned char raw[16];
	size_t got = 0;
	while (got < sizeof raw) {
		ssize_t n = getrandom(raw + got, sizeof raw - got, 0);
		if (n <= 0)
			return -1;
		got += (size_t)n;
	}
	(void)EVP_EncodeBlock((unsigned char *)out, raw, sizeof raw); /* 24 chars and a NUL */
	return 0;
}

bool bst_tunnel_accept_ok(const char *key, bst_str accept)
{
	static const char guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int mdlen = 0;
	char in[64];
	size_t kl = strlen(key);
	if (kl + sizeof guid - 1 > sizeof in)
		return false;
	memcpy(in, key, kl);
	memcpy(in + kl, guid, sizeof guid - 1);
	if (EVP_Digest(in, kl + sizeof guid - 1, md, &mdlen, EVP_sha1(), NULL) != 1 || mdlen != 20)
		return false;
	char want[32];
	int n = EVP_EncodeBlock((unsigned char *)want, md, 20);
	return n == 28 && accept.len == 28 && memcmp(accept.p, want, 28) == 0;
}

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
