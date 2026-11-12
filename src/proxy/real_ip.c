/* real_ip_header and real_ip_from: the client address a trusted front proxy reports. Only a
 * connection from an address in real_ip_from may change $remote_addr; anyone else's header is
 * ignored, so a client cannot claim to be somebody else. */
#include "core/addr.h"
#include "proxy/handler.h"

#include <string.h>

static bst_str trim(bst_str s)
{
	while (s.len > 0 && (s.p[0] == ' ' || s.p[0] == '\t')) {
		s.p++;
		s.len--;
	}
	while (s.len > 0 && (s.p[s.len - 1] == ' ' || s.p[s.len - 1] == '\t'))
		s.len--;
	return s;
}

/* One element of an X-Forwarded-For style list: an address, maybe [v6] or v4:port. */
static bool parse_elem(bst_str e, bst_ip *ip)
{
	if (bst_addr_parse(e, ip))
		return true;
	if (e.len > 2 && e.p[0] == '[') {
		const char *rb = memchr(e.p, ']', e.len);
		return rb != NULL && bst_addr_parse((bst_str){ e.p + 1, (uint32_t)(rb - e.p - 1) }, ip);
	}
	const char *colon = memchr(e.p, ':', e.len);
	if (colon != NULL && memchr(colon + 1, ':', e.len - (size_t)(colon - e.p) - 1) == NULL)
		return bst_addr_parse((bst_str){ e.p, (uint32_t)(colon - e.p) }, ip);
	return false;
}

void bst_proxy_real_ip(bst_stream *s)
{
	const bst_cfg_proxy *pc = &s->cfg->proxy;
	if (pc->real_ip_header == NULL || !s->has_peer ||
	    !bst_proxy_cidr_match(&pc->real_ip_from, &s->peer.ip))
		return;
	bst_str name = { pc->real_ip_header, (uint32_t)strlen(pc->real_ip_header) };
	const bst_header *h = NULL, *last = NULL;
	while ((h = bst_headers_next_name(&s->req.head.headers, h, name)) != NULL)
		last = h; /* the field the nearest proxy appended to */
	if (last == NULL)
		return;
	/* right to left: the first address that is not one of our trusted proxies */
	bst_str v = last->value;
	size_t end = v.len;
	bst_ip found;
	bool have = false;
	for (;;) {
		size_t st = end;
		while (st > 0 && v.p[st - 1] != ',')
			st--;
		bst_ip ip;
		if (!parse_elem(trim((bst_str){ v.p + st, (uint32_t)(end - st) }), &ip))
			break; /* garbage: stop trusting the list here */
		found = ip;
		have = true;
		if (!bst_proxy_cidr_match(&pc->real_ip_from, &ip) || st == 0)
			break;
		end = st - 1;
	}
	if (have) {
		s->peer.ip = found;
		s->peer.port = 0;
	}
}
