/* Message framing (RFC 9112 section 6.3) with the smuggling defences of the review: any request
 * whose length could be read two ways is refused, because the other party in the chain (a
 * proxy, a cache, an older server) may read it the other way. */
#include "http/semantics.h"
#include "http/token.h"

#include <string.h>

static bst_framing refuse(int *status, int code)
{
	*status = code;
	return (bst_framing){ .kind = BST_FRAMING_NONE };
}

static bst_str trim(bst_str s)
{
	while (s.len > 0 && (s.p[0] == ' ' || s.p[0] == '\t'))
		s.p++, s.len--;
	while (s.len > 0 && (s.p[s.len - 1] == ' ' || s.p[s.len - 1] == '\t'))
		s.len--;
	return s;
}

/* Transfer-Encoding: coding *("," coding). Returns 0 for exactly "chunked", else the status. */
static int check_te(bst_str v)
{
	bool chunked_last = false, chunked_seen = false, other = false;
	while (true) {
		const char *comma = memchr(v.p, ',', v.len);
		bst_str item = trim((bst_str){ v.p, comma ? (uint32_t)(comma - v.p) : v.len });
		if (!bst_is_token(item)) /* empty, or not a coding name */
			return 400;
		if (bst_str_ieq(item, BST_S("chunked"))) {
			if (chunked_seen)
				return 400; /* applied twice */
			chunked_seen = chunked_last = true;
		} else {
			chunked_last = false;
			other = true;
		}
		if (comma == NULL)
			break;
		v = (bst_str){ comma + 1, (uint32_t)(v.len - (uint32_t)(comma + 1 - v.p)) };
	}
	if (!chunked_last)
		return 400; /* RFC 9112 section 6.3: the length can not be determined */
	return other ? 501 : 0;     /* chunked is last: any coding before it is one we do not undo */
}

bst_framing bst_h1_message_framing(const bst_req_head *h, int *status)
{
	*status = 0;
	size_t ncl = bst_headers_count(&h->headers, BST_H_CONTENT_LENGTH);
	size_t nte = bst_headers_count(&h->headers, BST_H_TRANSFER_ENCODING);

	if (nte > 0) {
		if (h->version_minor == 0 || ncl > 0 || nte > 1)
			return refuse(status, 400);
		int st = check_te(bst_headers_get(&h->headers, BST_H_TRANSFER_ENCODING)->value);
		return st != 0 ? refuse(status, st) : (bst_framing){ .kind = BST_FRAMING_CHUNKED };
	}
	if (ncl > 1) /* even when the values agree: a proxy may keep either one */
		return refuse(status, 400);
	if (ncl == 1) {
		uint64_t n;
		if (!bst_str_to_u64(bst_headers_get(&h->headers, BST_H_CONTENT_LENGTH)->value, &n))
			return refuse(status, 400); /* sign, list, hex, space, empty or overflow */
		return (bst_framing){ .kind = n ? BST_FRAMING_LENGTH : BST_FRAMING_NONE, .length = n };
	}
	return (bst_framing){ .kind = BST_FRAMING_NONE };
}
