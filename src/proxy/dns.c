/* See dns.h. */
#include "proxy/dns.h"

#include <string.h>

#define HDR 12
#define MAX_JUMPS 32 /* compression pointers followed in one name */
#define FLAG_QR 0x8000u
#define FLAG_TC 0x0200u
#define FLAG_RD 0x0100u
#define OPCODE_MASK 0x7800u
#define RCODE_MASK 0x000fu

static uint16_t rd16(const uint8_t *p)
{
	return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t rd32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static char lower(char c)
{
	return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
}

/* A host name label: letters, digits, '-' and '_' (service names), 1 to 63 bytes. */
static bool label_ok(const char *p, size_t n)
{
	if (n == 0 || n > 63)
		return false;
	for (size_t i = 0; i < n; i++) {
		char c = p[i];
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
		      c == '-' || c == '_'))
			return false;
	}
	return true;
}

size_t bst_dns_query(uint8_t *buf, size_t cap, uint16_t id, const char *name, uint16_t qtype)
{
	size_t nl = strlen(name);
	if (nl > 0 && name[nl - 1] == '.')
		nl--;
	if (nl == 0 || nl > BST_DNS_MAX_NAME || cap < HDR + nl + 2 + 4)
		return 0;
	memset(buf, 0, HDR);
	buf[0] = (uint8_t)(id >> 8);
	buf[1] = (uint8_t)id;
	buf[2] = (uint8_t)(FLAG_RD >> 8); /* a stub resolver asks for recursion */
	buf[5] = 1;			  /* QDCOUNT */
	size_t o = HDR, start = 0;
	for (size_t i = 0; i <= nl; i++) {
		if (i == nl || name[i] == '.') {
			size_t ll = i - start;
			if (!label_ok(name + start, ll))
				return 0;
			buf[o++] = (uint8_t)ll;
			memcpy(buf + o, name + start, ll);
			o += ll;
			start = i + 1;
		}
	}
	buf[o++] = 0;
	buf[o++] = (uint8_t)(qtype >> 8);
	buf[o++] = (uint8_t)qtype;
	buf[o++] = 0;
	buf[o++] = 1; /* class IN */
	return o;
}

/* Decodes the name at *off into out (lower case, dots, no trailing dot, NUL-terminated) and
 * moves *off past it in the message (past the first pointer when there is one). Pointers must
 * point strictly backwards, at most MAX_JUMPS of them. */
static bool read_name(const uint8_t *m, size_t len, size_t *off, char out[BST_DNS_MAX_NAME + 1])
{
	size_t p = *off, o = 0, after = 0;
	unsigned jumps = 0;
	bool jumped = false;
	for (;;) {
		if (p >= len)
			return false;
		uint8_t l = m[p];
		if ((l & 0xc0) == 0xc0) {
			if (p + 1 >= len || ++jumps > MAX_JUMPS)
				return false;
			size_t to = ((size_t)(l & 0x3f) << 8) | m[p + 1];
			if (to >= p) /* forward or self: a loop or garbage */
				return false;
			if (!jumped) {
				after = p + 2;
				jumped = true;
			}
			p = to;
			continue;
		}
		if ((l & 0xc0) != 0) /* the extended label types are not used */
			return false;
		if (l == 0) {
			p++;
			break;
		}
		if (p + 1 + l > len)
			return false;
		if (o != 0) {
			if (o + 1 > BST_DNS_MAX_NAME)
				return false;
			out[o++] = '.';
		}
		if (o + l > BST_DNS_MAX_NAME)
			return false;
		for (size_t i = 0; i < l; i++)
			out[o++] = lower((char)m[p + 1 + i]);
		p += 1 + (size_t)l;
	}
	out[o] = 0;
	*off = jumped ? after : p;
	return true;
}

static bool name_eq(const char *a, const char *b)
{
	size_t bl = strlen(b);
	if (bl > 0 && b[bl - 1] == '.')
		bl--;
	if (strlen(a) != bl)
		return false;
	for (size_t i = 0; i < bl; i++)
		if (a[i] != lower(b[i]))
			return false;
	return true;
}

typedef struct rr {
	char owner[BST_DNS_MAX_NAME + 1];
	uint16_t type;
	uint32_t ttl;
	size_t rdoff, rdlen;
} rr;

static bool read_rr(const uint8_t *m, size_t len, size_t *off, rr *r)
{
	if (!read_name(m, len, off, r->owner) || *off + 10 > len)
		return false;
	const uint8_t *p = m + *off;
	r->type = rd16(p);
	r->ttl = rd32(p + 4) & 0x7fffffffu; /* RFC 2181: the top bit set means 0, treat as small */
	r->rdlen = rd16(p + 8);
	r->rdoff = *off + 10;
	if (r->rdoff + r->rdlen > len)
		return false;
	*off = r->rdoff + r->rdlen;
	return true;
}

bst_dns_status bst_dns_parse(const uint8_t *msg, size_t len, uint16_t id, const char *name,
			     uint16_t qtype, bst_dns_answer *out)
{
	memset(out, 0, sizeof *out);
	if (len < HDR)
		return BST_DNS_MALFORMED;
	uint16_t flags = rd16(msg + 2);
	if (rd16(msg) != id || !(flags & FLAG_QR) || (flags & OPCODE_MASK) != 0)
		return BST_DNS_IGNORE;
	unsigned qd = rd16(msg + 4), an = rd16(msg + 6);
	if (qd != 1)
		return BST_DNS_IGNORE;
	size_t off = HDR;
	char q[BST_DNS_MAX_NAME + 1];
	if (!read_name(msg, len, &off, q) || off + 4 > len)
		return BST_DNS_MALFORMED;
	if (!name_eq(q, name) || rd16(msg + off) != qtype || rd16(msg + off + 2) != 1)
		return BST_DNS_IGNORE; /* an answer to some other question */
	off += 4;
	if (flags & FLAG_TC)
		return BST_DNS_TRUNCATED;
	unsigned rc = flags & RCODE_MASK;
	if (rc == 3)
		return BST_DNS_NXDOMAIN;
	if (rc != 0)
		return BST_DNS_SERVFAIL;
	/* The chain of names that count: the question, then each CNAME target, in order. */
	char chain[BST_DNS_MAX_CNAMES + 1][BST_DNS_MAX_NAME + 1];
	size_t nchain = 1;
	memcpy(chain[0], q, sizeof q);
	uint32_t ttl = UINT32_MAX;
	/* CNAMEs first, in as many passes as hops (answers need not be in chain order). */
	size_t ans_off = off;
	for (unsigned pass = 0; pass < BST_DNS_MAX_CNAMES; pass++) {
		bool grew = false;
		off = ans_off;
		for (unsigned i = 0; i < an; i++) {
			rr r;
			if (!read_rr(msg, len, &off, &r))
				return BST_DNS_MALFORMED;
			if (r.type != BST_DNS_TYPE_CNAME || strcmp(r.owner, chain[nchain - 1]) != 0)
				continue;
			if (nchain > BST_DNS_MAX_CNAMES)
				return BST_DNS_MALFORMED; /* a chain longer than we follow */
			size_t t = r.rdoff;
			if (!read_name(msg, len, &t, chain[nchain]) || t != r.rdoff + r.rdlen)
				return BST_DNS_MALFORMED;
			for (size_t k = 0; k < nchain; k++)
				if (strcmp(chain[k], chain[nchain]) == 0)
					return BST_DNS_MALFORMED; /* a CNAME loop */
			nchain++;
			if (r.ttl < ttl)
				ttl = r.ttl;
			grew = true;
		}
		if (!grew)
			break;
	}
	off = ans_off;
	for (unsigned i = 0; i < an; i++) {
		rr r;
		if (!read_rr(msg, len, &off, &r))
			return BST_DNS_MALFORMED;
		if (r.type != qtype || strcmp(r.owner, chain[nchain - 1]) != 0)
			continue;
		size_t want = qtype == BST_DNS_TYPE_A ? 4 : 16;
		if (r.rdlen != want)
			return BST_DNS_MALFORMED;
		if (r.ttl < ttl)
			ttl = r.ttl;
		if (out->naddrs == BST_DNS_MAX_ADDRS)
			continue;
		bst_ip *ip = &out->addrs[out->naddrs++];
		memset(ip, 0, sizeof *ip);
		ip->family = qtype == BST_DNS_TYPE_A ? BST_IP_V4 : BST_IP_V6;
		memcpy(ip->b, msg + r.rdoff, want);
	}
	out->ttl = out->naddrs > 0 || nchain > 1 ? ttl : 0;
	return BST_DNS_OK;
}

const char *bst_dns_status_str(bst_dns_status st)
{
	switch (st) {
	case BST_DNS_OK:
		return "ok";
	case BST_DNS_IGNORE:
		return "not our answer";
	case BST_DNS_MALFORMED:
		return "malformed answer";
	case BST_DNS_TRUNCATED:
		return "truncated answer";
	case BST_DNS_NXDOMAIN:
		return "no such name";
	case BST_DNS_SERVFAIL:
		return "server failure";
	}
	return "?";
}
