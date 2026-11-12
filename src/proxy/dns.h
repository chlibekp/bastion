/* A small stub resolver's wire format (RFC 1035): one question out, A and AAAA answers in. Pure
 * functions over bytes; the helper owns the sockets (proxy/upstream.c). Every input byte is
 * hostile: names are bounded (255 bytes, 63 per label), compression pointers may only point
 * backwards and are bounded in number, so a loop is an error, and record counts never let the
 * parser read past the message. Workers never call any of this. */
#ifndef BST_PROXY_DNS_H
#define BST_PROXY_DNS_H

#include "core/addr.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BST_DNS_TYPE_A 1
#define BST_DNS_TYPE_CNAME 5
#define BST_DNS_TYPE_AAAA 28
#define BST_DNS_MAX_NAME 255   /* presentation form without the trailing dot */
#define BST_DNS_MAX_ADDRS 16   /* addresses one answer keeps; more are dropped */
#define BST_DNS_MAX_CNAMES 8   /* CNAME hops followed inside one answer */
#define BST_DNS_MAX_MSG 4096   /* largest message read */

typedef enum bst_dns_status {
	BST_DNS_OK = 0,	     /* addrs[0..naddrs) and ttl filled (naddrs may be 0: NODATA) */
	BST_DNS_IGNORE,	     /* not the answer to our question (ID, flags or question differ) */
	BST_DNS_MALFORMED,   /* broken message: treated as no answer */
	BST_DNS_TRUNCATED,   /* TC set: the UDP answer is incomplete */
	BST_DNS_NXDOMAIN,    /* the name does not exist */
	BST_DNS_SERVFAIL,    /* any other non-zero RCODE */
} bst_dns_status;

typedef struct bst_dns_answer {
	bst_ip addrs[BST_DNS_MAX_ADDRS];
	size_t naddrs;
	uint32_t ttl; /* the smallest TTL of the records used, seconds */
} bst_dns_answer;

/* Writes a recursive query for name (dots between labels, an optional trailing dot) of qtype.
 * The length, or 0 when name is not a valid host name or the buffer is too small. */
size_t bst_dns_query(uint8_t *buf, size_t cap, uint16_t id, const char *name, uint16_t qtype);

/* Parses the response to that query: only records of qtype owned by name or a CNAME of it,
 * reached through at most BST_DNS_MAX_CNAMES hops, count. */
bst_dns_status bst_dns_parse(const uint8_t *msg, size_t len, uint16_t id, const char *name,
			     uint16_t qtype, bst_dns_answer *out);

const char *bst_dns_status_str(bst_dns_status st);

#endif
