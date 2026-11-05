/* IP address parsing and formatting. The parser is hand-written and strict so that
 * dev (glibc) and release (musl) builds accept exactly the same inputs: ACL decisions
 * must not depend on libc. Input is a bst_str, never assumed NUL-terminated.
 *
 * Accepted: dotted-quad IPv4 (four decimal octets 0-255, no leading zeros, no
 * shorthand forms) and IPv6 text per RFC 4291 (hex groups of 1-4 digits, one "::"
 * standing for one or more zero groups, optional trailing dotted quad).
 * Rejected: zone IDs ("%eth0"), brackets, ports, whitespace, NUL, trailing garbage,
 * empty input, anything longer than 45 bytes.
 *
 * Embedded forms: only ::ffff:a.b.c.d is an IPv4-mapped address. "::10.0.0.1"
 * (IPv4-compatible) and every other form stay IPv6 and never equal IPv4 10.0.0.1. */
#ifndef BST_ADDR_H
#define BST_ADDR_H

#include "core/str.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum { BST_IP_V4 = 4, BST_IP_V6 = 6 } bst_ip_family;

/* b holds 4 (V4) or 16 (V6) bytes in network order; unused bytes are always zero, so
 * bst_ip_eq may be a memcmp. */
typedef struct bst_ip {
	uint8_t family;
	uint8_t b[16];
} bst_ip;

typedef struct bst_sockaddr {
	bst_ip ip;
	uint16_t port; /* host order */
} bst_sockaddr;

/* Longest text form: 8 groups of 4 digits + 7 colons = 39; with a mapped dotted quad
 * still below 45. Buffer for bst_addr_format. */
#define BST_ADDR_STRLEN 46

/* True and *out filled on success; false (and *out untouched) on any malformed input. */
bool bst_addr_parse(bst_str s, bst_ip *out);

/* Writes a NUL-terminated canonical form (lowercase, RFC 5952 zero compression) and
 * returns its length, or 0 if cap is too small or ip is invalid. Output re-parses to
 * an equal address. */
size_t bst_addr_format(const bst_ip *ip, char *buf, size_t cap);

bool bst_ip_eq(const bst_ip *a, const bst_ip *b);

/* Maps ::ffff:a.b.c.d to IPv4 a.b.c.d; everything else is returned unchanged. */
bst_ip bst_ip_canon(const bst_ip *ip);

#endif
