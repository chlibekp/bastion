/* PROXY protocol v1 and v2 (src/proxy/proxyproto.c): the specification's examples, the edge
 * cases of each version, and what the writers produce parsing back to the same addresses. */
#include "proxy/proxyproto.h"

#include "tap.h"

#include <string.h>

static const uint8_t SIG[12] = { 0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A };

static int parse_str(const char *s, bst_pp_info *i)
{
	return bst_pp_parse((const uint8_t *)s, strlen(s), i);
}

static bst_sockaddr sa(const char *ip, uint16_t port)
{
	bst_sockaddr a;
	memset(&a, 0, sizeof a);
	(void)bst_addr_parse((bst_str){ ip, (uint32_t)strlen(ip) }, &a.ip);
	a.port = port;
	return a;
}

static bool addr_is(const bst_sockaddr *a, const char *ip, uint16_t port)
{
	bst_sockaddr b = sa(ip, port);
	return a->port == port && bst_ip_eq(&a->ip, &b.ip);
}

TEST(v1_v2_vectors)
{
	bst_pp_info i;
	const char *tcp4 = "PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r\nGET /";
	ASSERT(parse_str(tcp4, &i) == 47); /* v1 TCP4 length stops at the CRLF */
	ASSERT(i.version == 1 && i.has_addr && addr_is(&i.src, "192.168.0.1", 56324) &&
		   addr_is(&i.dst, "192.168.0.11", 443)); /* v1 TCP4 addresses */
	const char *tcp6 = "PROXY TCP6 2001:db8::1 2001:db8::2 1000 80\r\n";
	ASSERT(parse_str(tcp6, &i) == (int)strlen(tcp6) && i.has_addr && addr_is(&i.src, "2001:db8::1", 1000)); /* v1 TCP6 */
	ASSERT(parse_str("PROXY UNKNOWN\r\n", &i) == 15 && !i.has_addr); /* v1 UNKNOWN */
	ASSERT(parse_str("PROXY UNKNOWN ffff::1 ffff::2 1 2\r\n", &i) > 0 && !i.has_addr); /* v1 UNKNOWN ignores what follows */

	uint8_t v2[16 + 12] = { 0 };
	memcpy(v2, SIG, 12);
	v2[12] = 0x21;
	v2[13] = 0x11;
	v2[15] = 12;
	const uint8_t a4[12] = { 10, 0, 0, 1, 10, 0, 0, 2, 0x1f, 0x90, 0x00, 0x50 };
	memcpy(v2 + 16, a4, 12);
	ASSERT(bst_pp_parse(v2, sizeof v2, &i) == 28 && i.version == 2 && !i.local &&
		   addr_is(&i.src, "10.0.0.1", 8080) && addr_is(&i.dst, "10.0.0.2", 80)); /* v2 TCP4 */

	uint8_t v6[16 + 36 + 5] = { 0 };
	memcpy(v6, SIG, 12);
	v6[12] = 0x21;
	v6[13] = 0x21;
	v6[15] = 36 + 5; /* with a TLV, skipped */
	v6[16 + 15] = 1;
	v6[16 + 31] = 2;
	v6[16 + 33] = 7;
	ASSERT(bst_pp_parse(v6, sizeof v6, &i) == (int)sizeof v6 && addr_is(&i.src, "::1", 7) &&
		   addr_is(&i.dst, "::2", 0)); /* v2 TCP6 with a TLV */

	uint8_t local[16];
	memcpy(local, SIG, 12);
	local[12] = 0x20;
	local[13] = 0;
	local[14] = local[15] = 0;
	ASSERT(bst_pp_parse(local, sizeof local, &i) == 16 && i.local && !i.has_addr); /* v2 LOCAL */
}

TEST(incremental)
{
	bst_pp_info i;
	const char *h = "PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n";
	size_t n = 0;
	int rc = 0;
	while (rc == 0 && n < strlen(h)) { /* read the way the accept side does */
		n += bst_pp_want((const uint8_t *)h, n);
		rc = bst_pp_parse((const uint8_t *)h, n, &i);
	}
	ASSERT(rc == (int)strlen(h) && n == strlen(h)); /* v1 read byte-exactly */
	uint8_t v2[16 + 12] = { 0 };
	memcpy(v2, SIG, 12);
	v2[12] = 0x21;
	v2[13] = 0x11;
	v2[15] = 12;
	n = 0;
	rc = 0;
	while (rc == 0) {
		n += bst_pp_want(v2, n);
		rc = bst_pp_parse(v2, n, &i);
	}
	ASSERT(rc == 28 && n == 28); /* v2 read byte-exactly */
	ASSERT(bst_pp_parse(v2, 5, &i) == 0); /* a v2 prefix needs more */
}

TEST(malformed)
{
	bst_pp_info i;
	ASSERT(parse_str("GET / HTTP/1.1\r\n", &i) < 0); /* no header at all */
	ASSERT(parse_str("PROXX TCP4", &i) < 0); /* bad v1 signature */
	ASSERT(parse_str("PROXY TCP4 1.2.3.4 5.6.7.8 1 2\n", &i) < 0); /* LF without CR */
	ASSERT(parse_str("PROXY TCP4 1.2.3.4 ::1 1 2\r\n", &i) < 0); /* family mismatch */
	ASSERT(parse_str("PROXY TCP4 1.2.3.4 5.6.7.8 1 65536\r\n", &i) < 0); /* port out of range */
	ASSERT(parse_str("PROXY TCP4 1.2.3.4  5.6.7.8 1 2\r\n", &i) < 0); /* double space */
	ASSERT(parse_str("PROXY TCP5 1.2.3.4 5.6.7.8 1 2\r\n", &i) < 0); /* unknown protocol */
	char longl[200];
	memset(longl, 'x', sizeof longl);
	memcpy(longl, "PROXY UNKNOWN ", 14);
	ASSERT(bst_pp_parse((const uint8_t *)longl, sizeof longl, &i) < 0); /* v1 line above 107 bytes */
	ASSERT(bst_pp_parse((const uint8_t *)longl, 100, &i) == 0); /* a v1 line below 107 needs more */
	ASSERT(parse_str("PROXY TCP4 1.2.3.4 5.6.7.8 1", &i) == 0); /* truncated v1 needs more */

	uint8_t v2[16 + 12] = { 0 };
	memcpy(v2, SIG, 12);
	v2[12] = 0x21;
	v2[13] = 0x11;
	v2[15] = 4; /* too short for two IPv4 addresses and ports */
	ASSERT(bst_pp_parse(v2, sizeof v2, &i) < 0); /* length below the address block */
	v2[14] = 0xff;
	v2[15] = 0xff;
	ASSERT(bst_pp_parse(v2, sizeof v2, &i) < 0); /* length above BST_PP_MAX */
	v2[14] = 0;
	v2[15] = 12;
	ASSERT(bst_pp_parse(v2, 20, &i) == 0); /* truncated v2 needs more */
	v2[12] = 0x11;
	ASSERT(bst_pp_parse(v2, sizeof v2, &i) < 0); /* version 1 in a v2 header */
	v2[12] = 0x22;
	ASSERT(bst_pp_parse(v2, sizeof v2, &i) < 0); /* unknown command */
	v2[12] = 0x21;
	v2[13] = 0x12;
	ASSERT(bst_pp_parse(v2, sizeof v2, &i) < 0); /* UDP is refused */
	v2[13] = 0x11;
	v2[3] = 0x0B;
	ASSERT(bst_pp_parse(v2, sizeof v2, &i) < 0); /* bad v2 signature */
}

TEST(write_roundtrip)
{
	bst_pp_info i;
	bst_sockaddr s4 = sa("203.0.113.7", 40000), d4 = sa("198.51.100.1", 443);
	char b1[BST_PP_V1_MAX + 1];
	size_t n = bst_pp_write_v1(&s4, &d4, b1, sizeof b1);
	ASSERT(n > 0 && memcmp(b1, "PROXY TCP4 203.0.113.7 198.51.100.1 40000 443\r\n", n) == 0); /* v1 written */
	uint8_t b2[BST_PP_V2_OUT_MAX];
	n = bst_pp_write_v2(&s4, &d4, b2, sizeof b2);
	ASSERT(n == 28 && bst_pp_parse(b2, n, &i) == 28 && addr_is(&i.src, "203.0.113.7", 40000) &&
		   addr_is(&i.dst, "198.51.100.1", 443)); /* v2 written and parsed back */
	bst_sockaddr s6 = sa("2001:db8::5", 1), mixed = sa("::ffff:10.0.0.1", 2);
	n = bst_pp_write_v2(&s6, &d4, b2, sizeof b2);
	ASSERT(n == 52 && bst_pp_parse(b2, n, &i) == 52 && i.src.ip.family == BST_IP_V6); /* mixed families map to v6 */
	n = bst_pp_write_v1(&mixed, &d4, b1, sizeof b1);
	ASSERT(n > 0 && strncmp(b1, "PROXY TCP4 10.0.0.1 ", 20) == 0); /* a v4-mapped address is written as v4 */
	ASSERT(bst_pp_write_v1(NULL, &d4, b1, sizeof b1) == 15); /* no client: UNKNOWN */
	n = bst_pp_write_v2(NULL, NULL, b2, sizeof b2);
	ASSERT(n == 16 && bst_pp_parse(b2, n, &i) == 16 && !i.has_addr && !i.local); /* v2 without address */
	ASSERT(bst_pp_write_v1(&s4, &d4, b1, 10) == 0); /* too small a buffer */
}

TAP_MAIN()
