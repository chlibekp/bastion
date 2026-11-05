#include "core/addr.h"
#include "core/cidr.h"
#include "tap.h"

#include <string.h>

#define PARSE_OK(lit, ipp) bst_addr_parse(BST_S(lit), (ipp))

static bool bad(const char *s, size_t n)
{
	bst_ip ip;
	return !bst_addr_parse((bst_str){ s, (uint32_t)n }, &ip);
}
#define BAD(lit) ASSERT(bad((lit), sizeof(lit) - 1))

static bool cidr_bad(const char *s, size_t n)
{
	bst_cidr c;
	return !bst_cidr_parse((bst_str){ s, (uint32_t)n }, &c);
}
#define CBAD(lit) ASSERT(cidr_bad((lit), sizeof(lit) - 1))

static int A, B, C;

static void add(bst_cidrset *s, const char *lit, int *v)
{
	bst_cidr c;
	if (!bst_cidr_parse((bst_str){ lit, (uint32_t)strlen(lit) }, &c) ||
	    bst_cidrset_add(s, &c, v) != 0) {
		printf("# setup failed for %s\n", lit);
		tap_state.current_failed = 1;
	}
}

static void *match(const bst_cidrset *s, const char *lit)
{
	bst_ip ip;
	if (!bst_addr_parse((bst_str){ lit, (uint32_t)strlen(lit) }, &ip)) {
		printf("# parse failed for %s\n", lit);
		tap_state.current_failed = 1;
		return NULL;
	}
	return bst_cidrset_match(s, &ip);
}

TEST(parse_rejects_bad)
{
	BAD("1.2.3");
	BAD("1.2.3.4.5");
	BAD("01.2.3.4");
	BAD("256.1.1.1");
	BAD("::g");
	BAD("1::2::3");
	BAD("");
	BAD("1.2.3.");
	BAD(".1.2.3");
	BAD("1..2.3");
	BAD("1.2.3.4 ");
	BAD(" 1.2.3.4");
	BAD("1.2.3.4x");
	BAD("1.2.3.0004");
	BAD("-1.2.3.4");
	BAD("0x1.2.3.4");
	BAD("1.2.3.4\0");
	BAD("1.2.\0" "3.4");
}

TEST(parse_rejects_bad_v6)
{
	BAD(":::");
	BAD("::1::");
	BAD(":1::2");
	BAD("1::2:");
	BAD("1:2:3:4:5:6:7");
	BAD("1:2:3:4:5:6:7:8:9");
	BAD("1:2:3:4:5:6:7::8");
	BAD("12345::");
	BAD("::1%eth0");
	BAD("fe80::1%eth0");
	BAD("fe80::1%");
	BAD("[::1]");
	BAD("::1 ");
	BAD(" ::1");
	BAD("::1\0");
	BAD("::1.2.3");
	BAD("::1.2.3.4.5");
	BAD("::01.2.3.4");
	BAD("::1.2.3.4:5");
	BAD("1.2.3.4::");
	BAD("1:2:3:4:5:6:7:1.2.3.4");
	BAD("::ffff:256.0.0.1");
	BAD("::/0");
}

TEST(parse_accepts_v6_forms)
{
	bst_ip ip;
	ASSERT(PARSE_OK("::", &ip));
	ASSERT(ip.family == BST_IP_V6);
	for (int i = 0; i < 16; i++)
		ASSERT_EQ(ip.b[i], 0);
	ASSERT(PARSE_OK("::1", &ip));
	ASSERT_EQ(ip.b[15], 1);
	ASSERT(PARSE_OK("1::", &ip));
	ASSERT_EQ(ip.b[1], 1);
	ASSERT(PARSE_OK("1:2:3:4:5:6:7::", &ip));
	ASSERT(PARSE_OK("::2:3:4:5:6:7:8", &ip));
	ASSERT(PARSE_OK("1:2:3:4:5:6:7:8", &ip));
	ASSERT(PARSE_OK("2001:DB8::ABcd", &ip));
	ASSERT_EQ(ip.b[0], 0x20);
	ASSERT_EQ(ip.b[14], 0xab);
	ASSERT_EQ(ip.b[15], 0xcd);
	ASSERT(PARSE_OK("0001:0002:0003:0004:0005:0006:0007:0008", &ip));
	ASSERT(PARSE_OK("1:2:3:4:5:6:1.2.3.4", &ip));
	ASSERT_EQ(ip.b[12], 1);
	ASSERT_EQ(ip.b[15], 4);
}

TEST(parse_v4_values)
{
	bst_ip ip;
	ASSERT(PARSE_OK("0.0.0.0", &ip));
	ASSERT(ip.family == BST_IP_V4);
	ASSERT(PARSE_OK("255.254.1.0", &ip));
	ASSERT_EQ(ip.b[0], 255);
	ASSERT_EQ(ip.b[1], 254);
	ASSERT_EQ(ip.b[2], 1);
	ASSERT_EQ(ip.b[3], 0);
	ASSERT_EQ(ip.b[4], 0);
}

TEST(parse_ignores_bytes_past_len)
{
	/* Valid text follows len; the parser must stop at len. */
	char buf[] = "1.2.3.4.5";
	bst_ip ip;
	ASSERT(bst_addr_parse((bst_str){ buf, 7 }, &ip));
	ASSERT_EQ(ip.b[3], 4);
	ASSERT(!bst_addr_parse((bst_str){ buf, 8 }, &ip));
}

TEST(canon_mapped_only)
{
	bst_ip m, c, k;
	ASSERT(PARSE_OK("::ffff:10.0.0.1", &m));
	c = bst_ip_canon(&m);
	ASSERT(PARSE_OK("10.0.0.1", &k));
	ASSERT(bst_ip_eq(&c, &k));
	/* hex form of the same mapped address */
	ASSERT(PARSE_OK("::ffff:a00:1", &m));
	c = bst_ip_canon(&m);
	ASSERT(bst_ip_eq(&c, &k));
	/* IPv4-compatible and other embeddings stay IPv6 */
	const char *keep[] = { "::10.0.0.1", "::a00:1", "::fffe:10.0.0.1", "64:ff9b::10.0.0.1",
			       "1::ffff:10.0.0.1", "::1:ffff:10.0.0.1" };
	for (size_t i = 0; i < sizeof keep / sizeof keep[0]; i++) {
		bst_ip ip;
		ASSERT(bst_addr_parse((bst_str){ keep[i], (uint32_t)strlen(keep[i]) }, &ip));
		c = bst_ip_canon(&ip);
		ASSERT(c.family == BST_IP_V6);
		ASSERT(bst_ip_eq(&c, &ip));
		ASSERT(!bst_ip_eq(&c, &k));
	}
	/* canon of IPv4 is identity */
	c = bst_ip_canon(&k);
	ASSERT(bst_ip_eq(&c, &k));
}

TEST(format_canonical_forms)
{
	static const struct { const char *in, *out; } t[] = {
		{ "1.2.3.4", "1.2.3.4" },
		{ "0.0.0.0", "0.0.0.0" },
		{ "::", "::" },
		{ "::1", "::1" },
		{ "1::", "1::" },
		{ "2001:0DB8:0:0:0:0:0:1", "2001:db8::1" },
		{ "1:0:0:2:0:0:0:3", "1:0:0:2::3" },
		{ "1:0:2:3:4:5:6:7", "1:0:2:3:4:5:6:7" },
		{ "1:2:0:4:5:6:7:8", "1:2:0:4:5:6:7:8" },
		{ "0:0:1:0:0:2:0:0", "::1:0:0:2:0:0" },
		{ "::ffff:1.2.3.4", "::ffff:102:304" },
		{ "::1.2.3.4", "::102:304" },
	};
	for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
		bst_ip ip, back;
		char buf[BST_ADDR_STRLEN];
		ASSERT(bst_addr_parse((bst_str){ t[i].in, (uint32_t)strlen(t[i].in) }, &ip));
		size_t n = bst_addr_format(&ip, buf, sizeof buf);
		ASSERT_EQ(n, strlen(t[i].out));
		ASSERT_STR(buf, t[i].out);
		ASSERT(bst_addr_parse((bst_str){ buf, (uint32_t)n }, &back));
		ASSERT(bst_ip_eq(&ip, &back));
	}
}

TEST(format_buffer_too_small)
{
	bst_ip ip;
	char buf[8];
	ASSERT(PARSE_OK("1.2.3.4", &ip));
	ASSERT_EQ(bst_addr_format(&ip, buf, 7), 0);
	ASSERT_EQ(bst_addr_format(&ip, buf, 8), 7);
	ASSERT(PARSE_OK("2001:db8::1", &ip));
	ASSERT_EQ(bst_addr_format(&ip, buf, sizeof buf), 0);
	ASSERT_EQ(bst_addr_format(&ip, buf, 0), 0);
}

TEST(cidr_parse_rejects_bad)
{
	CBAD("");
	CBAD("/8");
	CBAD("10.0.0.0");
	CBAD("10.0.0.0/");
	CBAD("10.0.0.0/33");
	CBAD("10.0.0.0/+8");
	CBAD("10.0.0.0/-8");
	CBAD("10.0.0.0/ 8");
	CBAD("10.0.0.0/8 ");
	CBAD("10.0.0.0/8x");
	CBAD("10.0.0.0/08");
	CBAD("10.0.0.0/0008");
	CBAD("10.0.0.0/8/8");
	CBAD("10.0.0.0/0x8");
	CBAD(" 10.0.0.0/8");
	CBAD("10.0.0.0/8\0");
	CBAD("10.0.0.0/\0" "8");
	CBAD("::/129");
	CBAD("::/129");
	CBAD("::/-1");
	CBAD("::/");
	CBAD("2001:db8::/32x");
	CBAD("fe80::%eth0/64");
	CBAD("fe80::/64%eth0");
	CBAD("10.0.0.0/999");
}

TEST(host_bits_set)
{
	CBAD("10.0.0.1/8");
	CBAD("11.0.0.0/7");
	CBAD("10.0.0.1/31");
	CBAD("0.0.0.1/0");
	CBAD("2001:db8::1/32");
	CBAD("::1/0");
	CBAD("::1/127");
	bst_cidr c;
	ASSERT(bst_cidr_parse(BST_S("10.0.0.1/32"), &c));
	ASSERT(bst_cidr_parse(BST_S("10.0.0.0/31"), &c));
	ASSERT(bst_cidr_parse(BST_S("10.0.0.0/7"), &c));
	ASSERT(bst_cidr_parse(BST_S("::1/128"), &c));
	ASSERT(bst_cidr_parse(BST_S("2001:db8::/32"), &c));
	ASSERT_EQ(c.prefix, 32);
}

TEST(cidr_parse_canonicalises_mapped)
{
	bst_cidr c;
	ASSERT(bst_cidr_parse(BST_S("::ffff:10.0.0.0/104"), &c));
	ASSERT(c.ip.family == BST_IP_V4);
	ASSERT_EQ(c.prefix, 8);
	ASSERT_EQ(c.ip.b[0], 10);
	/* shorter than 96 stays IPv6 */
	ASSERT(bst_cidr_parse(BST_S("::ffff:0:0/80"), &c) == false); /* host bits set */
	ASSERT(bst_cidr_parse(BST_S("::/80"), &c));
	ASSERT(c.ip.family == BST_IP_V6);
	ASSERT_EQ(c.prefix, 80);
}

TEST(mapped_v4)
{
	bst_cidrset *s = bst_cidrset_new();
	ASSERT(s);
	add(s, "10.0.0.0/8", &A);
	ASSERT(match(s, "::ffff:10.0.0.1") == &A);
	ASSERT(match(s, "::ffff:a00:1") == &A);
	ASSERT(match(s, "::ffff:11.0.0.1") == NULL);
	/* IPv4-compatible is a different address */
	ASSERT(match(s, "::10.0.0.1") == NULL);
	ASSERT(match(s, "::a00:1") == NULL);
	bst_cidrset_free(s);
}

TEST(mapped_cidr_matches_v4_and_mapped)
{
	bst_cidrset *s = bst_cidrset_new();
	add(s, "::ffff:10.0.0.0/104", &A);
	ASSERT(match(s, "10.1.2.3") == &A);
	ASSERT(match(s, "::ffff:10.1.2.3") == &A);
	ASSERT(match(s, "11.1.2.3") == NULL);
	bst_cidrset_free(s);
}

TEST(longest_prefix)
{
	bst_cidrset *s = bst_cidrset_new();
	add(s, "10.0.0.0/8", &A);
	add(s, "10.1.0.0/16", &B);
	ASSERT(match(s, "10.1.2.3") == &B);
	ASSERT(match(s, "10.2.2.3") == &A);
	ASSERT(match(s, "11.0.0.1") == NULL);
	bst_cidrset_free(s);
}

TEST(longest_prefix_insert_order_independent)
{
	/* Specific first, then general, then a sibling forcing a branch split. */
	bst_cidrset *s = bst_cidrset_new();
	add(s, "10.1.2.0/24", &C);
	add(s, "10.1.0.0/16", &B);
	add(s, "10.0.0.0/8", &A);
	add(s, "10.128.0.0/9", &B);
	ASSERT(match(s, "10.1.2.9") == &C);
	ASSERT(match(s, "10.1.3.9") == &B);
	ASSERT(match(s, "10.2.0.1") == &A);
	ASSERT(match(s, "10.200.0.1") == &B);
	ASSERT(match(s, "10.127.255.255") == &A);
	bst_cidrset_free(s);
}

TEST(branch_node_without_value_does_not_match)
{
	/* Two siblings create an internal node at /23 that carries no value. */
	bst_cidrset *s = bst_cidrset_new();
	add(s, "10.0.0.0/24", &A);
	add(s, "10.0.1.0/24", &B);
	ASSERT(match(s, "10.0.0.5") == &A);
	ASSERT(match(s, "10.0.1.5") == &B);
	ASSERT(match(s, "10.0.2.5") == NULL);
	ASSERT(match(s, "10.0.3.5") == NULL);
	bst_cidrset_free(s);
}

TEST(v6_prefix)
{
	bst_cidrset *s = bst_cidrset_new();
	add(s, "2001:db8::/32", &A);
	ASSERT(match(s, "2001:db8::1") == &A);
	ASSERT(match(s, "2001:db8:ffff::1") == &A);
	ASSERT(match(s, "2001:db9::1") == NULL);
	ASSERT(match(s, "2001:db7:ffff:ffff::1") == NULL);
	ASSERT(match(s, "2001:db8:0:0:0:0:0:0") == &A);
	bst_cidrset_free(s);
}

TEST(v6_longest_and_host)
{
	bst_cidrset *s = bst_cidrset_new();
	add(s, "2001:db8::/32", &A);
	add(s, "2001:db8:1::/48", &B);
	add(s, "2001:db8:1::5/128", &C);
	ASSERT(match(s, "2001:db8:1::5") == &C);
	ASSERT(match(s, "2001:db8:1::6") == &B);
	ASSERT(match(s, "2001:db8:2::6") == &A);
	bst_cidrset_free(s);
}

TEST(families_do_not_mix)
{
	bst_cidrset *s = bst_cidrset_new();
	add(s, "0.0.0.0/0", &A);
	ASSERT(match(s, "1.2.3.4") == &A);
	ASSERT(match(s, "255.255.255.255") == &A);
	ASSERT(match(s, "::ffff:1.2.3.4") == &A); /* canonicalised to IPv4 */
	ASSERT(match(s, "::") == NULL);
	ASSERT(match(s, "2001:db8::1") == NULL);
	ASSERT(match(s, "::1.2.3.4") == NULL);
	bst_cidrset_free(s);

	s = bst_cidrset_new();
	add(s, "::/0", &B);
	ASSERT(match(s, "::") == &B);
	ASSERT(match(s, "2001:db8::1") == &B);
	ASSERT(match(s, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") == &B);
	ASSERT(match(s, "::1.2.3.4") == &B); /* compat form is native IPv6 */
	ASSERT(match(s, "1.2.3.4") == NULL);
	ASSERT(match(s, "::ffff:1.2.3.4") == NULL); /* canon -> IPv4, not matched by ::/0 */
	bst_cidrset_free(s);
}

TEST(slash_zero_is_least_specific)
{
	bst_cidrset *s = bst_cidrset_new();
	add(s, "0.0.0.0/0", &A);
	add(s, "10.0.0.0/8", &B);
	add(s, "::/0", &C);
	add(s, "2001:db8::/32", &B);
	ASSERT(match(s, "10.1.1.1") == &B);
	ASSERT(match(s, "9.1.1.1") == &A);
	ASSERT(match(s, "2001:db8::1") == &B);
	ASSERT(match(s, "2001:db9::1") == &C);
	bst_cidrset_free(s);
}

TEST(duplicate_add_replaces_value)
{
	bst_cidrset *s = bst_cidrset_new();
	bst_cidr c;
	ASSERT(bst_cidr_parse(BST_S("10.0.0.0/8"), &c));
	ASSERT_EQ(bst_cidrset_add(s, &c, &A), 0);
	ASSERT_EQ(bst_cidrset_add(s, &c, &B), 0);
	ASSERT(match(s, "10.9.9.9") == &B);
	/* Duplicate of a node that was created as a branch point. */
	add(s, "10.0.0.0/16", &A);
	add(s, "10.1.0.0/16", &A);
	ASSERT(bst_cidr_parse(BST_S("10.0.0.0/15"), &c));
	ASSERT_EQ(bst_cidrset_add(s, &c, &C), 0);
	ASSERT_EQ(bst_cidrset_add(s, &c, &B), 0);
	ASSERT(match(s, "10.1.2.3") == &A);
	ASSERT(match(s, "10.0.2.3") == &A);
	bst_cidrset_free(s);
}

TEST(add_rejects_bad_args)
{
	bst_cidrset *s = bst_cidrset_new();
	bst_cidr c;
	ASSERT(bst_cidr_parse(BST_S("10.0.0.0/8"), &c));
	ASSERT_EQ(bst_cidrset_add(s, &c, NULL), -1);
	ASSERT_EQ(bst_cidrset_add(NULL, &c, &A), -1);
	ASSERT_EQ(bst_cidrset_add(s, NULL, &A), -1);
	c.prefix = 33;
	ASSERT_EQ(bst_cidrset_add(s, &c, &A), -1);
	ASSERT(match(s, "10.0.0.1") == NULL);
	bst_cidrset_free(s);
	bst_cidrset_free(NULL);
}

TEST(empty_set_matches_nothing)
{
	bst_cidrset *s = bst_cidrset_new();
	ASSERT(match(s, "1.2.3.4") == NULL);
	ASSERT(match(s, "::1") == NULL);
	bst_cidrset_free(s);
}

TEST(many_prefixes_against_reference)
{
	/* Every /16 under 10.x gets its own value; verify each resolves exactly. */
	static int vals[256];
	bst_cidrset *s = bst_cidrset_new();
	char txt[32];
	for (int i = 255; i >= 0; i--) {
		snprintf(txt, sizeof txt, "10.%d.0.0/16", i);
		add(s, txt, &vals[i]);
	}
	for (int i = 0; i < 256; i++) {
		snprintf(txt, sizeof txt, "10.%d.77.1", i);
		ASSERT(match(s, txt) == &vals[i]);
	}
	ASSERT(match(s, "11.0.0.1") == NULL);
	bst_cidrset_free(s);
}

TEST(add_canonicalises_mapped)
{
	bst_cidrset *s = bst_cidrset_new();
	bst_cidr c;
	memset(&c, 0, sizeof c);
	c.ip.family = BST_IP_V6;
	c.ip.b[10] = 0xff;
	c.ip.b[11] = 0xff;
	c.ip.b[12] = 10;
	c.prefix = 104;
	ASSERT_EQ(bst_cidrset_add(s, &c, &A), 0);
	ASSERT(match(s, "10.1.2.3") == &A);
	ASSERT(match(s, "::ffff:10.1.2.3") == &A);
	ASSERT(match(s, "11.1.2.3") == NULL);
	/* The same rule in IPv4 form is the same rule: it replaces the value. */
	bst_cidr v4;
	ASSERT(bst_cidr_parse(BST_S("10.0.0.0/8"), &v4));
	ASSERT_EQ(bst_cidrset_add(s, &v4, &B), 0);
	ASSERT(match(s, "10.1.2.3") == &B);
	ASSERT(match(s, "::ffff:10.1.2.3") == &B);
	/* A hand-built v6 rule below /96 never matches mapped addresses. */
	c.ip.b[10] = 0;
	c.ip.b[11] = 0;
	c.ip.b[12] = 0;
	c.prefix = 64;
	ASSERT_EQ(bst_cidrset_add(s, &c, &C), 0);
	ASSERT(match(s, "::ffff:10.1.2.3") == &B);
	ASSERT(match(s, "::1") == &C);
	bst_cidrset_free(s);
}

TAP_MAIN()
