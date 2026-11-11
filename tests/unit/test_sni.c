/* The server_name extension parser (tls/sni.c). */
#include "tap.h"
#include "tls/sni.h"

#include <string.h>

/* One host_name entry for name, as the extension body. */
static size_t ext(unsigned char *b, const char *name, size_t n)
{
	b[0] = (unsigned char)((n + 3) >> 8);
	b[1] = (unsigned char)(n + 3);
	b[2] = 0;
	b[3] = (unsigned char)(n >> 8);
	b[4] = (unsigned char)n;
	memcpy(b + 5, name, n);
	return n + 5;
}

static int parse(const char *name, char *out)
{
	unsigned char b[600];
	size_t l = ext(b, name, strlen(name));
	return bst_tls_sni_parse(b, l, out, BST_SNI_MAX + 1);
}

TEST(normalizes)
{
	char out[BST_SNI_MAX + 1];
	ASSERT_EQ(parse("A.Example", out), 9);
	ASSERT_STR(out, "a.example");
	ASSERT_EQ(parse("a.example.", out), 9); /* one trailing dot goes */
	ASSERT_STR(out, "a.example");
	ASSERT_EQ(parse("x_y-1.test", out), 10);
}

TEST(rejects_invalid)
{
	char out[BST_SNI_MAX + 1];
	ASSERT_EQ(parse("a b.example", out), -1);
	ASSERT_EQ(parse("a..example", out), -1);
	ASSERT_EQ(parse(".example", out), -1);
	ASSERT_EQ(parse("a.example..", out), -1);
	ASSERT_EQ(parse("*.example", out), -1);
	ASSERT_EQ(parse("a/b", out), -1);
	ASSERT_EQ(parse("", out), -1);
	ASSERT_EQ(parse(".", out), -1);
}

TEST(length_limit)
{
	char name[400], out[BST_SNI_MAX + 1];
	memset(name, 'a', sizeof name);
	name[253] = '\0';
	ASSERT_EQ(parse(name, out), 253);
	name[253] = 'a';
	name[254] = '\0';
	ASSERT_EQ(parse(name, out), -1);
	name[300] = '\0';
	ASSERT_EQ(parse(name, out), -1);
}

TEST(malformed_framing)
{
	char out[BST_SNI_MAX + 1];
	unsigned char b[32];
	ASSERT_EQ(bst_tls_sni_parse(b, 0, out, sizeof out), -1);
	ASSERT_EQ(bst_tls_sni_parse(b, 1, out, sizeof out), -1);
	size_t l = ext(b, "a.example", 9);
	ASSERT_EQ(bst_tls_sni_parse(b, l - 1, out, sizeof out), -1); /* list length lies */
	b[1] = 200;
	ASSERT_EQ(bst_tls_sni_parse(b, l, out, sizeof out), -1);
	/* no host_name entry at all: not an error */
	unsigned char other[] = { 0, 4, 7, 0, 1, 'x' };
	ASSERT_EQ(bst_tls_sni_parse(other, sizeof other, out, sizeof out), 0);
	/* a name type we do not know is skipped, a host_name after it still found */
	unsigned char good[] = { 0, 10, 7, 0, 1, 'x', 0, 0, 3, 'a', 'b', 'c' };
	ASSERT_EQ(bst_tls_sni_parse(good, sizeof good, out, sizeof out), 3);
	ASSERT_STR(out, "abc");
}

TAP_MAIN()
