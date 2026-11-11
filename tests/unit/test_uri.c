#include "route/uri.h"
#include "tap.h"

#include <string.h>

static int norm(const char *in, bst_uri_flags f, char *out, size_t cap)
{
	size_t n = 0;
	int rc = bst_uri_normalize((bst_str){ in, (uint32_t)strlen(in) }, out, cap, f, &n);
	if (rc == 0 && (n != strlen(out)))
		return -99;
	return rc;
}

#define OK(in, want)                                                                    \
	do {                                                                            \
		char o_[256];                                                           \
		ASSERT_EQ(norm(in, 0, o_, sizeof o_), 0);                               \
		ASSERT_STR(o_, want);                                                   \
	} while (0)

#define BAD(in, err)                                                                    \
	do {                                                                            \
		char o_[256];                                                           \
		ASSERT_EQ(norm(in, 0, o_, sizeof o_), err);                             \
	} while (0)

TEST(dot_segments)
{
	/* RFC 3986 section 5.2.4, the absolute-path examples */
	OK("/a/b/c/./../../g", "/a/g");
	OK("/a/b/c/.", "/a/b/c/");
	OK("/a/b/c/..", "/a/b/");
	OK("/a/b/c/../", "/a/b/");
	OK("/./a", "/a");
	OK("/a/./b/./c", "/a/b/c");
	OK("/a/b/", "/a/b/");
	OK("/", "/");
	OK("/a/..", "/");
	OK("/a/../b", "/b");
	OK("/..a/b..", "/..a/b..");
	OK("/a/.../b", "/a/.../b");
}

TEST(above_root)
{
	OK("/../../x", "/x");
	OK("/..", "/");
	OK("/a/../../..", "/");
	OK("/../a/../../b", "/b");
}

TEST(encoded_dots)
{
	OK("/%2e%2e/x", "/x");
	OK("/%2E%2e/x", "/x");
	OK("/a/%2e/b", "/a/b");
	OK("/.%2e/x", "/x");
	BAD("/a/%2e%2e%2f", BST_URI_E_SLASH);
}

TEST(encoded_slash)
{
	BAD("/a%2fb", BST_URI_E_SLASH);
	BAD("/a%2Fb", BST_URI_E_SLASH);
	BAD("/%2f", BST_URI_E_SLASH);
	char o[64];
	ASSERT_EQ(norm("/a%2fb", BST_URI_ALLOW_ENCODED_SLASH, o, sizeof o), 0);
	ASSERT_STR(o, "/a/b");
	/* an allowed encoded slash is a real separator, so dot removal sees it */
	ASSERT_EQ(norm("/a/..%2f..%2fx", BST_URI_ALLOW_ENCODED_SLASH, o, sizeof o), 0);
	ASSERT_STR(o, "/x");
}

TEST(nul)
{
	BAD("/a%00b", BST_URI_E_NUL);
	BAD("/%00", BST_URI_E_NUL);
	char o[16];
	size_t n;
	ASSERT_EQ(bst_uri_normalize((bst_str){ "/a\0b", 4 }, o, sizeof o, 0, &n), BST_URI_E_NUL);
}

TEST(bad_percent)
{
	BAD("/%zz", BST_URI_E_PERCENT);
	BAD("/%1", BST_URI_E_PERCENT);
	BAD("/%", BST_URI_E_PERCENT);
	BAD("/a%1g", BST_URI_E_PERCENT);
	BAD("/a%g1", BST_URI_E_PERCENT);
}

TEST(backslash)
{
	OK("/a\\b", "/a\\b");
	OK("/..\\x", "/..\\x");
	OK("/a/..%5cb", "/a/..\\b");
	OK("/%5c..%5c", "/\\..\\");
}

TEST(double_encoding)
{
	OK("/%252e", "/%2e");
	OK("/%252e%252e/x", "/%2e%2e/x");
	OK("/%25", "/%");
}

TEST(merge_slashes)
{
	char o[64];
	ASSERT_EQ(norm("//a///b", BST_URI_MERGE_SLASHES, o, sizeof o), 0);
	ASSERT_STR(o, "/a/b");
	ASSERT_EQ(norm("//a///b//", BST_URI_MERGE_SLASHES, o, sizeof o), 0);
	ASSERT_STR(o, "/a/b/");
	OK("//a///b", "//a///b");
	ASSERT_EQ(norm("/a//../b", BST_URI_MERGE_SLASHES, o, sizeof o), 0);
	ASSERT_STR(o, "/b");
}

TEST(form_and_space)
{
	BAD("", BST_URI_E_FORM);
	BAD("a/b", BST_URI_E_FORM);
	BAD("*", BST_URI_E_FORM);
	char o[3];
	ASSERT_EQ(norm("/ab", 0, o, 3), BST_URI_E_SPACE); /* needs the NUL too */
	char o4[4];
	ASSERT_EQ(norm("/ab", 0, o4, 4), 0);
}

TEST(in_place)
{
	char buf[64] = "/a/%2e%2e/b/./c/../d";
	size_t n;
	ASSERT_EQ(bst_uri_normalize((bst_str){ buf, (uint32_t)strlen(buf) }, buf, sizeof buf, 0, &n), 0);
	ASSERT_STR(buf, "/b/d");
	ASSERT_EQ(n, 4);
}

TEST(idempotent)
{
	static const char *const in[] = { "/a/b/../c", "/%252e%252e/x", "/a%5c..%5cb", "//a///b/",
					  "/%2e%2e/%2e/..", "/a b", "/%25%25", "/../a/./b/..", "/\x01\xff" };
	for (size_t i = 0; i < sizeof in / sizeof in[0]; i++) {
		char a[128], enc[512], b[512];
		size_t an, en, bn;
		bst_uri_flags f = i % 2 ? BST_URI_MERGE_SLASHES : 0;
		if (bst_uri_normalize((bst_str){ in[i], (uint32_t)strlen(in[i]) }, a, sizeof a, f, &an) != 0)
			continue;
		ASSERT_EQ(bst_uri_encode_path((bst_str){ a, (uint32_t)an }, enc, sizeof enc, &en), 0);
		ASSERT_EQ(bst_uri_normalize((bst_str){ enc, (uint32_t)en }, b, sizeof b, f, &bn), 0);
		ASSERT_EQ(an, bn);
		ASSERT(memcmp(a, b, an) == 0);
	}
}

TEST(encode_path)
{
	char o[64];
	size_t n;
	ASSERT_EQ(bst_uri_encode_path(BST_S("/a b/c%d?#"), o, sizeof o, &n), 0);
	ASSERT_STR(o, "/a%20b/c%25d%3F%23");
	ASSERT_EQ(bst_uri_encode_path(BST_S("/abc"), o, 4, &n), -1);
	ASSERT_EQ(bst_uri_encode_path((bst_str){ "\0", 1 }, o, sizeof o, &n), 0);
	ASSERT_STR(o, "%00");
}

TEST(query_get)
{
	bst_str v;
	ASSERT_EQ(bst_query_get(BST_S("a=1&b=2&c"), BST_S("b"), &v), 1);
	ASSERT(bst_str_eq(v, BST_S("2")));
	ASSERT_EQ(bst_query_get(BST_S("a=1&b=2&c"), BST_S("c"), &v), 1);
	ASSERT_EQ(v.len, 0);
	ASSERT_EQ(bst_query_get(BST_S("a=1&b=2&c"), BST_S("a"), &v), 1);
	ASSERT(bst_str_eq(v, BST_S("1")));
	ASSERT_EQ(bst_query_get(BST_S("a=1&b=2"), BST_S("x"), &v), 0);
	ASSERT_EQ(bst_query_get(BST_S("ab=1"), BST_S("a"), &v), 0);
	ASSERT_EQ(bst_query_get(BST_S(""), BST_S("a"), &v), 0);
	ASSERT_EQ(bst_query_get(BST_S("a=1"), BST_S(""), &v), 0);
	ASSERT_EQ(bst_query_get(BST_S("x=1&x=2"), BST_S("x"), &v), 1);
	ASSERT(bst_str_eq(v, BST_S("1")));
}

TAP_MAIN()
