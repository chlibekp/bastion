#include "core/json.h"
#include "tap.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Parse from an exact-size heap copy so ASan flags any read past len. */
static bst_json *parse_n(bst_arena *a, const char *s, size_t n, bst_err *e)
{
	char *c = malloc(n ? n : 1);
	if (!c)
		abort();
	memcpy(c, s, n);
	bst_json *j = bst_json_parse(a, c, n, e);
	free(c);
	return j;
}

static bool ok_n(const char *s, size_t n)
{
	bst_arena *a = bst_arena_new(4096);
	bst_err e;
	bool r = parse_n(a, s, n, &e) != NULL;
	bst_arena_free(a);
	return r;
}
#define OK(lit) ASSERT(ok_n((lit), sizeof(lit) - 1))
#define BAD(lit) ASSERT(!ok_n((lit), sizeof(lit) - 1))

TEST(rfc8259_valid_invalid)
{
	OK("null"); OK("true"); OK("false"); OK("0"); OK("-0"); OK("1"); OK("-12.5e+3");
	OK("1E-2"); OK("0.0"); OK("\"\""); OK("[]"); OK("{}"); OK("[1,2,3]");
	OK(" \t\r\n[ 1 , { \"a\" : [ ] } ]\n"); OK("{\"a\":{\"b\":[null,true,false]}}");
	OK("\"\\\" \\\\ \\/ \\b \\f \\n \\r \\t\""); OK("\"\xe2\x82\xac \xf0\x9f\x98\x80\"");
	OK("\"\\u00e9\\u20ac\"");

	BAD(""); BAD(" "); BAD("nul"); BAD("nulll"); BAD("True"); BAD("[1,]"); BAD("[,1]");
	BAD("[1 2]"); BAD("{\"a\":1,}"); BAD("{,}"); BAD("{\"a\"}"); BAD("{\"a\":}");
	BAD("{a:1}"); BAD("{'a':1}"); BAD("'a'"); BAD("[1"); BAD("{\"a\":1"); BAD("]");
	BAD("\"abc"); BAD("\"\\x\""); BAD("\"\\u12\""); BAD("\"\\u12g4\""); BAD("\"\\");
	BAD("{\"a\":1}{}"); BAD("1 2"); BAD("[] x"); BAD("[]\0"); BAD("// c\n1"); BAD("[1]/*x*/");
	BAD("\xef\xbb\xbf[]"); BAD("\xef\xbb\xbf" "1");
	BAD("\x0b[]"); BAD("\xc2\xa0[]"); BAD("[1,\x0c 2]");
}

TEST(number_grammar)
{
	BAD("01"); BAD("+1"); BAD("1."); BAD(".5"); BAD("-"); BAD("1e"); BAD("1e+"); BAD("0x10");
	BAD("NaN"); BAD("Infinity"); BAD("-Infinity"); BAD("--1"); BAD("-01"); BAD("1.e3");
	BAD("1.5.2"); BAD("0e"); BAD("-.5"); BAD("1_0"); BAD("[01]"); BAD("[1.]");
	OK("0e0"); OK("-0.0e-0"); OK("10"); OK("[0,-1,1e5]");
}

static int nest(const char *open, const char *close, int n)
{
	size_t ol = strlen(open), cl = strlen(close);
	size_t total = (size_t)n * (ol + cl) + 8;
	char *s = malloc(total);
	size_t p = 0;
	if (!s)
		abort();
	for (int i = 0; i < n; i++) {
		memcpy(s + p, open, ol);
		p += ol;
	}
	p += (size_t)sprintf(s + p, "1");
	for (int i = 0; i < n; i++) {
		memcpy(s + p, close, cl);
		p += cl;
	}
	bool r = ok_n(s, p);
	free(s);
	return r;
}

TEST(depth_limit)
{
	ASSERT_EQ(BST_JSON_MAX_DEPTH, 64);
	ASSERT(nest("[", "]", 64));
	ASSERT(!nest("[", "]", 65));
	ASSERT(nest("{\"a\":", "}", 64));
	ASSERT(!nest("{\"a\":", "}", 65));
	ASSERT(!nest("[", "]", 1000000));
	ASSERT(!nest("{\"a\":", "}", 300000));
	/* unterminated deep input must also stop at the limit, not recurse */
	char *s = malloc(500000);
	memset(s, '[', 500000);
	ASSERT(!ok_n(s, 500000));
	free(s);
}

TEST(duplicate_key)
{
	BAD("{\"a\":1,\"a\":2}");
	BAD("{\"a\":1,\"a\":1}");
	BAD("{\"a\":1,\"\\u0061\":2}");
	BAD("{\"\\u00e9\":1,\"\xc3\xa9\":2}");
	BAD("{\"a\\nb\":1,\"x\":0,\"a\\u000ab\":2}");
	BAD("{\"o\":{\"k\":1,\"k\":2}}");
	BAD("[{\"k\":1,\"k\":2}]");
	OK("{\"a\":1,\"b\":2}");
	OK("{\"a\":{\"a\":1},\"b\":{\"a\":2}}");
	OK("{\"a\":1,\"A\":2}");
	OK("{\"a\":1,\"a \":2}");
	OK("{\"\":1,\"a\":2}");
	BAD("{\"\":1,\"\":2}");
}

static double now(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

/* Builds {"k0":0,...,"k<n-1>":..} and optionally repeats "k0" at the end. */
static char *big_obj(int n, bool dup_last, size_t *len)
{
	size_t cap = (size_t)n * 24 + 64;
	char *s = malloc(cap);
	size_t p = 0;
	if (!s)
		abort();
	s[p++] = '{';
	for (int i = 0; i < n; i++)
		p += (size_t)sprintf(s + p, "%s\"k%d\":%d", i ? "," : "", i, i);
	if (dup_last)
		p += (size_t)sprintf(s + p, ",\"k0\":0");
	s[p++] = '}';
	*len = p;
	return s;
}

TEST(large_object_bounded)
{
	/* Pairwise comparison of 200k keys would be 2e10 compares; the hash table keeps this
	 * linear. The generous bound only catches quadratic behaviour. */
	size_t len;
	char *s = big_obj(200000, false, &len);
	bst_arena *a = bst_arena_new(1 << 20);
	bst_err e;
	double t0 = now();
	bst_json *j = parse_n(a, s, len, &e);
	double dt = now() - t0;
	ASSERT(j != NULL);
	ASSERT_EQ(bst_json_arr_len(j), 200000);
	int64_t v;
	ASSERT_EQ(bst_json_int(bst_json_get(j, "k199999"), &v), BST_JSON_INT_OK);
	ASSERT_EQ(v, 199999);
	ASSERT(dt < 5.0);
	bst_arena_free(a);
	free(s);

	/* a duplicate at the very end of a large object is still found */
	s = big_obj(200000, true, &len);
	a = bst_arena_new(1 << 20);
	t0 = now();
	ASSERT(parse_n(a, s, len, &e) == NULL);
	ASSERT(now() - t0 < 5.0);
	ASSERT(strstr(e.msg, "duplicate") != NULL);
	bst_arena_free(a);
	free(s);
}

TEST(bad_unicode)
{
	BAD("\"\\ud800\""); BAD("\"\\udbff\""); BAD("\"\\udc00\""); BAD("\"\\udfff\"");
	BAD("\"\\ud800x\""); BAD("\"\\ud800\\u0041\""); BAD("\"\\ud800\\ud800\"");
	BAD("\"\\udc00\\ud800\""); BAD("\"\\ud800\\\\\"");
	BAD("\"\xff\""); BAD("\"\x80\""); BAD("\"\xc0\x80\""); BAD("\"\xc1\xbf\"");
	BAD("\"\xc2\""); BAD("\"\xe0\x80\x80\""); BAD("\"\xe0\x9f\xbf\"");
	BAD("\"\xed\xa0\x80\""); BAD("\"\xed\xbf\xbf\""); BAD("\"\xf0\x80\x80\x80\"");
	BAD("\"\xf0\x8f\xbf\xbf\""); BAD("\"\xf4\x90\x80\x80\""); BAD("\"\xf5\x80\x80\x80\"");
	BAD("\"\xf8\x88\x80\x80\x80\""); BAD("\"\xe2\x82\""); BAD("\"\xe2\x82\x41\"");
	/* keys are validated the same way */
	BAD("{\"\xed\xa0\x80\":1}"); BAD("{\"\xff\":1}"); BAD("{\"\\ud800\":1}");
	BAD("{\"\xc0\xaf\":1}"); BAD("{\"\xf4\x90\x80\x80\":1}");
	/* boundaries that are valid */
	OK("\"\xc2\x80\""); OK("\"\xdf\xbf\""); OK("\"\xe0\xa0\x80\""); OK("\"\xed\x9f\xbf\"");
	OK("\"\xee\x80\x80\""); OK("\"\xef\xbf\xbf\""); OK("\"\xf0\x90\x80\x80\"");
	OK("\"\xf4\x8f\xbf\xbf\""); OK("{\"\xf4\x8f\xbf\xbf\":1}");
}

TEST(surrogate_pairs)
{
	bst_arena *a = bst_arena_new(4096);
	bst_err e;
	bst_str s;
	bst_json *j = parse_n(a, "\"\\ud83d\\ude00\"", 14, &e);
	ASSERT(j && bst_json_str(j, &s));
	ASSERT(s.len == 4 && memcmp(s.p, "\xf0\x9f\x98\x80", 4) == 0);
	ASSERT(s.p[4] == '\0');
	j = parse_n(a, "\"\\uDBFF\\uDFFF\"", 14, &e);
	ASSERT(j && bst_json_str(j, &s));
	ASSERT(s.len == 4 && memcmp(s.p, "\xf4\x8f\xbf\xbf", 4) == 0);
	j = parse_n(a, "\"\\u00E9\\u20AC\"", 14, &e);
	ASSERT(j && bst_json_str(j, &s));
	ASSERT(s.len == 5 && memcmp(s.p, "\xc3\xa9\xe2\x82\xac", 5) == 0);
	bst_arena_free(a);
}

TEST(nul_and_control_chars)
{
	/* Embedded U+0000 is rejected outright, in strings and in keys. */
	BAD("\"\\u0000\""); BAD("\"a\\u0000b\""); BAD("{\"\\u0000\":1}"); BAD("{\"a\\u0000\":1}");
	BAD("\"a\0b\""); BAD("{\"a\0\":1}");
	OK("\"\\u0001\"");
	/* Raw control characters are rejected, DEL is allowed by RFC 8259. */
	for (int c = 0; c < 0x20; c++) {
		char d[5] = { '"', 'a', (char)c, '"', 0 };
		ASSERT(!ok_n(d, 4));
		char k[9] = { '{', '"', 'a', (char)c, '"', ':', '1', '}', 0 };
		ASSERT(!ok_n(k, 8));
	}
	OK("\"\x7f\"");
}

static int64_t IV;
static bst_json_int_rc int_of(const char *lit, size_t n)
{
	static bst_arena *a;
	if (!a)
		a = bst_arena_new(4096);
	bst_err e;
	bst_json *j = parse_n(a, lit, n, &e);
	if (!j)
		return (bst_json_int_rc)-1;
	IV = 12345;
	return bst_json_int(j, &IV);
}
#define INT_RC(lit) int_of((lit), sizeof(lit) - 1)

TEST(int_range)
{
	ASSERT_EQ(INT_RC("9007199254740991"), BST_JSON_INT_OK);
	ASSERT_EQ(IV, 9007199254740991LL);
	ASSERT_EQ(INT_RC("-9007199254740991"), BST_JSON_INT_OK);
	ASSERT_EQ(IV, -9007199254740991LL);
	ASSERT_EQ(INT_RC("9007199254740992"), BST_JSON_INT_RANGE);
	ASSERT_EQ(IV, 12345);
	ASSERT_EQ(INT_RC("-9007199254740992"), BST_JSON_INT_RANGE);
	ASSERT_EQ(INT_RC("9007199254740993"), BST_JSON_INT_RANGE);
	ASSERT_EQ(INT_RC("18446744073709551616"), BST_JSON_INT_RANGE);
	ASSERT_EQ(INT_RC("99999999999999999999999999999999999999"), BST_JSON_INT_RANGE);
	ASSERT_EQ(INT_RC("1e400"), BST_JSON_INT_RANGE);
	ASSERT_EQ(INT_RC("-1e400"), BST_JSON_INT_RANGE);
	ASSERT_EQ(INT_RC("1e99999999999999999999"), BST_JSON_INT_RANGE);
	ASSERT_EQ(INT_RC("1e16"), BST_JSON_INT_RANGE);
	ASSERT_EQ(INT_RC("90071992547409910e-1"), BST_JSON_INT_OK);
	ASSERT_EQ(IV, 9007199254740991LL);
	ASSERT_EQ(INT_RC("90071992547409920e-1"), BST_JSON_INT_RANGE);
}

static bst_json_int_rc int_big(const char *pre, size_t zeros, const char *post)
{
	size_t n = strlen(pre) + zeros + strlen(post);
	char *s = malloc(n);
	if (!s)
		abort();
	size_t p = strlen(pre);
	memcpy(s, pre, p);
	memset(s + p, '0', zeros);
	memcpy(s + p + zeros, post, strlen(post));
	bst_arena *a = bst_arena_new(1 << 16);
	bst_err e;
	bst_json *j = parse_n(a, s, n, &e);
	bst_json_int_rc rc = j ? bst_json_int(j, &IV) : (bst_json_int_rc)-1;
	bst_arena_free(a);
	free(s);
	return rc;
}

TEST(int_saturated_exponent)
{
	/* A saturated exponent must never cancel against a long mantissa. */
	ASSERT_EQ(int_big("1", 1000000, "e-10000000"), BST_JSON_INT_NOT_INTEGER);
	ASSERT_EQ(int_big("17", 1000000, "e-10000000"), BST_JSON_INT_NOT_INTEGER);
	ASSERT_EQ(int_big("-1", 1000000, "e-10000000"), BST_JSON_INT_NOT_INTEGER);
	ASSERT_EQ(int_big("1", 2000000, "e-20000000"), BST_JSON_INT_NOT_INTEGER);
	ASSERT_EQ(int_big("0.", 999999, "1e10000000"), BST_JSON_INT_RANGE);
	ASSERT_EQ(int_big("0.", 1000000, "1e10000000"), BST_JSON_INT_RANGE);
}

TEST(int_forms)
{
	ASSERT_EQ(INT_RC("0"), BST_JSON_INT_OK);
	ASSERT_EQ(IV, 0);
	/* -0 is valid JSON and is the integer 0 */
	ASSERT_EQ(INT_RC("-0"), BST_JSON_INT_OK);
	ASSERT_EQ(IV, 0);
	ASSERT_EQ(INT_RC("-0.0e5"), BST_JSON_INT_OK);
	ASSERT_EQ(IV, 0);
	ASSERT_EQ(INT_RC("0e999999999999"), BST_JSON_INT_OK);
	ASSERT_EQ(IV, 0);
	ASSERT_EQ(INT_RC("42"), BST_JSON_INT_OK);
	ASSERT_EQ(IV, 42);
	ASSERT_EQ(INT_RC("-42"), BST_JSON_INT_OK);
	ASSERT_EQ(IV, -42);
	/* integral values spelled with an exponent or fraction are integers */
	ASSERT_EQ(INT_RC("1e2"), BST_JSON_INT_OK);
	ASSERT_EQ(IV, 100);
	ASSERT_EQ(INT_RC("1E+2"), BST_JSON_INT_OK);
	ASSERT_EQ(IV, 100);
	ASSERT_EQ(INT_RC("1.0"), BST_JSON_INT_OK);
	ASSERT_EQ(IV, 1);
	ASSERT_EQ(INT_RC("1.50e1"), BST_JSON_INT_OK);
	ASSERT_EQ(IV, 15);
	ASSERT_EQ(INT_RC("12e-1"), BST_JSON_INT_NOT_INTEGER);
	ASSERT_EQ(INT_RC("120e-1"), BST_JSON_INT_OK);
	ASSERT_EQ(IV, 12);
	ASSERT_EQ(INT_RC("1.5"), BST_JSON_INT_NOT_INTEGER);
	ASSERT_EQ(INT_RC("-1.5"), BST_JSON_INT_NOT_INTEGER);
	ASSERT_EQ(INT_RC("0.5"), BST_JSON_INT_NOT_INTEGER);
	ASSERT_EQ(INT_RC("1e-1"), BST_JSON_INT_NOT_INTEGER);
	ASSERT_EQ(INT_RC("1e-400"), BST_JSON_INT_NOT_INTEGER);
	ASSERT_EQ(INT_RC("0.0000001"), BST_JSON_INT_NOT_INTEGER);
	ASSERT_EQ(INT_RC("\"1\""), BST_JSON_INT_NOT_NUMBER);
	ASSERT_EQ(INT_RC("true"), BST_JSON_INT_NOT_NUMBER);
	ASSERT_EQ(INT_RC("[1]"), BST_JSON_INT_NOT_NUMBER);
	ASSERT_EQ(bst_json_int(NULL, &IV), BST_JSON_INT_NOT_NUMBER);
}

TEST(accessors)
{
	bst_arena *a = bst_arena_new(4096);
	bst_err e;
	const char doc[] = "{\"s\":\"hi\",\"b\":true,\"n\":null,\"a\":[1,\"x\",[]],\"o\":{}}";
	bst_json *j = parse_n(a, doc, sizeof doc - 1, &e);
	ASSERT(j);
	ASSERT_EQ(bst_json_typeof(j), BST_JSON_OBJ);
	bst_str s;
	ASSERT(bst_json_str(bst_json_get(j, "s"), &s) && s.len == 2 && !memcmp(s.p, "hi", 2));
	bool b = false;
	ASSERT(bst_json_bool(bst_json_get(j, "b"), &b) && b);
	ASSERT(!bst_json_bool(bst_json_get(j, "s"), &b));
	ASSERT_EQ(bst_json_typeof(bst_json_get(j, "n")), BST_JSON_NULL);
	ASSERT(bst_json_get(j, "zz") == NULL);
	ASSERT(bst_json_get(bst_json_get(j, "a"), "s") == NULL);
	const bst_json *arr = bst_json_get(j, "a");
	ASSERT_EQ(bst_json_arr_len(arr), 3);
	ASSERT_EQ(bst_json_typeof(bst_json_arr_at(arr, 1)), BST_JSON_STR);
	ASSERT(bst_json_arr_at(arr, 3) == NULL);
	ASSERT(bst_json_arr_at(j, 0) == NULL);
	ASSERT(!bst_json_str(arr, &s));
	bst_str k;
	ASSERT(bst_json_obj_at(j, 0, &k) && k.len == 1 && k.p[0] == 's');
	ASSERT(bst_json_obj_at(j, 5, &k) == NULL);
	ASSERT_EQ(bst_json_arr_len(bst_json_get(j, "o")), 0);
	bst_arena_free(a);
}

TEST(errors_are_safe_and_located)
{
	bst_arena *a = bst_arena_new(4096);
	bst_err e;
	const char doc[] = "[1,\n  2,\n  \"\xff\x01 %s %n \\\"junk\"]";
	ASSERT(parse_n(a, doc, sizeof doc - 1, &e) == NULL);
	ASSERT_EQ(e.line, 3);
	ASSERT(e.col >= 3);
	ASSERT(e.msg[0] != '\0');
	for (const char *p = e.msg; *p; p++)
		ASSERT((unsigned char)*p >= 0x20 && (unsigned char)*p < 0x7f);
	ASSERT(strstr(e.msg, "junk") == NULL);
	/* NULL err is allowed */
	ASSERT(bst_json_parse(a, "[", 1, NULL) == NULL);
	ASSERT(bst_json_parse(a, NULL, 0, &e) == NULL);
	bst_arena_free(a);
}

TEST(no_read_past_len)
{
	const char doc[] = "{\"a\":[1,-2.5e3,true,false,null,\"x\\u00e9\\ud83d\\ude00\"],\"b\":{\"c\":\"d\"}}";
	for (size_t n = 0; n < sizeof doc - 1; n++)
		ASSERT(!ok_n(doc, n));
	ASSERT(ok_n(doc, sizeof doc - 1));
	/* truncations of each multi-byte construct */
	const char u[] = "\"\xf0\x9f\x98\x80\\ud83d\\ude00\"";
	for (size_t n = 0; n < sizeof u - 1; n++)
		ASSERT(!ok_n(u, n));
}

static bst_str S(const char *s)
{
	return (bst_str){ s, (uint32_t)strlen(s) };
}

TEST(writer_escapes)
{
	bst_jw w;
	bst_jw_init(&w);
	bst_jw_obj_begin(&w);
	bst_jw_key(&w, S("q\"\\/"));
	bst_jw_str(&w, S("a\"b\\c\n\r\t\b\f\x01\x1f \x7f\xc3\xa9"));
	bst_jw_key(&w, S("n"));
	bst_jw_int(&w, -9007199254740991LL);
	bst_jw_key(&w, S("arr"));
	bst_jw_arr_begin(&w);
	bst_jw_bool(&w, true);
	bst_jw_null(&w);
	bst_jw_int(&w, 0);
	bst_jw_arr_begin(&w);
	bst_jw_arr_end(&w);
	bst_jw_arr_end(&w);
	bst_jw_obj_end(&w);
	ASSERT(bst_jw_finish(&w));
	ASSERT_STR(w.buf,
		   "{\"q\\\"\\\\/\":\"a\\\"b\\\\c\\n\\r\\t\\b\\f\\u0001\\u001f \x7f\xc3\xa9\","
		   "\"n\":-9007199254740991,\"arr\":[true,null,0,[]]}");

	bst_arena *a = bst_arena_new(4096);
	bst_err e;
	bst_json *j = parse_n(a, w.buf, w.len, &e);
	ASSERT(j);
	bst_str s;
	ASSERT(bst_json_str(bst_json_get(j, "q\"\\/"), &s));
	ASSERT(s.len == 16 && memcmp(s.p, "a\"b\\c\n\r\t\b\f\x01\x1f \x7f\xc3\xa9", 16) == 0);
	int64_t v;
	ASSERT_EQ(bst_json_int(bst_json_get(j, "n"), &v), BST_JSON_INT_OK);
	ASSERT_EQ(v, -9007199254740991LL);

	/* tree writer reproduces an equal document */
	bst_jw w2;
	bst_jw_init(&w2);
	bst_jw_value(&w2, j);
	ASSERT(bst_jw_finish(&w2));
	ASSERT_EQ(w2.len, w.len);
	ASSERT(memcmp(w2.buf, w.buf, w.len) == 0);
	bst_jw_free(&w2);
	bst_jw_free(&w);
	bst_arena_free(a);
}

TEST(writer_every_control_char_roundtrips)
{
	char all[0x80];
	for (int i = 1; i < 0x80; i++)
		all[i - 1] = (char)i;
	bst_jw w;
	bst_jw_init(&w);
	bst_jw_str(&w, (bst_str){ all, 0x7f });
	ASSERT(bst_jw_finish(&w));
	for (int i = 0; i < 0x20; i++)
		ASSERT(memchr(w.buf, i, w.len) == NULL || i == 0);
	bst_arena *a = bst_arena_new(4096);
	bst_err e;
	bst_json *j = parse_n(a, w.buf, w.len, &e);
	ASSERT(j);
	bst_str s;
	ASSERT(bst_json_str(j, &s) && s.len == 0x7f && memcmp(s.p, all, 0x7f) == 0);
	bst_arena_free(a);
	bst_jw_free(&w);
}

static bool finish_fails(void (*f)(bst_jw *))
{
	bst_jw w;
	bst_jw_init(&w);
	f(&w);
	bool r = !bst_jw_finish(&w);
	bst_jw_free(&w);
	return r;
}
static void m_arr_obj(bst_jw *w) { bst_jw_arr_begin(w); bst_jw_obj_end(w); }
static void m_obj_arr(bst_jw *w) { bst_jw_obj_begin(w); bst_jw_arr_end(w); }
static void m_val_in_obj(bst_jw *w) { bst_jw_obj_begin(w); bst_jw_int(w, 1); bst_jw_obj_end(w); }
static void m_key_in_arr(bst_jw *w) { bst_jw_arr_begin(w); bst_jw_key(w, S("k")); bst_jw_int(w, 1); bst_jw_arr_end(w); }
static void m_two_str(bst_jw *w) { bst_jw_str(w, S("a")); bst_jw_str(w, S("b")); }
static void m_two_int(bst_jw *w) { bst_jw_int(w, 1); bst_jw_int(w, 2); }
static void m_two_cont(bst_jw *w) { bst_jw_arr_begin(w); bst_jw_arr_end(w); bst_jw_arr_begin(w); bst_jw_arr_end(w); }
static void m_empty(bst_jw *w) { (void)w; }
static void m_key_top(bst_jw *w) { bst_jw_key(w, S("k")); }
static void m_dangling_key(bst_jw *w) { bst_jw_obj_begin(w); bst_jw_key(w, S("k")); bst_jw_obj_end(w); }
static void m_two_keys(bst_jw *w) { bst_jw_obj_begin(w); bst_jw_key(w, S("a")); bst_jw_key(w, S("b")); bst_jw_int(w, 1); bst_jw_obj_end(w); }
static void m_after_close(bst_jw *w) { bst_jw_arr_begin(w); bst_jw_arr_end(w); bst_jw_int(w, 1); }

TEST(writer_enforces_structure)
{
	ASSERT(finish_fails(m_arr_obj));
	ASSERT(finish_fails(m_obj_arr));
	ASSERT(finish_fails(m_val_in_obj));
	ASSERT(finish_fails(m_key_in_arr));
	ASSERT(finish_fails(m_two_str));
	ASSERT(finish_fails(m_two_int));
	ASSERT(finish_fails(m_two_cont));
	ASSERT(finish_fails(m_empty));
	ASSERT(finish_fails(m_key_top));
	ASSERT(finish_fails(m_dangling_key));
	ASSERT(finish_fails(m_two_keys));
	ASSERT(finish_fails(m_after_close));
	/* a lone scalar is a valid document, and the output is NUL-terminated */
	bst_jw w;
	bst_jw_init(&w);
	bst_jw_int(&w, 7);
	ASSERT(bst_jw_finish(&w));
	ASSERT_STR(w.buf, "7");
	bst_jw_free(&w);
	bst_jw_init(&w);
	bst_jw_obj_begin(&w);
	bst_jw_obj_end(&w);
	ASSERT(bst_jw_finish(&w));
	ASSERT_STR(w.buf, "{}");
	bst_jw_free(&w);
}

TEST(writer_lossy)
{
	/* strict still fails */
	bst_jw w;
	bst_jw_init(&w);
	bst_jw_str(&w, S("evil\xff"));
	ASSERT(!bst_jw_finish(&w));
	bst_jw_free(&w);

	bst_jw_init(&w);
	bst_jw_obj_begin(&w);
	bst_jw_key(&w, S("ip"));
	bst_jw_str_lossy(&w, S("1.2.3.4"));
	bst_jw_key(&w, S("ua"));
	bst_jw_str_lossy(&w, (bst_str){ "e\xffv\0\xed\xa0\x80\xc0\x80\xf4\x90\x80\x80\xe2\x82", 15 });
	bst_jw_key(&w, S("c1"));
	bst_jw_str_lossy(&w, S("a\xc2\x9b" "b\xe2\x80\xa8\xe2\x80\xa9 \xc3\xa9 \x01\"\\"));
	bst_jw_obj_end(&w);
	ASSERT(bst_jw_finish(&w));
	ASSERT(strstr(w.buf, "\xc2\x9b") == NULL);
	ASSERT(strstr(w.buf, "\xe2\x80\xa8") == NULL);
	ASSERT(strstr(w.buf, "\\u009b") != NULL);
	ASSERT(strstr(w.buf, "\\u2028") != NULL);
	ASSERT(strstr(w.buf, "\\u2029") != NULL);
	bst_arena *a = bst_arena_new(4096);
	bst_err e;
	bst_json *j = parse_n(a, w.buf, w.len, &e);
	ASSERT(j);
	bst_str s;
	ASSERT(bst_json_str(bst_json_get(j, "ua"), &s));
	ASSERT(s.len > 0 && memchr(s.p, 0xff, s.len) == NULL);
	ASSERT(memcmp(s.p, "e\xef\xbf\xbdv\xef\xbf\xbd", 8) == 0);
	ASSERT(bst_json_str(bst_json_get(j, "ip"), &s) && s.len == 7);
	bst_arena_free(a);
	bst_jw_free(&w);

	/* every single byte value and a mixed buffer always yield a parseable document */
	for (int b = 0; b < 256; b++) {
		char x[3] = { 'a', (char)b, 'z' };
		bst_jw_init(&w);
		bst_jw_str_lossy(&w, (bst_str){ x, 3 });
		ASSERT(bst_jw_finish(&w));
		ASSERT(ok_n(w.buf, w.len));
		bst_jw_free(&w);
	}
}

TEST(writer_rejects_bad_input)
{
	bst_jw w;
	bst_jw_init(&w);
	bst_jw_str(&w, S("\xed\xa0\x80"));
	ASSERT(!bst_jw_finish(&w));
	bst_jw_free(&w);

	bst_jw_init(&w);
	bst_jw_str(&w, (bst_str){ "a\0b", 3 });
	ASSERT(!bst_jw_finish(&w));
	bst_jw_free(&w);

	bst_jw_init(&w);
	for (int i = 0; i < BST_JSON_MAX_DEPTH + 1; i++)
		bst_jw_arr_begin(&w);
	ASSERT(!bst_jw_finish(&w));
	bst_jw_free(&w);

	bst_jw_init(&w);
	for (int i = 0; i < BST_JSON_MAX_DEPTH; i++)
		bst_jw_arr_begin(&w);
	for (int i = 0; i < BST_JSON_MAX_DEPTH; i++)
		bst_jw_arr_end(&w);
	ASSERT(bst_jw_finish(&w));
	bst_jw_free(&w);

	bst_jw_init(&w);
	bst_jw_arr_end(&w); /* unbalanced */
	ASSERT(!bst_jw_finish(&w));
	bst_jw_free(&w);

	bst_jw_init(&w);
	bst_jw_arr_begin(&w);
	ASSERT(!bst_jw_finish(&w)); /* unclosed */
	bst_jw_free(&w);
}

/* Generous CPU-time ceiling. Linear arena append parses 8 MiB in about 0.5 s under ASan;
 * a quadratic chunk-list walk takes about 95 s at -O2. The margin absorbs slow CI and TSan. */
#define ARENA_LINEAR_CPU_LIMIT_S 30.0

TEST(arena_small_chunks_linear)
{
	size_t n = (size_t)8 << 20;
	char *s = malloc(n + 4);
	if (!s)
		abort();
	s[0] = '[';
	for (size_t i = 0; i < n / 2; i++) {
		s[1 + 2 * i] = '0';
		s[2 + 2 * i] = ',';
	}
	s[n + 1] = '0';
	s[n + 2] = ']';
	bst_arena *a = bst_arena_new(4096);
	bst_err e;
	struct timespec t0, t1;
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t0);
	bst_json *j = parse_n(a, s, n + 3, &e);
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t1);
	double cpu = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
	printf("# parse cpu %.2f s\n", cpu);
	ASSERT(j != NULL);
	ASSERT(bst_arena_mapped(a) / 4096 > 10000);
	ASSERT(cpu < ARENA_LINEAR_CPU_LIMIT_S);
	bst_arena_free(a);
	free(s);
}

TAP_MAIN()
