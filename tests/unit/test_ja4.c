/* The JA4 fingerprint (tls/ja4.c): published vectors, GREASE, ordering and the odd cases. */
#include "tap.h"
#include "tls/ja4.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- a ClientHello builder ---- */

typedef struct {
	uint8_t b[4096];
	size_t n;
} buf;

static void u8(buf *o, unsigned v) { o->b[o->n++] = (uint8_t)v; }
static void u16(buf *o, unsigned v) { u8(o, v >> 8); u8(o, v & 255); }
static void raw(buf *o, const void *p, size_t n) { memcpy(o->b + o->n, p, n); o->n += n; }

/* Appends one extension holding body. */
static void ext(buf *e, unsigned type, const void *body, size_t n)
{
	u16(e, type);
	u16(e, (unsigned)n);
	raw(e, body, n);
}

static void hello(buf *o, const uint16_t *ciphers, size_t nc, const buf *exts)
{
	buf m = { .n = 0 };
	u16(&m, 0x0303);
	for (unsigned i = 0; i < 32; i++)
		u8(&m, i);
	u8(&m, 0);
	u16(&m, (unsigned)(nc * 2));
	for (size_t i = 0; i < nc; i++)
		u16(&m, ciphers[i]);
	u8(&m, 1);
	u8(&m, 0);
	if (exts != NULL) {
		u16(&m, (unsigned)exts->n);
		raw(&m, exts->b, exts->n);
	}
	o->n = 0;
	u8(o, 1);
	u8(o, (unsigned)(m.n >> 16));
	u16(o, (unsigned)(m.n & 0xffff));
	raw(o, m.b, m.n);
}

static void alpn_ext(buf *e, const char *name, size_t n)
{
	uint8_t b[300];
	b[0] = 0;
	b[1] = (uint8_t)(n + 1);
	b[2] = (uint8_t)n;
	memcpy(b + 3, name, n);
	ext(e, 0x0010, b, n + 3);
}

static void sigalgs_ext(buf *e, const uint16_t *v, size_t n)
{
	uint8_t b[64];
	b[0] = 0;
	b[1] = (uint8_t)(n * 2);
	for (size_t i = 0; i < n; i++) {
		b[2 + 2 * i] = (uint8_t)(v[i] >> 8);
		b[3 + 2 * i] = (uint8_t)v[i];
	}
	ext(e, 0x000d, b, n * 2 + 2);
}

static void sni_ext(buf *e)
{
	static const uint8_t b[] = { 0, 14, 0, 0, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm' };
	ext(e, 0x0000, b, sizeof b);
}

static int fp(const buf *h, char out[40])
{
	bst_client_hello ch;
	if (bst_client_hello_parse(h->b, h->n, &ch) != 0)
		return -1;
	return bst_ja4_compute(&ch, 't', out);
}

/* ---- published vectors ---- */

/* The value of the first "key": "..." after *pos in the file text, advancing *pos; NULL at the end. */
static char *field(char **pos, const char *key)
{
	char pat[32];
	snprintf(pat, sizeof pat, "\"%s\": \"", key);
	char *p = strstr(*pos, pat);
	if (p == NULL)
		return NULL;
	p += strlen(pat);
	char *q = strchr(p, '"');
	*q = '\0';
	*pos = q + 1;
	return p;
}

TEST(vectors)
{
	FILE *f = fopen("tests/fixtures/ja4_vectors.json", "re");
	ASSERT(f != NULL);
	static char text[400000];
	size_t n = fread(text, 1, sizeof text - 1, f);
	fclose(f);
	text[n] = '\0';
	char *pos = text;
	int total = 0, spec_alpn = 0;
	for (;;) {
		char *ja4 = field(&pos, "ja4"), *hex = field(&pos, "hello");
		if (ja4 == NULL || hex == NULL)
			break;
		uint8_t raw_[4096];
		size_t len = strlen(hex) / 2;
		ASSERT(len <= sizeof raw_);
		for (size_t i = 0; i < len; i++) {
			unsigned v;
			sscanf(hex + 2 * i, "%2x", &v);
			raw_[i] = (uint8_t)v;
		}
		bst_client_hello ch;
		char out[40];
		ASSERT_EQ(bst_client_hello_parse(raw_, len, &ch), 0);
		ASSERT_EQ(bst_ja4_compute(&ch, 't', out), 0);
		total++;
		if (strcmp(out, ja4) == 0)
			continue;
		/* The one known difference: a first ALPN name that does not end in an alphanumeric byte. The
		 * written spec prints the hex nibbles, the Python and Rust tools of the same repository
		 * print "99" (JA4 vector source commit c6469a7). Everything else must match. */
		ASSERT(strncmp(ja4 + 8, "99", 2) == 0);
		ASSERT(strncmp(out, ja4, 8) == 0 && strcmp(out + 10, ja4 + 10) == 0);
		ASSERT(strncmp(out + 8, "bd", 2) == 0);
		spec_alpn++;
	}
	ASSERT(total >= 80);
	ASSERT_EQ(spec_alpn, 1);
}

TEST(spec_example_lists)
{
	/* The worked example of technical_details/JA4.md, built from its lists. */
	static const uint16_t c[] = { 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9,
				      0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035 };
	static const uint16_t order[] = { 0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d,
					  0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015 };
	static const uint16_t sig[] = { 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601 };
	buf e = { .n = 0 }, h;
	for (size_t i = 0; i < sizeof order / sizeof order[0]; i++) {
		switch (order[i]) {
		case 0x0000: sni_ext(&e); break;
		case 0x0010: alpn_ext(&e, "h2", 2); break;
		case 0x000d: sigalgs_ext(&e, sig, 8); break;
		case 0x002b: { static const uint8_t v[] = { 2, 3, 4 }; ext(&e, 0x002b, v, 3); break; }
		default: ext(&e, order[i], "", 0);
		}
	}
	hello(&h, c, 15, &e);
	char out[40];
	ASSERT_EQ(fp(&h, out), 0);
	ASSERT_STR(out, "t13d1516h2_8daaf6152771_e5627efa2ab1");
}

TEST(grease_ignored)
{
	static const uint16_t plain[] = { 0x1301, 0xc02b };
	static const uint16_t greased[] = { 0x0a0a, 0x1301, 0xfafa, 0xc02b };
	buf a = { .n = 0 }, b = { .n = 0 }, ha, hb;
	static const uint16_t sig[] = { 0x0403 }, sig_g[] = { 0x2a2a, 0x0403 };
	sigalgs_ext(&a, sig, 1);
	ext(&b, 0x3a3a, "", 0);
	sigalgs_ext(&b, sig_g, 2);
	static const uint8_t gv[] = { 4, 0x7a, 0x7a, 3, 4 };
	ext(&b, 0x002b, gv, sizeof gv);
	static const uint8_t pv[] = { 2, 3, 4 };
	ext(&a, 0x002b, pv, sizeof pv);
	hello(&ha, plain, 2, &a);
	hello(&hb, greased, 4, &b);
	char x[40], y[40];
	ASSERT_EQ(fp(&ha, x), 0);
	ASSERT_EQ(fp(&hb, y), 0);
	ASSERT_STR(x, y);
}

TEST(sorted_lists)
{
	static const uint16_t c1[] = { 0xc02b, 0x1301 }, c2[] = { 0x1301, 0xc02b };
	buf e1 = { .n = 0 }, e2 = { .n = 0 }, h1, h2;
	ext(&e1, 0x000a, "", 0);
	ext(&e1, 0x0005, "", 0);
	ext(&e2, 0x0005, "", 0);
	ext(&e2, 0x000a, "", 0);
	hello(&h1, c1, 2, &e1);
	hello(&h2, c2, 2, &e2);
	char x[40], y[40];
	ASSERT_EQ(fp(&h1, x), 0);
	ASSERT_EQ(fp(&h2, y), 0);
	ASSERT_STR(x, y);
	/* but the order of the signature algorithms counts */
	static const uint16_t s1[] = { 0x0403, 0x0804 }, s2[] = { 0x0804, 0x0403 };
	buf e3 = { .n = 0 }, e4 = { .n = 0 }, h3, h4;
	sigalgs_ext(&e3, s1, 2);
	sigalgs_ext(&e4, s2, 2);
	hello(&h3, c1, 2, &e3);
	hello(&h4, c1, 2, &e4);
	ASSERT_EQ(fp(&h3, x), 0);
	ASSERT_EQ(fp(&h4, y), 0);
	ASSERT(strcmp(x, y) != 0);
}

TEST(sni_and_alpn_leave_the_extension_hash)
{
	static const uint16_t c[] = { 0x1301 };
	buf with = { .n = 0 }, without = { .n = 0 }, h1, h2;
	sni_ext(&with);
	alpn_ext(&with, "h2", 2);
	ext(&with, 0x000a, "", 0);
	ext(&without, 0x000a, "", 0);
	hello(&h1, c, 1, &with);
	hello(&h2, c, 1, &without);
	char x[40], y[40];
	ASSERT_EQ(fp(&h1, x), 0);
	ASSERT_EQ(fp(&h2, y), 0);
	ASSERT(strcmp(x + 24, y + 24) == 0); /* the extension hash is the same */
	ASSERT(x[3] == 'd' && y[3] == 'i');
	ASSERT(strncmp(x + 8, "h2", 2) == 0 && strncmp(y + 8, "00", 2) == 0);
}

TEST(no_alpn)
{
	static const uint16_t c[] = { 0x1301 };
	buf e = { .n = 0 }, h;
	sni_ext(&e);
	hello(&h, c, 1, &e);
	char out[40];
	ASSERT_EQ(fp(&h, out), 0);
	ASSERT(strncmp(out, "t12d0101", 8) == 0 && strncmp(out + 8, "00_", 3) == 0);
}

TEST(no_sni)
{
	static const uint16_t c[] = { 0x1301 };
	buf e = { .n = 0 }, h;
	alpn_ext(&e, "http/1.1", 8);
	hello(&h, c, 1, &e);
	char out[40];
	ASSERT_EQ(fp(&h, out), 0);
	ASSERT(strncmp(out, "t12i0101h1_", 11) == 0);
}

TEST(empty_ciphers)
{
	buf e = { .n = 0 }, h;
	ext(&e, 0x000a, "", 0);
	hello(&h, NULL, 0, &e);
	char out[40];
	ASSERT_EQ(fp(&h, out), 0);
	ASSERT(strncmp(out, "t12i0001", 8) == 0);
	ASSERT(strncmp(out + 11, "000000000000_", 13) == 0);
	/* and no extensions at all */
	hello(&h, NULL, 0, NULL);
	ASSERT_EQ(fp(&h, out), 0);
	ASSERT_STR(out, "t12i000000_000000000000_000000000000");
}

TEST(non_ascii_alpn)
{
	static const uint16_t c[] = { 0x1301 };
	static const struct { const char *name; size_t n; const char *want; } t[] = {
		{ "\xab", 1, "ab" },	  { " ", 1, "20" },	   { "\xab\xcd", 2, "ad" },
		{ " a", 2, "21" },	  { "0\xab", 2, "3b" },	   { "a ", 2, "60" },
		{ "01\xab\xcd", 4, "3d" }, { "0\xab\xcd" "1", 4, "01" }, { "x", 1, "xx" },
		{ "h2", 2, "h2" },
	};
	for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
		buf e = { .n = 0 }, h;
		alpn_ext(&e, t[i].name, t[i].n);
		hello(&h, c, 1, &e);
		char out[40];
		ASSERT_EQ(fp(&h, out), 0);
		ASSERT(strncmp(out + 8, t[i].want, 2) == 0);
	}
}

TEST(counts_cap_at_99)
{
	uint16_t c[120];
	for (size_t i = 0; i < 120; i++)
		c[i] = (uint16_t)(0x1000 + i);
	buf e = { .n = 0 }, h;
	for (unsigned i = 0; i < 110; i++)
		ext(&e, 0x2000 + i, "", 0);
	hello(&h, c, 120, &e);
	char out[40];
	ASSERT_EQ(fp(&h, out), 0);
	ASSERT(strncmp(out, "t12i9999", 8) == 0);
}

TEST(quic_prefix_and_bad_transport)
{
	static const uint16_t c[] = { 0x1301 };
	buf h;
	hello(&h, c, 1, NULL);
	bst_client_hello ch;
	char out[40];
	ASSERT_EQ(bst_client_hello_parse(h.b, h.n, &ch), 0);
	ASSERT_EQ(bst_ja4_compute(&ch, 'q', out), 0);
	ASSERT(out[0] == 'q');
	ASSERT_EQ(bst_ja4_compute(&ch, 'x', out), -1);
}

TEST(malformed_hellos_are_refused)
{
	static const uint16_t c[] = { 0x1301 };
	buf e = { .n = 0 }, h;
	alpn_ext(&e, "h2", 2);
	hello(&h, c, 1, &e);
	bst_client_hello ch;
	for (size_t cut = 0; cut < h.n; cut++)
		ASSERT_EQ(bst_client_hello_parse(h.b, cut, &ch), -1); /* only the whole message parses */
	h.b[0] = 2; /* not a ClientHello */
	ASSERT_EQ(bst_client_hello_parse(h.b, h.n, &ch), -1);
	h.b[0] = 1;
	h.b[h.n - 5] = 99; /* an ALPN list length that disagrees with its extension */
	ASSERT_EQ(bst_client_hello_parse(h.b, h.n, &ch), -1);
}

TAP_MAIN()
