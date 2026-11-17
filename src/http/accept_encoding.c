#include "http/accept_encoding.h"

#include "http/token.h"

#include <stdbool.h>
#include <stddef.h>

/* q in thousandths; -1: not listed */
typedef struct ae_q {
	int enc[BST_ENC_COUNT_];
	int star;
} ae_q;

static bool ows(char c)
{
	return c == ' ' || c == '\t';
}

/* qvalue = ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] ). -1 when invalid. */
static int parse_q(bst_str v)
{
	if (v.len == 0 || v.len > 5 || (v.p[0] != '0' && v.p[0] != '1'))
		return -1;
	int q = (v.p[0] - '0') * 1000;
	if (v.len == 1)
		return q;
	if (v.p[1] != '.')
		return -1;
	int scale = 100;
	for (uint32_t i = 2; i < v.len; i++, scale /= 10) {
		if (v.p[i] < '0' || v.p[i] > '9')
			return -1;
		q += (v.p[i] - '0') * scale;
	}
	return q > 1000 ? -1 : q;
}

static int coding_of(bst_str t)
{
	if (bst_str_ieq(t, BST_S("zstd")))
		return BST_ENC_ZSTD;
	if (bst_str_ieq(t, BST_S("br")))
		return BST_ENC_BR;
	if (bst_str_ieq(t, BST_S("gzip")) || bst_str_ieq(t, BST_S("x-gzip")))
		return BST_ENC_GZIP;
	if (bst_str_ieq(t, BST_S("identity")))
		return BST_ENC_IDENTITY;
	if (bst_str_eq(t, BST_S("*")))
		return -2;
	return -1; /* a coding we do not make: ignored */
}

/* One element: coding *( OWS ";" OWS name "=" value ). false when malformed. */
static bool parse_elem(bst_str e, ae_q *out)
{
	uint32_t i = 0;
	while (i < e.len && bst_is_tchar((unsigned char)e.p[i]))
		i++;
	bst_str tok = { e.p, i };
	if (tok.len == 0)
		return false;
	int q = 1000;
	while (i < e.len) {
		while (i < e.len && ows(e.p[i]))
			i++;
		if (i == e.len)
			break;
		if (e.p[i] != ';')
			return false;
		i++;
		while (i < e.len && ows(e.p[i]))
			i++;
		uint32_t n0 = i;
		while (i < e.len && bst_is_tchar((unsigned char)e.p[i]))
			i++;
		bst_str name = { e.p + n0, i - n0 };
		if (name.len == 0 || i == e.len || e.p[i] != '=')
			return false;
		i++;
		uint32_t v0 = i;
		while (i < e.len && bst_is_tchar((unsigned char)e.p[i]))
			i++;
		bst_str val = { e.p + v0, i - v0 };
		if (val.len == 0)
			return false;
		if (bst_str_ieq(name, BST_S("q"))) {
			q = parse_q(val);
			if (q < 0)
				return false;
		}
	}
	int c = coding_of(tok);
	if (c == -2)
		out->star = q;
	else if (c >= 0)
		out->enc[c] = q;
	return true;
}

bst_encoding bst_negotiate_encoding(bst_str ae, uint32_t allowed)
{
	ae_q q = { .enc = { -1, -1, -1, -1 }, .star = -1 };
	uint32_t i = 0;
	while (i < ae.len) {
		uint32_t s = i;
		while (i < ae.len && ae.p[i] != ',')
			i++;
		uint32_t e = i;
		while (s < e && ows(ae.p[s]))
			s++;
		while (e > s && ows(ae.p[e - 1]))
			e--;
		if (e > s && !parse_elem((bst_str){ ae.p + s, e - s }, &q))
			return BST_ENC_IDENTITY;
		if (i < ae.len)
			i++; /* the comma */
	}
	/* identity is acceptable unless excluded by itself or by *;q=0; unlisted, it weighs the
	 * lowest positive q, so any acceptable coding is preferred to it */
	int qid = q.enc[BST_ENC_IDENTITY] >= 0 ? q.enc[BST_ENC_IDENTITY] : q.star >= 0 ? q.star : 1;
	bst_encoding best = BST_ENC_IDENTITY;
	int bestq = 0;
	static const bst_encoding order[] = { BST_ENC_ZSTD, BST_ENC_BR, BST_ENC_GZIP };
	for (size_t k = 0; k < sizeof order / sizeof order[0]; k++) {
		bst_encoding c = order[k];
		if (!(allowed & BST_ENC_BIT(c)))
			continue;
		int qc = q.enc[c] >= 0 ? q.enc[c] : q.star >= 0 ? q.star : 0;
		if (qc > bestq) {
			best = c;
			bestq = qc;
		}
	}
	if (best != BST_ENC_IDENTITY && bestq < qid)
		return BST_ENC_IDENTITY;
	return best;
}

bst_str bst_encoding_name(bst_encoding e)
{
	switch (e) {
	case BST_ENC_ZSTD:
		return BST_S("zstd");
	case BST_ENC_BR:
		return BST_S("br");
	case BST_ENC_GZIP:
		return BST_S("gzip");
	default:
		return BST_S("identity");
	}
}
