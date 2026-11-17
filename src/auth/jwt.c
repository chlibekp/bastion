/* See jwt.h. Also the auth_jwt mechanism (auth/auth_common.h) and its directives. */
#include "auth/jwt.h"

#include "auth/auth_common.h"
#include "auth/jwks.h"
#include "config/compile.h"
#include "config/values.h"
#include "core/b64.h"
#include "core/log.h"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ecdsa.h>
#include <openssl/rsa.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ---- verification ---- */

static const struct {
	const char *name;
	uint32_t bit;
	const char *md;
	size_t rawsig; /* ECDSA r||s length, 0 for others */
} algs[] = {
	{ "ES256", BST_JWT_ES256, "SHA256", 64 }, { "ES384", BST_JWT_ES384, "SHA384", 96 },
	{ "RS256", BST_JWT_RS256, "SHA256", 0 },  { "PS256", BST_JWT_PS256, "SHA256", 0 },
	{ "EdDSA", BST_JWT_EDDSA, NULL, 0 },	  { "HS256", BST_JWT_HS256, "SHA256", 0 },
};

const char *bst_jwt_rc_str(bst_jwt_rc rc)
{
	static const char *const s[] = { "ok", "malformed", "algorithm", "key", "signature", "crit",
					 "expired", "not yet valid", "iss", "aud", "claim" };
	return (unsigned)rc < sizeof s / sizeof s[0] ? s[rc] : "?";
}

/* A base64url segment into a fresh arena buffer (NUL-terminated). */
static bool seg(bst_arena *a, bst_str in, uint8_t **out, size_t *len)
{
	size_t cap = (size_t)in.len * 3 / 4 + 3;
	uint8_t *b = bst_arena_alloc(a, cap + 1);
	if (b == NULL)
		return false;
	long n = bst_b64_decode(in.p, in.len, b, cap, BST_B64_URL | BST_B64_PAD_FORBIDDEN);
	if (n < 0)
		return false;
	b[n] = 0;
	*out = b;
	*len = (size_t)n;
	return true;
}

static bool sig_ok(const bst_jwk *k, size_t ai, const char *in, size_t inl, const uint8_t *sig,
		   size_t sl)
{
	if (algs[ai].bit == BST_JWT_HS256) {
		if (k->secret == NULL || sl != 32)
			return false;
		uint8_t mac[32];
		size_t ml = 0;
		EVP_MAC *m = EVP_MAC_fetch(NULL, "HMAC", NULL);
		EVP_MAC_CTX *mc = m ? EVP_MAC_CTX_new(m) : NULL;
		EVP_MAC_free(m);
		OSSL_PARAM ps[] = { OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA256", 0),
				    OSSL_PARAM_construct_end() };
		bool ok = mc && EVP_MAC_init(mc, k->secret, k->secret_len, ps) == 1 &&
			  EVP_MAC_update(mc, (const uint8_t *)in, inl) == 1 &&
			  EVP_MAC_final(mc, mac, &ml, sizeof mac) == 1 && ml == 32 &&
			  CRYPTO_memcmp(mac, sig, 32) == 0;
		EVP_MAC_CTX_free(mc);
		return ok;
	}
	if (k->pkey == NULL)
		return false;
	uint8_t der[160];
	const uint8_t *s = sig;
	size_t dl = sl;
	if (algs[ai].rawsig != 0) { /* JOSE r||s to the DER OpenSSL verifies */
		size_t h = algs[ai].rawsig / 2;
		if (sl != algs[ai].rawsig)
			return false;
		ECDSA_SIG *es = ECDSA_SIG_new();
		BIGNUM *r = BN_bin2bn(sig, (int)h, NULL), *ss = BN_bin2bn(sig + h, (int)h, NULL);
		if (es == NULL || r == NULL || ss == NULL || ECDSA_SIG_set0(es, r, ss) != 1) {
			BN_free(r);
			BN_free(ss);
			ECDSA_SIG_free(es);
			return false;
		}
		uint8_t *p = der;
		int n = i2d_ECDSA_SIG(es, NULL);
		if (n <= 0 || (size_t)n > sizeof der) {
			ECDSA_SIG_free(es);
			return false;
		}
		n = i2d_ECDSA_SIG(es, &p);
		ECDSA_SIG_free(es);
		s = der;
		dl = (size_t)n;
	}
	EVP_MD_CTX *mc = EVP_MD_CTX_new();
	EVP_PKEY_CTX *pc = NULL;
	bool ok = mc != NULL &&
		  EVP_DigestVerifyInit_ex(mc, &pc, algs[ai].md, NULL, NULL, k->pkey, NULL) == 1;
	if (ok && algs[ai].bit == BST_JWT_PS256)
		ok = EVP_PKEY_CTX_set_rsa_padding(pc, RSA_PKCS1_PSS_PADDING) == 1 &&
		     EVP_PKEY_CTX_set_rsa_pss_saltlen(pc, RSA_PSS_SALTLEN_DIGEST) == 1;
	else if (ok && algs[ai].bit == BST_JWT_RS256)
		ok = EVP_PKEY_CTX_set_rsa_padding(pc, RSA_PKCS1_PADDING) == 1;
	ok = ok && EVP_DigestVerify(mc, s, dl, (const uint8_t *)in, inl) == 1;
	EVP_MD_CTX_free(mc);
	return ok;
}

static bool num(const bst_json *o, const char *k, int64_t *v, bool *bad)
{
	const bst_json *j = bst_json_get(o, k);
	if (j == NULL)
		return false;
	if (bst_json_int(j, v) != BST_JSON_INT_OK)
		*bad = true;
	return true;
}

static bool aud_ok(const bst_jwt_cfg *c, const bst_json *aud)
{
	if (aud == NULL)
		return false;
	size_t n = bst_json_typeof(aud) == BST_JSON_ARR ? bst_json_arr_len(aud) : 1;
	for (size_t i = 0; i < n; i++) {
		const bst_json *v = bst_json_typeof(aud) == BST_JSON_ARR ? bst_json_arr_at(aud, i) : aud;
		bst_str s;
		if (!bst_json_str(v, &s))
			return false;
		for (size_t k = 0; k < c->naud; k++)
			if (bst_str_eq(s, (bst_str){ c->aud[k], (uint32_t)strlen(c->aud[k]) }))
				return true;
	}
	return false;
}

bst_jwt_rc bst_jwt_verify(bst_str tok, const bst_jwt_cfg *c, int64_t now, bst_arena *a,
			  bst_jwt_claims *out)
{
	memset(out, 0, sizeof *out);
	if (tok.len == 0 || tok.len > BST_JWT_MAX)
		return BST_JWT_MALFORMED;
	const char *d1 = memchr(tok.p, '.', tok.len);
	const char *d2 = d1 ? memchr(d1 + 1, '.', (size_t)(tok.p + tok.len - d1 - 1)) : NULL;
	if (d1 == NULL || d2 == NULL || memchr(d2 + 1, '.', (size_t)(tok.p + tok.len - d2 - 1)) != NULL)
		return BST_JWT_MALFORMED;
	bst_str h64 = { tok.p, (uint32_t)(d1 - tok.p) };
	bst_str p64 = { d1 + 1, (uint32_t)(d2 - d1 - 1) };
	bst_str s64 = { d2 + 1, (uint32_t)(tok.p + tok.len - d2 - 1) };
	uint8_t *hb, *pb, *sb;
	size_t hl, pl, sl;
	if (h64.len == 0 || p64.len == 0 || s64.len == 0 || !seg(a, h64, &hb, &hl) ||
	    !seg(a, p64, &pb, &pl) || !seg(a, s64, &sb, &sl))
		return BST_JWT_MALFORMED;
	bst_err e = { .msg = "" };
	const bst_json *hdr = bst_json_parse(a, (const char *)hb, hl, &e);
	if (hdr == NULL || bst_json_typeof(hdr) != BST_JSON_OBJ)
		return BST_JWT_MALFORMED;
	const bst_json *aj = bst_json_get(hdr, "alg");
	bst_str alg;
	if (aj == NULL || !bst_json_str(aj, &alg))
		return BST_JWT_ALG;
	size_t ai = sizeof algs / sizeof algs[0];
	for (size_t i = 0; i < sizeof algs / sizeof algs[0]; i++)
		if (bst_str_eq(alg, (bst_str){ algs[i].name, (uint32_t)strlen(algs[i].name) }))
			ai = i;
	if (ai == sizeof algs / sizeof algs[0] || (c->algs & algs[ai].bit) == 0)
		return BST_JWT_ALG; /* "none" in any case is simply not in the table */
	if (bst_json_get(hdr, "crit") != NULL)
		return BST_JWT_CRIT; /* no extension is understood here */
	const bst_json *kj = bst_json_get(hdr, "kid");
	bst_str kid = { NULL, 0 };
	if (kj != NULL && !bst_json_str(kj, &kid))
		return BST_JWT_MALFORMED;
	const bst_jwk *k = bst_jwks_find(c->keys, kid, kj != NULL, algs[ai].bit);
	if (k == NULL)
		return BST_JWT_KEY;
	if (!sig_ok(k, ai, tok.p, (size_t)(d2 - tok.p), sb, sl))
		return BST_JWT_SIGNATURE;
	const bst_json *pay = bst_json_parse(a, (const char *)pb, pl, &e);
	if (pay == NULL || bst_json_typeof(pay) != BST_JSON_OBJ)
		return BST_JWT_MALFORMED; /* duplicate members fail here too */
	int64_t exp = 0, nbf = 0, iat = 0;
	bool bad = false;
	bool has_exp = num(pay, "exp", &exp, &bad), has_nbf = num(pay, "nbf", &nbf, &bad),
	     has_iat = num(pay, "iat", &iat, &bad);
	if (bad)
		return BST_JWT_MALFORMED;
	int64_t lw = c->leeway_s;
	if (has_exp && now >= exp + lw)
		return BST_JWT_EXPIRED;
	if ((has_nbf && now + lw < nbf) || (has_iat && iat > now + lw))
		return BST_JWT_NOT_YET;
	if (c->iss != NULL) {
		const bst_json *ij = bst_json_get(pay, "iss");
		bst_str iss;
		if (ij == NULL || !bst_json_str(ij, &iss) ||
		    !bst_str_eq(iss, (bst_str){ c->iss, (uint32_t)strlen(c->iss) }))
			return BST_JWT_ISS;
	}
	if (c->naud > 0 && !aud_ok(c, bst_json_get(pay, "aud")))
		return BST_JWT_AUD;
	for (size_t i = 0; i < c->nrequired; i++)
		if (bst_json_get(pay, c->required[i]) == NULL)
			return BST_JWT_CLAIM;
	out->payload = pay;
	out->exp = has_exp ? exp : 0;
	return BST_JWT_OK;
}

/* ---- the mechanism ---- */

static bst_str token_of(bst_stream *s, const bst_jwt_cfg *c)
{
	bst_str none = { NULL, 0 };
	const bst_headers *hs = &s->req.head.headers;
	if (c->cookie != NULL) {
		size_t cl = strlen(c->cookie);
		for (const bst_header *h = bst_headers_next(hs, NULL, BST_H_COOKIE); h != NULL;
		     h = bst_headers_next(hs, h, BST_H_COOKIE)) {
			bst_str v = h->value;
			uint32_t i = 0;
			while (i < v.len) {
				while (i < v.len && (v.p[i] == ' ' || v.p[i] == ';'))
					i++;
				uint32_t st = i;
				while (i < v.len && v.p[i] != ';')
					i++;
				bst_str kv = { v.p + st, i - st };
				if (kv.len > cl && memcmp(kv.p, c->cookie, cl) == 0 && kv.p[cl] == '=')
					return (bst_str){ kv.p + cl + 1, (uint32_t)(kv.len - cl - 1) };
			}
		}
		return none;
	}
	const char *hn = c->header ? c->header : "Authorization";
	bst_str name = { hn, (uint32_t)strlen(hn) };
	const bst_header *h = bst_headers_get_name(hs, name);
	if (h == NULL || bst_headers_next_name(hs, h, name) != NULL)
		return none;
	bst_str v = h->value;
	if (v.len < 8 || !bst_str_ieq((bst_str){ v.p, 7 }, BST_S("bearer ")))
		return none;
	uint32_t i = 7;
	while (i < v.len && v.p[i] == ' ')
		i++;
	return (bst_str){ v.p + i, v.len - i };
}

/* A claim's value as header text: strings and integers only, and never one with a byte that
 * could end or fold a header line. */
static bool claim_text(bst_stream *s, const bst_json *j, bst_str *out)
{
	if (j == NULL)
		return false;
	if (bst_json_typeof(j) == BST_JSON_STR) {
		if (!bst_json_str(j, out))
			return false;
	} else if (bst_json_typeof(j) != BST_JSON_NUM || !bst_json_num_text(j, out)) {
		return false;
	}
	(void)s;
	for (uint32_t i = 0; i < out->len; i++) {
		unsigned char ch = (unsigned char)out->p[i];
		if (ch < 0x20 || ch == 0x7f)
			return false;
	}
	return true;
}

void bst_auth_jwt_start(bst_auth_run *r)
{
	bst_stream *s = bst_auth_stream(r);
	const bst_jwt_cfg *c = s->cfg->auth.jwt;
	bst_headers *rq = &s->req.head.headers;
	for (size_t i = 0; i < c->nmaps; i++) /* the client's own copies never pass */
		(void)bst_headers_remove_name(rq, (bst_str){ c->maps[i].header,
							     (uint32_t)strlen(c->maps[i].header) });
	bst_str tok = token_of(s, c);
	if (tok.p == NULL) {
		bst_auth_step(r, 401, BST_S("WWW-Authenticate"), BST_S("Bearer"));
		return;
	}
	bst_jwt_claims cl;
	bst_jwt_rc rc = bst_jwt_verify(tok, c, (int64_t)time(NULL), s->arena, &cl);
	if (rc != BST_JWT_OK) {
		bst_log(BST_LOG_INFO, "auth_jwt: token refused (%s)", bst_jwt_rc_str(rc));
		bst_auth_step(r, 401, BST_S("WWW-Authenticate"), BST_S("Bearer error=\"invalid_token\""));
		return;
	}
	s->jwt_claims = cl.payload;
	for (size_t i = 0; i < c->nmaps; i++) {
		bst_str v;
		if (claim_text(s, bst_json_get(cl.payload, c->maps[i].claim), &v))
			(void)bst_headers_add(rq, (bst_str){ c->maps[i].header,
							     (uint32_t)strlen(c->maps[i].header) }, v);
	}
	bst_str sub;
	if (claim_text(s, bst_json_get(cl.payload, "sub"), &sub))
		s->auth_user = sub;
	bst_auth_step(r, 0, (bst_str){ NULL, 0 }, (bst_str){ NULL, 0 });
}

/* ---- directives ---- */

#define GSL (BST_CTX_GLOBAL | BST_CTX_SERVER | BST_CTX_LOCATION)

static int split_list(bst_cfg_ctx *c, const bst_ast_arg *v, const char ***out, size_t *n, bst_err *e)
{
	size_t cnt = 1;
	for (size_t i = 0; i < v->len; i++)
		cnt += v->text[i] == ',';
	const char **l = bst_arena_alloc(c->arena, cnt * sizeof *l);
	if (l == NULL) {
		bst_err_set(e, "out of memory");
		return -1;
	}
	size_t k = 0, st = 0;
	for (size_t i = 0; i <= v->len; i++)
		if (i == v->len || v->text[i] == ',') {
			if (i > st && (l[k] = bst_cfg_strdup(c, v->text + st, i - st, e)) == NULL)
				return -1;
			if (i > st)
				k++;
			st = i + 1;
		}
	*out = l;
	*n = k;
	return 0;
}

static void jwks_free_cb(void *p)
{
	bst_jwks_free(p);
}

/* Key sets loaded by this compile, handed to the config's cleanups by the post hook. */
static bst_jwks **g_pend;
static size_t g_npend, g_cap;

static int ap_jwt(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *p0 = bst_dir_pos(d, n, 0);
	if (p0 != NULL && p0->len == 3 && memcmp(p0->text, "off", 3) == 0) {
		c->common->auth.jwt = NULL;
		return 0;
	}
	bst_jwt_cfg *j = bst_arena_alloc(c->arena, sizeof *j);
	if (j == NULL) {
		bst_err_set(e, "out of memory");
		return -1;
	}
	memset(j, 0, sizeof *j);
	j->algs = BST_JWT_ES256 | BST_JWT_ES384 | BST_JWT_RS256 | BST_JWT_PS256 | BST_JWT_EDDSA;
	bst_ast_arg v;
	bool secret = bst_dir_opt(d, n, "secret=", &v);
	bool keys = !secret && bst_dir_opt(d, n, "keys=", &v);
	if (!secret && !keys) {
		bst_err_set(e, "auth_jwt: keys=<file> or secret=<file> is required");
		bst_cfg_err_at(e, &n->loc);
		return -1;
	}
	char *path = bst_cfg_strdup(c, v.text, v.len, e);
	if (path == NULL)
		return -1;
	if (strncmp(path, "http://", 7) == 0 || strncmp(path, "https://", 8) == 0) {
		bst_err_set(e, "auth_jwt: keys= from a URL is not supported yet; use a JWKS file");
		bst_cfg_err_at(e, &v.loc);
		return -1;
	}
	char why[160];
	bst_jwks *ks = bst_jwks_load_file(path, secret, why, sizeof why);
	if (ks == NULL) {
		bst_err_set(e, "auth_jwt: can not load '%s': %s", path, why);
		bst_cfg_err_at(e, &v.loc);
		return -1;
	}
	if (g_npend == g_cap) {
		size_t nc = g_cap ? g_cap * 2 : 8;
		bst_jwks **np = realloc(g_pend, nc * sizeof *np);
		if (np == NULL) {
			bst_jwks_free(ks);
			bst_err_set(e, "out of memory");
			return -1;
		}
		g_pend = np;
		g_cap = nc;
	}
	g_pend[g_npend++] = ks;
	j->keys = ks;
	if (bst_dir_opt(d, n, "alg=", &v)) {
		const char **l;
		size_t cnt;
		if (split_list(c, &v, &l, &cnt, e) != 0)
			return -1;
		j->algs = 0;
		for (size_t i = 0; i < cnt; i++) {
			uint32_t b = 0;
			for (size_t k = 0; k < sizeof algs / sizeof algs[0]; k++)
				if (strcmp(l[i], algs[k].name) == 0)
					b = algs[k].bit;
			if (b == 0) {
				bst_err_set(e, "auth_jwt: alg '%s' is not one of ES256 ES384 RS256 PS256 EdDSA HS256", l[i]);
				bst_cfg_err_at(e, &v.loc);
				return -1;
			}
			j->algs |= b;
		}
	}
	if (secret)
		j->algs = BST_JWT_HS256; /* a secret only ever verifies HS256 */
	else
		j->algs &= ~(uint32_t)BST_JWT_HS256; /* and HS256 needs an explicit secret */
	if (bst_dir_opt(d, n, "iss=", &v) && (j->iss = bst_cfg_strdup(c, v.text, v.len, e)) == NULL)
		return -1;
	if (bst_dir_opt(d, n, "aud=", &v) && split_list(c, &v, (const char ***)&j->aud, &j->naud, e) != 0)
		return -1;
	if (bst_dir_opt(d, n, "leeway=", &v)) {
		uint64_t us = 0;
		(void)bst_parse_duration_us((bst_str){ v.text, (uint32_t)v.len }, &us);
		j->leeway_s = (int64_t)(us / 1000000);
	}
	if (bst_dir_opt(d, n, "header=", &v) && (j->header = bst_cfg_strdup(c, v.text, v.len, e)) == NULL)
		return -1;
	if (bst_dir_opt(d, n, "cookie=", &v) && (j->cookie = bst_cfg_strdup(c, v.text, v.len, e)) == NULL)
		return -1;
	/* claim maps and required claims set before (same scope) are kept */
	const bst_jwt_cfg *prev = c->common->auth.jwt;
	if (prev != NULL) {
		j->maps = prev->maps;
		j->nmaps = prev->nmaps;
		j->required = prev->required;
		j->nrequired = prev->nrequired;
	}
	c->common->auth.jwt = j;
	return 0;
}

static bst_jwt_cfg *own_jwt(bst_cfg_ctx *c, bst_err *e, const bst_ast_node *n)
{
	const bst_jwt_cfg *cur = c->common->auth.jwt;
	if (cur == NULL) {
		bst_err_set(e, "auth_jwt must come first in this scope");
		bst_cfg_err_at(e, &n->loc);
		return NULL;
	}
	bst_jwt_cfg *j = bst_arena_alloc(c->arena, sizeof *j);
	if (j == NULL) {
		bst_err_set(e, "out of memory");
		return NULL;
	}
	*j = *cur;
	c->common->auth.jwt = j;
	return j;
}

static int ap_claim_header(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	bst_jwt_cfg *j = own_jwt(c, e, n);
	if (j == NULL)
		return -1;
	bst_jwt_map *m = bst_arena_alloc(c->arena, (j->nmaps + 1) * sizeof *m);
	if (m == NULL) {
		bst_err_set(e, "out of memory");
		return -1;
	}
	if (j->nmaps > 0)
		memcpy(m, j->maps, j->nmaps * sizeof *m);
	const bst_ast_arg *a0 = bst_dir_pos(d, n, 0), *a1 = bst_dir_pos(d, n, 1);
	if ((m[j->nmaps].claim = bst_cfg_strdup(c, a0->text, a0->len, e)) == NULL ||
	    (m[j->nmaps].header = bst_cfg_strdup(c, a1->text, a1->len, e)) == NULL)
		return -1;
	j->maps = m;
	j->nmaps++;
	return 0;
}

static int ap_required(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	bst_jwt_cfg *j = own_jwt(c, e, n);
	if (j == NULL)
		return -1;
	size_t np = bst_dir_npos(d, n);
	const char **l = bst_arena_alloc(c->arena, (j->nrequired + np) * sizeof *l);
	if (l == NULL) {
		bst_err_set(e, "out of memory");
		return -1;
	}
	if (j->nrequired > 0)
		memcpy(l, j->required, j->nrequired * sizeof *l);
	for (size_t i = 0; i < np; i++) {
		const bst_ast_arg *a = bst_dir_pos(d, n, i);
		if ((l[j->nrequired + i] = bst_cfg_strdup(c, a->text, a->len, e)) == NULL)
			return -1;
	}
	j->required = l;
	j->nrequired += np;
	return 0;
}

static int post_jwks(bst_config *cfg, bst_cfg_ctx *c, bst_err *e)
{
	(void)c;
	for (size_t i = 0; i < g_npend; i++)
		if (bst_config_on_free(cfg, jwks_free_cb, g_pend[i], e) != 0)
			return -1;
	g_npend = 0;
	return 0;
}
BST_CFG_POST(post_jwks);

static const bst_optspec jwt_opts[] = {
	{ .key = "keys=", .type = { .kind = BST_T_PATH } },
	{ .key = "secret=", .type = { .kind = BST_T_PATH } },
	{ .key = "alg=", .type = { .kind = BST_T_STRING } },
	{ .key = "iss=", .type = { .kind = BST_T_STRING } },
	{ .key = "aud=", .type = { .kind = BST_T_STRING } },
	{ .key = "leeway=", .type = { .kind = BST_T_DURATION, .min = 0, .max = 3600ll * 1000000 } },
	{ .key = "header=", .type = { .kind = BST_T_STRING } },
	{ .key = "cookie=", .type = { .kind = BST_T_STRING } },
};

static const bst_directive jwt_dirs[] = {
	{ .name = "auth_jwt", .contexts = GSL, .apply = ap_jwt,
	  .doc = "JWT bearer authentication: auth_jwt keys=<JWKS or PEM file> [alg=ES256,RS256,..] "
		 "[iss=..] [aud=a,b] [leeway=30s] [header=Authorization | cookie=name], or "
		 "secret=<file> for HS256 (the only way HS256 is ever accepted), or off. Allowed "
		 "algorithms: ES256, ES384, RS256, PS256, EdDSA; `none` never. Keys are picked by kid; "
		 "an unknown kid is refused. exp, nbf and iat are checked with leeway. $auth_user is "
		 "the sub claim, $jwt_claim_NAME any claim.",
	  .args = { .min_args = 0, .max_args = 1, .pos = { { .kind = BST_T_STRING } }, .opts = jwt_opts,
		    .nopts = sizeof jwt_opts / sizeof jwt_opts[0] } },
	{ .name = "auth_jwt_claim_header", .contexts = GSL, .apply = ap_claim_header, .repeatable = true,
	  .doc = "auth_jwt_claim_header <claim> <header>: the claim (a string or a number) goes to the "
		 "upstream in that request header. The client's own copies of the header are always "
		 "removed, and a value with a control byte (CR, LF) is never sent.",
	  .args = { .min_args = 2, .max_args = 2,
		    .pos = { { .kind = BST_T_STRING }, { .kind = BST_T_STRING } } } },
	{ .name = "auth_jwt_required_claim", .contexts = GSL, .apply = ap_required, .repeatable = true,
	  .doc = "Claims a token must carry to pass.",
	  .args = { .min_args = 1, .max_args = BST_ARGS_ANY, .pos = { { .kind = BST_T_STRING } } } },
};
BST_DIRECTIVES(jwt_dirs);
