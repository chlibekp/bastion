/* See challenge.h. */
#include "sec/challenge.h"

#include "core/arena.h"
#include "core/buf.h"
#include "core/chain.h"
#include "core/counters.h"
#include "core/log.h"
#include "filters/extras.h"
#include "sec/escalate.h"
#include "sec/sec.h"

#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/uio.h>
#include <time.h>

extern const unsigned char bst_embed_challenge_page[], bst_embed_challenge_page_end[];
extern const unsigned char bst_embed_challenge_client[], bst_embed_challenge_client_end[];

static const uint8_t *g_key;
static bst_counter_id c_issued = BST_COUNTER_INVALID, c_passed = BST_COUNTER_INVALID,
		      c_failed = BST_COUNTER_INVALID;

static void count(bst_counter_id id)
{
	if (id != BST_COUNTER_INVALID)
		bst_counter_add(id, 1);
}

int bst_challenge_setup(void *mem)
{
	if (getrandom(mem, BST_CHALLENGE_KEY_LEN, 0) != BST_CHALLENGE_KEY_LEN)
		return -1;
	g_key = mem;
	c_issued = bst_counter_register("bastion_challenge_issued_total", "challenge pages sent", NULL);
	c_passed = bst_counter_register("bastion_challenge_passed_total", "challenges solved: a pass was set", NULL);
	c_failed = bst_counter_register("bastion_challenge_failed_total",
					"answers to the challenge that were refused", NULL);
	return 0;
}

void bst_challenge_use_key(const uint8_t *key)
{
	g_key = key;
}

uint64_t bst_challenge_now(void)
{
	struct timespec t;
	clock_gettime(CLOCK_REALTIME, &t);
	return (uint64_t)t.tv_sec;
}

/* ---- the MACs ---- */

/* The secret of generation gen: HMAC(key, "bastion-challenge-gen:" || gen as 8 bytes). */
static void secret_of(uint64_t gen, uint8_t out[32])
{
	static const char tag[] = "bastion-challenge-gen:";
	uint8_t msg[sizeof tag - 1 + 8];
	memcpy(msg, tag, sizeof tag - 1);
	for (int i = 0; i < 8; i++)
		msg[sizeof tag - 1 + (size_t)i] = (uint8_t)(gen >> (56 - 8 * i));
	unsigned len = 32;
	if (HMAC(EVP_sha256(), g_key, BST_CHALLENGE_KEY_LEN, msg, sizeof msg, out, &len) == NULL)
		memset(out, 0, 32);
}

/* hex of the first n bytes of HMAC(secret, a || b); a and b are short (under 128 bytes) */
static void mac_hex(const uint8_t secret[32], const void *a, size_t alen, const void *b, size_t blen, char *out,
		    size_t n)
{
	uint8_t md[32], msg[256];
	unsigned len = sizeof md;
	if (alen + blen > sizeof msg) {
		memset(md, 0xff, sizeof md);
	} else {
		memcpy(msg, a, alen);
		if (blen > 0)
			memcpy(msg + alen, b, blen);
		if (HMAC(EVP_sha256(), secret, 32, msg, alen + blen, md, &len) == NULL)
			memset(md, 0xff, sizeof md); /* never a valid MAC: every comparison fails */
	}
	static const char hx[] = "0123456789abcdef";
	for (size_t i = 0; i < n; i++) {
		out[2 * i] = hx[md[i] >> 4];
		out[2 * i + 1] = hx[md[i] & 15];
	}
}

/* The client's network: family and the address cut to the configured prefix. */
static void prefix_of(const bst_challenge_cfg *c, const bst_ip *ip, uint8_t out[17])
{
	bst_ip x = bst_ip_canon(ip);
	unsigned p = x.family == BST_IP_V4 ? (c->prefix4 ? c->prefix4 : 24) : (c->prefix6 ? c->prefix6 : 56);
	unsigned n = x.family == BST_IP_V4 ? 4 : 16;
	memset(out, 0, 17);
	out[0] = x.family;
	for (unsigned i = 0; i < n; i++) {
		unsigned bits = p > i * 8 ? p - i * 8 : 0;
		out[1 + i] = x.b[i] & (bits >= 8 ? 0xff : (uint8_t)(0xff00u >> bits));
	}
}

static uint64_t rotate(const bst_challenge_cfg *c)
{
	uint64_t r = c->rotate_s;
	if (r == 0)
		r = c->pass_ttl_s > c->token_ttl_s ? c->pass_ttl_s : c->token_ttl_s;
	return r > 0 ? r : 3600;
}

static unsigned difficulty(const bst_challenge_cfg *c)
{
	return c->difficulty > 0 ? c->difficulty : 16;
}

#define IPH 8	/* bytes of the IP prefix hash in a token */
#define MACB 16 /* bytes of a MAC */

/* token: "<exp>.<iphash>.<mac>" under the secret of gen */
static size_t token_for(const bst_challenge_cfg *c, uint64_t gen, const uint8_t pfx[17], uint64_t exp, char *out,
			size_t cap)
{
	uint8_t sec[32];
	secret_of(gen, sec);
	char iph[2 * IPH], head[64], tail[16];
	mac_hex(sec, "ip|", 3, pfx, 17, iph, IPH);
	int hn = snprintf(head, sizeof head, "tok|%llu.%.*s", (unsigned long long)exp, 2 * IPH, iph);
	int tn = snprintf(tail, sizeof tail, "|%u", difficulty(c));
	int n = snprintf(out, cap, "%llu.%.*s.", (unsigned long long)exp, 2 * IPH, iph);
	if (hn < 0 || tn < 0 || n < 0 || (size_t)n + 2 * MACB + 1 > cap) {
		OPENSSL_cleanse(sec, sizeof sec);
		return 0;
	}
	mac_hex(sec, head, (size_t)hn, tail, (size_t)tn, out + n, MACB);
	OPENSSL_cleanse(sec, sizeof sec);
	out[n + 2 * MACB] = '\0';
	return (size_t)n + 2 * MACB;
}

size_t bst_challenge_issue(const bst_challenge_cfg *c, const bst_ip *ip, uint64_t now, char *out, size_t cap)
{
	if (g_key == NULL)
		return 0;
	uint8_t pfx[17];
	prefix_of(c, ip, pfx);
	uint64_t ttl = c->token_ttl_s ? c->token_ttl_s : 300;
	return token_for(c, now / rotate(c), pfx, now + ttl, out, cap);
}

static bool parse_u64(bst_str s, uint64_t *out)
{
	if (s.len == 0 || s.len > 19)
		return false;
	uint64_t x = 0;
	for (uint32_t i = 0; i < s.len; i++) {
		if (s.p[i] < '0' || s.p[i] > '9')
			return false;
		x = x * 10 + (uint64_t)(s.p[i] - '0');
	}
	*out = x;
	return true;
}

static bool ct_eq(const char *a, const char *b, size_t n)
{
	return CRYPTO_memcmp(a, b, n) == 0;
}

bool bst_challenge_zero_bits(const uint8_t *h, unsigned bits)
{
	unsigned i = 0;
	for (; bits >= 8; bits -= 8, i++)
		if (h[i] != 0)
			return false;
	return bits == 0 || (h[i] >> (8 - bits)) == 0;
}

bool bst_challenge_verify_pow(const bst_challenge_cfg *c, bst_str token, bst_str nonce, const bst_ip *ip,
			      uint64_t now)
{
	if (g_key == NULL || token.len == 0 || token.len >= BST_CHALLENGE_TOKEN_MAX || nonce.len == 0 || nonce.len > 32)
		return false;
	for (uint32_t i = 0; i < nonce.len; i++)
		if (nonce.p[i] <= ' ' || nonce.p[i] > '~')
			return false;
	const char *dot = memchr(token.p, '.', token.len);
	uint64_t exp;
	if (dot == NULL || !parse_u64((bst_str){ token.p, (uint32_t)(dot - token.p) }, &exp) || exp <= now)
		return false;
	uint8_t pfx[17];
	prefix_of(c, ip, pfx);
	uint64_t r = rotate(c), g = now / r;
	bool ok = false;
	char want[BST_CHALLENGE_TOKEN_MAX];
	for (uint64_t k = 0; k < 2 && k <= g && !ok; k++) { /* this generation and the one before */
		size_t n = token_for(c, g - k, pfx, exp, want, sizeof want);
		ok = n == token.len && ct_eq(want, token.p, n);
	}
	if (!ok)
		return false;
	/* the work: SHA-256(token "." nonce) */
	uint8_t md[32];
	EVP_MD_CTX *x = EVP_MD_CTX_new();
	unsigned len = 0;
	bool hashed = x != NULL && EVP_DigestInit_ex(x, EVP_sha256(), NULL) == 1 &&
		      EVP_DigestUpdate(x, token.p, token.len) == 1 && EVP_DigestUpdate(x, ".", 1) == 1 &&
		      EVP_DigestUpdate(x, nonce.p, nonce.len) == 1 && EVP_DigestFinal_ex(x, md, &len) == 1;
	EVP_MD_CTX_free(x);
	return hashed && bst_challenge_zero_bits(md, difficulty(c));
}

static size_t pass_for(const bst_challenge_cfg *c, uint64_t gen, const uint8_t pfx[17], uint64_t exp, char *out,
		       size_t cap)
{
	(void)c;
	uint8_t sec[32];
	char head[40];
	int hn = snprintf(head, sizeof head, "pass|%llu|", (unsigned long long)exp);
	int n = snprintf(out, cap, "%llu.", (unsigned long long)exp);
	if (hn < 0 || n < 0 || (size_t)n + 2 * MACB + 1 > cap)
		return 0;
	secret_of(gen, sec);
	mac_hex(sec, head, (size_t)hn, pfx, 17, out + n, MACB);
	OPENSSL_cleanse(sec, sizeof sec);
	out[n + 2 * MACB] = '\0';
	return (size_t)n + 2 * MACB;
}

size_t bst_challenge_pass(const bst_challenge_cfg *c, const bst_ip *ip, uint64_t now, char *out, size_t cap)
{
	if (g_key == NULL)
		return 0;
	uint8_t pfx[17];
	prefix_of(c, ip, pfx);
	uint64_t ttl = c->pass_ttl_s ? c->pass_ttl_s : 3600;
	return pass_for(c, now / rotate(c), pfx, now + ttl, out, cap);
}

bool bst_challenge_cookie_valid(const bst_challenge_cfg *c, bst_str cookie, const bst_ip *ip, uint64_t now)
{
	if (g_key == NULL || cookie.len == 0 || cookie.len >= BST_CHALLENGE_PASS_MAX)
		return false;
	const char *dot = memchr(cookie.p, '.', cookie.len);
	uint64_t exp;
	if (dot == NULL || !parse_u64((bst_str){ cookie.p, (uint32_t)(dot - cookie.p) }, &exp) || exp <= now)
		return false;
	uint8_t pfx[17];
	prefix_of(c, ip, pfx);
	uint64_t r = rotate(c), g = now / r;
	char want[BST_CHALLENGE_PASS_MAX];
	bool ok = false;
	for (uint64_t k = 0; k < 2 && k <= g; k++) {
		size_t n = pass_for(c, g - k, pfx, exp, want, sizeof want);
		ok |= n == cookie.len && ct_eq(want, cookie.p, n); /* no early exit on a match */
	}
	return ok;
}

/* ---- the request side ---- */

static bool under_attack(void)
{
	return false; /* `challenge auto` turns on under attack (Task 6) */
}

bool bst_challenge_active(const bst_stream *s, bool force)
{
	const bst_challenge_cfg *c = &s->cfg->sec.challenge;
	return force || c->mode == BST_CHAL_ON || (c->mode == BST_CHAL_AUTO && under_attack());
}

static bst_str cookie_named(const bst_stream *s, const char *name)
{
	size_t nl = strlen(name);
	const bst_header *h = NULL;
	while ((h = bst_headers_next(&s->req.head.headers, h, BST_H_COOKIE)) != NULL) {
		const char *p = h->value.p, *end = p + h->value.len;
		while (p < end) {
			while (p < end && (*p == ' ' || *p == ';' || *p == '\t'))
				p++;
			const char *semi = memchr(p, ';', (size_t)(end - p));
			const char *e = semi != NULL ? semi : end;
			if ((size_t)(e - p) > nl && p[nl] == '=' && memcmp(p, name, nl) == 0)
				return (bst_str){ p + nl + 1, (uint32_t)(e - p - (ptrdiff_t)nl - 1) };
			p = e;
		}
	}
	return (bst_str){ NULL, 0 };
}

static bool allowlisted(const bst_stream *s)
{
	const bst_cfg_list *l = &s->cfg->sec.challenge_allow;
	if (!s->sec_ip_set || l->n == 0)
		return false;
	bst_ip ip = bst_ip_canon(&s->sec_ip);
	for (size_t i = 0; i < l->n; i++) {
		const bst_cidr *x = l->items[i];
		if (x->ip.family != ip.family)
			continue;
		unsigned p = x->prefix;
		bool m = true;
		for (unsigned k = 0; k < 16 && p > 0 && m; k++) {
			unsigned bits = p >= 8 ? 8 : p;
			uint8_t mask = (uint8_t)(0xff00u >> bits);
			m = (ip.b[k] & mask) == (x->ip.b[k] & mask);
			p -= bits;
		}
		if (m)
			return true;
	}
	return false;
}

static bool accepts_html(const bst_stream *s)
{
	const bst_header *h = NULL;
	while ((h = bst_headers_next(&s->req.head.headers, h, BST_H_ACCEPT)) != NULL)
		if (h->value.len >= 9 && memmem(h->value.p, h->value.len, "text/html", 9) != NULL)
			return true;
	return false;
}

/* Sends status with headers (name, value pairs, NULL-terminated) and body. */
static void respond(bst_stream *s, int status, const char *const *hdrs, const char *body, size_t len)
{
	bst_resp_head h;
	memset(&h, 0, sizeof h);
	h.status = status;
	h.content_length = (int64_t)len;
	bst_headers_init(&h.headers, s->arena);
	for (size_t i = 0; hdrs != NULL && hdrs[i] != NULL; i += 2)
		if (bst_headers_add(&h.headers, (bst_str){ hdrs[i], (uint32_t)strlen(hdrs[i]) },
				    (bst_str){ hdrs[i + 1], (uint32_t)strlen(hdrs[i + 1]) }) != 0)
			goto fail;
	if (bst_stream_send_head(s, &h, len == 0) != 0 || len == 0)
		return;
	bst_buf *b = bst_buf_new(len);
	bst_chain *c = bst_arena_alloc(s->arena, sizeof *c);
	if (b == NULL || c == NULL) {
		if (b != NULL)
			bst_buf_unref(b);
		goto fail;
	}
	memcpy(b->data, body, len);
	b->len = len;
	bst_chain_init(c, s->chain_slab);
	if (bst_chain_add_mem(c, b, 0, len) == 0)
		(void)bst_stream_send_body(s, c, true, NULL, NULL);
	bst_buf_unref(b);
	return;
fail:
	s->ops->reset(s, BST_STREAM_ERR_INTERNAL);
}

/* A growing text in the stream's arena. */
typedef struct sbuf {
	char *p;
	size_t n, cap;
	bool oom;
} sbuf;

static void put(bst_stream *s, sbuf *b, const char *p, size_t n)
{
	if (b->oom)
		return;
	if (b->n + n > b->cap) {
		size_t nc = (b->cap ? b->cap * 2 : 8192);
		while (nc < b->n + n)
			nc *= 2;
		char *np = bst_arena_alloc(s->arena, nc);
		if (np == NULL) {
			b->oom = true;
			return;
		}
		if (b->n > 0)
			memcpy(np, b->p, b->n);
		b->p = np;
		b->cap = nc;
	}
	memcpy(b->p + b->n, p, n);
	b->n += n;
}

static void puts_(bst_stream *s, sbuf *b, const char *p)
{
	put(s, b, p, strlen(p));
}

/* v as the inside of a JavaScript string literal safe in an HTML script element. */
static void put_js(bst_stream *s, sbuf *b, bst_str v)
{
	for (uint32_t i = 0; i < v.len; i++) {
		unsigned char ch = (unsigned char)v.p[i];
		char e[8];
		if (ch < 0x20 || ch == '"' || ch == '\\' || ch == '<' || ch == '>' || ch == '&' || ch == '\'' ||
		    ch == 0x7f) {
			snprintf(e, sizeof e, "\\u%04x", ch);
			put(s, b, e, 6);
		} else if (ch == 0xe2 && i + 2 < v.len && (unsigned char)v.p[i + 1] == 0x80 &&
			   ((unsigned char)v.p[i + 2] == 0xa8 || (unsigned char)v.p[i + 2] == 0xa9)) {
			put(s, b, (unsigned char)v.p[i + 2] == 0xa8 ? "\\u2028" : "\\u2029", 6);
			i += 2;
		} else {
			put(s, b, (const char *)&v.p[i], 1);
		}
	}
}

/* Where to send the client back to: its own request target when it is a local path. */
static bst_str back_to(const bst_stream *s)
{
	bst_str t = s->req.head.target;
	if (t.len == 0 || t.p[0] != '/' || (t.len > 1 && (t.p[1] == '/' || t.p[1] == '\\')))
		return BST_S("/");
	return t;
}

static void send_challenge(bst_stream *s)
{
	const bst_challenge_cfg *c = &s->cfg->sec.challenge;
	count(c_issued);
	if (!accepts_html(s)) {
		static const char body[] = "403 Forbidden: this resource asks for a browser challenge. "
					   "Clients that are not browsers need an allowlisted address.\n";
		static const char *const h[] = { "Content-Type", "text/plain; charset=utf-8", "Cache-Control",
						 "no-store", "Bastion-Challenge", "required", NULL };
		respond(s, 403, h, body, sizeof body - 1);
		return;
	}
	char token[BST_CHALLENGE_TOKEN_MAX], nonce[33];
	uint8_t rnd[16];
	if (!s->sec_ip_set || bst_challenge_issue(c, &s->sec_ip, bst_challenge_now(), token, sizeof token) == 0 ||
	    getrandom(rnd, sizeof rnd, 0) != (ssize_t)sizeof rnd) {
		(void)bst_send_error(s, 500);
		return;
	}
	for (int i = 0; i < 16; i++)
		snprintf(nonce + 2 * i, 3, "%02x", rnd[i]);
	/* the script that replaces the placeholder */
	sbuf js = { 0 };
	char head[320];
	int hn = snprintf(head, sizeof head, "<script nonce=\"%s\">window.BASTION={\"token\":\"%s\",\"difficulty\":%u,"
					     "\"verifyUrl\":\"" BST_CHALLENGE_PATH "\",\"redirect\":\"", nonce, token,
			  difficulty(c));
	if (hn < 0 || (size_t)hn >= sizeof head) {
		(void)bst_send_error(s, 500);
		return;
	}
	puts_(s, &js, head);
	put_js(s, &js, back_to(s));
	puts_(s, &js, "\"};</script>\n<script nonce=\"");
	puts_(s, &js, nonce);
	puts_(s, &js, "\">");
	put(s, &js, (const char *)bst_embed_challenge_client,
	    (size_t)(bst_embed_challenge_client_end - bst_embed_challenge_client));
	puts_(s, &js, "</script>");
	/* the page with its placeholders replaced */
	const char *page = c->page != NULL ? c->page : (const char *)bst_embed_challenge_page;
	size_t plen = c->page != NULL ? c->page_len
				      : (size_t)(bst_embed_challenge_page_end - bst_embed_challenge_page);
	static const char ph_script[] = "{{bastion_challenge}}", ph_nonce[] = "{{bastion_nonce}}";
	sbuf out = { 0 };
	for (size_t i = 0; i < plen;) {
		if (plen - i >= sizeof ph_script - 1 && memcmp(page + i, ph_script, sizeof ph_script - 1) == 0) {
			if (js.p != NULL)
				put(s, &out, js.p, js.n);
			i += sizeof ph_script - 1;
		} else if (plen - i >= sizeof ph_nonce - 1 && memcmp(page + i, ph_nonce, sizeof ph_nonce - 1) == 0) {
			puts_(s, &out, nonce);
			i += sizeof ph_nonce - 1;
		} else {
			const char *nx = memchr(page + i, '{', plen - i);
			size_t run = nx == NULL ? plen - i : nx == page + i ? 1 : (size_t)(nx - (page + i));
			put(s, &out, page + i, run);
			i += run;
		}
	}
	char csp[256];
	snprintf(csp, sizeof csp,
		 "default-src 'self'; script-src 'nonce-%s'; style-src 'self' 'nonce-%s'; worker-src blob:; "
		 "form-action 'self'; base-uri 'none'; frame-ancestors 'none'", nonce, nonce);
	const char *const h[] = { "Content-Type", "text/html; charset=utf-8", "Cache-Control", "no-store",
				  "Content-Security-Policy", csp, NULL };
	if (js.oom || out.oom) {
		(void)bst_send_error(s, 500);
		return;
	}
	respond(s, 403, h, out.p, out.n);
}

/* ---- the verify endpoint ---- */

#define FORM_MAX 4096

typedef struct verify {
	char body[FORM_MAX];
	size_t n;
	bool over;
} verify;

static int hexv(char ch)
{
	return ch >= '0' && ch <= '9' ? ch - '0' : ch >= 'a' && ch <= 'f' ? ch - 'a' + 10 : ch >= 'A' && ch <= 'F' ? ch - 'A' + 10 : -1;
}

/* A form field, decoded into the arena; empty when absent. */
static bst_str field(bst_stream *s, const char *body, size_t n, const char *name)
{
	size_t nl = strlen(name);
	const char *p = body, *end = body + n;
	while (p < end) {
		const char *amp = memchr(p, '&', (size_t)(end - p));
		const char *e = amp != NULL ? amp : end;
		if ((size_t)(e - p) > nl && p[nl] == '=' && memcmp(p, name, nl) == 0) {
			const char *v = p + nl + 1;
			char *o = bst_arena_alloc(s->arena, (size_t)(e - v) + 1);
			if (o == NULL)
				return (bst_str){ NULL, 0 };
			uint32_t k = 0;
			for (const char *q = v; q < e; q++) {
				if (*q == '%' && e - q > 2 && hexv(q[1]) >= 0 && hexv(q[2]) >= 0) {
					o[k++] = (char)(hexv(q[1]) * 16 + hexv(q[2]));
					q += 2;
				} else {
					o[k++] = *q == '+' ? ' ' : *q;
				}
			}
			o[k] = '\0';
			return (bst_str){ o, k };
		}
		p = e + 1;
	}
	return (bst_str){ "", 0 };
}

/* A redirect target the client may name: a local path, nothing that leaves the site. */
static bool local_path(bst_str r)
{
	if (r.len == 0 || r.len > 2048 || r.p[0] != '/')
		return false;
	if (r.len > 1 && (r.p[1] == '/' || r.p[1] == '\\'))
		return false; /* //evil.example, /\evil.example */
	for (uint32_t i = 0; i < r.len; i++)
		if ((unsigned char)r.p[i] < 0x21 || r.p[i] == 0x7f || r.p[i] == '\\')
			return false;
	return true;
}

static void finish_verify(bst_stream *s, verify *v)
{
	const bst_challenge_cfg *c = &s->cfg->sec.challenge;
	uint64_t now = bst_challenge_now();
	bst_str token = field(s, v->body, v->n, "token"), nonce = field(s, v->body, v->n, "nonce"),
		redirect = field(s, v->body, v->n, "redirect");
	if (v->over || token.p == NULL || nonce.p == NULL || redirect.p == NULL || !s->sec_ip_set ||
	    !bst_challenge_verify_pow(c, token, nonce, &s->sec_ip, now)) {
		count(c_failed);
		bst_sec_strike_stream(&c->esc, s, BST_STRIKE_CHALLENGE, c->prefix6 ? c->prefix6 : 64);
		static const char body[] = "403 Forbidden: the challenge answer was not accepted.\n";
		static const char *const h[] = { "Content-Type", "text/plain; charset=utf-8", "Cache-Control",
						 "no-store", NULL };
		respond(s, 403, h, body, sizeof body - 1);
		return;
	}
	char pass[BST_CHALLENGE_PASS_MAX], cookie[256];
	size_t pn = bst_challenge_pass(c, &s->sec_ip, now, pass, sizeof pass);
	const char *name = c->cookie_name != NULL ? c->cookie_name : "bastion_pass";
	int cn = snprintf(cookie, sizeof cookie, "%s=%.*s; Path=/; Max-Age=%llu; HttpOnly; SameSite=Lax%s", name,
			  (int)pn, pass, (unsigned long long)(c->pass_ttl_s ? c->pass_ttl_s : 3600),
			  bst_stream_is_tls(s) ? "; Secure" : "");
	if (pn == 0 || cn < 0 || (size_t)cn >= sizeof cookie) {
		(void)bst_send_error(s, 500);
		return;
	}
	count(c_passed);
	char loc[2100];
	snprintf(loc, sizeof loc, "%.*s", local_path(redirect) ? (int)redirect.len : 1,
		 local_path(redirect) ? redirect.p : "/");
	const char *const h[] = { "Location", loc, "Set-Cookie", cookie, "Cache-Control", "no-store", NULL };
	respond(s, 303, h, NULL, 0);
}

static void v_request(bst_stream *s)
{
	verify *v = s->hctx;
	if (s->req.framing.kind == BST_FRAMING_NONE) { /* no body: the answer is missing */
		finish_verify(s, v);
		return;
	}
	if (s->req.framing.kind == BST_FRAMING_LENGTH && s->req.framing.length > FORM_MAX) {
		(void)bst_send_error(s, 413);
		return;
	}
	bst_stream_read_body(s, FORM_MAX);
}

static void v_body(bst_stream *s, bst_chain *ch, bool end)
{
	verify *v = s->hctx;
	struct iovec iov[16];
	int k = bst_chain_to_iov(ch, iov, 16);
	for (int i = 0; i < k; i++) {
		size_t room = FORM_MAX - v->n, n = iov[i].iov_len < room ? iov[i].iov_len : room;
		memcpy(v->body + v->n, iov[i].iov_base, n);
		v->n += n;
		if (n < iov[i].iov_len)
			v->over = true;
	}
	bst_chain_clear(ch);
	if (v->over) {
		(void)bst_send_error(s, 413);
		return;
	}
	if (end)
		finish_verify(s, v);
	else
		bst_stream_read_body(s, FORM_MAX);
}

static void v_reset(bst_stream *s, bst_stream_err why)
{
	(void)s, (void)why;
}

static const bst_handler_ops verify_ops = { .on_request = v_request, .on_body = v_body, .on_reset = v_reset };

bool bst_challenge_is_verify(const bst_stream *s)
{
	return s->uri.len == sizeof BST_CHALLENGE_PATH - 1 && memcmp(s->uri.p, BST_CHALLENGE_PATH, s->uri.len) == 0;
}

bool bst_challenge_check(bst_stream *s, bool force)
{
	const bst_challenge_cfg *c = &s->cfg->sec.challenge;
	if (bst_challenge_is_verify(s) && (c->mode != BST_CHAL_OFF || force)) {
		if (s->req.head.method != BST_M_POST) {
			(void)bst_send_error(s, 405);
			return true;
		}
		verify *v = bst_arena_alloc(s->arena, sizeof *v);
		if (v == NULL) {
			(void)bst_send_error(s, 500);
			return true;
		}
		memset(v, 0, sizeof *v);
		bst_stream_set_handler(s, &verify_ops, v);
		return true;
	}
	if (!bst_challenge_active(s, force) || allowlisted(s))
		return false;
	const char *name = c->cookie_name != NULL ? c->cookie_name : "bastion_pass";
	bst_str pass = cookie_named(s, name);
	if (s->sec_ip_set && pass.p != NULL && bst_challenge_cookie_valid(c, pass, &s->sec_ip, bst_challenge_now()))
		return false;
	send_challenge(s);
	return true;
}

const char *bst_challenge_load_page(const char *path, bst_arena *a, size_t *len, bool *warn, char *why, size_t cap)
{
	FILE *f = fopen(path, "re");
	if (f == NULL) {
		snprintf(why, cap, "%s", strerror(errno));
		return NULL;
	}
	char *buf = NULL;
	size_t n = 0, bc = 0;
	char chunk[8192];
	size_t r;
	while ((r = fread(chunk, 1, sizeof chunk, f)) > 0) {
		if (n + r > (1u << 20)) {
			snprintf(why, cap, "larger than 1 MiB");
			free(buf);
			fclose(f);
			return NULL;
		}
		if (n + r > bc) {
			bc = (n + r) * 2;
			char *nb = realloc(buf, bc);
			if (nb == NULL) {
				free(buf);
				fclose(f);
				snprintf(why, cap, "out of memory");
				return NULL;
			}
			buf = nb;
		}
		memcpy(buf + n, chunk, r);
		n += r;
	}
	bool err = ferror(f) != 0;
	fclose(f);
	char *out = err ? NULL : bst_arena_alloc(a, n + 1);
	if (out == NULL) {
		free(buf);
		snprintf(why, cap, err ? "read error" : "out of memory");
		return NULL;
	}
	if (n > 0)
		memcpy(out, buf, n);
	out[n] = '\0';
	free(buf);
	*len = n;
	*warn = memmem(out, n, "{{bastion_challenge}}", 21) == NULL;
	return out;
}
