#include "tls/ocsp.h"

#include "core/log.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

typedef _Atomic uint64_t aword;

/* One staple: a sequence word (odd while the helper writes), the length, the expiry in wall-clock
 * milliseconds, and the DER in atomic words, so a racing reader is never a data race. */
typedef struct slot {
	aword seq, len, expiry_ms;
	aword der[BST_OCSP_MAX / 8];
} slot;

struct bst_ocsp_cert {
	X509 *leaf;
	STACK_OF(X509) *chain; /* issuer first: the signer candidates */
	X509_STORE *store;
	OCSP_CERTID *id;
	unsigned char *req;
	int reqlen;
	char name[96];
	char host[256], *path;
	bst_sockaddr addr;
	bool has_url, from_file;
	unsigned slot;
};

static bst_ocsp_cert g_tab[BST_OCSP_SLOTS];
static size_t g_n;
static slot *g_region;

size_t bst_ocsp_region_size(void)
{
	return BST_OCSP_SLOTS * sizeof(slot);
}

size_t bst_ocsp_count(void)
{
	return g_n;
}

bst_ocsp_cert *bst_ocsp_at(size_t i)
{
	return &g_tab[i];
}

const char *bst_ocsp_name(const bst_ocsp_cert *c)
{
	return c->name;
}

bool bst_ocsp_fetchable(const bst_ocsp_cert *c)
{
	return c->has_url && !c->from_file;
}

const unsigned char *bst_ocsp_request(const bst_ocsp_cert *c, int *len)
{
	*len = c->reqlen;
	return c->req;
}

const char *bst_ocsp_host(const bst_ocsp_cert *c)
{
	return c->host;
}

const char *bst_ocsp_path(const bst_ocsp_cert *c)
{
	return c->path;
}

bst_sockaddr bst_ocsp_addr(const bst_ocsp_cert *c)
{
	return c->addr;
}

static uint64_t wall_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

unsigned long long bst_ocsp_expiry(const bst_ocsp_cert *c)
{
	uint64_t e = atomic_load_explicit(&g_region[c->slot].expiry_ms, memory_order_relaxed);
	return atomic_load_explicit(&g_region[c->slot].len, memory_order_relaxed) != 0 ? e : 0;
}

/* ---- validation and publication ---- */

static void publish(slot *s, const unsigned char *der, size_t len, uint64_t expiry)
{
	uint64_t seq = atomic_load_explicit(&s->seq, memory_order_relaxed);
	atomic_store_explicit(&s->seq, seq + 1, memory_order_relaxed);
	atomic_thread_fence(memory_order_release);
	uint64_t w[BST_OCSP_MAX / 8] = { 0 };
	memcpy(w, der, len);
	for (size_t i = 0; i < (len + 7) / 8; i++)
		atomic_store_explicit(&s->der[i], w[i], memory_order_relaxed);
	atomic_store_explicit(&s->len, len, memory_order_relaxed);
	atomic_store_explicit(&s->expiry_ms, expiry, memory_order_relaxed);
	atomic_store_explicit(&s->seq, seq + 2, memory_order_release);
}

int bst_ocsp_accept(bst_ocsp_cert *c, const unsigned char *der, size_t len, const char **why)
{
	int rc = -1;
	OCSP_RESPONSE *r = NULL;
	OCSP_BASICRESP *bs = NULL;
	if (len == 0 || len > BST_OCSP_MAX) {
		*why = "response is empty or larger than the staple limit";
		return -1;
	}
	const unsigned char *p = der;
	ERR_clear_error();
	r = d2i_OCSP_RESPONSE(NULL, &p, (long)len);
	if (r == NULL) {
		*why = "not a DER OCSP response";
		goto out;
	}
	if (OCSP_response_status(r) != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
		*why = "the responder did not answer successfully";
		goto out;
	}
	bs = OCSP_response_get1_basic(r);
	if (bs == NULL) {
		*why = "no basic response";
		goto out;
	}
	/* the signer is the issuer or a certificate it delegated to, chained to the issuer chain */
	if (OCSP_basic_verify(bs, c->chain, c->store, 0) <= 0) {
		*why = "signature or signer chain not valid";
		goto out;
	}
	int st = 0, reason = 0;
	ASN1_GENERALIZEDTIME *rev = NULL, *thisu = NULL, *nextu = NULL;
	if (OCSP_resp_find_status(bs, c->id, &st, &reason, &rev, &thisu, &nextu) != 1) {
		*why = "the response is for another certificate";
		goto out;
	}
	if (st != V_OCSP_CERTSTATUS_GOOD) {
		*why = "the certificate's status is not good";
		goto out;
	}
	if (OCSP_check_validity(thisu, nextu, 300, -1) != 1) {
		*why = "the response is not currently valid";
		goto out;
	}
	uint64_t expiry = wall_ms() + 3600 * 1000ULL; /* no nextUpdate: an hour */
	if (nextu != NULL) {
		struct tm tm;
		if (ASN1_TIME_to_tm(nextu, &tm) == 1)
			expiry = (uint64_t)timegm(&tm) * 1000;
	}
	publish(&g_region[c->slot], der, len, expiry);
	rc = 0;
out:
	OCSP_BASICRESP_free(bs);
	OCSP_RESPONSE_free(r);
	ERR_clear_error();
	return rc;
}

/* ---- the worker's side ---- */

static int status_cb(SSL *ssl, void *arg)
{
	(void)arg;
	X509 *x = SSL_get_certificate(ssl);
	bst_ocsp_cert *c = NULL;
	for (size_t i = 0; i < g_n && g_region != NULL; i++)
		if (g_tab[i].leaf == x)
			c = &g_tab[i];
	if (c == NULL)
		return SSL_TLSEXT_ERR_NOACK;
	slot *s = &g_region[c->slot];
	unsigned char *buf = OPENSSL_malloc(BST_OCSP_MAX);
	if (buf == NULL)
		return SSL_TLSEXT_ERR_NOACK;
	for (unsigned spins = 0; spins < 1000000; spins++) {
		uint64_t s1 = atomic_load_explicit(&s->seq, memory_order_acquire);
		if (s1 & 1)
			continue;
		uint64_t len = atomic_load_explicit(&s->len, memory_order_relaxed);
		uint64_t exp = atomic_load_explicit(&s->expiry_ms, memory_order_relaxed);
		if (len == 0 || len > BST_OCSP_MAX)
			break;
		uint64_t w[BST_OCSP_MAX / 8];
		for (size_t i = 0; i < (len + 7) / 8; i++)
			w[i] = atomic_load_explicit(&s->der[i], memory_order_relaxed);
		atomic_thread_fence(memory_order_acquire);
		if (atomic_load_explicit(&s->seq, memory_order_relaxed) != s1)
			continue;
		if (exp <= wall_ms())
			break; /* an old staple is never served past its nextUpdate */
		memcpy(buf, w, len);
		if (SSL_set_tlsext_status_ocsp_resp(ssl, buf, (long)len) != 1) {
			OPENSSL_free(buf);
			return SSL_TLSEXT_ERR_NOACK;
		}
		return SSL_TLSEXT_ERR_OK; /* the SSL owns buf now */
	}
	OPENSSL_free(buf);
	return SSL_TLSEXT_ERR_NOACK;
}

void bst_ocsp_ctx(SSL_CTX *ctx)
{
	(void)SSL_CTX_set_tlsext_status_cb(ctx, status_cb);
}

/* ---- master: collecting what to staple ---- */

static bool wants(const bst_cfg_tls *t)
{
	return t->ctx != NULL && t->profile != NULL && (t->profile->ocsp_stapling || t->nocsp_files > 0);
}

bool bst_ocsp_wanted(const bst_config *cfg)
{
	for (size_t i = 0; i < cfg->global.nservers; i++)
		if (wants(&cfg->global.servers[i]->tls))
			return true;
	return false;
}

/* http://host[:port]/path only: the helper speaks plain HTTP. */
static int parse_url(bst_ocsp_cert *c, const char *url)
{
	if (strncmp(url, "http://", 7) != 0)
		return -1;
	const char *h = url + 7, *slash = strchr(h, '/');
	size_t hl = slash != NULL ? (size_t)(slash - h) : strlen(h);
	char hp[300];
	if (hl == 0 || hl >= sizeof hp)
		return -1;
	memcpy(hp, h, hl);
	hp[hl] = '\0';
	const char *port = "80";
	char *colon = strrchr(hp, ':');
	if (colon != NULL && strchr(hp, ']') == NULL) {
		*colon = '\0';
		port = colon + 1;
	}
	c->path = strdup(slash != NULL ? slash : "/");
	if (c->path == NULL)
		return -1;
	snprintf(c->host, sizeof c->host, "%s", hp);
	struct addrinfo hints = { .ai_socktype = SOCK_STREAM }, *res = NULL;
	if (getaddrinfo(hp, port, &hints, &res) != 0 || res == NULL)
		return -1;
	memset(&c->addr, 0, sizeof c->addr);
	if (res->ai_family == AF_INET) {
		const struct sockaddr_in *a = (const struct sockaddr_in *)(const void *)res->ai_addr;
		c->addr.ip.family = BST_IP_V4;
		memcpy(c->addr.ip.b, &a->sin_addr, 4);
		c->addr.port = ntohs(a->sin_port);
	} else if (res->ai_family == AF_INET6) {
		const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)(const void *)res->ai_addr;
		c->addr.ip.family = BST_IP_V6;
		memcpy(c->addr.ip.b, &a->sin6_addr, 16);
		c->addr.port = ntohs(a->sin6_port);
	} else {
		freeaddrinfo(res);
		return -1;
	}
	freeaddrinfo(res);
	return 0;
}

static int add_cert(const bst_cfg_tls *t, SSL_CTX *ctx, X509 *leaf, const char *label, bst_err *err)
{
	for (size_t i = 0; i < g_n; i++)
		if (g_tab[i].leaf == leaf)
			return 0;
	if (g_n >= BST_OCSP_SLOTS) {
		bst_err_set(err, "ocsp: more than %d certificates to staple", BST_OCSP_SLOTS);
		return -1;
	}
	STACK_OF(X509) *chain = NULL;
	if (SSL_CTX_get0_chain_certs(ctx, &chain) != 1 || chain == NULL || sk_X509_num(chain) == 0) {
		bst_log(BST_LOG_INFO, "tls: %s has no issuer in its chain file: no OCSP staple", label);
		return 0;
	}
	bst_ocsp_cert *c = &g_tab[g_n];
	memset(c, 0, sizeof *c);
	c->leaf = leaf;
	c->slot = (unsigned)g_n;
	snprintf(c->name, sizeof c->name, "%s", label);
	c->chain = chain;
	c->store = X509_STORE_new();
	X509_STORE_set_flags(c->store, X509_V_FLAG_PARTIAL_CHAIN);
	for (int i = 0; i < sk_X509_num(chain); i++)
		(void)X509_STORE_add_cert(c->store, sk_X509_value(chain, i));
	c->id = OCSP_cert_to_id(NULL, leaf, sk_X509_value(chain, 0));
	OCSP_REQUEST *rq = OCSP_REQUEST_new();
	OCSP_CERTID *rid = c->id != NULL ? OCSP_CERTID_dup(c->id) : NULL;
	if (c->store == NULL || c->id == NULL || rq == NULL || rid == NULL || OCSP_request_add0_id(rq, rid) == NULL) {
		OCSP_REQUEST_free(rq);
		bst_err_set(err, "ocsp: cannot build the request for %s", label);
		return -1;
	}
	c->reqlen = i2d_OCSP_REQUEST(rq, &c->req);
	OCSP_REQUEST_free(rq);
	const char *url = t->ocsp_responder;
	STACK_OF(OPENSSL_STRING) *aia = url == NULL ? X509_get1_ocsp(leaf) : NULL;
	if (url == NULL && aia != NULL && sk_OPENSSL_STRING_num(aia) > 0)
		url = sk_OPENSSL_STRING_value(aia, 0);
	if (url == NULL) {
		bst_log(BST_LOG_INFO, "tls: %s names no OCSP responder: no staple, no fetch", label);
	} else if (parse_url(c, url) != 0) {
		bst_log(BST_LOG_WARN, "tls: %s: OCSP responder \"%s\" is not a usable http URL: no staple", label, url);
	} else {
		c->has_url = true;
	}
	X509_email_free(aia);
	g_n++;
	return 0;
}

static unsigned char *read_file(const char *path, size_t *len)
{
	FILE *f = fopen(path, "rb");
	if (f == NULL)
		return NULL;
	unsigned char *b = malloc(BST_OCSP_MAX + 1);
	*len = b != NULL ? fread(b, 1, BST_OCSP_MAX + 1, f) : 0;
	fclose(f);
	return b;
}

int bst_ocsp_setup(bst_config *cfg, void *region, bst_err *err)
{
	g_region = region;
	g_n = 0;
	for (size_t i = 0; i < cfg->global.nservers; i++) {
		bst_cfg_tls *t = &cfg->global.servers[i]->tls;
		if (!wants(t))
			continue;
		size_t first = g_n;
		SSL_CTX *ctxs[2] = { t->ctx, t->default_ctx };
		for (int k = 0; k < 2; k++) {
			SSL_CTX *ctx = ctxs[k];
			if (ctx == NULL)
				continue;
			for (long ok = SSL_CTX_set_current_cert(ctx, SSL_CERT_SET_FIRST); ok;
			     ok = SSL_CTX_set_current_cert(ctx, SSL_CERT_SET_NEXT)) {
				X509 *x = SSL_CTX_get0_certificate(ctx);
				char label[96];
				snprintf(label, sizeof label, "certificate #%zu of server %zu", g_n + 1, i + 1);
				if (x != NULL && add_cert(t, ctx, x, label, err) != 0)
					return -1;
			}
		}
		for (size_t f = 0; f < t->nocsp_files; f++) {
			size_t len = 0;
			unsigned char *der = read_file(t->ocsp_files[f], &len);
			if (der == NULL) {
				bst_err_set(err, "ocsp_file %s: %s", t->ocsp_files[f], strerror(errno));
				return -1;
			}
			bool matched = false;
			const char *why = "no certificate";
			for (size_t j = first; j < g_n && !matched; j++) {
				const char *w = NULL;
				if (bst_ocsp_accept(&g_tab[j], der, len, &w) == 0) {
					matched = true;
					g_tab[j].from_file = true;
				} else if (strstr(w, "another certificate") == NULL) {
					why = w; /* it is this certificate's, and it is bad */
				}
			}
			free(der);
			if (!matched && strcmp(why, "no certificate") == 0) {
				bst_err_set(err, "ocsp_file %s matches no certificate of this server", t->ocsp_files[f]);
				return -1;
			}
			if (!matched)
				bst_log(BST_LOG_WARN, "tls: ocsp_file %s not stapled: %s", t->ocsp_files[f], why);
		}
	}
	return 0;
}
