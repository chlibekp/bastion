#include "tls/early.h"

#include "core/log.h"
#include "tls/sni.h"

#include <openssl/evp.h>
#include <string.h>
#include <time.h>

static _Atomic uint64_t *table;
static unsigned window_s = 20;

size_t bst_early_size(void)
{
	return BST_EARLY_SLOTS * sizeof(uint64_t);
}

bool bst_early_wanted(const bst_config *cfg)
{
	for (size_t i = 0; i < cfg->global.nservers; i++) {
		const bst_cfg_tls *t = &cfg->global.servers[i]->tls;
		if (t->ctx != NULL && t->profile != NULL && t->profile->early_data &&
		    t->client_auth == BST_CLIENT_AUTH_OFF)
			return true;
	}
	return false;
}

void bst_early_use(void *region)
{
	table = region;
}

bool bst_early_active(void)
{
	return table != NULL;
}

/* ---- the table ---- */

static bool expired(uint32_t exp, uint32_t now)
{
	uint32_t d = (exp - now) & 0xffffffu;
	return d == 0 || d >= 0x800000u; /* behind now, modulo 2^24 seconds */
}

static bool live(uint64_t v, uint32_t now)
{
	return v != 0 && !expired((uint32_t)(v & 0xffffffu), now);
}

bool bst_early_claim(void *region, uint64_t fp, uint32_t now_s, unsigned window)
{
	_Atomic uint64_t *t = region;
	uint64_t key = fp & 0xffffffffffull;
	if (key == 0)
		key = 1;
	uint32_t base = (uint32_t)((key * 0x9e3779b97f4a7c15ull) >> 50) & (BST_EARLY_SLOTS - 1);
	for (int attempt = 0; attempt < 4; attempt++) {
		int free_at = -1;
		uint64_t freev = 0;
		for (unsigned i = 0; i < BST_EARLY_PROBE; i++) {
			uint64_t v = atomic_load(&t[(base + i) & (BST_EARLY_SLOTS - 1)]);
			if (!live(v, now_s)) {
				if (free_at < 0) {
					free_at = (int)i;
					freev = v;
				}
				continue;
			}
			if ((v >> 24) == key)
				return false; /* seen */
		}
		if (free_at < 0)
			return false; /* no room: no early data */
		uint64_t mine = key << 24 | ((now_s + window + 1) & 0xffffffu);
		_Atomic uint64_t *slot = &t[(base + (unsigned)free_at) & (BST_EARLY_SLOTS - 1)];
		if (!atomic_compare_exchange_strong(slot, &freev, mine))
			continue; /* another claim got there first: look again */
		/* Two claims of one ticket can pick different free slots when one of them expires between
		 * their scans. The one that sits further from the base gives way. */
		for (int i = 0; i < free_at; i++) {
			uint64_t v = atomic_load(&t[(base + (unsigned)i) & (BST_EARLY_SLOTS - 1)]);
			if (live(v, now_s) && (v >> 24) == key) {
				uint64_t m = mine;
				(void)atomic_compare_exchange_strong(slot, &m, 0);
				return false;
			}
		}
		return true;
	}
	return false;
}

/* ---- the policy ---- */

static uint32_t mono_s(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint32_t)ts.tv_sec;
}

static bool fingerprint(SSL *ssl, uint64_t *out)
{
	SSL_SESSION *s = SSL_get_session(ssl);
	if (s == NULL)
		return false;
	unsigned char secret[64], md[EVP_MAX_MD_SIZE];
	size_t n = SSL_SESSION_get_master_key(s, secret, sizeof secret);
	unsigned mdl = 0;
	if (n == 0 || EVP_Digest(secret, n, md, &mdl, EVP_sha256(), NULL) != 1 || mdl < 8)
		return false;
	OPENSSL_cleanse(secret, sizeof secret);
	uint64_t v = 0;
	for (int i = 0; i < 8; i++)
		v = v << 8 | md[i];
	*out = v;
	return true;
}

int bst_early_allow(SSL *ssl, void *arg)
{
	(void)arg;
	const bst_cfg_server *srv = bst_tls_sni_chosen(ssl);
	if (table == NULL || srv == NULL || srv->tls.profile == NULL || !srv->tls.profile->early_data ||
	    srv->tls.client_auth != BST_CLIENT_AUTH_OFF)
		return 0;
	uint64_t fp;
	if (!fingerprint(ssl, &fp))
		return 0;
	unsigned w = (unsigned)(srv->tls.profile->early_window_ms / 1000);
	bool first = bst_early_claim(table, fp, mono_s(), w != 0 ? w : window_s);
	bst_log(BST_LOG_DEBUG, first ? "tls: early data accepted" : "tls: early data refused: the ticket was used before");
	return first ? 1 : 0;
}

void bst_early_ctx(SSL_CTX *ctx, const bst_cfg_tls_profile *p, bool mtls)
{
	uint32_t max = p->early_data && !mtls ? (uint32_t)p->early_max_size : 0;
	SSL_CTX_set_max_early_data(ctx, max);
	SSL_CTX_set_recv_max_early_data(ctx, max);
	if (max != 0) {
		SSL_CTX_set_options(ctx, SSL_OP_NO_ANTI_REPLAY);
		SSL_CTX_set_allow_early_data_cb(ctx, bst_early_allow, NULL);
	}
}
