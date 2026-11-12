#include "tls/tickets.h"

#include "core/time.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

/* The region is an array of 64-bit atomic words, so a reader racing the writer is never a data
 * race: [0] sequence (odd while writing), [1] key count, then BST_TICKET_KEYS_MAX entries of
 * ENTRY_WORDS words each (name, aes, hmac, created_ms), newest first. */
#define ENTRY_WORDS 11
#define HDR_WORDS 2
#define KEYS_WORDS (HDR_WORDS + BST_TICKET_KEYS_MAX * ENTRY_WORDS)
/* Then the QUIC secrets: written once by master before any fork, never changed, so no seqlock. */
#define QUIC_WORDS (BST_QUIC_SECRETS_LEN / 8)
#define REGION_WORDS (KEYS_WORDS + QUIC_WORDS)

typedef _Atomic uint64_t aword;

static void *g_region;
static const void *g_quic;

size_t bst_tickets_size(void)
{
	return REGION_WORDS * sizeof(uint64_t);
}

int bst_tickets_quic_init(void *region)
{
	unsigned char s[BST_QUIC_SECRETS_LEN];
	if (getrandom(s, sizeof s, 0) != (ssize_t)sizeof s)
		return -1;
	uint64_t w[QUIC_WORDS];
	memcpy(w, s, sizeof s);
	aword *q = (aword *)region + KEYS_WORDS;
	for (size_t i = 0; i < QUIC_WORDS; i++)
		atomic_store_explicit(&q[i], w[i], memory_order_relaxed);
	memset(s, 0, sizeof s);
	memset(w, 0, sizeof w);
	g_quic = region;
	return 0;
}

int bst_tickets_quic_secrets(unsigned char out[BST_QUIC_SECRETS_LEN])
{
	if (g_quic == NULL)
		return -1;
	const aword *q = (const aword *)g_quic + KEYS_WORDS;
	uint64_t w[QUIC_WORDS];
	for (size_t i = 0; i < QUIC_WORDS; i++)
		w[i] = atomic_load_explicit(&q[i], memory_order_relaxed);
	memcpy(out, w, sizeof w);
	memset(w, 0, sizeof w);
	return 0;
}

static void put_key(aword *e, const bst_ticket_key *k)
{
	uint64_t w[ENTRY_WORDS];
	memcpy(w, k->name, 16);
	memcpy(w + 2, k->aes, 32);
	memcpy(w + 6, k->hmac, 32);
	w[10] = k->created_ms;
	for (int i = 0; i < ENTRY_WORDS; i++)
		atomic_store_explicit(&e[i], w[i], memory_order_relaxed);
}

static void get_key(const aword *e, bst_ticket_key *k)
{
	uint64_t w[ENTRY_WORDS];
	for (int i = 0; i < ENTRY_WORDS; i++)
		w[i] = atomic_load_explicit(&e[i], memory_order_relaxed);
	memcpy(k->name, w, 16);
	memcpy(k->aes, w + 2, 32);
	memcpy(k->hmac, w + 6, 32);
	k->created_ms = w[10];
}

void bst_tickets_publish(void *region, const bst_ticket_key *keys, unsigned n)
{
	aword *r = region;
	uint64_t seq = atomic_load_explicit(&r[0], memory_order_relaxed);
	atomic_store_explicit(&r[0], seq + 1, memory_order_relaxed); /* odd: writing */
	atomic_thread_fence(memory_order_release);
	for (unsigned i = 0; i < n; i++)
		put_key(r + HDR_WORDS + (size_t)i * ENTRY_WORDS, &keys[i]);
	atomic_store_explicit(&r[1], n, memory_order_relaxed);
	atomic_store_explicit(&r[0], seq + 2, memory_order_release); /* even: done */
}

unsigned bst_tickets_snapshot(const void *region, bst_ticket_key *out, unsigned max)
{
	const aword *r = region;
	if (r == NULL)
		return 0;
	/* A writer killed between its two sequence stores would leave the count odd for ever: after
	 * a bounded wait a reader gives up and the handshake is a full one, never a hang. */
	for (unsigned spins = 0; spins < 1000000; spins++) {
		uint64_t s1 = atomic_load_explicit(&r[0], memory_order_acquire);
		if (s1 & 1)
			continue; /* a rotation is in progress: a few microseconds */
		uint64_t n = atomic_load_explicit(&r[1], memory_order_relaxed);
		if (n > BST_TICKET_KEYS_MAX)
			n = BST_TICKET_KEYS_MAX;
		if (n > max)
			n = max;
		for (uint64_t i = 0; i < n; i++)
			get_key(r + HDR_WORDS + (size_t)i * ENTRY_WORDS, &out[i]);
		atomic_thread_fence(memory_order_acquire);
		if (atomic_load_explicit(&r[0], memory_order_relaxed) == s1)
			return (unsigned)n;
	}
	return 0;
}

static int fresh_key(bst_ticket_key *k)
{
	if (getrandom(k, offsetof(bst_ticket_key, created_ms), 0) != (ssize_t)offsetof(bst_ticket_key, created_ms))
		return -1;
	k->created_ms = bst_now_ms();
	return 0;
}

int bst_tickets_rotate(void *region, unsigned keep)
{
	if (keep < 1)
		keep = 1;
	if (keep > BST_TICKET_KEYS_MAX)
		keep = BST_TICKET_KEYS_MAX;
	bst_ticket_key keys[BST_TICKET_KEYS_MAX];
	unsigned n = bst_tickets_snapshot(region, keys + 1, keep - 1);
	if (fresh_key(&keys[0]) != 0)
		return -1;
	bst_tickets_publish(region, keys, n + 1);
	memset(keys, 0, sizeof keys);
	return 0;
}

static int hexval(int c)
{
	return isdigit(c) ? c - '0' : (c | 32) >= 'a' && (c | 32) <= 'f' ? (c | 32) - 'a' + 10 : -1;
}

/* One key per line, 160 hex characters (16 name, 32 AES, 32 HMAC bytes), newest first. */
static int load_file(const char *file, bst_ticket_key *keys, unsigned *n, unsigned keep, bst_err *err)
{
	int fd = open(file, O_RDONLY | O_CLOEXEC);
	struct stat st;
	if (fd < 0 || fstat(fd, &st) != 0) {
		bst_err_set(err, "tickets file %s: %s", file, strerror(errno));
		if (fd >= 0)
			close(fd);
		return -1;
	}
	if (st.st_mode & 077) {
		bst_err_set(err, "tickets file %s must not be readable by group or others (chmod 600)", file);
		close(fd);
		return -1;
	}
	char buf[BST_TICKET_KEYS_MAX * 200];
	ssize_t len = read(fd, buf, sizeof buf - 1);
	close(fd);
	if (len < 0) {
		bst_err_set(err, "tickets file %s: %s", file, strerror(errno));
		return -1;
	}
	buf[len] = '\0';
	*n = 0;
	for (char *line = strtok(buf, "\n"); line != NULL && *n < keep; line = strtok(NULL, "\n")) {
		while (isspace((unsigned char)*line))
			line++;
		if (*line == '\0' || *line == '#')
			continue;
		size_t hl = strlen(line);
		while (hl > 0 && isspace((unsigned char)line[hl - 1]))
			hl--;
		if (hl != 160) {
			bst_err_set(err, "tickets file %s: a key is 160 hex characters (16+32+32 bytes)", file);
			return -1;
		}
		unsigned char raw[80];
		for (size_t i = 0; i < 80; i++) {
			int a = hexval(line[2 * i]), b = hexval(line[2 * i + 1]);
			if (a < 0 || b < 0) {
				bst_err_set(err, "tickets file %s: not hexadecimal", file);
				return -1;
			}
			raw[i] = (unsigned char)(a * 16 + b);
		}
		bst_ticket_key *k = &keys[(*n)++];
		memcpy(k->name, raw, 16);
		memcpy(k->aes, raw + 16, 32);
		memcpy(k->hmac, raw + 48, 32);
		k->created_ms = bst_now_ms();
		memset(raw, 0, sizeof raw);
	}
	if (*n == 0) {
		bst_err_set(err, "tickets file %s holds no key", file);
		return -1;
	}
	return 0;
}

int bst_tickets_init(void *region, unsigned keep, const char *file, bst_err *err)
{
	bst_ticket_key keys[BST_TICKET_KEYS_MAX];
	unsigned n = 1;
	if (keep < 1)
		keep = 1;
	if (keep > BST_TICKET_KEYS_MAX)
		keep = BST_TICKET_KEYS_MAX;
	int rc = 0;
	if (file != NULL) {
		rc = load_file(file, keys, &n, keep, err);
	} else if (fresh_key(&keys[0]) != 0) {
		bst_err_set(err, "tickets: no randomness for a ticket key");
		rc = -1;
	}
	if (rc == 0)
		bst_tickets_publish(region, keys, n);
	memset(keys, 0, sizeof keys);
	return rc;
}

int bst_tickets_protect(void *region)
{
	(void)madvise(region, bst_tickets_size(), MADV_DONTDUMP);
	return mlock(region, bst_tickets_size()) != 0;
}

void bst_tickets_use(void *region)
{
	g_region = region;
}

/* RFC 5077 section 4: name | iv | encrypted state | HMAC. enc=1 seals with the newest key; enc=0
 * finds the key by its name and says (2) when it is not the newest, so OpenSSL issues a fresh
 * ticket under the current key. */
static int ticket_cb(SSL *s, unsigned char name[16], unsigned char iv[EVP_MAX_IV_LENGTH],
		     EVP_CIPHER_CTX *cctx, EVP_MAC_CTX *hctx, int enc)
{
	(void)s;
	bst_ticket_key keys[BST_TICKET_KEYS_MAX];
	unsigned n = bst_tickets_snapshot(g_region, keys, BST_TICKET_KEYS_MAX);
	int rc = 0;
	const bst_ticket_key *k = NULL;
	if (n == 0)
		goto out;
	if (enc) {
		k = &keys[0];
		if (RAND_bytes(iv, EVP_CIPHER_get_iv_length(EVP_aes_256_cbc())) != 1)
			goto out;
		memcpy(name, k->name, 16);
	} else {
		for (unsigned i = 0; i < n; i++) {
			if (memcmp(keys[i].name, name, 16) == 0) {
				k = &keys[i];
				rc = i == 0 ? 1 : 2;
				break;
			}
		}
		if (k == NULL) {
			rc = 0; /* unknown key: a full handshake */
			goto out;
		}
	}
	OSSL_PARAM p[2] = {
		OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char *)"sha256", 0),
		OSSL_PARAM_construct_end(),
	};
	if (EVP_MAC_init(hctx, k->hmac, sizeof k->hmac, p) != 1 ||
	    EVP_CipherInit_ex(cctx, EVP_aes_256_cbc(), NULL, k->aes, iv, enc) != 1) {
		rc = enc ? -1 : 0;
		goto out;
	}
	if (enc)
		rc = 1;
out:
	OPENSSL_cleanse(keys, sizeof keys);
	return rc;
}

void bst_tickets_ctx(SSL_CTX *ctx)
{
	SSL_CTX_set_tlsext_ticket_key_evp_cb(ctx, ticket_cb);
}

bool bst_tickets_policy(const bst_config *cfg, uint64_t *rotate_ms, unsigned *keep, const char **file)
{
	for (size_t i = 0; i < cfg->global.nservers; i++) {
		const bst_cfg_tls *t = &cfg->global.servers[i]->tls;
		if (t->ctx != NULL && t->profile != NULL && t->profile->tickets) {
			*rotate_ms = t->profile->tickets_rotate_ms;
			*keep = t->profile->tickets_keep;
			*file = t->profile->tickets_file;
			return true;
		}
	}
	return false;
}
