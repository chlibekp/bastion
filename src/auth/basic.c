/* See basic.h. */
#include "auth/basic.h"

#include "auth/auth_common.h"
#include "core/b64.h"
#include "core/log.h"
#include "io/aio.h"
#include "io/loop.h"
#include "proc/worker.h"

#include <ctype.h>
#include <errno.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <termios.h>
#include <unistd.h>

#define AUTH_VALUE_MAX 4096 /* the longest Authorization value looked at */
#define CRED_MAX 3072	    /* decoded user:password */
#define CACHE_SLOTS 512

/* ---- PHC strings ---- */

static bool take(bst_str *s, const char *lit)
{
	size_t n = strlen(lit);
	if (s->len < n || memcmp(s->p, lit, n) != 0)
		return false;
	s->p += n;
	s->len -= (uint32_t)n;
	return true;
}

static bool take_u32(bst_str *s, uint32_t max, uint32_t *out)
{
	uint64_t v = 0;
	uint32_t i = 0;
	while (i < s->len && i < 11 && isdigit((unsigned char)s->p[i]))
		v = v * 10 + (uint64_t)(s->p[i++] - '0');
	if (i == 0 || v > max || (i > 1 && s->p[0] == '0'))
		return false;
	s->p += i;
	s->len -= i;
	*out = (uint32_t)v;
	return true;
}

static bst_str until(bst_str *s, char c)
{
	uint32_t i = 0;
	while (i < s->len && s->p[i] != c)
		i++;
	bst_str r = { s->p, i };
	s->p += i;
	s->len -= i;
	return r;
}

int bst_phc_parse(bst_str s, bst_phc *out)
{
	memset(out, 0, sizeof *out);
	uint32_t v;
	if (!take(&s, "$argon2id$v=") || !take_u32(&s, 255, &v) || v != 19 || !take(&s, "$m=") ||
	    !take_u32(&s, 1u << 20, &out->m_kib) || !take(&s, ",t=") || !take_u32(&s, 64, &out->t) ||
	    !take(&s, ",p=") || !take_u32(&s, 64, &out->p) || !take(&s, "$"))
		return -1;
	if (out->t < 1 || out->p < 1 || out->m_kib < 8 * out->p)
		return -1;
	bst_str salt = until(&s, '$');
	if (!take(&s, "$"))
		return -1;
	long sl = bst_b64_decode(salt.p, salt.len, out->salt, sizeof out->salt,
				 BST_B64_STD | BST_B64_PAD_FORBIDDEN);
	long hl = bst_b64_decode(s.p, s.len, out->hash, sizeof out->hash,
				 BST_B64_STD | BST_B64_PAD_FORBIDDEN);
	if (sl < 8 || hl < 16)
		return -1;
	out->salt_len = (size_t)sl;
	out->hash_len = (size_t)hl;
	return 0;
}

bool bst_phc_weak(const bst_phc *h)
{
	return h->m_kib < 19456 || h->t < 2;
}

size_t bst_phc_format(const bst_phc *h, char *out, size_t cap)
{
	char salt[96], hash[192];
	if (bst_b64_encode(h->salt, h->salt_len, salt, sizeof salt, BST_B64_STD, false) == 0 ||
	    bst_b64_encode(h->hash, h->hash_len, hash, sizeof hash, BST_B64_STD, false) == 0)
		return 0;
	int n = snprintf(out, cap, "$argon2id$v=19$m=%u,t=%u,p=%u$%s$%s", h->m_kib, h->t, h->p, salt, hash);
	return n > 0 && (size_t)n < cap ? (size_t)n : 0;
}

int bst_argon2id(const char *pass, size_t plen, const bst_phc *h, uint8_t *out)
{
	EVP_KDF *kdf = EVP_KDF_fetch(NULL, "ARGON2ID", NULL);
	if (kdf == NULL)
		return -1;
	EVP_KDF_CTX *kc = EVP_KDF_CTX_new(kdf);
	EVP_KDF_free(kdf);
	if (kc == NULL)
		return -1;
	uint32_t iter = h->t, mem = h->m_kib, lanes = h->p, threads = 1;
	OSSL_PARAM ps[] = {
		OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, (void *)pass, plen),
		OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)h->salt, h->salt_len),
		OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &iter),
		OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &mem),
		OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &lanes),
		OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS, &threads),
		OSSL_PARAM_construct_end(),
	};
	int rc = EVP_KDF_derive(kc, out, h->hash_len, ps) == 1 ? 0 : -1;
	EVP_KDF_CTX_free(kc);
	return rc;
}

/* ---- the Authorization value ---- */

int bst_basic_decode(bst_str value, char *buf, size_t cap, bst_str *user, bst_str *pass)
{
	if (value.len > AUTH_VALUE_MAX || value.len < 6 ||
	    !bst_str_ieq((bst_str){ value.p, 5 }, BST_S("basic")) || value.p[5] != ' ')
		return -1;
	uint32_t i = 5;
	while (i < value.len && value.p[i] == ' ')
		i++;
	uint32_t e = value.len;
	while (e > i && value.p[e - 1] == ' ')
		e--;
	if (cap == 0)
		return -1;
	long n = bst_b64_decode(value.p + i, e - i, (uint8_t *)buf, cap - 1,
				BST_B64_STD | BST_B64_PAD_OPTIONAL);
	if (n <= 0)
		return -1;
	buf[n] = '\0';
	char *colon = memchr(buf, ':', (size_t)n);
	if (colon == NULL)
		return -1;
	for (char *p = buf; p < colon; p++)
		if ((unsigned char)*p < 0x20 || *p == 0x7f)
			return -1;
	*user = (bst_str){ buf, (uint32_t)(colon - buf) };
	*pass = (bst_str){ colon + 1, (uint32_t)(n - (colon - buf) - 1) };
	return 0;
}

/* ---- the users file (loaded by auth_directives.c) ---- */

typedef struct bentry {
	const char *user;
	uint32_t ulen;
	bst_phc h;
} bentry;

struct bst_basic_users {
	size_t map_len;
	size_t n;
	bst_phc dummy; /* hashed for an unknown user: the same cost as a real one */
	bentry e[];
};

void bst_basic_users_free(void *p)
{
	bst_basic_users *u = p;
	if (u == NULL)
		return;
	size_t len = u->map_len;
	OPENSSL_cleanse(u, len);
	munmap(u, len);
}

const bst_basic_users *bst_basic_users_load(const char *path, unsigned *weak, char *why, size_t whycap)
{
	*weak = 0;
	FILE *f = fopen(path, "re");
	if (f == NULL) {
		snprintf(why, whycap, "%s", strerror(errno));
		return NULL;
	}
	bentry *tmp = NULL;
	size_t n = 0, cap = 0, names = 0;
	char line[1024];
	unsigned lineno = 0;
	const char *err = NULL;
	while (err == NULL && fgets(line, sizeof line, f) != NULL) {
		lineno++;
		size_t l = strlen(line);
		if (l == sizeof line - 1 && line[l - 1] != '\n') {
			err = "line too long";
			break;
		}
		while (l > 0 && (line[l - 1] == '\n' || line[l - 1] == '\r'))
			line[--l] = '\0';
		if (l == 0 || line[0] == '#')
			continue;
		char *colon = strchr(line, ':');
		if (colon == NULL || colon == line || colon - line > 255) {
			err = "expected user:hash";
			break;
		}
		if (n == cap) {
			size_t nc = cap ? cap * 2 : 16;
			bentry *nt = realloc(tmp, nc * sizeof *nt);
			if (nt == NULL) {
				err = "out of memory";
				break;
			}
			tmp = nt;
			cap = nc;
		}
		bentry *b = &tmp[n];
		if (bst_phc_parse((bst_str){ colon + 1, (uint32_t)strlen(colon + 1) }, &b->h) != 0) {
			err = "not an Argon2id PHC string";
			break;
		}
		b->ulen = (uint32_t)(colon - line);
		char *u = malloc(b->ulen + 1);
		if (u == NULL) {
			err = "out of memory";
			break;
		}
		memcpy(u, line, b->ulen);
		u[b->ulen] = '\0';
		b->user = u;
		names += b->ulen + 1;
		if (bst_phc_weak(&b->h))
			(*weak)++;
		n++;
	}
	OPENSSL_cleanse(line, sizeof line);
	fclose(f);
	bst_basic_users *out = NULL;
	if (err == NULL) {
		size_t len = sizeof *out + n * sizeof(bentry) + names;
		long pg = sysconf(_SC_PAGESIZE);
		len = (len + (size_t)pg - 1) / (size_t)pg * (size_t)pg;
		void *m = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (m == MAP_FAILED) {
			err = "out of memory";
		} else {
			(void)madvise(m, len, MADV_DONTDUMP); /* never in a core file */
			out = m;
			out->map_len = len;
			out->n = n;
			char *names_p = (char *)&out->e[n];
			for (size_t i = 0; i < n; i++) {
				out->e[i] = tmp[i];
				memcpy(names_p, tmp[i].user, tmp[i].ulen + 1);
				out->e[i].user = names_p;
				names_p += tmp[i].ulen + 1;
			}
			/* the dummy: the costliest entry's parameters, a random salt and hash */
			bst_phc d = { .m_kib = 19456, .t = 2, .p = 1, .salt_len = 16, .hash_len = 32 };
			for (size_t i = 0; i < n; i++)
				if ((uint64_t)out->e[i].h.m_kib * out->e[i].h.t >= (uint64_t)d.m_kib * d.t) {
					d = out->e[i].h;
				}
			if (RAND_bytes(d.salt, (int)d.salt_len) != 1 || RAND_bytes(d.hash, (int)d.hash_len) != 1) {
				bst_basic_users_free(out);
				out = NULL;
				err = "no randomness";
			} else {
				out->dummy = d;
			}
		}
	}
	for (size_t i = 0; i < n; i++) {
		OPENSSL_cleanse((void *)tmp[i].user, tmp[i].ulen);
		free((void *)tmp[i].user);
	}
	if (tmp != NULL)
		OPENSSL_cleanse(tmp, cap * sizeof *tmp);
	free(tmp);
	if (err != NULL)
		snprintf(why, whycap, "line %u: %s", lineno, err);
	return out;
}

/* Index of the user, scanning every entry so the time does not depend on where it is; -1. */
static long find_user(const bst_basic_users *u, bst_str name)
{
	long found = -1;
	for (size_t i = 0; i < u->n; i++) {
		const bentry *b = &u->e[i];
		size_t l = b->ulen < name.len ? b->ulen : name.len;
		int diff = CRYPTO_memcmp(b->user, name.p, l) | (b->ulen != name.len);
		if (diff == 0 && found < 0)
			found = (long)i;
	}
	return found;
}

bool bst_basic_users_check(const bst_basic_users *u, bst_str user, bst_str pass)
{
	long i = find_user(u, user);
	const bst_phc *h = i >= 0 ? &u->e[i].h : &u->dummy; /* the same cost either way */
	uint8_t got[BST_PHC_HASH_MAX];
	bool match = bst_argon2id(pass.p, pass.len, h, got) == 0 &&
		     CRYPTO_memcmp(got, h->hash, h->hash_len) == 0;
	OPENSSL_cleanse(got, sizeof got);
	return match && i >= 0;
}

/* ---- the verified-credentials cache (per worker) ---- */

typedef struct cslot {
	uint8_t key[32];
	uint64_t exp_ms;
	const bst_basic_users *users;
	uint32_t uidx;
	bool used;
} cslot;

static cslot g_cache[CACHE_SLOTS];
static uint8_t g_hkey[32];
static bool g_hkey_set;
static unsigned g_inflight;

/* HMAC-SHA256 of the decoded credentials under a random per-worker key: the cache never holds
 * anything a memory reader could replay. */
static bool cache_key(bst_str user, bst_str pass, uint8_t out[32])
{
	if (!g_hkey_set) {
		if (RAND_bytes(g_hkey, sizeof g_hkey) != 1)
			return false;
		g_hkey_set = true;
	}
	EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
	EVP_MAC_CTX *mc = mac ? EVP_MAC_CTX_new(mac) : NULL;
	EVP_MAC_free(mac);
	if (mc == NULL)
		return false;
	OSSL_PARAM ps[] = { OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA256", 0),
			    OSSL_PARAM_construct_end() };
	size_t len = 0;
	uint8_t zero = 0;
	bool ok = EVP_MAC_init(mc, g_hkey, sizeof g_hkey, ps) == 1 &&
		  EVP_MAC_update(mc, (const uint8_t *)user.p, user.len) == 1 &&
		  EVP_MAC_update(mc, &zero, 1) == 1 &&
		  EVP_MAC_update(mc, (const uint8_t *)pass.p, pass.len) == 1 &&
		  EVP_MAC_final(mc, out, &len, 32) == 1 && len == 32;
	EVP_MAC_CTX_free(mc);
	return ok;
}

static cslot *cache_find(const uint8_t key[32], const bst_basic_users *u, uint64_t now)
{
	cslot *c = &g_cache[(key[0] | (unsigned)key[1] << 8) % CACHE_SLOTS];
	if (!c->used || c->users != u || c->exp_ms <= now || CRYPTO_memcmp(c->key, key, 32) != 0)
		return NULL;
	return c;
}

static void cache_put(const uint8_t key[32], const bst_basic_users *u, uint32_t uidx, uint64_t exp)
{
	cslot *c = &g_cache[(key[0] | (unsigned)key[1] << 8) % CACHE_SLOTS];
	memcpy(c->key, key, 32);
	c->users = u;
	c->uidx = uidx;
	c->exp_ms = exp;
	c->used = true;
}

/* ---- the check ---- */

typedef struct bjob {
	bst_auth_run *r;
	bool cancelled;
	const bst_basic_users *users;
	long uidx; /* -1: unknown user, the dummy is hashed */
	bst_phc h;
	char pass[CRED_MAX];
	size_t plen;
	uint8_t key[32];
	bool have_key;
	bool ok;
	bst_loop *loop;
} bjob;

static void job_free(bjob *j)
{
	OPENSSL_cleanse(j, sizeof *j);
	free(j);
}

static void job_work(void *arg)
{
	bjob *j = arg;
	uint8_t got[BST_PHC_HASH_MAX];
	bool match = bst_argon2id(j->pass, j->plen, &j->h, got) == 0 &&
		     CRYPTO_memcmp(got, j->h.hash, j->h.hash_len) == 0;
	OPENSSL_cleanse(got, sizeof got);
	j->ok = match && j->uidx >= 0;
}

static void job_cancel(void *p)
{
	((bjob *)p)->cancelled = true; /* freed when the hash comes back */
}

static void deny(bst_auth_run *r)
{
	bst_stream *s = bst_auth_stream(r);
	const char *realm = s->cfg->auth.basic_realm;
	size_t n = strlen(realm) + 32;
	char *v = bst_arena_alloc(s->arena, n);
	if (v == NULL) {
		bst_auth_step(r, 500, (bst_str){ NULL, 0 }, (bst_str){ NULL, 0 });
		return;
	}
	int l = snprintf(v, n, "Basic realm=\"%s\", charset=\"UTF-8\"", realm);
	bst_auth_step(r, 401, BST_S("WWW-Authenticate"), (bst_str){ v, (uint32_t)l });
}

static void let_in(bst_auth_run *r, const bst_basic_users *u, uint32_t uidx)
{
	bst_stream *s = bst_auth_stream(r);
	const bentry *b = &u->e[uidx];
	char *name = bst_arena_alloc(s->arena, b->ulen + 1);
	if (name == NULL) {
		bst_auth_step(r, 500, (bst_str){ NULL, 0 }, (bst_str){ NULL, 0 });
		return;
	}
	memcpy(name, b->user, b->ulen + 1);
	s->auth_user = (bst_str){ name, b->ulen };
	bst_auth_step(r, 0, (bst_str){ NULL, 0 }, (bst_str){ NULL, 0 });
}

static void job_done(void *arg)
{
	bjob *j = arg;
	g_inflight--;
	if (j->cancelled) {
		job_free(j);
		return;
	}
	bst_auth_run *r = j->r;
	bst_stream *s = bst_auth_stream(r);
	if (j->ok) {
		if (j->have_key && s->cfg->auth.cache_ttl_ms > 0)
			cache_put(j->key, j->users, (uint32_t)j->uidx,
				  bst_loop_now_ms(j->loop) + s->cfg->auth.cache_ttl_ms);
		const bst_basic_users *u = j->users;
		uint32_t idx = (uint32_t)j->uidx;
		job_free(j);
		let_in(r, u, idx);
		return;
	}
	job_free(j);
	deny(r);
}

void bst_auth_basic_start(bst_auth_run *r)
{
	bst_stream *s = bst_auth_stream(r);
	const bst_cfg_auth *a = &s->cfg->auth;
	if (a->basic_users == NULL) { /* auth_basic without a file: closed, never open */
		bst_log(BST_LOG_ERROR, "auth_basic \"%s\" has no auth_basic_file: 500", a->basic_realm);
		bst_auth_step(r, 500, (bst_str){ NULL, 0 }, (bst_str){ NULL, 0 });
		return;
	}
	const bst_header *ah = bst_headers_get(&s->req.head.headers, BST_H_AUTHORIZATION);
	if (ah == NULL || bst_headers_next(&s->req.head.headers, ah, BST_H_AUTHORIZATION) != NULL) {
		deny(r);
		return;
	}
	char buf[CRED_MAX];
	bst_str user, pass;
	if (bst_basic_decode(ah->value, buf, sizeof buf, &user, &pass) != 0) {
		OPENSSL_cleanse(buf, sizeof buf);
		deny(r);
		return;
	}
	bst_loop *loop = bst_worker_loop(s->worker);
	uint8_t key[32];
	bool have_key = cache_key(user, pass, key);
	if (have_key) {
		cslot *c = cache_find(key, a->basic_users, bst_loop_now_ms(loop));
		if (c != NULL) {
			OPENSSL_cleanse(buf, sizeof buf);
			let_in(r, a->basic_users, c->uidx);
			return;
		}
	}
	if (g_inflight >= a->max_concurrent) {
		OPENSSL_cleanse(buf, sizeof buf);
		bst_auth_step(r, 503, BST_S("Retry-After"), BST_S("1"));
		return;
	}
	bjob *j = calloc(1, sizeof *j);
	if (j == NULL) {
		OPENSSL_cleanse(buf, sizeof buf);
		bst_auth_step(r, 503, BST_S("Retry-After"), BST_S("1"));
		return;
	}
	j->r = r;
	j->users = a->basic_users;
	j->uidx = find_user(a->basic_users, user);
	j->h = j->uidx >= 0 ? a->basic_users->e[j->uidx].h : a->basic_users->dummy;
	memcpy(j->pass, pass.p, pass.len);
	j->plen = pass.len;
	memcpy(j->key, key, sizeof key);
	j->have_key = have_key;
	j->loop = loop;
	OPENSSL_cleanse(buf, sizeof buf);
	g_inflight++;
	if (bst_aio_submit(loop, job_work, job_done, j) != 0) {
		g_inflight--;
		job_free(j);
		bst_auth_step(r, 503, BST_S("Retry-After"), BST_S("1"));
		return;
	}
	bst_auth_set_pending(r, job_cancel, j);
}

/* ---- bastion passwd ---- */

static int read_pass(const char *prompt, char *out, size_t cap)
{
	struct termios old, quiet;
	bool tty = isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &old) == 0;
	if (tty) {
		fputs(prompt, stderr);
		quiet = old;
		quiet.c_lflag &= (tcflag_t)~ECHO;
		(void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &quiet);
	}
	char *got = fgets(out, (int)cap, stdin);
	if (tty) {
		(void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);
		fputc('\n', stderr);
	}
	if (got == NULL)
		return -1;
	size_t l = strlen(out);
	if (l == cap - 1 && out[l - 1] != '\n')
		return -1;
	while (l > 0 && (out[l - 1] == '\n' || out[l - 1] == '\r'))
		out[--l] = '\0';
	return l > 0 ? 0 : -1;
}

int bst_passwd_main(int argc, char **argv)
{
	bst_phc h = { .m_kib = 65536, .t = 3, .p = 1, .salt_len = 16, .hash_len = 32 };
	const char *user = NULL;
	for (int i = 1; i < argc; i++) {
		const char *a = argv[i];
		if ((strcmp(a, "-m") == 0 || strcmp(a, "-t") == 0 || strcmp(a, "-p") == 0) && i + 1 < argc) {
			char *end;
			unsigned long v = strtoul(argv[++i], &end, 10);
			if (*end != '\0' || v == 0 || v > (1ul << 20)) {
				fprintf(stderr, "bastion passwd: bad %s value\n", a);
				return 2;
			}
			if (a[1] == 'm')
				h.m_kib = (uint32_t)v;
			else if (a[1] == 't')
				h.t = (uint32_t)v;
			else
				h.p = (uint32_t)v;
		} else if (a[0] != '-' && user == NULL) {
			user = a;
		} else {
			fputs("usage: bastion passwd [-m KiB] [-t iterations] [-p lanes] [user]\n", stderr);
			return 2;
		}
	}
	if (h.t > 64 || h.p > 64 || h.m_kib < 8 * h.p) {
		fputs("bastion passwd: parameters out of range\n", stderr);
		return 2;
	}
	if (user != NULL && (strchr(user, ':') != NULL || strlen(user) > 255)) {
		fputs("bastion passwd: a user name can not contain ':' or exceed 255 bytes\n", stderr);
		return 2;
	}
	char p1[1024], p2[1024];
	if (read_pass("Password: ", p1, sizeof p1) != 0) {
		fputs("bastion passwd: no password read\n", stderr);
		return 1;
	}
	if (isatty(STDIN_FILENO)) {
		if (read_pass("Again: ", p2, sizeof p2) != 0 || strcmp(p1, p2) != 0) {
			OPENSSL_cleanse(p1, sizeof p1);
			OPENSSL_cleanse(p2, sizeof p2);
			fputs("bastion passwd: the passwords differ\n", stderr);
			return 1;
		}
		OPENSSL_cleanse(p2, sizeof p2);
	}
	if (bst_phc_weak(&h))
		fputs("bastion passwd: warning: below m=19456, t=2 is weak\n", stderr);
	char line[512];
	int rc = 1;
	if (RAND_bytes(h.salt, (int)h.salt_len) == 1 && bst_argon2id(p1, strlen(p1), &h, h.hash) == 0 &&
	    bst_phc_format(&h, line, sizeof line) > 0) {
		printf("%s%s%s\n", user ? user : "", user ? ":" : "", line);
		rc = 0;
	} else {
		fputs("bastion passwd: hashing failed (OpenSSL with Argon2id is needed)\n", stderr);
	}
	OPENSSL_cleanse(p1, sizeof p1);
	return rc;
}
