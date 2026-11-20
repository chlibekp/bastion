/* ACME certificate automation (RFC 8555), for servers with `tls auto`.
 *
 * Processes. The protocol runs in a short-lived job that master forks when work may be due
 * (bst_acme_master_*): never in a worker, and never in master itself, so a slow or hostile CA
 * cannot stall signal handling. The job resolves the CA's host, loads the trust store, opens the
 * storage directory and starts the DNS hook runner first, then drops to `user` and applies a
 * seccomp filter of its own role (BST_SANDBOX_ACME: the helper's list, with outbound connect and
 * file writes beneath the storage descriptor through openat2 RESOLVE_BENEATH). Every ACME URL
 * must be on the directory's host, which was resolved before the filter.
 *
 * Challenges. HTTP-01 key authorizations go in a shared memory table that workers answer from at
 * /.well-known/acme-challenge/<token> (acme_http01.c): only a token in the table is served.
 * TLS-ALPN-01 certificates go in the same region, served to a ClientHello that offers only
 * `acme-tls/1` for that SNI name (acme_alpn.c). DNS-01 runs `dns_hook set|clear <name> <value>`
 * through execve with a fixed environment, no shell, from a runner the job forks before its
 * sandbox (acme_dns.c).
 *
 * Certificates. Storage: <storage>/accounts/<ca id>/{account.key,kid}, and
 * <storage>/certs/<first name>/{cert.pem,key.pem}, every key 0600 in a 0700 directory. At load,
 * a `tls auto` server without a certificate gets a temporary self-signed one (marked by a `temp`
 * file), so its port serves at once. A new certificate and key are written next to the old pair
 * and swapped in as one behind a commit marker (bst_acme_recover_pair finishes or discards an
 * install a crash interrupted), then the job exits with BST_ACME_EXIT_INSTALLED and master runs a reload (proc/reload.h),
 * the same path as any certificate change: new connections get it, old ones finish.
 *
 * Renewal and failures. A certificate is renewed renew_before its notAfter, or earlier when the
 * CA's renewal information (ARI, `ari on`) suggests a window that has started. A failed attempt
 * backs off exponentially per server (state/<name>), never below a CA's Retry-After; the old
 * certificate (or the temporary one) stays in use meanwhile, and one server's failure never
 * holds back another's. */
#ifndef BST_OPS_ACME_H
#define BST_OPS_ACME_H

#include "config/compile.h"
#include "core/str.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define BST_ACME_LE_URL "https://acme-v02.api.letsencrypt.org/directory"
#define BST_ACME_LE_STAGING_URL "https://acme-staging-v02.api.letsencrypt.org/directory"
#define BST_ACME_ZEROSSL_URL "https://acme.zerossl.com/v2/DV90"
#define BST_ACME_DEFAULT_STORAGE "/var/lib/bastion/acme"

/* The job's exit status: nothing changed, or a certificate was installed (reload). */
#define BST_ACME_EXIT_OK 0
#define BST_ACME_EXIT_INSTALLED 10

typedef enum bst_acme_challenge {
	BST_ACME_HTTP01,
	BST_ACME_ALPN01,
	BST_ACME_DNS01,
} bst_acme_challenge;

typedef enum bst_acme_key_type { BST_ACME_KEY_P256, BST_ACME_KEY_RSA2048 } bst_acme_key_type;

typedef struct bst_cfg_acme {
	const char *email;	/* NULL: an account without contact */
	const char *ca;		/* the directory URL as resolved from `ca` and `staging` */
	bool public_ca;		/* `ca letsencrypt` or `ca zerossl` */
	bool zerossl;
	bool staging;
	const char *storage;
	bst_acme_challenge challenge;
	const char *dns_hook;
	bst_acme_key_type key_type;
	uint64_t renew_before_s;
	bool ari;
	const char *eab_kid, *eab_hmac; /* external account binding; eab_hmac is base64url */
	const char *ca_root;		/* PEM bundle to trust for the CA instead of the system's */
	bst_cfg_loc loc;
} bst_cfg_acme;

/* ---- shared memory between the job and the workers ---- */

#define BST_ACME_TOKENS 64
#define BST_ACME_TOKEN_MAX 128
#define BST_ACME_KEYAUTH_MAX 256
#define BST_ACME_ALPN_CERTS 16
#define BST_ACME_NAME_MAX 256
#define BST_ACME_PEM_MAX 6144

/* Master, before any child: the region, when some server has `tls auto`. 0, or -1 with err. */
int bst_acme_setup(const bst_config *cfg, bst_err *err);

/* HTTP-01 (acme_http01.c). A token is base64url only; anything else is never stored or served. */
bool bst_acme_token_valid(bst_str token);
int bst_acme_http01_put(bst_str token, bst_str keyauth);
void bst_acme_http01_remove(bst_str token);
/* Copies the key authorization of a token into out: its length, or -1 when unknown. */
int bst_acme_http01_get(bst_str token, char *out, size_t cap);

/* Router hook, before rewrites: answers /.well-known/acme-challenge/<token> from the table on
 * a `tls auto` server, and redirects plain HTTP to https on an implied port 80. true when it
 * answered. */
struct bst_stream;
bool bst_acme_http01_serve(struct bst_stream *s);

/* TLS-ALPN-01 (acme_alpn.c). */
int bst_acme_alpn_put(const char *name, const char *cert_pem, size_t cert_len, const char *key_pem,
		      size_t key_len);
void bst_acme_alpn_remove(const char *name);
/* tls/sni.c, in the ClientHello callback: when the client offers only acme-tls/1 and a
 * challenge certificate exists for name, installs it on ssl. true when it did. */
bool bst_acme_alpn_hello(void *ssl, const char *name, size_t len);
/* The DER of the acmeIdentifier extension's value for a key authorization (RFC 8737). */
void bst_acme_alpn_digest(bst_str keyauth, unsigned char out[32]);
/* A self-signed challenge certificate for name carrying the digest: malloc'd PEMs. 0 or -1. */
int bst_acme_alpn_cert(const char *name, const unsigned char digest[32], char **cert_pem,
		       size_t *cert_len, char **key_pem, size_t *key_len);

/* ---- the job's building blocks (acme_crypto.c), exposed for tests ---- */

/* base64url without padding of n bytes: malloc'd, NUL-terminated, or NULL. */
char *bst_acme_b64url(const void *p, size_t n);
/* The account JWK ({"crv","kty","x","y"} in that order, RFC 7638) of a P-256 key. */
char *bst_acme_jwk(void *pkey);
/* The JWK thumbprint (base64url of SHA-256 of the JWK). */
char *bst_acme_thumbprint(void *pkey);
/* A flattened JWS (RFC 7515) with ES256. kid NULL: the JWK goes in the header. payload NULL:
 * POST-as-GET (empty payload). malloc'd, or NULL. */
char *bst_acme_jws(void *pkey, const char *kid, const char *nonce, const char *url, const char *payload);
/* The externalAccountBinding object: an HS256 JWS of the account JWK. */
char *bst_acme_eab(void *pkey, const char *kid, const char *hmac_b64url, const char *url);
/* A new P-256 or RSA-2048 key. */
void *bst_acme_keygen(bst_acme_key_type t);
/* PEM of a private key, malloc'd. */
char *bst_acme_key_pem(void *pkey, size_t *len);
void *bst_acme_key_from_pem(const char *pem, size_t len);
void bst_acme_key_free(void *pkey);
/* A DER CSR for names, base64url. */
char *bst_acme_csr(void *pkey, const char *const *names, size_t n);
/* A self-signed certificate for names, valid days: PEM, malloc'd. */
char *bst_acme_selfsigned(void *pkey, const char *const *names, size_t n, int days, size_t *len);

/* Seconds to wait after the fails-th failure in a row (1-based), and at least retry_after. */
uint64_t bst_acme_backoff_s(unsigned fails, uint64_t retry_after_s, uint64_t base_s);
/* A Retry-After value: delta seconds or an HTTP date, relative to now (unix seconds). */
bool bst_acme_retry_after(const char *v, int64_t now, uint64_t *out_s);
/* An RFC 3339 timestamp to unix seconds. */
bool bst_acme_rfc3339(const char *s, size_t len, int64_t *out);

/* The certificate files of a server: <storage>/certs/<first name>/{cert,key}.pem. */
int bst_acme_cert_paths(const bst_cfg_acme *a, const bst_cfg_server *s, char *crt, char *key,
			size_t cap);
/* Settles an interrupted install in certdir (relative to the storage descriptor dir, no `..`):
 * a committed new pair is renamed into place (1), an uncommitted one deleted (2), nothing to do
 * (0), or -1 with errno. Run before the pair is read. */
int bst_acme_recover_pair(int dir, const char *certdir);

/* ---- master ---- */

struct bst_runtime;
/* Called when a generation is ready: the first job runs soon after. */
void bst_acme_master_ready(const bst_config *cfg, uint64_t now_ms);
/* The time of the next thing to do (start a job, kill a late one), 0 for none. */
uint64_t bst_acme_master_next(void);
/* Runs that thing when due. */
void bst_acme_master_tick(struct bst_runtime *rt, uint64_t now_ms);
/* A child exited: -1 when it is not the job, 0 when it was, 1 when it installed a certificate
 * and master should reload. */
int bst_acme_master_reaped(pid_t pid, int status, uint64_t now_ms);
/* Stops a running job (reload, shutdown). */
void bst_acme_master_stop(void);

/* The job itself, in the forked child. Returns its exit status. */
int bst_acme_job(struct bst_runtime *rt);

/* DNS-01 hook runner (acme_dns.c): forked before the sandbox, then asked over a socket. */
int bst_acme_dns_start(const char *hook);
int bst_acme_dns_run(const char *verb, const char *name, const char *value);
void bst_acme_dns_stop(void);

#endif
