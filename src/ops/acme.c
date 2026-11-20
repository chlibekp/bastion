/* The ACME job and master's scheduling of it (ops/acme.h). */
#include "ops/acme_priv.h"

#include "core/arena.h"
#include "core/json.h"
#include "core/log.h"
#include "io/net.h"
#include "ops/http_client.h"
#include "proc/runtime.h"
#include "proc/sandbox.h"
#include "proc/signals.h"

#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <linux/openat2.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK_S (12 * 3600) /* look again at least this often */
#define JOB_DEADLINE_MS (15u * 60u * 1000u)
#define BACKOFF_BASE_S 60

static uint64_t test_env(const char *name, uint64_t dflt)
{
#ifdef BST_TEST
	const char *v = getenv(name);
	if (v != NULL && *v != '\0')
		return strtoull(v, NULL, 10);
#else
	(void)name;
#endif
	return dflt;
}

/* ================= master ================= */

static struct {
	pid_t pid;
	int pipe;	  /* the job's report: seconds until it wants to run again */
	uint64_t at;	  /* next start, 0: none */
	uint64_t kill_at; /* a job past its deadline, 0: none */
} M = { .pipe = -1 };

void bst_acme_master_ready(const bst_config *cfg, uint64_t now_ms)
{
	if (cfg->global.acme == NULL || bst_acme_region_ == NULL || M.pid > 0)
		return;
	M.at = now_ms + test_env("BST_TEST_ACME_FIRST_MS", 1000);
}

uint64_t bst_acme_master_next(void)
{
	uint64_t t = M.pid > 0 ? M.kill_at : M.at;
	return t;
}

void bst_acme_master_tick(bst_runtime *rt, uint64_t now_ms)
{
	if (M.pid > 0) {
		if (M.kill_at != 0 && now_ms >= M.kill_at) {
			bst_log(BST_LOG_WARN, "acme: job (pid %ld) outlived its deadline: killing it", (long)M.pid);
			kill(M.pid, SIGKILL);
			M.kill_at = 0;
		}
		return;
	}
	if (M.at == 0 || now_ms < M.at)
		return;
	M.at = 0;
	int p[2];
	if (pipe2(p, O_CLOEXEC) != 0) {
		bst_log(BST_LOG_ERROR, "acme: pipe: %s", strerror(errno));
		M.at = now_ms + 60000;
		return;
	}
	pid_t pid = fork();
	if (pid < 0) {
		bst_log(BST_LOG_ERROR, "acme: fork: %s", strerror(errno));
		close(p[0]);
		close(p[1]);
		M.at = now_ms + 60000;
		return;
	}
	if (pid == 0) {
		close(p[0]);
		M.pipe = p[1];
		_exit(bst_acme_job(rt));
	}
	close(p[1]);
	M.pid = pid;
	M.pipe = p[0];
	M.kill_at = now_ms + test_env("BST_TEST_ACME_JOB_DEADLINE_MS", JOB_DEADLINE_MS);
}

int bst_acme_master_reaped(pid_t pid, int status, uint64_t now_ms)
{
	if (M.pid <= 0 || pid != M.pid)
		return -1;
	char buf[32] = "";
	ssize_t n = M.pipe >= 0 ? read(M.pipe, buf, sizeof buf - 1) : -1;
	if (M.pipe >= 0)
		close(M.pipe);
	M.pipe = -1;
	M.pid = 0;
	M.kill_at = 0;
	uint64_t secs = n > 0 ? strtoull(buf, NULL, 10) : 0;
	bool ok = WIFEXITED(status) && (WEXITSTATUS(status) == BST_ACME_EXIT_OK ||
					WEXITSTATUS(status) == BST_ACME_EXIT_INSTALLED);
	if (!ok) {
		bst_log(BST_LOG_ERROR, "acme: job failed (%s %d): next try in 5 minutes",
			WIFEXITED(status) ? "exit" : "signal",
			WIFEXITED(status) ? WEXITSTATUS(status) : WTERMSIG(status));
		secs = 300;
	}
	if (secs < 1)
		secs = 1;
	if (secs > CHECK_S)
		secs = CHECK_S;
	uint64_t ms = secs * 1000u, cap = test_env("BST_TEST_ACME_CHECK_MS", 0);
	if (cap != 0 && ms > cap)
		ms = cap;
	M.at = now_ms + ms;
	return ok && WEXITSTATUS(status) == BST_ACME_EXIT_INSTALLED ? 1 : 0;
}

void bst_acme_master_stop(void)
{
	if (M.pid > 0)
		kill(M.pid, SIGKILL); /* reaped as an unknown child, by this image or the next */
	M.pid = 0;
	M.at = M.kill_at = 0;
	if (M.pipe >= 0)
		close(M.pipe);
	M.pipe = -1;
}

/* ================= the job ================= */

typedef struct job {
	const bst_cfg_acme *a;
	bst_hc hc;
	int dir; /* the storage directory */
	char acct_dir[64];
	bst_arena *arena;
	/* the directory */
	char new_nonce[1024], new_account[1024], new_order[1024], renewal_info[1024];
	char nonce[256];
	void *key; /* the account key */
	char *thumb;
	char kid[1024];
	uint64_t retry_after_s; /* from the last 429 or 503 */
	char why[512];		/* the last failure */
} job;

static void why(job *j, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void why(job *j, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(j->why, sizeof j->why, fmt, ap);
	va_end(ap);
}

static int64_t unix_now(void)
{
	return (int64_t)time(NULL);
}

static uint64_t mono_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* ---- files beneath the storage descriptor ---- */

static int open_beneath(int dir, const char *path, int flags, mode_t mode)
{
	struct open_how how = { .flags = (uint64_t)flags | O_CLOEXEC | O_NOFOLLOW, .mode = mode,
				.resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS };
	return (int)syscall(SYS_openat2, dir, path, &how, sizeof how);
}

/* The whole file, malloc'd and NUL-terminated, or NULL (errno). Small files only. Read to the
 * end rather than sized with fstat: libc's fstat is newfstatat on some systems, which the
 * filter does not allow. */
static char *read_file(int dir, const char *path, size_t *len)
{
	int fd = open_beneath(dir, path, O_RDONLY, 0);
	if (fd < 0)
		return NULL;
	size_t cap = 4096, off = 0;
	char *buf = malloc(cap);
	while (buf != NULL) {
		if (off + 1 == cap) {
			char *nb = cap >= BST_HC_MAX_BODY ? NULL : realloc(buf, cap * 2);
			if (nb == NULL) {
				free(buf);
				buf = NULL;
				errno = EFBIG;
				break;
			}
			buf = nb;
			cap *= 2;
		}
		ssize_t r = read(fd, buf + off, cap - 1 - off);
		if (r < 0) {
			free(buf);
			buf = NULL;
			break;
		}
		if (r == 0)
			break;
		off += (size_t)r;
	}
	close(fd);
	if (buf == NULL)
		return NULL;
	buf[off] = '\0';
	*len = off;
	return buf;
}

static int write_file(int dir, const char *path, const char *data, size_t len)
{
	char tmp[600];
	snprintf(tmp, sizeof tmp, "%s.tmp", path);
	(void)unlinkat(dir, tmp, 0);
	int fd = open_beneath(dir, tmp, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd < 0)
		return -1;
	size_t off = 0;
	while (off < len) {
		ssize_t w = write(fd, data + off, len - off);
		if (w <= 0) {
			close(fd);
			(void)unlinkat(dir, tmp, 0);
			return -1;
		}
		off += (size_t)w;
	}
	if (fsync(fd) != 0) {
		close(fd);
		(void)unlinkat(dir, tmp, 0);
		return -1;
	}
	/* the raw call: libc turns renameat2 with no flags into renameat, which the filter refuses */
	if (close(fd) != 0 || syscall(SYS_renameat2, dir, tmp, dir, path, 0) != 0) {
		(void)unlinkat(dir, tmp, 0);
		return -1;
	}
	return 0;
}

/* Makes the renames into a directory durable. */
static int sync_dir(int dir, const char *path)
{
	int fd = open_beneath(dir, path, O_RDONLY | O_DIRECTORY, 0);
	if (fd < 0)
		return -1;
	int rc = fsync(fd);
	close(fd);
	return rc;
}

/* ---- installing a certificate and its key as one ----
 *
 * cert.pem and key.pem are two files, so a new pair is written beside the old one as
 * cert.pem.next and key.pem.next (each fsynced), then a `commit` marker is written: that is the
 * point of no return. Each .next file is then renamed into place and the marker removed. A crash
 * before the marker leaves the old pair, and the next look discards the .next files; a crash after
 * it is finished by bst_acme_recover_pair, which config load (acme_directives.c) and the job both
 * run before they read the pair. So the pair a server loads always belongs together. */

static void pair_path(char *out, size_t cap, const char *d, const char *leaf)
{
	snprintf(out, cap, "%s/%s", d, leaf);
}

static int finish_pair(int dir, const char *d)
{
	char kn[600], k[600], cn[600], c[600], m[600];
	pair_path(kn, sizeof kn, d, "key.pem.next");
	pair_path(k, sizeof k, d, "key.pem");
	pair_path(cn, sizeof cn, d, "cert.pem.next");
	pair_path(c, sizeof c, d, "cert.pem");
	pair_path(m, sizeof m, d, "commit");
	/* ENOENT: that half was renamed before the crash */
	if (syscall(SYS_renameat2, dir, kn, dir, k, 0) != 0 && errno != ENOENT)
		return -1;
	if (syscall(SYS_renameat2, dir, cn, dir, c, 0) != 0 && errno != ENOENT)
		return -1;
	if (sync_dir(dir, d) != 0 || unlinkat(dir, m, 0) != 0)
		return -1;
	return sync_dir(dir, d);
}

int bst_acme_recover_pair(int dir, const char *d)
{
	char m[600], kn[600], cn[600];
	pair_path(m, sizeof m, d, "commit");
	pair_path(kn, sizeof kn, d, "key.pem.next");
	pair_path(cn, sizeof cn, d, "cert.pem.next");
	int fd = open_beneath(dir, m, O_RDONLY, 0);
	if (fd >= 0) {
		close(fd);
		return finish_pair(dir, d) == 0 ? 1 : -1;
	}
	if (errno != ENOENT)
		return -1;
	/* never committed: whatever was written of the new pair is not used */
	bool had = unlinkat(dir, kn, 0) == 0;
	had |= unlinkat(dir, cn, 0) == 0;
	return had ? 2 : 0;
}

static int install_pair(int dir, const char *d, const char *key, size_t kl, const char *crt, size_t cl)
{
	char kn[600], cn[600], m[600];
	pair_path(kn, sizeof kn, d, "key.pem.next");
	pair_path(cn, sizeof cn, d, "cert.pem.next");
	pair_path(m, sizeof m, d, "commit");
	if (write_file(dir, kn, key, kl) != 0 || write_file(dir, cn, crt, cl) != 0 || sync_dir(dir, d) != 0) {
		int saved = errno;
		(void)unlinkat(dir, kn, 0);
		(void)unlinkat(dir, cn, 0);
		errno = saved;
		return -1;
	}
	if (write_file(dir, m, "", 0) != 0 || sync_dir(dir, d) != 0)
		return -1; /* either way the next look sorts it out: marker absent or present */
	return finish_pair(dir, d);
}

/* ---- JSON ---- */

static const bst_json *parse_json(job *j, const bst_hc_resp *r)
{
	bst_arena_reset(j->arena);
	bst_err e = { .msg = "" };
	const bst_json *v = r->body != NULL && r->len > 0 ? bst_json_parse(j->arena, r->body, r->len, &e) : NULL;
	if (v == NULL || bst_json_typeof(v) != BST_JSON_OBJ) {
		why(j, "the CA sent a malformed JSON response (HTTP %d)", r->status);
		return NULL;
	}
	return v;
}

/* A string member copied into out (truncated never: too long is a failure). */
static bool jstr(const bst_json *o, const char *key, char *out, size_t cap)
{
	const bst_json *v = o != NULL ? bst_json_get(o, key) : NULL;
	bst_str s;
	if (v == NULL || !bst_json_str(v, &s) || s.len >= cap)
		return false;
	for (uint32_t i = 0; i < s.len; i++)
		if ((unsigned char)s.p[i] < 0x20) /* nothing that could reach a log line or a header */
			return false;
	memcpy(out, s.p, s.len);
	out[s.len] = '\0';
	return true;
}

/* The CA's problem document (RFC 7807) as a failure reason. */
static void problem(job *j, const bst_hc_resp *r, const char *what)
{
	char type[128] = "", detail[256] = "";
	bst_arena_reset(j->arena);
	bst_err e = { .msg = "" };
	const bst_json *v = r->body != NULL && r->len > 0 ? bst_json_parse(j->arena, r->body, r->len, &e) : NULL;
	if (v != NULL) {
		(void)jstr(v, "type", type, sizeof type);
		(void)jstr(v, "detail", detail, sizeof detail);
	}
	why(j, "%s: HTTP %d%s%s%s%s", what, r->status, type[0] ? " " : "", type, detail[0] ? ": " : "", detail);
	if ((r->status == 429 || r->status == 503) && r->retry_after[0] != '\0') {
		uint64_t s = 0;
		if (bst_acme_retry_after(r->retry_after, unix_now(), &s))
			j->retry_after_s = s;
	}
}

/* ---- requests ---- */

static int get(job *j, const char *method, const char *url, bst_hc_resp *r)
{
	char err[256];
	if (bst_hc_request(&j->hc, method, url, NULL, NULL, 0, r, err, sizeof err) != 0) {
		why(j, "%s %s: %s", method, url, err);
		return -1;
	}
	if (r->nonce[0] != '\0')
		snprintf(j->nonce, sizeof j->nonce, "%s", r->nonce);
	return 0;
}

static bool is_bad_nonce(job *j, const bst_hc_resp *r)
{
	if (r->status != 400)
		return false;
	char type[128] = "";
	bst_arena_reset(j->arena);
	bst_err e = { .msg = "" };
	const bst_json *v = r->len > 0 ? bst_json_parse(j->arena, r->body, r->len, &e) : NULL;
	return v != NULL && jstr(v, "type", type, sizeof type) &&
	       strcmp(type, "urn:ietf:params:acme:error:badNonce") == 0;
}

/* A signed POST. payload NULL: POST-as-GET. A badNonce answer is retried with the nonce it
 * carries, a few times. 0 with r filled (any status), or -1. */
static int post(job *j, const char *url, const char *payload, bool jwk, bst_hc_resp *r)
{
	for (int attempt = 0; attempt < 5; attempt++) {
		if (j->nonce[0] == '\0') {
			bst_hc_resp h;
			if (get(j, "HEAD", j->new_nonce, &h) != 0)
				return -1;
			bst_hc_resp_free(&h);
			if (j->nonce[0] == '\0') {
				why(j, "the CA gave no Replay-Nonce");
				return -1;
			}
		}
		char *jws = bst_acme_jws(j->key, jwk ? NULL : j->kid, j->nonce, url, payload);
		j->nonce[0] = '\0'; /* used */
		if (jws == NULL) {
			why(j, "signing a request failed");
			return -1;
		}
		char err[256];
		int rc = bst_hc_request(&j->hc, "POST", url, "application/jose+json", jws, strlen(jws), r, err,
					sizeof err);
		free(jws);
		if (rc != 0) {
			why(j, "POST %s: %s", url, err);
			return -1;
		}
		if (r->nonce[0] != '\0')
			snprintf(j->nonce, sizeof j->nonce, "%s", r->nonce);
		if (!is_bad_nonce(j, r))
			return 0;
		bst_log(BST_LOG_DEBUG, "acme: badNonce from the CA: retrying with a fresh nonce");
		bst_hc_resp_free(r);
	}
	why(j, "the CA rejected every nonce");
	return -1;
}

/* Waits as the CA asks (Retry-After) or by default, bounded. */
static void poll_wait(job *j, const bst_hc_resp *r, unsigned round)
{
	uint64_t s = 0;
	uint64_t ms = round < 4 ? 500u << round : 5000u;
	if (r->retry_after[0] != '\0' && bst_acme_retry_after(r->retry_after, unix_now(), &s))
		ms = s > 30 ? 30000u : s * 1000u;
	if (ms < 200)
		ms = 200;
	bst_hc_sleep(&j->hc, ms);
}

static int directory(job *j)
{
	bst_hc_resp r;
	if (get(j, "GET", j->a->ca, &r) != 0)
		return -1;
	int rc = -1;
	if (r.status != 200) {
		problem(j, &r, "the ACME directory");
		goto out;
	}
	const bst_json *v = parse_json(j, &r);
	if (v == NULL)
		goto out;
	if (!jstr(v, "newNonce", j->new_nonce, sizeof j->new_nonce) ||
	    !jstr(v, "newAccount", j->new_account, sizeof j->new_account) ||
	    !jstr(v, "newOrder", j->new_order, sizeof j->new_order)) {
		why(j, "the ACME directory lacks newNonce, newAccount or newOrder");
		goto out;
	}
	if (!jstr(v, "renewalInfo", j->renewal_info, sizeof j->renewal_info))
		j->renewal_info[0] = '\0';
	rc = 0;
out:
	bst_hc_resp_free(&r);
	return rc;
}

/* The account: its key from storage (or a new one), its URL from storage (or newAccount). */
static int account(job *j)
{
	char path[160];
	size_t len = 0;
	snprintf(path, sizeof path, "%s/account.key", j->acct_dir);
	char *pem = read_file(j->dir, path, &len);
	if (pem != NULL) {
		j->key = bst_acme_key_from_pem(pem, len);
		OPENSSL_cleanse(pem, len);
		free(pem);
		if (j->key == NULL) {
			why(j, "the stored account key is unreadable");
			return -1;
		}
	} else {
		j->key = bst_acme_keygen(BST_ACME_KEY_P256);
		size_t kl = 0;
		char *kp = j->key != NULL ? bst_acme_key_pem(j->key, &kl) : NULL;
		int w = kp != NULL ? write_file(j->dir, path, kp, kl) : -1;
		if (kp != NULL) {
			OPENSSL_cleanse(kp, kl);
			free(kp);
		}
		if (w != 0) {
			why(j, "storing the account key: %s", strerror(errno));
			return -1;
		}
		bst_log(BST_LOG_INFO, "acme: made a new account key");
	}
	j->thumb = bst_acme_thumbprint(j->key);
	if (j->thumb == NULL) {
		why(j, "the account key is not P-256");
		return -1;
	}
	snprintf(path, sizeof path, "%s/kid", j->acct_dir);
	char *kid = read_file(j->dir, path, &len);
	if (kid != NULL && len > 0 && len < sizeof j->kid && strchr(kid, '\n') == NULL) {
		memcpy(j->kid, kid, len + 1);
		free(kid);
		return 0;
	}
	free(kid);
	/* newAccount: contact, terms, and the external account binding when configured */
	char *eab = NULL;
	if (j->a->eab_kid != NULL) {
		eab = bst_acme_eab(j->key, j->a->eab_kid, j->a->eab_hmac, j->new_account);
		if (eab == NULL) {
			why(j, "external account binding: eab_hmac is not valid base64url");
			return -1;
		}
	}
	char *payload = NULL;
	if (asprintf(&payload, "{\"termsOfServiceAgreed\":true%s%s%s%s%s}",
		     j->a->email != NULL ? ",\"contact\":[\"mailto:" : "", j->a->email != NULL ? j->a->email : "",
		     j->a->email != NULL ? "\"]" : "", eab != NULL ? ",\"externalAccountBinding\":" : "",
		     eab != NULL ? eab : "") < 0)
		payload = NULL;
	free(eab);
	if (payload == NULL) {
		why(j, "out of memory");
		return -1;
	}
	bst_hc_resp r;
	int rc = post(j, j->new_account, payload, true, &r);
	free(payload);
	if (rc != 0)
		return -1;
	rc = -1;
	if ((r.status != 200 && r.status != 201) || r.location[0] == '\0') {
		problem(j, &r, "creating the ACME account");
	} else if (strlen(r.location) >= sizeof j->kid) {
		why(j, "the account URL is too long");
	} else {
		snprintf(j->kid, sizeof j->kid, "%s", r.location);
		if (write_file(j->dir, path, j->kid, strlen(j->kid)) != 0)
			why(j, "storing the account URL: %s", strerror(errno));
		else
			rc = 0;
		bst_log(BST_LOG_INFO, "acme: account %s", j->kid);
	}
	bst_hc_resp_free(&r);
	return rc;
}

/* ---- one server ---- */

typedef struct pending {
	char token[BST_ACME_TOKEN_MAX];
	char name[BST_ACME_NAME_MAX];
	char value[64]; /* dns-01: the TXT value */
	bool set;
} pending;

static void cleanup(job *j, pending *p, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		if (!p[i].set)
			continue;
		if (j->a->challenge == BST_ACME_HTTP01)
			bst_acme_http01_remove((bst_str){ p[i].token, (uint32_t)strlen(p[i].token) });
		else if (j->a->challenge == BST_ACME_ALPN01)
			bst_acme_alpn_remove(p[i].name);
		else
			(void)bst_acme_dns_run("clear", p[i].name, p[i].value);
		p[i].set = false;
	}
}

static const char *chall_name(bst_acme_challenge c)
{
	return c == BST_ACME_HTTP01 ? "http-01" : c == BST_ACME_ALPN01 ? "tls-alpn-01" : "dns-01";
}

/* Prepares and answers one authorization. 0: answered or already valid (*answered says which),
 * -1: failed. */
static int authorize(job *j, const char *url, pending *p, bool *answered)
{
	*answered = false;
	bst_hc_resp r;
	if (post(j, url, NULL, false, &r) != 0)
		return -1;
	int rc = -1;
	char status[32], chall_url[1024], token[BST_ACME_TOKEN_MAX], name[BST_ACME_NAME_MAX];
	const bst_json *v;
	if (r.status != 200) {
		problem(j, &r, "fetching an authorization");
		goto out;
	}
	v = parse_json(j, &r);
	if (v == NULL)
		goto out;
	const bst_json *id = bst_json_get(v, "identifier");
	if (!jstr(v, "status", status, sizeof status) || !jstr(id, "value", name, sizeof name)) {
		why(j, "an authorization without status or identifier");
		goto out;
	}
	if (strcmp(status, "valid") == 0) {
		rc = 0;
		goto out;
	}
	if (strcmp(status, "pending") != 0) {
		why(j, "authorization for %s is %s", name, status);
		goto out;
	}
	const bst_json *cs = bst_json_get(v, "challenges");
	const char *want = chall_name(j->a->challenge);
	bool found = false;
	for (size_t i = 0; cs != NULL && i < bst_json_arr_len(cs); i++) {
		const bst_json *ch = bst_json_arr_at(cs, i);
		char type[32];
		if (jstr(ch, "type", type, sizeof type) && strcmp(type, want) == 0 &&
		    jstr(ch, "url", chall_url, sizeof chall_url) && jstr(ch, "token", token, sizeof token)) {
			found = true;
			break;
		}
	}
	if (!found) {
		why(j, "the CA offers no %s challenge for %s", want, name);
		goto out;
	}
	bst_str tok = { token, (uint32_t)strlen(token) };
	if (!bst_acme_token_valid(tok)) {
		why(j, "the CA sent a token that is not base64url");
		goto out;
	}
	char keyauth[BST_ACME_KEYAUTH_MAX];
	int kl = snprintf(keyauth, sizeof keyauth, "%s.%s", token, j->thumb);
	if (kl <= 0 || (size_t)kl >= sizeof keyauth) {
		why(j, "key authorization too long");
		goto out;
	}
	snprintf(p->token, sizeof p->token, "%s", token);
	snprintf(p->name, sizeof p->name, "%s", name);
	if (j->a->challenge == BST_ACME_HTTP01) {
		if (bst_acme_http01_put(tok, (bst_str){ keyauth, (uint32_t)kl }) != 0) {
			why(j, "the challenge table is full");
			goto out;
		}
	} else {
		unsigned char d[32];
		bst_acme_alpn_digest((bst_str){ keyauth, (uint32_t)kl }, d);
		if (j->a->challenge == BST_ACME_ALPN01) {
			char *cp = NULL, *kp = NULL;
			size_t cl = 0, klen = 0;
			int ok = bst_acme_alpn_cert(name, d, &cp, &cl, &kp, &klen) == 0 &&
				 bst_acme_alpn_put(name, cp, cl, kp, klen) == 0;
			if (kp != NULL)
				OPENSSL_cleanse(kp, klen);
			free(kp);
			free(cp);
			if (!ok) {
				why(j, "making the tls-alpn-01 certificate for %s failed", name);
				goto out;
			}
		} else {
			char *val = bst_acme_b64url(d, 32);
			if (val == NULL) {
				why(j, "out of memory");
				goto out;
			}
			snprintf(p->value, sizeof p->value, "%s", val);
			free(val);
			const char *base = name[0] == '*' && name[1] == '.' ? name + 2 : name;
			p->set = true; /* clear even when set failed half-way */
			int hr = bst_acme_dns_run("set", base, p->value);
			snprintf(p->name, sizeof p->name, "%s", base);
			if (hr != 0) {
				why(j, "dns_hook set %s failed (status %d)", base, hr);
				goto out;
			}
		}
	}
	p->set = true;
	bst_hc_resp_free(&r);
	if (post(j, chall_url, "{}", false, &r) != 0)
		return -1;
	if (r.status != 200) {
		problem(j, &r, "answering the challenge");
		goto out;
	}
	*answered = true;
	rc = 0;
out:
	bst_hc_resp_free(&r);
	return rc;
}

/* Polls an authorization until it is valid. */
static int await_authz(job *j, const char *url, uint64_t deadline_ms)
{
	for (unsigned round = 0;; round++) {
		bst_hc_resp r;
		if (post(j, url, NULL, false, &r) != 0)
			return -1;
		if (r.status != 200) {
			problem(j, &r, "polling an authorization");
			bst_hc_resp_free(&r);
			return -1;
		}
		const bst_json *v = parse_json(j, &r);
		char status[32];
		if (v == NULL || !jstr(v, "status", status, sizeof status)) {
			bst_hc_resp_free(&r);
			if (v != NULL)
				why(j, "an authorization without status");
			return -1;
		}
		if (strcmp(status, "valid") == 0) {
			bst_hc_resp_free(&r);
			return 0;
		}
		if (strcmp(status, "pending") != 0) {
			/* the reason sits in the failed challenge's error */
			char detail[256] = "";
			const bst_json *cs = bst_json_get(v, "challenges");
			for (size_t i = 0; cs != NULL && i < bst_json_arr_len(cs) && !detail[0]; i++)
				(void)jstr(bst_json_get(bst_json_arr_at(cs, i), "error"), "detail", detail,
					   sizeof detail);
			why(j, "validation failed (%s)%s%s", status, detail[0] ? ": " : "", detail);
			bst_hc_resp_free(&r);
			return -1;
		}
		if (mono_ms() >= deadline_ms) {
			bst_hc_resp_free(&r);
			why(j, "validation still pending at the deadline");
			return -1;
		}
		poll_wait(j, &r, round);
		bst_hc_resp_free(&r);
	}
}

/* The order's state after finalize: polls until valid, and fills cert_url. */
static int await_order(job *j, const char *order_url, char *cert_url, size_t cap, uint64_t deadline_ms)
{
	for (unsigned round = 0;; round++) {
		bst_hc_resp r;
		if (post(j, order_url, NULL, false, &r) != 0)
			return -1;
		const bst_json *v = r.status == 200 ? parse_json(j, &r) : NULL;
		char status[32];
		if (r.status != 200)
			problem(j, &r, "polling the order");
		if (v == NULL || !jstr(v, "status", status, sizeof status)) {
			bst_hc_resp_free(&r);
			return -1;
		}
		if (strcmp(status, "valid") == 0) {
			bool ok = jstr(v, "certificate", cert_url, cap);
			bst_hc_resp_free(&r);
			if (!ok)
				why(j, "a valid order without a certificate URL");
			return ok ? 0 : -1;
		}
		if (strcmp(status, "processing") != 0 && strcmp(status, "ready") != 0) {
			why(j, "the order is %s", status);
			bst_hc_resp_free(&r);
			return -1;
		}
		if (mono_ms() >= deadline_ms) {
			why(j, "the order is still %s at the deadline", status);
			bst_hc_resp_free(&r);
			return -1;
		}
		poll_wait(j, &r, round);
		bst_hc_resp_free(&r);
	}
}

/* The stored certificate's first certificate, or NULL. */
static X509 *stored_cert(job *j, const char *dir)
{
	char path[600];
	size_t len = 0;
	snprintf(path, sizeof path, "%s/cert.pem", dir);
	char *pem = read_file(j->dir, path, &len);
	if (pem == NULL)
		return NULL;
	BIO *b = BIO_new_mem_buf(pem, (int)len);
	X509 *x = b != NULL ? PEM_read_bio_X509(b, NULL, NULL, NULL) : NULL;
	BIO_free(b);
	free(pem);
	return x;
}

static int64_t not_after(const X509 *x)
{
	struct tm tm;
	if (ASN1_TIME_to_tm(X509_get0_notAfter(x), &tm) != 1)
		return 0;
	return (int64_t)timegm(&tm);
}

/* ARI (RFC 9773): the start of the suggested renewal window, or 0 when unknown. */
static int64_t ari_start(job *j, X509 *x)
{
	if (!j->a->ari || j->renewal_info[0] == '\0')
		return 0;
	const ASN1_OCTET_STRING *aki = X509_get0_authority_key_id(x);
	const ASN1_INTEGER *serial = X509_get0_serialNumber(x);
	if (aki == NULL || serial == NULL)
		return 0;
	unsigned char sb[64];
	int sl = ASN1_STRING_length(serial);
	const unsigned char *sp = ASN1_STRING_get0_data(serial);
	if (sl <= 0 || sl > 60)
		return 0;
	size_t o = 0;
	if (sp[0] & 0x80)
		sb[o++] = 0; /* the DER encoding's leading zero */
	memcpy(sb + o, sp, (size_t)sl);
	char *a64 = bst_acme_b64url(ASN1_STRING_get0_data(aki), (size_t)ASN1_STRING_length(aki));
	char *s64 = bst_acme_b64url(sb, o + (size_t)sl);
	char url[2048];
	int64_t start = 0;
	if (a64 != NULL && s64 != NULL &&
	    (size_t)snprintf(url, sizeof url, "%s/%s.%s", j->renewal_info, a64, s64) < sizeof url) {
		bst_hc_resp r;
		if (get(j, "GET", url, &r) == 0) {
			const bst_json *v = r.status == 200 ? parse_json(j, &r) : NULL;
			char st[64];
			if (v != NULL && jstr(bst_json_get(v, "suggestedWindow"), "start", st, sizeof st) &&
			    !bst_acme_rfc3339(st, strlen(st), &start))
				start = 0;
			bst_hc_resp_free(&r);
		}
	}
	free(a64);
	free(s64);
	return start;
}

static int issue(job *j, const bst_cfg_server *s, const char *dir)
{
	/* the order */
	size_t cap = 64 + s->nnames * (BST_ACME_NAME_MAX + 32);
	char *ids = malloc(cap);
	if (ids == NULL) {
		why(j, "out of memory");
		return -1;
	}
	size_t o = (size_t)snprintf(ids, cap, "{\"identifiers\":[");
	for (size_t i = 0; i < s->nnames; i++)
		o += (size_t)snprintf(ids + o, cap - o, "%s{\"type\":\"dns\",\"value\":\"%s\"}", i ? "," : "",
				      s->names[i]);
	snprintf(ids + o, cap - o, "]}");
	bst_hc_resp r;
	int rc = post(j, j->new_order, ids, false, &r);
	free(ids);
	if (rc != 0)
		return -1;
	char order_url[1024], finalize[1024];
	char **authz = NULL;
	size_t nauthz = 0;
	pending *pend = NULL;
	char *csr = NULL, *payload = NULL;
	void *key = NULL;
	rc = -1;
	if (r.status != 201 || r.location[0] == '\0' || strlen(r.location) >= sizeof order_url) {
		problem(j, &r, "creating the order");
		goto out;
	}
	snprintf(order_url, sizeof order_url, "%s", r.location);
	const bst_json *v = parse_json(j, &r);
	if (v == NULL)
		goto out;
	const bst_json *az = bst_json_get(v, "authorizations");
	nauthz = az != NULL ? bst_json_arr_len(az) : 0;
	if (nauthz == 0 || nauthz > 100 || !jstr(v, "finalize", finalize, sizeof finalize)) {
		why(j, "an order without authorizations or finalize URL");
		goto out;
	}
	authz = calloc(nauthz, sizeof *authz);
	pend = calloc(nauthz, sizeof *pend);
	if (authz == NULL || pend == NULL) {
		why(j, "out of memory");
		goto out;
	}
	for (size_t i = 0; i < nauthz; i++) {
		char u[1024];
		bst_str sv;
		const bst_json *e = bst_json_arr_at(az, i);
		if (e == NULL || !bst_json_str(e, &sv) || sv.len >= sizeof u || memchr(sv.p, '\0', sv.len)) {
			why(j, "a malformed authorization URL");
			goto out;
		}
		memcpy(u, sv.p, sv.len);
		u[sv.len] = '\0';
		authz[i] = strdup(u);
		if (authz[i] == NULL) {
			why(j, "out of memory");
			goto out;
		}
	}
	bst_hc_resp_free(&r);
	bst_log(BST_LOG_INFO, "acme: %s: ordering a certificate for %zu name%s (%s)", s->names[0], s->nnames,
		s->nnames == 1 ? "" : "s", chall_name(j->a->challenge));
	uint64_t deadline = mono_ms() + test_env("BST_TEST_ACME_VALIDATION_MS", 180000);
	bool *answered = calloc(nauthz, sizeof *answered);
	if (answered == NULL) {
		why(j, "out of memory");
		goto out;
	}
	int arc = 0;
	for (size_t i = 0; i < nauthz && arc == 0; i++)
		arc = authorize(j, authz[i], &pend[i], &answered[i]);
	for (size_t i = 0; i < nauthz && arc == 0; i++)
		if (answered[i])
			arc = await_authz(j, authz[i], deadline);
	free(answered);
	cleanup(j, pend, nauthz);
	if (arc != 0)
		goto out;
	/* finalize with a new key */
	key = bst_acme_keygen(j->a->key_type);
	csr = key != NULL ? bst_acme_csr(key, s->names, s->nnames) : NULL;
	if (csr == NULL || asprintf(&payload, "{\"csr\":\"%s\"}", csr) < 0) {
		payload = NULL;
		why(j, "making the CSR failed");
		goto out;
	}
	if (post(j, finalize, payload, false, &r) != 0)
		goto out;
	if (r.status != 200) {
		problem(j, &r, "finalizing the order");
		goto out;
	}
	bst_hc_resp_free(&r);
	char cert_url[1024];
	if (await_order(j, order_url, cert_url, sizeof cert_url, deadline) != 0)
		goto out;
	if (post(j, cert_url, NULL, false, &r) != 0)
		goto out;
	if (r.status != 200 || r.len == 0) {
		problem(j, &r, "downloading the certificate");
		goto out;
	}
	/* the chain must hold a certificate for this key */
	BIO *b = BIO_new_mem_buf(r.body, (int)r.len);
	X509 *x = b != NULL ? PEM_read_bio_X509(b, NULL, NULL, NULL) : NULL;
	BIO_free(b);
	bool match = x != NULL && X509_check_private_key(x, key) == 1;
	X509_free(x);
	if (!match) {
		why(j, "the CA's certificate does not match the key");
		goto out;
	}
	size_t kl = 0;
	char *kp = bst_acme_key_pem(key, &kl);
	char mpath[600];
	snprintf(mpath, sizeof mpath, "%s/temp", dir);
	int w = kp != NULL ? install_pair(j->dir, dir, kp, kl, r.body, r.len) : -1;
	if (kp != NULL) {
		OPENSSL_cleanse(kp, kl);
		free(kp);
	}
	if (w != 0) {
		why(j, "storing the certificate: %s", strerror(errno));
		goto out;
	}
	(void)unlinkat(j->dir, mpath, 0);
	rc = 0;
out:
	bst_hc_resp_free(&r);
	if (pend != NULL)
		cleanup(j, pend, nauthz);
	for (size_t i = 0; authz != NULL && i < nauthz; i++)
		free(authz[i]);
	free(authz);
	free(pend);
	free(csr);
	free(payload);
	bst_acme_key_free(key);
	return rc;
}

/* Per-server failure state: "<fails> <unix time of the next try>". */
static void state_get(job *j, const char *name, unsigned *fails, int64_t *next)
{
	char path[600];
	size_t len;
	snprintf(path, sizeof path, "state/%s", name);
	*fails = 0;
	*next = 0;
	char *t = read_file(j->dir, path, &len);
	if (t == NULL)
		return;
	unsigned long long f = 0;
	long long n = 0;
	if (sscanf(t, "%llu %lld", &f, &n) == 2 && f < 64) {
		*fails = (unsigned)f;
		*next = n;
	}
	free(t);
}

static void state_put(job *j, const char *name, unsigned fails, int64_t next)
{
	char path[600], buf[64];
	snprintf(path, sizeof path, "state/%s", name);
	if (fails == 0) {
		(void)unlinkat(j->dir, path, 0);
		return;
	}
	int n = snprintf(buf, sizeof buf, "%u %lld\n", fails, (long long)next);
	if (write_file(j->dir, path, buf, (size_t)n) != 0)
		bst_log(BST_LOG_WARN, "acme: storing the retry state: %s", strerror(errno));
}

static bool ready_for_ca(job *j, bool *tried)
{
	if (*tried)
		return j->key != NULL && j->kid[0] != '\0';
	*tried = true;
	return directory(j) == 0 && account(j) == 0;
}

/* One server: renews when due; *next: the earliest time this server needs the job again. */
static void server(job *j, const bst_cfg_server *s, bool *ca_tried, int64_t *next, bool *installed)
{
	int64_t now = unix_now();
	char name[256], dir[300];
	snprintf(name, sizeof name, "%s", s->names[0]);
	if (name[0] == '*')
		name[0] = '_';
	snprintf(dir, sizeof dir, "certs/%s", name);
	unsigned fails;
	int64_t retry_at;
	state_get(j, name, &fails, &retry_at);
	if (retry_at > now) {
		bst_log(BST_LOG_INFO, "acme: %s: backing off after %u failure%s: retry in %llds", s->names[0],
			fails, fails == 1 ? "" : "s", (long long)(retry_at - now));
		if (retry_at < *next)
			*next = retry_at;
		return;
	}
	int rec = bst_acme_recover_pair(j->dir, dir);
	if (rec < 0)
		bst_log(BST_LOG_WARN, "acme: %s: finishing an interrupted install: %s", s->names[0], strerror(errno));
	else if (rec == 1)
		bst_log(BST_LOG_INFO, "acme: %s: finished an interrupted install", s->names[0]);
	char marker[320];
	size_t ml;
	snprintf(marker, sizeof marker, "%s/temp", dir);
	char *m = read_file(j->dir, marker, &ml);
	bool temp = m != NULL;
	free(m);
	X509 *x = stored_cert(j, dir);
	const char *reason = NULL;
	char because[96];
	int64_t renew_at = 0;
	if (x == NULL || temp) {
		reason = x == NULL ? "no certificate" : "only a temporary certificate";
	} else {
		int64_t na = not_after(x);
		renew_at = na - (int64_t)j->a->renew_before_s;
		if (renew_at <= now) {
			snprintf(because, sizeof because, "expires in %lldh", (long long)(na - now) / 3600);
			reason = because;
		} else if (ready_for_ca(j, ca_tried)) {
			int64_t ari = ari_start(j, x);
			if (ari > 0 && ari <= now)
				reason = "the CA's renewal window has started";
			else if (ari > 0 && ari < renew_at)
				renew_at = ari;
		}
	}
	X509_free(x);
	if (reason == NULL) {
		bst_log(BST_LOG_INFO, "acme: %s: certificate valid, renewal in %llds", s->names[0],
			(long long)(renew_at - now));
		if (renew_at < *next)
			*next = renew_at;
		return;
	}
	bst_log(BST_LOG_INFO, "acme: %s: %s: requesting one", s->names[0], reason);
	j->retry_after_s = 0;
	if (ready_for_ca(j, ca_tried) && issue(j, s, dir) == 0) {
		state_put(j, name, 0, 0);
		bst_log(BST_LOG_INFO, "acme: %s: certificate installed", s->names[0]);
		*installed = true;
		return;
	}
	fails++;
	uint64_t d = bst_acme_backoff_s(fails, j->retry_after_s,
					test_env("BST_TEST_ACME_BACKOFF_S", BACKOFF_BASE_S));
	state_put(j, name, fails, now + (int64_t)d);
	bst_log(BST_LOG_ERROR, "acme: %s: %s: the current certificate stays; retry in %llus (failure %u)",
		s->names[0], j->why[0] ? j->why : "failed", (unsigned long long)d, fails);
	if (now + (int64_t)d < *next)
		*next = now + (int64_t)d;
}

/* ---- the process ---- */

static uid_t chown_uid;
static gid_t chown_gid;

/* The storage tree is writable by the user root hands it to, so it is walked by descriptor:
 * every directory is opened relative to its parent with O_NOFOLLOW, and every change is made
 * through the opened descriptor. A symlink anywhere (swapped in mid-walk or not) is never
 * followed; a file is changed only when it is a regular file with one link (a hard link to a
 * file outside the tree is refused); devices, FIFOs and sockets are left alone. */
static bool needs_chown(const struct stat *st, uid_t uid, gid_t gid)
{
	return (uid != (uid_t)-1 && st->st_uid != uid) || (gid != (gid_t)-1 && st->st_gid != gid);
}

static int chown_dir(int dfd, uid_t uid, gid_t gid, unsigned depth)
{
	struct stat st;
	int bad = 0;
	if (fstat(dfd, &st) != 0 || !S_ISDIR(st.st_mode))
		return -1;
	if (needs_chown(&st, uid, gid) && fchown(dfd, uid, gid) != 0)
		bad = -1;
	if (depth >= 16)
		return bad;
	int lfd = dup(dfd);
	DIR *d = lfd >= 0 ? fdopendir(lfd) : NULL;
	if (d == NULL) {
		if (lfd >= 0)
			close(lfd);
		return -1;
	}
	struct dirent *de;
	while ((de = readdir(d)) != NULL) {
		if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
			continue;
		if (fstatat(dfd, de->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0)
			continue;
		if (S_ISDIR(st.st_mode)) {
			int cfd = openat(dfd, de->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
			if (cfd < 0)
				continue; /* swapped for something else meanwhile */
			if (chown_dir(cfd, uid, gid, depth + 1) != 0)
				bad = -1;
			close(cfd);
		} else if (S_ISREG(st.st_mode) && needs_chown(&st, uid, gid)) {
			int ffd = openat(dfd, de->d_name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_NOCTTY | O_CLOEXEC);
			if (ffd < 0)
				continue;
			if (fstat(ffd, &st) == 0 && S_ISREG(st.st_mode) && st.st_nlink == 1) {
				if (fchown(ffd, uid, gid) != 0)
					bad = -1;
			} else {
				bst_log(BST_LOG_WARN, "acme: storage: %s is not a plain file: ownership left alone",
					de->d_name);
			}
			close(ffd);
		}
	}
	closedir(d);
	return bad;
}

int bst_acme_chown_tree(int dfd, uid_t uid, gid_t gid)
{
	return chown_dir(dfd, uid, gid, 0);
}

static bool is_public_host(const char *url)
{
	return strstr(url, "letsencrypt.org") != NULL || strstr(url, "zerossl.com") != NULL;
}

/* Forked from master, the job holds everything master had open: the PID file, every child's
 * channel, the listeners, the status region, the kept regions' memfds, the signalfd. None of
 * it is its business. inherited_fds records what is open above 2 at the fork; once the job
 * has its own log description and crash pipe (made while the inherited ones are still open,
 * so they cannot reuse a number), close_inherited closes every recorded one but keep. */
typedef struct fd_id {
	bool open;
	dev_t dev;
	ino_t ino;
} fd_id;

typedef struct fdset {
	fd_id *open; /* open[fd]: inherited, and what it was */
	int top;     /* entries in open */
} fdset;

static int highest_fd(void)
{
	int top = -1;
	DIR *d = opendir("/proc/self/fd");
	if (d != NULL) {
		int self = dirfd(d);
		struct dirent *de;
		while ((de = readdir(d)) != NULL) {
			char *end;
			long v = strtol(de->d_name, &end, 10);
			if (*end == '\0' && end != de->d_name && v != self && v > top && v < INT32_MAX)
				top = (int)v;
		}
		closedir(d);
		return top;
	}
	long max = sysconf(_SC_OPEN_MAX); /* no /proc: every possible number */
	return max > 0 && max < 1048576 ? (int)max - 1 : 1048575;
}

static void inherited_fds(fdset *s)
{
	s->top = highest_fd() + 1;
	s->open = s->top > 3 ? calloc((size_t)s->top, sizeof *s->open) : NULL;
	struct stat st;
	for (int fd = 3; s->open != NULL && fd < s->top; fd++)
		if (fstat(fd, &st) == 0)
			s->open[fd] = (fd_id){ .open = true, .dev = st.st_dev, .ino = st.st_ino };
}

/* A number the log or the crash handler closed and reused meanwhile names another file now:
 * it is the job's own, and stays. */
static void close_inherited(fdset *s, int keep)
{
	struct stat st;
	for (int fd = 3; s->open != NULL && fd < s->top; fd++)
		if (s->open[fd].open && fd != keep && fstat(fd, &st) == 0 &&
		    st.st_dev == s->open[fd].dev && st.st_ino == s->open[fd].ino)
			(void)close(fd);
	if (s->open == NULL && s->top > 3)
		bst_log(BST_LOG_WARN, "acme: out of memory: descriptors inherited from master stay open");
	free(s->open);
	s->open = NULL;
}

int bst_acme_job(bst_runtime *rt)
{
	int report = M.pipe;
	fdset inh;
	inherited_fds(&inh);
	sigset_t none;
	sigemptyset(&none);
	sigprocmask(SIG_SETMASK, &none, NULL);
	bst_signals_child();
	bst_io_ignore_sigpipe(); /* a CA closing mid-write is an error, not a death */
	prctl(PR_SET_PDEATHSIG, SIGKILL);
	prctl(PR_SET_NAME, "bst:acme");
	bst_log_set_tag("acme");
	if (setsid() < 0)
		bst_log(BST_LOG_WARN, "acme: setsid: %s", strerror(errno));
	bst_logsink_attach(rt->log_base_fd, rt->log_level);
	bst_crash_install();
	close_inherited(&inh, report); /* the log and the crash pipe are the job's own by now */
	rt->log_base_fd = rt->log_inherited = -1;
	bst_sandbox_sanitizer_prepare("acme");
	const bst_config *cfg = rt->cfg;
	static job j;
	memset(&j, 0, sizeof j);
	j.a = cfg->global.acme;
	j.dir = -1;
#ifdef BST_TEST
	/* Tests and CI never reach a public CA, whatever a config says. */
	if ((j.a->public_ca || is_public_host(j.a->ca)) && getenv("BST_TEST_ACME_ALLOW_PUBLIC") == NULL) {
		bst_log(BST_LOG_ERROR, "acme: a test build does not contact the public CA %s", j.a->ca);
		return 1;
	}
#else
	(void)is_public_host;
#endif
	/* Before the sandbox: ownership, the storage descriptor, the CA's address and trust store,
	 * the account directory, the DNS hook runner. */
	j.dir = open(j.a->storage, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (j.dir < 0) {
		bst_log(BST_LOG_ERROR, "acme: storage %s: %s", j.a->storage, strerror(errno));
		return 1;
	}
	if (rt->drop_uid || rt->drop_gid) {
		chown_uid = rt->drop_uid ? rt->uid : (uid_t)-1;
		chown_gid = rt->drop_gid ? rt->gid : (gid_t)-1;
		if (bst_acme_chown_tree(j.dir, chown_uid, chown_gid) != 0)
			bst_log(BST_LOG_WARN, "acme: storage %s: some ownership could not be set", j.a->storage);
	}
	char err[256] = "";
	/* No address or no trust store: every server backs off as for any other CA failure. */
	bool ca_ok = bst_hc_open(&j.hc, j.a->ca, j.a->ca_root, (int)test_env("BST_TEST_ACME_TIMEOUT_MS", 30000),
				 err, sizeof err) == 0;
	{
		unsigned char d[32];
		unsigned int dl = 0;
		(void)EVP_Digest(j.a->ca, strlen(j.a->ca), d, &dl, EVP_sha256(), NULL);
		char hex[17];
		for (int i = 0; i < 8; i++)
			snprintf(hex + 2 * i, 3, "%02x", d[i]);
		snprintf(j.acct_dir, sizeof j.acct_dir, "accounts/%s", hex);
		if (mkdirat(j.dir, j.acct_dir, 0700) != 0 && errno != EEXIST) {
			bst_log(BST_LOG_ERROR, "acme: storage %s/%s: %s", j.a->storage, j.acct_dir, strerror(errno));
			return 1;
		}
		if ((rt->drop_uid || rt->drop_gid) &&
		    fchownat(j.dir, j.acct_dir, chown_uid, chown_gid, AT_SYMLINK_NOFOLLOW) != 0)
			bst_log(BST_LOG_WARN, "acme: chown: %s", strerror(errno));
	}
	if (j.a->challenge == BST_ACME_DNS01 && bst_acme_dns_start(j.a->dns_hook, cfg) != 0) {
		bst_log(BST_LOG_ERROR, "acme: starting the dns_hook runner: %s", strerror(errno));
		return 1;
	}
	j.arena = bst_arena_new(65536);
	if (j.arena == NULL)
		return 1;
	bst_child_drop(rt);
	const char *wr[1] = { j.a->storage };
	bst_sandbox_paths paths = { .write = wr, .nwrite = 1 };
	bst_err e = { .msg = "" };
	if (bst_sandbox_apply(&cfg->global.sandbox, BST_SANDBOX_ACME, &paths, &e) != 0) {
		bst_log(BST_LOG_ERROR, "acme: sandbox: %s", e.msg);
		return 1;
	}
	/* The work. */
	bool ca_tried = !ca_ok, installed = false;
	if (!ca_ok)
		snprintf(j.why, sizeof j.why, "%s", err);
	int64_t next = unix_now() + CHECK_S;
	for (size_t i = 0; i < cfg->global.nservers; i++)
		if (cfg->global.servers[i]->tls_auto)
			server(&j, cfg->global.servers[i], &ca_tried, &next, &installed);
	bst_acme_dns_stop();
	int64_t wait = next - unix_now();
	char out[32];
	int n = snprintf(out, sizeof out, "%lld\n", (long long)(wait < 1 ? 1 : wait));
	if (report >= 0 && write(report, out, (size_t)n) != n)
		bst_log(BST_LOG_WARN, "acme: reporting to master: %s", strerror(errno));
	bst_acme_key_free(j.key);
	free(j.thumb);
	return installed ? BST_ACME_EXIT_INSTALLED : BST_ACME_EXIT_OK;
}
