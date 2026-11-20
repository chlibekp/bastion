/* The `acme {}` block and `tls auto` (ops/acme.h), and the post hook that turns `tls auto` into
 * listeners and a certificate entry: the stored certificate, else a temporary self-signed one
 * made here, so the TLS context (post_tls_resolve, which runs after this hook) always has a
 * certificate to load. */
#include "config/compile.h"
#include "config/values.h"
#include "core/log.h"
#include "core/str.h"
#include "ops/acme.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define AC BST_CTX_ACME

static bst_str as_str(const bst_ast_arg *a)
{
	return (bst_str){ a->text, (uint32_t)a->len };
}

static bst_cfg_acme *A(bst_cfg_ctx *c)
{
	return c->global->acme;
}

static int ap_acme(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)d;
	bst_cfg_acme *a = bst_arena_alloc(c->arena, sizeof *a);
	if (a == NULL) {
		bst_err_set(e, "out of memory");
		return -1;
	}
	memset(a, 0, sizeof *a);
	a->ca = BST_ACME_LE_URL;
	a->public_ca = true;
	a->storage = BST_ACME_DEFAULT_STORAGE;
	a->renew_before_s = 30 * 86400;
	a->ari = true;
	c->global->acme = a;
	return bst_cfg_loc_at(c, &n->loc, &a->loc, e);
}

static int dup_arg(bst_cfg_ctx *c, const bst_ast_arg *a, const char **out, bst_err *e)
{
	*out = bst_cfg_strdup(c, a->text, a->len, e);
	return *out == NULL ? -1 : 0;
}

static int ap_email(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	const char *at = memchr(a->text, '@', a->len);
	bool ok = at != NULL && at != a->text && at + 1 < a->text + a->len && a->len < 254;
	for (size_t i = 0; ok && i < a->len; i++) /* it goes into a JSON string and a mailto: URL */
		ok = (unsigned char)a->text[i] > ' ' && (unsigned char)a->text[i] < 0x7f &&
		     a->text[i] != '"' && a->text[i] != '\\';
	if (!ok) {
		bst_err_set(e, "acme email: expected an address such as admin@example.com");
		bst_cfg_err_at(e, &a->loc);
		return -1;
	}
	return dup_arg(c, a, &A(c)->email, e);
}

static int ap_ca(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	bst_str v = as_str(a);
	bst_cfg_acme *x = A(c);
	if (bst_str_eq(v, BST_S("letsencrypt"))) {
		x->ca = BST_ACME_LE_URL;
		x->public_ca = true;
		x->zerossl = false;
		return 0;
	}
	if (bst_str_eq(v, BST_S("zerossl"))) {
		x->ca = BST_ACME_ZEROSSL_URL;
		x->public_ca = x->zerossl = true;
		return 0;
	}
	x->zerossl = false;
	if (a->len < 9 || strncmp(a->text, "https://", 8) != 0) {
		bst_err_set(e, "acme ca: letsencrypt, zerossl or an https:// directory URL");
		bst_cfg_err_at(e, &a->loc);
		return -1;
	}
	for (size_t i = 0; i < a->len; i++)
		if ((unsigned char)a->text[i] <= ' ' || a->text[i] == '"' || a->text[i] == '\\' ||
		    (unsigned char)a->text[i] >= 0x7f) {
			bst_err_set(e, "acme ca: the URL has a character a URL cannot have");
			bst_cfg_err_at(e, &a->loc);
			return -1;
		}
	x->public_ca = false;
	return dup_arg(c, a, &x->ca, e);
}

static int ap_staging(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	(void)bst_parse_bool(as_str(bst_dir_pos(d, n, 0)), &A(c)->staging);
	return 0;
}

static int ap_storage(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	if (a->text[0] != '/') {
		bst_err_set(e, "acme storage: an absolute path");
		bst_cfg_err_at(e, &a->loc);
		return -1;
	}
	return dup_arg(c, a, &A(c)->storage, e);
}

static const char *const challenges[] = { "http-01", "tls-alpn-01", "dns-01", NULL };
static const char *const key_types[] = { "ecdsa-p256", "rsa-2048", NULL };

static int ap_challenge(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	size_t i = 0;
	(void)bst_parse_enum(as_str(bst_dir_pos(d, n, 0)), challenges, &i);
	A(c)->challenge = (bst_acme_challenge)i;
	return 0;
}

static int ap_dns_hook(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	if (a->text[0] != '/') {
		bst_err_set(e, "acme dns_hook: the absolute path of a program (run with execve, no shell)");
		bst_cfg_err_at(e, &a->loc);
		return -1;
	}
	return dup_arg(c, a, &A(c)->dns_hook, e);
}

static int ap_key_type(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	size_t i = 0;
	(void)bst_parse_enum(as_str(bst_dir_pos(d, n, 0)), key_types, &i);
	A(c)->key_type = (bst_acme_key_type)i;
	return 0;
}

static int ap_renew_before(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	uint64_t us = 0;
	(void)bst_parse_duration_us(as_str(a), &us);
	if (us < 3600ull * 1000000ull) {
		bst_err_set(e, "acme renew_before: at least 1h");
		bst_cfg_err_at(e, &a->loc);
		return -1;
	}
	A(c)->renew_before_s = us / 1000000u;
	return 0;
}

static int ap_ari(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	(void)bst_parse_bool(as_str(bst_dir_pos(d, n, 0)), &A(c)->ari);
	return 0;
}

static int ap_eab_kid(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	return dup_arg(c, bst_dir_pos(d, n, 0), &A(c)->eab_kid, e);
}

static int ap_eab_hmac(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	return dup_arg(c, bst_dir_pos(d, n, 0), &A(c)->eab_hmac, e);
}

static int ap_ca_root(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	return dup_arg(c, bst_dir_pos(d, n, 0), &A(c)->ca_root, e);
}

static int ap_tls_auto(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)d;
	c->server->tls_auto = true;
	return bst_cfg_loc_at(c, &n->loc, &c->server->tls_auto_loc, e);
}

/* ---- the post hook ---- */

static int fail_at(bst_cfg_ctx *c, const bst_cfg_loc *loc, bst_err *e, const char *msg)
{
	bst_err_set(e, "%s", msg);
	bst_cfg_err_at(e, bst_cfg_src(c, loc));
	return -1;
}

static int mkdir_private(const char *path, bst_err *e)
{
	if (mkdir(path, 0700) != 0 && errno != EEXIST) {
		bst_err_set(e, "acme storage: creating %s: %s", path, strerror(errno));
		return -1;
	}
	struct stat st;
	if (lstat(path, &st) != 0 || !S_ISDIR(st.st_mode)) {
		bst_err_set(e, "acme storage: %s is not a directory", path);
		return -1;
	}
	if ((st.st_mode & 077) != 0 && chmod(path, 0700) != 0) {
		bst_err_set(e, "acme storage: %s: chmod 0700: %s", path, strerror(errno));
		return -1;
	}
	return 0;
}

/* Writes path through path.tmp and a rename, 0600. */
static int write_private(const char *path, const char *data, size_t len, bst_err *e)
{
	char tmp[4200];
	snprintf(tmp, sizeof tmp, "%s.tmp", path);
	(void)unlink(tmp);
	int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
	if (fd < 0) {
		bst_err_set(e, "acme storage: creating %s: %s", tmp, strerror(errno));
		return -1;
	}
	size_t off = 0;
	while (off < len) {
		ssize_t w = write(fd, data + off, len - off);
		if (w <= 0) {
			bst_err_set(e, "acme storage: writing %s: %s", tmp, strerror(errno));
			close(fd);
			unlink(tmp);
			return -1;
		}
		off += (size_t)w;
	}
	if (fsync(fd) != 0 || close(fd) != 0 || rename(tmp, path) != 0) {
		bst_err_set(e, "acme storage: writing %s: %s", path, strerror(errno));
		unlink(tmp);
		return -1;
	}
	return 0;
}

/* A temporary self-signed certificate, so the port serves before the first issuance. */
static int temp_cert(const bst_cfg_acme *a, const bst_cfg_server *s, const char *crt, const char *key,
		     bst_err *e)
{
	void *k = bst_acme_keygen(a->key_type);
	if (k == NULL) {
		bst_err_set(e, "acme: generating a key failed");
		return -1;
	}
	size_t kl = 0, cl = 0;
	char *kp = bst_acme_key_pem(k, &kl);
	char *cp = bst_acme_selfsigned(k, s->names, s->nnames, 90, &cl);
	bst_acme_key_free(k);
	int rc = -1;
	char marker[4200];
	snprintf(marker, sizeof marker, "%.*s/temp", (int)(strrchr(crt, '/') - crt), crt);
	if (kp == NULL || cp == NULL) {
		bst_err_set(e, "acme: making a temporary certificate failed");
	} else if (write_private(marker, "temporary self-signed certificate\n", 34, e) == 0 &&
		   write_private(key, kp, kl, e) == 0 && write_private(crt, cp, cl, e) == 0) {
		rc = 0;
	}
	if (kp != NULL) {
		memset(kp, 0, kl);
		free(kp);
	}
	free(cp);
	return rc;
}

static bool name_ok(const char *n, bool dns01)
{
	if (n[0] == '*') {
		if (!dns01 || n[1] != '.')
			return false;
		n += 2;
	}
	size_t l = strlen(n);
	if (l == 0 || l > 253 || strchr(n, '.') == NULL)
		return false;
	for (size_t i = 0; i < l; i++)
		if (!((n[i] >= 'a' && n[i] <= 'z') || (n[i] >= '0' && n[i] <= '9') || n[i] == '-' || n[i] == '.'))
			return false;
	return true;
}

int bst_acme_cert_paths(const bst_cfg_acme *a, const bst_cfg_server *s, char *crt, char *key, size_t cap)
{
	char dir[256];
	snprintf(dir, sizeof dir, "%s", s->names[0]);
	if (dir[0] == '*')
		dir[0] = '_'; /* a wildcard's directory */
	int n1 = snprintf(crt, cap, "%s/certs/%s/cert.pem", a->storage, dir);
	int n2 = snprintf(key, cap, "%s/certs/%s/key.pem", a->storage, dir);
	return n1 > 0 && (size_t)n1 < cap && n2 > 0 && (size_t)n2 < cap ? 0 : -1;
}

static int add_listen(bst_cfg_ctx *c, bst_cfg_server *s, uint16_t port, bool tls, bst_err *e)
{
	bst_cfg_listen l;
	memset(&l, 0, sizeof l);
	l.addr.ip.family = BST_IP_V4;
	l.addr.port = port;
	l.tls = tls;
	l.http2 = tls;
	l.loc = s->tls_auto_loc;
	return bst_cfg_push_owned(c, &s->listens, &s->nlistens, &s->listens_cap_, sizeof l, &l, e);
}

static int post_acme(bst_config *cfg, bst_cfg_ctx *c, bst_err *e)
{
	bst_cfg_global *g = &cfg->global;
	bst_cfg_acme *a = g->acme;
	if (a != NULL && a->public_ca && !a->zerossl && a->staging)
		a->ca = BST_ACME_LE_STAGING_URL;
	if (a != NULL && a->challenge == BST_ACME_DNS01 && a->dns_hook == NULL)
		return fail_at(c, &a->loc, e, "acme: challenge dns-01 needs a dns_hook");
	if (a != NULL && (a->eab_kid == NULL) != (a->eab_hmac == NULL))
		return fail_at(c, &a->loc, e, "acme: eab_kid and eab_hmac go together");
	if (a != NULL && a->zerossl && a->eab_kid == NULL)
		return fail_at(c, &a->loc, e, "acme: ca zerossl needs eab_kid and eab_hmac");
	bool any = false;
	for (size_t i = 0; i < g->nservers; i++) {
		bst_cfg_server *s = g->servers[i];
		if (!s->tls_auto)
			continue;
		any = true;
		if (a == NULL)
			return fail_at(c, &s->tls_auto_loc, e, "tls auto needs an acme {} block");
		if (s->nnames == 0)
			return fail_at(c, &s->tls_auto_loc, e,
				       "tls auto needs the server's names: add \"name example.com;\"");
		if (s->tls.ncerts > 0 || s->tls.has_default_cert)
			return fail_at(c, &s->tls_auto_loc, e, "tls auto and tls_cert cannot be combined");
		for (size_t j = 0; j < s->nnames; j++)
			if ((s->name_res != NULL && s->name_res[j] != NULL) ||
			    !name_ok(s->names[j], a->challenge == BST_ACME_DNS01))
				return fail_at(c, &s->name_locs[j], e,
					       "tls auto: every name must be a plain host name with a dot "
					       "(a wildcard *.name only with challenge dns-01)");
	}
	if (!any)
		return 0;
	char path[4096];
	if (mkdir_private(a->storage, e) != 0)
		goto at_block;
	snprintf(path, sizeof path, "%s/certs", a->storage);
	if (mkdir_private(path, e) != 0)
		goto at_block;
	snprintf(path, sizeof path, "%s/state", a->storage);
	if (mkdir_private(path, e) != 0)
		goto at_block;
	snprintf(path, sizeof path, "%s/accounts", a->storage);
	if (mkdir_private(path, e) != 0)
		goto at_block;
	for (size_t i = 0; i < g->nservers; i++) {
		bst_cfg_server *s = g->servers[i];
		if (!s->tls_auto)
			continue;
		if (s->nlistens == 0) { /* implied: 443 with TLS and HTTP/2, 80 for challenges and redirects */
			if (add_listen(c, s, 443, true, e) != 0 || add_listen(c, s, 80, false, e) != 0)
				return -1;
			s->acme_redirect = true;
		}
		char crt[4096], key[4096];
		if (bst_acme_cert_paths(a, s, crt, key, sizeof crt) != 0)
			return fail_at(c, &s->tls_auto_loc, e, "tls auto: storage path too long");
		snprintf(path, sizeof path, "%.*s", (int)(strrchr(crt, '/') - crt), crt);
		if (mkdir_private(path, e) != 0)
			goto at_block;
		if ((access(crt, R_OK) != 0 || access(key, R_OK) != 0) && temp_cert(a, s, crt, key, e) != 0)
			goto at_block;
		bst_cfg_tls_cert t = { .loc = s->tls_auto_loc };
		t.crt = bst_cfg_strdup(c, crt, strlen(crt), e);
		t.key = bst_cfg_strdup(c, key, strlen(key), e);
		if (t.crt == NULL || t.key == NULL ||
		    bst_cfg_push_owned(c, &s->tls.certs, &s->tls.ncerts, &s->tls.certs_cap_, sizeof t, &t, e) != 0)
			return -1;
	}
	return 0;
at_block:
	bst_cfg_err_at(e, bst_cfg_src(c, &a->loc));
	return -1;
}
BST_CFG_POST(post_acme);

static const bst_directive acme_dirs[] = {
	{ .name = "acme", .contexts = BST_CTX_GLOBAL, .apply = ap_acme, .child_ctx = AC,
	  .doc = "Automatic certificates over ACME (RFC 8555) for servers with `tls auto`, off "
		 "without this block. The protocol runs in a short-lived sandboxed job master forks "
		 "(never in a worker); a new certificate is installed through a reload. Account and "
		 "certificate keys are made locally and stored 0600 under `storage`.",
	  .args = { .block = BST_BLOCK_REQUIRED } },
	{ .name = "email", .contexts = AC, .apply = ap_email,
	  .doc = "The account's contact address, sent to the CA (expiry notices).",
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_STRING } } } },
	{ .name = "ca", .contexts = AC, .apply = ap_ca, .default_value = "letsencrypt",
	  .doc = "letsencrypt, zerossl (needs eab_kid and eab_hmac) or the https:// URL of an ACME "
		 "directory. Every URL the CA hands out must be on the directory's host.",
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_STRING } } } },
	{ .name = "staging", .contexts = AC, .apply = ap_staging, .default_value = "off",
	  .doc = "on: Let's Encrypt's staging directory instead of production (for `ca letsencrypt`).",
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_BOOL } } } },
	{ .name = "storage", .contexts = AC, .apply = ap_storage, .default_value = BST_ACME_DEFAULT_STORAGE,
	  .doc = "The directory for accounts, certificates and keys: 0700, keys 0600, owned by `user`.",
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_PATH } } } },
	{ .name = "challenge", .contexts = AC, .apply = ap_challenge, .default_value = "http-01",
	  .doc = "http-01 (port 80 must reach this server), tls-alpn-01 (port 443) or dns-01 "
		 "(dns_hook; also the only one for *.wildcard names).",
	  .args = { .min_args = 1, .max_args = 1,
		    .pos = { { .kind = BST_T_ENUM, .enum_values = challenges } } } },
	{ .name = "dns_hook", .contexts = AC, .apply = ap_dns_hook,
	  .doc = "dns-01: the program that publishes the TXT record, run with execve (no shell) as "
		 "`<hook> set|clear <name> <value>` with only PATH and LANG in its environment; exit "
		 "0 once the record is visible.",
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_PATH } } } },
	{ .name = "key_type", .contexts = AC, .apply = ap_key_type, .default_value = "ecdsa-p256",
	  .doc = "The certificate key: ecdsa-p256 or rsa-2048. The account key is always P-256.",
	  .args = { .min_args = 1, .max_args = 1,
		    .pos = { { .kind = BST_T_ENUM, .enum_values = key_types } } } },
	{ .name = "renew_before", .contexts = AC, .apply = ap_renew_before, .default_value = "30d",
	  .doc = "Renew this long before the certificate expires (at least 1h).",
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_DURATION } } } },
	{ .name = "ari", .contexts = AC, .apply = ap_ari, .default_value = "on",
	  .doc = "on: also renew when the CA's renewal information (RFC 9773) suggests a window "
		 "that has started.",
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_BOOL } } } },
	{ .name = "eab_kid", .contexts = AC, .apply = ap_eab_kid,
	  .doc = "External account binding: the key id the CA gave.",
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_STRING } } } },
	{ .name = "eab_hmac", .contexts = AC, .apply = ap_eab_hmac,
	  .doc = "External account binding: the base64url HMAC key the CA gave. Never logged.",
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_STRING } } } },
	{ .name = "ca_root", .contexts = AC, .apply = ap_ca_root,
	  .doc = "A PEM bundle to trust for the CA's HTTPS instead of the system's (a private CA).",
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_PATH } } } },
	{ .name = "tls", .subname = "auto", .contexts = BST_CTX_SERVER, .apply = ap_tls_auto,
	  .doc = "The server's certificate comes from the `acme {}` block, for every `name`. "
		 "Without a `listen`, the server listens on 443 (tls http2) and on 80, which "
		 "redirects to https except for ACME challenges. A temporary self-signed certificate "
		 "serves until the first one is issued.",
	  .args = { .min_args = 0, .max_args = 0 } },
};
BST_DIRECTIVES(acme_dirs);
