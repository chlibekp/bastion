/* TLS directives (Phase 6): tls_profile blocks (named, global, shared by the servers that name
 * them) and the per-server certificate, SNI and client-authentication settings. They only parse,
 * validate and record; src/tls/ builds the contexts from the result, and post_tls_resolve builds
 * each server's SSL_CTX so that `bastion -t` loads every certificate and key.
 *
 * Every figure has a default in the table (and in bst_tls_profile_defaults, which gives the
 * profile of a server that names none the same values: test_tls_ctx keeps the two in step). */
#include "config/compile.h"
#include "config/errfmt.h"
#include "config/schema_priv.h"
#include "config/values.h"
#include "core/str.h"
#include "http/http.h"
#include "tls/ctx.h"

#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEF_VERSIONS "1.2 1.3"
#define DEF_GROUPS "X25519MLKEM768 X25519 P-256"
/* OpenSSL rule strings: every ECDHE suite with an AEAD cipher, nothing else. Short, because a
 * directive default is limited in length. */
#define DEF_CIPHERS12 "ECDHE+AESGCM ECDHE+CHACHA20"
#define DEF_SUITES13 "TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256"
#define DEF_SIGALGS                                                                     \
	"ecdsa_secp256r1_sha256 ecdsa_secp384r1_sha384 ed25519 rsa_pss_rsae_sha256 "     \
	"rsa_pss_rsae_sha384 rsa_pkcs1_sha256"
#define DEF_TICKET_ROTATE_MS (12ull * 3600 * 1000)
#define DEF_TICKET_KEEP 3u
#define DEF_EARLY_MAX 16384ull
#define DEF_HANDSHAKE_MS 10000ull

static bst_str as_str(const bst_ast_arg *a)
{
	return (bst_str){ a->text, (uint32_t)a->len };
}

static int fail_at(bst_err *e, const bst_ast_arg *a, const char *msg)
{
	bst_err_set(e, "%s", msg);
	bst_cfg_err_at(e, &a->loc);
	return -1;
}

static bool flag(const bst_ast_arg *a)
{
	bool v = false;
	(void)bst_parse_bool(as_str(a), &v);
	return v;
}

static uint64_t dur_ms(const bst_ast_arg *a)
{
	uint64_t v = 0;
	(void)bst_parse_duration_us(as_str(a), &v);
	return v / 1000;
}

/* The positionals joined with ':' (what OpenSSL's list strings use), in the config arena. */
static const char *join_colon(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			      bst_err *e)
{
	size_t np = bst_dir_npos(d, n), total = 1;
	for (size_t i = 0; i < np; i++)
		total += bst_dir_pos(d, n, i)->len + 1;
	char *out = bst_arena_alloc(c->arena, total);
	if (out == NULL) {
		bst_err_set(e, "out of memory");
		return NULL;
	}
	size_t o = 0;
	for (size_t i = 0; i < np; i++) {
		const bst_ast_arg *a = bst_dir_pos(d, n, i);
		if (i > 0)
			out[o++] = ':';
		memcpy(out + o, a->text, a->len);
		o += a->len;
	}
	out[o] = '\0';
	return out;
}

/* The same colon list from a space separated default. */
static const char *colon(bst_arena *a, const char *spaced)
{
	size_t n = strlen(spaced);
	char *out = bst_arena_alloc(a, n + 1);
	if (out == NULL)
		return NULL;
	for (size_t i = 0; i <= n; i++)
		out[i] = spaced[i] == ' ' ? ':' : spaced[i];
	return out;
}

static uint32_t method_mask(const char *spaced)
{
	uint32_t m = 0;
	const char *p = spaced;
	while (*p) {
		const char *q = p;
		while (*q && *q != ' ')
			q++;
		m |= 1u << bst_method_from((bst_str){ p, (uint32_t)(q - p) });
		p = *q ? q + 1 : q;
	}
	return m;
}

/* The documented defaults. A string needs an arena: the caller's. 0, or -1 on exhaustion. */
static int profile_defaults(bst_cfg_tls_profile *p, const char *name, bst_arena *a)
{
	memset(p, 0, sizeof *p);
	p->name = name;
	p->min_version = TLS1_2_VERSION;
	p->max_version = TLS1_3_VERSION;
	p->groups = colon(a, DEF_GROUPS);
	p->ciphers_tls12 = colon(a, DEF_CIPHERS12);
	p->ciphersuites_tls13 = colon(a, DEF_SUITES13);
	p->sigalgs = colon(a, DEF_SIGALGS);
	p->prefer_server_ciphers = true;
	p->dh_none = true;
	p->handshake_timeout_ms = DEF_HANDSHAKE_MS;
	p->ktls = BST_KTLS_TX;
	p->tickets = true;
	p->tickets_rotate_ms = DEF_TICKET_ROTATE_MS;
	p->tickets_keep = DEF_TICKET_KEEP;
	p->ocsp_stapling = false;
	p->early_data = false;
	p->early_methods = method_mask("GET HEAD");
	p->early_max_size = DEF_EARLY_MAX;
	return p->groups && p->ciphers_tls12 && p->ciphersuites_tls13 && p->sigalgs ? 0 : -1;
}

/* ---- the block ---- */

static int ap_tls_profile_block(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
				bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	bst_cfg_tls_profile *p = bst_arena_alloc(c->arena, sizeof *p);
	bst_cfg_loc loc;
	if (p == NULL) {
		bst_err_set(e, "out of memory");
		return -1;
	}
	const char *name = bst_cfg_strdup(c, a->text, a->len, e);
	/* The block's own directives (all defaulted in the table) overwrite these. */
	if (name == NULL || profile_defaults(p, name, c->arena) != 0 ||
	    bst_cfg_loc_at(c, &a->loc, &loc, e) != 0) {
		if (name != NULL)
			bst_err_set(e, "out of memory");
		return -1;
	}
	bst_cfg_global *g = c->global;
	if (bst_cfg_push_owned(c, &g->tls_profiles, &g->ntls_profiles, &g->tls_profiles_cap_,
			       sizeof p, &p, e) != 0)
		return -1;
	size_t ni = g->ntls_profiles - 1;
	if (bst_cfg_push_owned(c, &g->tls_profile_locs, &ni, &g->tls_profile_locs_cap_, sizeof loc,
			       &loc, e) != 0)
		return -1;
	c->tls_profile = p;
	return 0;
}

#define PROF (c->tls_profile)

static int ap_versions(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	int lo = TLS1_3_VERSION, hi = TLS1_2_VERSION;
	for (size_t i = 0; i < bst_dir_npos(d, n); i++) {
		int v = strcmp(bst_dir_pos(d, n, i)->text, "1.3") == 0 ? TLS1_3_VERSION : TLS1_2_VERSION;
		lo = v < lo ? v : lo;
		hi = v > hi ? v : hi;
	}
	PROF->min_version = lo;
	PROF->max_version = hi;
	return 0;
}

static int ap_groups(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	return (PROF->groups = join_colon(c, d, n, e)) != NULL ? 0 : -1;
}
static int ap_ciphers12(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	return (PROF->ciphers_tls12 = join_colon(c, d, n, e)) != NULL ? 0 : -1;
}
static int ap_suites13(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	return (PROF->ciphersuites_tls13 = join_colon(c, d, n, e)) != NULL ? 0 : -1;
}
static int ap_sigalgs(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	return (PROF->sigalgs = join_colon(c, d, n, e)) != NULL ? 0 : -1;
}
static int ap_prefer(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	PROF->prefer_server_ciphers = flag(bst_dir_pos(d, n, 0));
	return 0;
}
static int ap_dh_none(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	PROF->dh_none = flag(bst_dir_pos(d, n, 0));
	return 0;
}
static int ap_reneg(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)c, (void)d, (void)n, (void)e; /* only `off` passes the schema: renegotiation is refused */
	return 0;
}
static int ap_hs_timeout(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	PROF->handshake_timeout_ms = dur_ms(bst_dir_pos(d, n, 0));
	return 0;
}

static int ap_ktls(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const char *m = bst_dir_pos(d, n, 0)->text;
	PROF->ktls = strcmp(m, "off") == 0 ? BST_KTLS_OFF : strcmp(m, "tx") == 0 ? BST_KTLS_TX
									      : BST_KTLS_TXRX;
	PROF->ktls_require = bst_dir_has_require(d, n);
	return bst_cfg_loc_of(c, n, &PROF->ktls_loc, e);
}

static int ap_tickets(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *off = bst_dir_pos(d, n, 0);
	bst_ast_arg rot, keep, file;
	bool hr = bst_dir_opt(d, n, "rotate=", &rot), hk = bst_dir_opt(d, n, "keep=", &keep),
	     hf = bst_dir_opt(d, n, "file=", &file);
	if (off != NULL) {
		if (hr || hk || hf)
			return fail_at(e, off, "tickets off takes no options");
		PROF->tickets = false;
		return 0;
	}
	PROF->tickets = true;
	PROF->tickets_rotate_ms = DEF_TICKET_ROTATE_MS;
	PROF->tickets_keep = DEF_TICKET_KEEP;
	PROF->tickets_file = NULL;
	if (hr)
		PROF->tickets_rotate_ms = dur_ms(&rot);
	if (hk) {
		uint64_t v = 0;
		(void)bst_str_to_u64(as_str(&keep), &v);
		PROF->tickets_keep = (unsigned)v;
	}
	if (hf && (PROF->tickets_file = bst_cfg_strdup(c, file.text, file.len, e)) == NULL)
		return -1;
	return 0;
}

static int ap_ocsp(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	PROF->ocsp_stapling = flag(bst_dir_pos(d, n, 0));
	return 0;
}
static int ap_early(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	PROF->early_data = flag(bst_dir_pos(d, n, 0));
	return 0;
}
static int ap_early_methods(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			    bst_err *e)
{
	(void)e;
	uint32_t m = 0;
	for (size_t i = 0; i < bst_dir_npos(d, n); i++) {
		const bst_ast_arg *a = bst_dir_pos(d, n, i);
		m |= 1u << bst_method_from(as_str(a));
	}
	PROF->early_methods = m;
	return 0;
}
static int ap_early_max(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	uint64_t v = 0;
	(void)bst_parse_size(as_str(bst_dir_pos(d, n, 0)), &v);
	PROF->early_max_size = v;
	return 0;
}

/* ---- server ---- */

#define TLS (c->server->tls)

static int ap_server_profile(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			     bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	TLS.profile_name = bst_cfg_strdup(c, a->text, a->len, e);
	return TLS.profile_name != NULL ? bst_cfg_loc_at(c, &a->loc, &TLS.profile_loc, e) : -1;
}

static int read_cert(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
		     bst_cfg_tls_cert *out, bst_err *e)
{
	const bst_ast_arg *crt = bst_dir_pos(d, n, 0), *key = bst_dir_pos(d, n, 1);
	out->crt = bst_cfg_strdup(c, crt->text, crt->len, e);
	out->key = out->crt != NULL ? bst_cfg_strdup(c, key->text, key->len, e) : NULL;
	return out->key != NULL ? bst_cfg_loc_of(c, n, &out->loc, e) : -1;
}

static int ap_tls_cert(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	bst_cfg_tls_cert t;
	memset(&t, 0, sizeof t);
	if (read_cert(c, d, n, &t, e) != 0)
		return -1;
	return bst_cfg_push_owned(c, &TLS.certs, &TLS.ncerts, &TLS.certs_cap_, sizeof t, &t, e);
}

static int ap_default_cert(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			   bst_err *e)
{
	TLS.has_default_cert = true;
	return read_cert(c, d, n, &TLS.default_cert, e);
}

static int ap_sni_required(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			   bst_err *e)
{
	(void)e;
	TLS.sni_required = flag(bst_dir_pos(d, n, 0));
	return 0;
}
static int ap_ja4(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	TLS.ja4 = flag(bst_dir_pos(d, n, 0));
	return 0;
}

static int ap_sni_mismatch(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			   bst_err *e)
{
	(void)e;
	TLS.sni_reject = strcmp(bst_dir_pos(d, n, 0)->text, "reject") == 0;
	return 0;
}
static int ap_host_sni(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	TLS.host_sni = strcmp(bst_dir_pos(d, n, 0)->text, "allow") == 0 ? BST_HOST_SNI_ALLOW
									: BST_HOST_SNI_421;
	return 0;
}
static int ap_client_auth(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			  bst_err *e)
{
	(void)e;
	const char *m = bst_dir_pos(d, n, 0)->text;
	TLS.client_auth = strcmp(m, "required") == 0   ? BST_CLIENT_AUTH_REQUIRED
			  : strcmp(m, "optional") == 0 ? BST_CLIENT_AUTH_OPTIONAL
						       : BST_CLIENT_AUTH_OFF;
	return 0;
}
static int ap_client_ca(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	return (TLS.client_ca = bst_cfg_strdup(c, a->text, a->len, e)) != NULL ? 0 : -1;
}
static int ap_client_crl(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	return (TLS.client_crl = bst_cfg_strdup(c, a->text, a->len, e)) != NULL ? 0 : -1;
}
static int ap_verify_depth(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			   bst_err *e)
{
	(void)e;
	uint64_t v = 0;
	(void)bst_str_to_u64(as_str(bst_dir_pos(d, n, 0)), &v);
	TLS.verify_depth = (unsigned)v;
	return 0;
}
static int ap_http_on_tls(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			  bst_err *e)
{
	(void)e;
	TLS.http_on_tls = strcmp(bst_dir_pos(d, n, 0)->text, "respond") == 0 ? BST_HTTP_ON_TLS_RESPOND
									     : BST_HTTP_ON_TLS_CLOSE;
	return 0;
}
static int ap_ocsp_file(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	const char *p = bst_cfg_strdup(c, a->text, a->len, e);
	return p != NULL ? bst_cfg_push_owned(c, &TLS.ocsp_files, &TLS.nocsp_files,
					      &TLS.ocsp_files_cap_, sizeof p, &p, e)
			 : -1;
}
static int ap_ocsp_responder(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			     bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	return (TLS.ocsp_responder = bst_cfg_strdup(c, a->text, a->len, e)) != NULL ? 0 : -1;
}
static int ap_auth_mtls(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	c->common->auth_mtls = flag(bst_dir_pos(d, n, 0));
	return 0;
}

/* ---- the table ---- */

#define ARG1(...) .args = { .min_args = 1, .max_args = 1, .pos = { __VA_ARGS__ } }
#define TLSP BST_CTX_TLS_PROFILE
#define SRV BST_CTX_SERVER
#define SEC 1000000LL

static const char *const ev_versions[] = { "1.2", "1.3", NULL };
static const char *const ev_ktls[] = { "off", "tx", "tx+rx", NULL };
static const char *const ev_off[] = { "off", NULL };
static const char *const ev_sni_mismatch[] = { "default", "reject", NULL };
static const char *const ev_host_sni[] = { "421", "allow", NULL };
static const char *const ev_client_auth[] = { "off", "optional", "required", NULL };
static const char *const ev_http_on_tls[] = { "close", "respond", NULL };
static const char *const ev_methods[] = { "GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS",
					   "PATCH", NULL };

static const bst_optspec tickets_opts[] = {
	{ .key = "rotate=", .type = { .kind = BST_T_DURATION, .min = 60 * SEC, .max = 30LL * 86400 * SEC } },
	{ .key = "keep=", .type = { .kind = BST_T_INT, .min = 1, .max = 16 } },
	{ .key = "file=", .type = { .kind = BST_T_PATH } },
};

static const bst_directive tls_dirs[] = {
	{ .name = "tls_profile", .contexts = BST_CTX_GLOBAL, .apply = ap_tls_profile_block,
	  .repeatable = true, .child_ctx = TLSP,
	  .doc = "A named set of TLS choices that servers share: protocol versions, key exchange "
		 "groups, ciphers, kTLS, session tickets, OCSP stapling and 0-RTT. A server picks one "
		 "with `tls_profile name;` and falls back to the documented defaults when it names none.",
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_STRING } },
		    .block = BST_BLOCK_REQUIRED } },
	{ .name = "versions", .contexts = TLSP, .apply = ap_versions, .default_value = DEF_VERSIONS,
	  .doc = "TLS protocol versions offered: 1.2, 1.3, or both. TLS 1.0 and 1.1 cannot be enabled.",
	  .args = { .min_args = 1, .max_args = 2, .pos = { { .kind = BST_T_ENUM, .enum_values = ev_versions } } } },
	{ .name = "groups", .contexts = TLSP, .apply = ap_groups, .default_value = DEF_GROUPS,
	  .doc = "Key exchange groups in order of preference (OpenSSL names). The default leads with "
		 "the post-quantum hybrid X25519MLKEM768, then X25519 and P-256.",
	  .args = { .min_args = 1, .max_args = 16, .pos = { { .kind = BST_T_STRING } } } },
	{ .name = "ciphers_tls12", .contexts = TLSP, .apply = ap_ciphers12, .default_value = DEF_CIPHERS12,
	  .doc = "TLS 1.2 cipher suites in order of preference (OpenSSL names). The default is "
		 "ECDHE key exchange with AEAD ciphers only.",
	  .args = { .min_args = 1, .max_args = 32, .pos = { { .kind = BST_T_STRING } } } },
	{ .name = "ciphersuites_tls13", .contexts = TLSP, .apply = ap_suites13, .default_value = DEF_SUITES13,
	  .doc = "TLS 1.3 cipher suites in order of preference.",
	  .args = { .min_args = 1, .max_args = 8, .pos = { { .kind = BST_T_STRING } } } },
	{ .name = "sigalgs", .contexts = TLSP, .apply = ap_sigalgs, .default_value = DEF_SIGALGS,
	  .doc = "Signature algorithms the server accepts and uses, in order of preference. SHA-1 "
		 "signatures are not in the default.",
	  .args = { .min_args = 1, .max_args = 32, .pos = { { .kind = BST_T_STRING } } } },
	{ .name = "prefer_server_ciphers", .contexts = TLSP, .apply = ap_prefer, .default_value = "on",
	  .doc = "The server's cipher order wins over the client's.", ARG1({ .kind = BST_T_BOOL }) },
	{ .name = "dh_none", .contexts = TLSP, .apply = ap_dh_none, .default_value = "on",
	  .doc = "Never offer finite-field Diffie-Hellman (DHE) in TLS 1.2, even when ciphers_tls12 "
		 "names a DHE suite.", ARG1({ .kind = BST_T_BOOL }) },
	{ .name = "renegotiation", .contexts = TLSP, .apply = ap_reneg, .default_value = "off",
	  .doc = "TLS 1.2 renegotiation is always refused; the only accepted value is off.",
	  ARG1({ .kind = BST_T_ENUM, .enum_values = ev_off }) },
	{ .name = "handshake_timeout", .contexts = TLSP, .apply = ap_hs_timeout, .default_value = "10s",
	  .doc = "Time a client has to finish the TLS handshake, from the first byte of the connection. "
		 "A client that stalls or never starts is closed at the deadline.",
	  ARG1({ .kind = BST_T_DURATION, .min = 1 * SEC, .max = 3600 * SEC }) },
	{ .name = "ktls", .contexts = TLSP, .apply = ap_ktls, .default_value = "tx", .require = true,
	  .doc = "Kernel TLS: tx lets the kernel encrypt responses, so files go out by sendfile; "
		 "tx+rx also decrypts in the kernel; off keeps TLS in user space. Where the kernel, "
		 "the module or the cipher cannot do it, the connection runs in user space with one "
		 "warning per start; `require` makes that a startup error. A client KeyUpdate that asks "
		 "the server to rekey its sending direction closes a kTLS connection.",
	  ARG1({ .kind = BST_T_ENUM, .enum_values = ev_ktls }) },
	{ .name = "tickets", .contexts = TLSP, .apply = ap_tickets, .default_value = "rotate=12h keep=3",
	  .doc = "Session tickets for resumption. `off` disables them. Otherwise keys rotate every "
		 "`rotate`, and the newest `keep` keys decrypt old tickets; `file=` reads the keys from a "
		 "file so several instances resume each other's tickets. Key material lives in one "
		 "shared, non-dumpable memory region. Every profile that enables tickets must agree on "
		 "rotate, keep and file.",
	  .args = { .min_args = 0, .max_args = 1, .pos = { { .kind = BST_T_ENUM, .enum_values = ev_off } },
		    .opts = tickets_opts, .nopts = sizeof tickets_opts / sizeof tickets_opts[0] } },
	{ .name = "ocsp_stapling", .contexts = TLSP, .apply = ap_ocsp, .default_value = "off",
	  .doc = "Staple an OCSP response to the handshake. The helper process fetches and verifies "
		 "responses; a certificate with no OCSP URL is skipped silently.",
	  ARG1({ .kind = BST_T_BOOL }) },
	{ .name = "early_data", .contexts = TLSP, .apply = ap_early, .default_value = "off",
	  .doc = "Accept TLS 1.3 0-RTT early data. Off by default: early data can be replayed, so "
		 "only the methods of early_data_methods are served from it, once per ticket across all "
		 "workers; anything else is answered 425 Too Early. Never accepted on a server that "
		 "requests client certificates.", ARG1({ .kind = BST_T_BOOL }) },
	{ .name = "early_data_methods", .contexts = TLSP, .apply = ap_early_methods,
	  .default_value = "GET HEAD",
	  .doc = "Request methods that may be served from early data (they must be safe to replay).",
	  .args = { .min_args = 1, .max_args = 7, .pos = { { .kind = BST_T_ENUM, .enum_values = ev_methods } } } },
	{ .name = "early_data_max_size", .contexts = TLSP, .apply = ap_early_max, .default_value = "16k",
	  .doc = "Most early data bytes a connection may send before the handshake completes.",
	  ARG1({ .kind = BST_T_SIZE, .min = 1, .max = 1 << 20 }) },
	/* server */
	{ .name = "tls_profile", .contexts = SRV, .apply = ap_server_profile,
	  .doc = "The tls_profile block this server uses; default: the documented defaults.",
	  ARG1({ .kind = BST_T_STRING }) },
	{ .name = "tls_cert", .contexts = SRV, .apply = ap_tls_cert, .repeatable = true,
	  .doc = "Certificate chain (PEM, leaf first) and its private key. Give two, one RSA and one "
		 "ECDSA, to serve each client the one it prefers. Master reads both files before the "
		 "sandbox; workers never can.",
	  .args = { .min_args = 2, .max_args = 2, .pos = { { .kind = BST_T_PATH }, { .kind = BST_T_PATH } } } },
	{ .name = "tls_default_cert", .contexts = SRV, .apply = ap_default_cert,
	  .doc = "Certificate and key for a handshake that carries no SNI, or one that names no server "
		 "(unless sni_mismatch is reject). Default: the certificates of the listener's default server.",
	  .args = { .min_args = 2, .max_args = 2, .pos = { { .kind = BST_T_PATH }, { .kind = BST_T_PATH } } } },
	{ .name = "sni_required", .contexts = SRV, .apply = ap_sni_required, .default_value = "off",
	  .doc = "Fail the handshake of a client that sends no server name. Read on the default server "
		 "of the listener.", ARG1({ .kind = BST_T_BOOL }) },
	{ .name = "tls_ja4", .contexts = SRV, .apply = ap_ja4, .default_value = "off",
	  .doc = "Compute the JA4 fingerprint of each client's TLS ClientHello, for $ja4 (logs, rules). "
		 "Off costs nothing. Read on the default server of the listener, because the hello "
		 "arrives before a server is chosen.", ARG1({ .kind = BST_T_BOOL }) },
	{ .name = "sni_mismatch", .contexts = SRV, .apply = ap_sni_mismatch, .default_value = "default",
	  .doc = "A server name no server answers to: `default` serves the default certificate, `reject` "
		 "fails the handshake with an unrecognized_name alert. Read on the default server.",
	  ARG1({ .kind = BST_T_ENUM, .enum_values = ev_sni_mismatch }) },
	{ .name = "host_sni_mismatch", .contexts = SRV, .apply = ap_host_sni, .default_value = "421",
	  .doc = "A request whose Host (or :authority) belongs to another server than the one the TLS "
		 "handshake chose by SNI: `421` answers 421 Misdirected Request, so no site's content "
		 "reaches a client through another site's certificate; `allow` serves it. A request for "
		 "a server that asks for client certificates is always 421. A connection that sent no SNI "
		 "is not compared.",
	  ARG1({ .kind = BST_T_ENUM, .enum_values = ev_host_sni }) },
	{ .name = "tls_client_auth", .contexts = SRV, .apply = ap_client_auth, .default_value = "off",
	  .doc = "Client certificates: off, optional (verified if sent, else the connection goes on "
		 "and a location with auth_mtls answers 403) or required (no certificate fails the "
		 "handshake). Needs tls_client_ca.",
	  ARG1({ .kind = BST_T_ENUM, .enum_values = ev_client_auth }) },
	{ .name = "tls_client_ca", .contexts = SRV, .apply = ap_client_ca,
	  .doc = "PEM file of the certificate authorities that sign accepted client certificates.",
	  ARG1({ .kind = BST_T_PATH }) },
	{ .name = "tls_client_crl", .contexts = SRV, .apply = ap_client_crl,
	  .doc = "PEM file of certificate revocation lists. When set, a client certificate whose "
		 "issuer has no CRL here, or that is listed, is refused.", ARG1({ .kind = BST_T_PATH }) },
	{ .name = "tls_client_verify_depth", .contexts = SRV, .apply = ap_verify_depth,
	  .default_value = "4", .doc = "Longest accepted client certificate chain.",
	  ARG1({ .kind = BST_T_INT, .min = 1, .max = 16 }) },
	{ .name = "http_on_tls_port", .contexts = SRV, .apply = ap_http_on_tls, .default_value = "close",
	  .doc = "A client that speaks plain HTTP to a TLS port: `close` drops the connection, `respond` "
		 "answers a small 400 page in plain text. Read on the default server of the listener.",
	  ARG1({ .kind = BST_T_ENUM, .enum_values = ev_http_on_tls }) },
	{ .name = "ocsp_file", .contexts = SRV, .apply = ap_ocsp_file, .repeatable = true,
	  .doc = "A DER OCSP response to staple, read at start and when it changes; matched to the "
		 "certificate it answers for. Used instead of a fetch.", ARG1({ .kind = BST_T_PATH }) },
	{ .name = "ocsp_responder_override", .contexts = SRV, .apply = ap_ocsp_responder,
	  .doc = "URL of the OCSP responder to use instead of the one named in the certificate "
		 "(http only: the helper speaks plain HTTP).", ARG1({ .kind = BST_T_STRING }) },
	{ .name = "auth_mtls", .contexts = SRV | BST_CTX_LOCATION, .apply = ap_auth_mtls,
	  .default_value = "off",
	  .doc = "Requests here need a verified client certificate: 403 without one. Use it with "
		 "tls_client_auth optional to protect some locations only.",
	  ARG1({ .kind = BST_T_BOOL }) },
};
BST_DIRECTIVES(tls_dirs);

/* ---- resolving, validating, building ---- */

typedef struct pkey {
	const char *name;
	size_t idx;
} pkey;

static int cmp_pkey(const void *x, const void *y)
{
	const pkey *a = x, *b = y;
	int c = strcmp(a->name, b->name);
	return c != 0 ? c : a->idx < b->idx ? -1 : a->idx > b->idx;
}

static int cmp_pkey_name(const void *k, const void *y)
{
	return strcmp((const char *)k, ((const pkey *)y)->name);
}

static void free_ctx(void *p)
{
	SSL_CTX_free(p);
}

static int tickets_agree(const bst_cfg_tls_profile *a, const bst_cfg_tls_profile *b)
{
	if (a->tickets_rotate_ms != b->tickets_rotate_ms || a->tickets_keep != b->tickets_keep)
		return 0;
	if ((a->tickets_file == NULL) != (b->tickets_file == NULL))
		return 0;
	return a->tickets_file == NULL || strcmp(a->tickets_file, b->tickets_file) == 0;
}

static int post_tls_resolve(bst_config *cfg, bst_cfg_ctx *c, bst_err *e)
{
	bst_cfg_global *g = &cfg->global;
	if (profile_defaults(&g->tls_default, "default", cfg->arena) != 0) {
		bst_err_set(e, "out of memory");
		return -1;
	}
	pkey *sorted = malloc((g->ntls_profiles ? g->ntls_profiles : 1) * sizeof *sorted);
	if (sorted == NULL) {
		bst_err_set(e, "out of memory");
		return -1;
	}
	for (size_t i = 0; i < g->ntls_profiles; i++)
		sorted[i] = (pkey){ g->tls_profiles[i]->name, i };
	qsort(sorted, g->ntls_profiles, sizeof *sorted, cmp_pkey);
	size_t dup = SIZE_MAX;
	for (size_t i = 1; i < g->ntls_profiles; i++)
		if (strcmp(sorted[i - 1].name, sorted[i].name) == 0 && sorted[i].idx < dup)
			dup = sorted[i].idx;
	if (dup != SIZE_MAX) {
		char tok[BST_SCHEMA_MAX_TOKEN_SHOWN + 8];
		bst_cfg_shown(g->tls_profiles[dup]->name, strlen(g->tls_profiles[dup]->name), tok, sizeof tok);
		bst_err_set(e, "duplicate tls_profile \"%s\"", tok);
		bst_cfg_err_at(e, bst_cfg_src(c, &g->tls_profile_locs[dup]));
		free(sorted);
		return -1;
	}
	for (size_t i = 0; i < g->nservers; i++) /* a port is either TLS or not, for every server on it */
		for (size_t j = 0; j < g->servers[i]->nlistens; j++) {
			const bst_cfg_listen *a = &g->servers[i]->listens[j];
			for (size_t k = i; k < g->nservers; k++)
				for (size_t m = k == i ? j + 1 : 0; m < g->servers[k]->nlistens; m++) {
					const bst_cfg_listen *b = &g->servers[k]->listens[m];
					if (a->addr.port != b->addr.port || !bst_ip_eq(&a->addr.ip, &b->addr.ip) ||
					    a->tls == b->tls)
						continue;
					bst_err_set(e, "listen: one address has `tls` on one server and not on "
						       "another; a port is either TLS or plain for every server on it");
					bst_cfg_err_at(e, bst_cfg_src(c, &b->loc));
					free(sorted);
					return -1;
				}
		}
	const bst_cfg_tls_profile *ticket_ref = NULL;
	for (size_t i = 0; i < g->nservers; i++) {
		bst_cfg_server *s = g->servers[i];
		bst_cfg_tls *t = &s->tls;
		bool tls_listen = false;
		for (size_t j = 0; j < s->nlistens; j++)
			tls_listen |= s->listens[j].tls;
		if (t->profile_name != NULL) {
			const pkey *hit = bsearch(t->profile_name, sorted, g->ntls_profiles, sizeof *sorted,
						  cmp_pkey_name);
			if (hit == NULL) {
				char tok[BST_SCHEMA_MAX_TOKEN_SHOWN + 8];
				bst_cfg_shown(t->profile_name, strlen(t->profile_name), tok, sizeof tok);
				bst_err_set(e, "undefined tls_profile \"%s\" (define it with `tls_profile %s { ... }`)",
					    tok, tok);
				bst_cfg_err_at(e, bst_cfg_src(c, &t->profile_loc));
				free(sorted);
				return -1;
			}
			t->profile = g->tls_profiles[hit->idx];
		} else {
			t->profile = &g->tls_default;
		}
		if (tls_listen && t->ncerts == 0) {
			bst_err_set(e, "a server with a `tls` listener needs at least one tls_cert");
			bst_cfg_err_at(e, bst_cfg_src(c, &s->loc));
			free(sorted);
			return -1;
		}
		if (t->client_auth != BST_CLIENT_AUTH_OFF && t->client_ca == NULL) {
			bst_err_set(e, "tls_client_auth needs tls_client_ca");
			bst_cfg_err_at(e, bst_cfg_src(c, &s->loc));
			free(sorted);
			return -1;
		}
		if (t->ncerts == 0)
			continue;
		if (!tls_listen)
			bst_cfg_warn_at(c, bst_cfg_src(c, &s->loc),
					"server with tls_cert and no `tls` listener: the certificate is never used");
		for (size_t k = 0; k < t->ncerts; k++) {
			int v = bst_tls_cert_validity(t->certs[k].crt);
			if (v == -1 || v == 1) {
				char tok[BST_SCHEMA_MAX_TOKEN_SHOWN + 8];
				bst_cfg_shown(t->certs[k].crt, strlen(t->certs[k].crt), tok, sizeof tok);
				bst_cfg_warn_at(c, bst_cfg_src(c, &t->certs[k].loc), "certificate %s is %s", tok,
						v == -1 ? "expired" : "not yet valid");
			}
		}
		if (t->profile->tickets) {
			if (ticket_ref != NULL && !tickets_agree(ticket_ref, t->profile)) {
				bst_err_set(e, "tickets: every tls_profile that enables tickets must use the "
					       "same rotate, keep and file");
				bst_cfg_err_at(e, bst_cfg_src(c, &s->loc));
				free(sorted);
				return -1;
			}
			ticket_ref = t->profile;
		}
		SSL_CTX *ctx = bst_tls_ctx_build(t, e);
		if (ctx == NULL) {
			bst_cfg_err_at(e, bst_cfg_src(c, &t->certs[0].loc));
			free(sorted);
			return -1;
		}
		if (bst_config_on_free(cfg, free_ctx, ctx, e) != 0) {
			SSL_CTX_free(ctx);
			free(sorted);
			return -1;
		}
		t->ctx = ctx;
		if (t->has_default_cert) {
			/* tls_default_cert: a context of its own, for a handshake with no SNI or an unknown
			 * one (tls/sni.c) */
			bst_cfg_tls only = *t;
			only.certs = &t->default_cert;
			only.ncerts = 1;
			SSL_CTX *dctx = bst_tls_ctx_build(&only, e);
			if (dctx == NULL) {
				bst_cfg_err_at(e, bst_cfg_src(c, &t->default_cert.loc));
				free(sorted);
				return -1;
			}
			if (bst_config_on_free(cfg, free_ctx, dctx, e) != 0) {
				SSL_CTX_free(dctx);
				free(sorted);
				return -1;
			}
			t->default_ctx = dctx;
		}
	}
	free(sorted);
	return 0;
}
BST_CFG_POST(post_tls_resolve);
