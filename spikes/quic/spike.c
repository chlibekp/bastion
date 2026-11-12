/* QUIC backend spike (Phase 8, Task 1). Throwaway: not part of any build.
 *
 * A minimal HTTP/3 server on ngtcp2 + ngtcp2_crypto_ossl + nghttp3 and the pinned OpenSSL, one UDP
 * socket, poll(2). It answers every request with 200 and a short body that names what the TLS layer
 * saw (group, resumption, 0-RTT), and logs the same per connection on stderr.
 *
 *   spike CERT KEY PORT [TICKETKEY_HEX]
 * TICKETKEY_HEX (80 hex bytes: 16 name, 32 AES, 32 HMAC) makes the session ticket key fixed, so two
 * spike processes on different ports stand in for two workers sharing Phase 6 ticket keys. */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#define MAXC 64
#define SCIDLEN 18

typedef struct conn {
	bool used;
	ngtcp2_conn *q;
	nghttp3_conn *h;
	SSL *ssl;
	ngtcp2_crypto_ossl_ctx *octx;
	ngtcp2_crypto_conn_ref ref;
	ngtcp2_cid scid;
	struct sockaddr_storage peer;
	socklen_t peerlen;
	char body[256];
	size_t blen;
	bool logged;
} conn;

static int fd;
static struct sockaddr_storage local;
static socklen_t locallen;
static SSL_CTX *sctx;
static conn conns[MAXC];
static uint8_t static_secret[32];
static unsigned char tk[80];
static bool fixed_tk;

static uint64_t now_ns(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (uint64_t)t.tv_sec * NGTCP2_SECONDS + (uint64_t)t.tv_nsec;
}

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *r) { return ((conn *)r->user_data)->q; }
static void rand_cb(uint8_t *d, size_t n, const ngtcp2_rand_ctx *c) { (void)c, RAND_bytes(d, (int)n); }

static int new_cid(ngtcp2_conn *q, ngtcp2_cid *cid, ngtcp2_stateless_reset_token *tok, size_t len, void *ud)
{
	(void)q, (void)ud;
	RAND_bytes(cid->data, (int)len);
	cid->datalen = len;
	return ngtcp2_crypto_generate_stateless_reset_token(tok->data, static_secret, sizeof static_secret, cid) == 0
		       ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
}

static int h_recv_header(nghttp3_conn *h, int64_t sid, int32_t t, nghttp3_rcbuf *n, nghttp3_rcbuf *v, uint8_t f,
			 void *ud, void *sud)
{
	(void)h, (void)sid, (void)t, (void)n, (void)v, (void)f, (void)ud, (void)sud;
	return 0;
}

static nghttp3_ssize read_body(nghttp3_conn *h, int64_t sid, nghttp3_vec *vec, size_t cnt, uint32_t *fl, void *ud,
			       void *sud)
{
	(void)h, (void)sid, (void)cnt, (void)sud;
	conn *c = ud;
	vec[0].base = (uint8_t *)c->body;
	vec[0].len = c->blen;
	*fl |= NGHTTP3_DATA_FLAG_EOF;
	return 1;
}

static void describe(conn *c)
{
	const char *g = SSL_group_to_name(c->ssl, SSL_get_negotiated_group(c->ssl));
	int early = SSL_get_early_data_status(c->ssl);
	c->blen = (size_t)snprintf(c->body, sizeof c->body, "group=%s resumed=%d early=%s version=0x%x\n",
				   g ? g : "?", SSL_session_reused(c->ssl),
				   early == SSL_EARLY_DATA_ACCEPTED ? "accepted" : early == SSL_EARLY_DATA_REJECTED ? "rejected" : "none",
				   ngtcp2_conn_get_negotiated_version(c->q));
}

static int h_end_headers(nghttp3_conn *h, int64_t sid, int fin, void *ud, void *sud)
{
	(void)fin, (void)sud;
	conn *c = ud;
	describe(c);
	char len[16];
	snprintf(len, sizeof len, "%zu", c->blen);
	nghttp3_nv nva[] = {
		{ (uint8_t *)":status", (uint8_t *)"200", 7, 3, 0 },
		{ (uint8_t *)"content-length", (uint8_t *)len, 14, strlen(len), 0 },
	};
	nghttp3_data_reader dr = { .read_data = read_body };
	return nghttp3_conn_submit_response(h, sid, nva, 2, &dr) == 0 ? 0 : NGHTTP3_ERR_CALLBACK_FAILURE;
}

static int h_deferred(nghttp3_conn *h, int64_t sid, size_t n, void *ud, void *sud)
{
	(void)h, (void)sud;
	conn *c = ud;
	ngtcp2_conn_extend_max_stream_offset(c->q, sid, n);
	ngtcp2_conn_extend_max_offset(c->q, n);
	return 0;
}

static int h_recv_data(nghttp3_conn *h, int64_t sid, const uint8_t *d, size_t n, void *ud, void *sud)
{
	(void)d;
	return h_deferred(h, sid, n, ud, sud);
}

static int setup_h3(conn *c)
{
	if (c->h != NULL)
		return 0;
	nghttp3_callbacks cb = { .recv_header = h_recv_header, .end_headers = h_end_headers, .recv_data = h_recv_data,
				 .deferred_consume = h_deferred };
	nghttp3_settings s;
	nghttp3_settings_default(&s);
	if (nghttp3_conn_server_new(&c->h, &cb, &s, NULL, c) != 0)
		return -1;
	ngtcp2_transport_params const *rp = ngtcp2_conn_get_local_transport_params(c->q);
	nghttp3_conn_set_max_client_streams_bidi(c->h, rp->initial_max_streams_bidi);
	int64_t a, b, d;
	if (ngtcp2_conn_open_uni_stream(c->q, &a, NULL) || nghttp3_conn_bind_control_stream(c->h, a) ||
	    ngtcp2_conn_open_uni_stream(c->q, &b, NULL) || ngtcp2_conn_open_uni_stream(c->q, &d, NULL) ||
	    nghttp3_conn_bind_qpack_streams(c->h, b, d))
		return -1;
	return 0;
}

static int recv_tx_key(ngtcp2_conn *q, ngtcp2_encryption_level lvl, void *ud)
{
	(void)q;
	return lvl == NGTCP2_ENCRYPTION_LEVEL_1RTT && setup_h3(ud) != 0 ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}

static int recv_stream_data(ngtcp2_conn *q, uint32_t fl, int64_t sid, uint64_t off, const uint8_t *d, size_t n,
			    void *ud, void *sud)
{
	(void)off, (void)sud;
	conn *c = ud;
	if (setup_h3(c) != 0)
		return NGTCP2_ERR_CALLBACK_FAILURE;
	nghttp3_ssize k = nghttp3_conn_read_stream2(c->h, sid, d, n, fl & NGTCP2_STREAM_DATA_FLAG_FIN, now_ns());
	if (k < 0)
		return NGTCP2_ERR_CALLBACK_FAILURE;
	ngtcp2_conn_extend_max_stream_offset(q, sid, (uint64_t)k);
	ngtcp2_conn_extend_max_offset(q, (uint64_t)k);
	return 0;
}

static int acked(ngtcp2_conn *q, int64_t sid, uint64_t off, uint64_t n, void *ud, void *sud)
{
	(void)q, (void)off, (void)sud;
	return nghttp3_conn_add_ack_offset(((conn *)ud)->h, sid, n) == 0 ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
}

static int stream_close(ngtcp2_conn *q, uint32_t fl, int64_t sid, uint64_t code, void *ud, void *sud)
{
	(void)q, (void)sud;
	conn *c = ud;
	if (!(fl & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET))
		code = NGHTTP3_H3_NO_ERROR;
	if (c->h != NULL)
		nghttp3_conn_close_stream(c->h, sid, code);
	return 0;
}

static int extend_bidi(ngtcp2_conn *q, uint64_t max, void *ud)
{
	(void)q;
	conn *c = ud;
	if (c->h != NULL)
		nghttp3_conn_set_max_client_streams_bidi(c->h, max);
	return 0;
}

static int handshake_done(ngtcp2_conn *q, void *ud)
{
	(void)q;
	conn *c = ud;
	describe(c);
	fprintf(stderr, "spike: handshake %s", c->body);
	return 0;
}

static int ticket_cb(SSL *s, unsigned char name[16], unsigned char *iv, EVP_CIPHER_CTX *ectx, EVP_MAC_CTX *hctx,
		     int enc)
{
	(void)s;
	OSSL_PARAM p[] = { OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, tk + 48, 32),
			   OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char *)"SHA256", 0),
			   OSSL_PARAM_construct_end() };
	if (enc) {
		memcpy(name, tk, 16);
		RAND_bytes(iv, 16);
		EVP_EncryptInit_ex(ectx, EVP_aes_256_cbc(), NULL, tk + 16, iv);
		EVP_MAC_CTX_set_params(hctx, p);
		return 1;
	}
	if (memcmp(name, tk, 16) != 0)
		return 0;
	EVP_DecryptInit_ex(ectx, EVP_aes_256_cbc(), NULL, tk + 16, iv);
	EVP_MAC_CTX_set_params(hctx, p);
	return 1;
}

static int alpn_cb(SSL *s, const unsigned char **out, unsigned char *outlen, const unsigned char *in,
		   unsigned inlen, void *arg)
{
	(void)s, (void)arg;
	for (unsigned i = 0; i + 1 <= inlen; i += 1u + in[i])
		if (in[i] == 2 && i + 3 <= inlen && memcmp(in + i + 1, "h3", 2) == 0) {
			*out = in + i + 1;
			*outlen = 2;
			return SSL_TLSEXT_ERR_OK;
		}
	return SSL_TLSEXT_ERR_ALERT_FATAL;
}

/* SPIKE_DENY_EARLY=1: the allow-early-data callback (Phase 6 anti-replay hook) refuses. */
static int allow_early(SSL *s, void *arg)
{
	(void)s, (void)arg;
	const char *d = getenv("SPIKE_DENY_EARLY");
	return d == NULL || *d != '1';
}

static conn *find(const uint8_t *dcid, size_t len)
{
	for (int i = 0; i < MAXC; i++) {
		if (!conns[i].used)
			continue;
		ngtcp2_cid ids[16];
		size_t n = ngtcp2_conn_get_scid(conns[i].q, ids);
		for (size_t k = 0; k < n && k < 16; k++)
			if (ids[k].datalen == len && memcmp(ids[k].data, dcid, len) == 0)
				return &conns[i];
	}
	return NULL;
}

static void conn_free(conn *c)
{
	nghttp3_conn_del(c->h);
	ngtcp2_conn_del(c->q);
	SSL_free(c->ssl);
	ngtcp2_crypto_ossl_ctx_del(c->octx);
	memset(c, 0, sizeof *c);
}

static void send_retry(const ngtcp2_pkt_hd *hd, const struct sockaddr_storage *from, socklen_t fl)
{
	uint8_t tok[NGTCP2_CRYPTO_MAX_RETRY_TOKENLEN2], out[1500];
	ngtcp2_cid scid = { .datalen = SCIDLEN };
	RAND_bytes(scid.data, SCIDLEN);
	ngtcp2_ssize tl = ngtcp2_crypto_generate_retry_token2(tok, static_secret, sizeof static_secret, hd->version,
							      (const ngtcp2_sockaddr *)from, fl, &scid, &hd->dcid, now_ns());
	if (tl < 0)
		return;
	ngtcp2_ssize n = ngtcp2_crypto_write_retry(out, sizeof out, hd->version, &hd->scid, &scid, &hd->dcid, tok, (size_t)tl);
	if (n > 0)
		sendto(fd, out, (size_t)n, 0, (const struct sockaddr *)from, fl);
	fprintf(stderr, "spike: sent Retry\n");
}

static conn *accept_conn(const ngtcp2_pkt_hd *hd, const struct sockaddr_storage *from, socklen_t fl)
{
	ngtcp2_cid odcid;
	bool retried = false;
	if (hd->tokenlen > 0 && hd->token[0] == NGTCP2_CRYPTO_TOKEN_MAGIC_RETRY2) {
		if (ngtcp2_crypto_verify_retry_token2(&odcid, hd->token, hd->tokenlen, static_secret, sizeof static_secret,
						      hd->version, (const ngtcp2_sockaddr *)from, fl, &hd->dcid,
						      10 * NGTCP2_SECONDS, now_ns()) != 0)
			return NULL;
		retried = true;
	}
	conn *c = NULL;
	for (int i = 0; i < MAXC && c == NULL; i++)
		if (!conns[i].used)
			c = &conns[i];
	if (c == NULL)
		return NULL;
	c->used = true;
	c->peer = *from;
	c->peerlen = fl;
	ngtcp2_callbacks cb = {
		.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb,
		.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
		.encrypt = ngtcp2_crypto_encrypt_cb,
		.decrypt = ngtcp2_crypto_decrypt_cb,
		.hp_mask = ngtcp2_crypto_hp_mask_cb,
		.rand = rand_cb,
		.update_key = ngtcp2_crypto_update_key_cb,
		.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
		.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
		.version_negotiation = ngtcp2_crypto_version_negotiation_cb,
		.get_new_connection_id2 = new_cid,
		.get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb,
		.recv_stream_data = recv_stream_data,
		.acked_stream_data_offset = acked,
		.stream_close = stream_close,
		.extend_max_remote_streams_bidi = extend_bidi,
		.recv_tx_key = recv_tx_key,
		.handshake_completed = handshake_done,
	};
	ngtcp2_settings s;
	ngtcp2_settings_default(&s);
	s.initial_ts = now_ns();
	static uint32_t vers[] = { NGTCP2_PROTO_VER_V2, NGTCP2_PROTO_VER_V1 };
	s.preferred_versions = vers;
	s.preferred_versionslen = 2;
	s.available_versions = vers;
	s.available_versionslen = 2;
	ngtcp2_transport_params p;
	ngtcp2_transport_params_default(&p);
	p.initial_max_streams_bidi = 100;
	p.initial_max_streams_uni = 3;
	p.initial_max_data = 1 << 20;
	p.initial_max_stream_data_bidi_remote = 256 << 10;
	p.initial_max_stream_data_uni = 256 << 10;
	p.max_idle_timeout = 30 * NGTCP2_SECONDS;
	p.original_dcid = retried ? odcid : hd->dcid;
	p.original_dcid_present = 1;
	if (retried) {
		p.retry_scid = hd->dcid;
		p.retry_scid_present = 1;
		s.token = hd->token;
		s.tokenlen = hd->tokenlen;
		s.token_type = NGTCP2_TOKEN_TYPE_RETRY;
	}
	p.stateless_reset_token_present = 1;
	c->scid.datalen = SCIDLEN;
	RAND_bytes(c->scid.data, SCIDLEN);
	ngtcp2_crypto_generate_stateless_reset_token(p.stateless_reset_token, static_secret, sizeof static_secret,
						     &c->scid);
	ngtcp2_path path = { { (struct sockaddr *)&local, locallen }, { (struct sockaddr *)&c->peer, c->peerlen }, NULL };
	if (ngtcp2_conn_server_new(&c->q, &hd->scid, &c->scid, &path, hd->version, &cb, &s, &p, NULL, c) != 0)
		goto fail;
	c->ssl = SSL_new(sctx);
	if (ngtcp2_crypto_ossl_ctx_new(&c->octx, c->ssl) != 0 || ngtcp2_crypto_ossl_configure_server_session(c->ssl) != 0)
		goto fail;
	SSL_set_quic_tls_early_data_enabled(c->ssl, 1); /* without it the server rejects every 0-RTT */
	c->ref.get_conn = get_conn;
	c->ref.user_data = c;
	SSL_set_app_data(c->ssl, &c->ref);
	SSL_set_accept_state(c->ssl);
	ngtcp2_conn_set_tls_native_handle(c->q, c->octx);
	return c;
fail:
	conn_free(c);
	return NULL;
}

static void flush(conn *c)
{
	uint8_t buf[1500];
	ngtcp2_path_storage ps;
	ngtcp2_path_storage_zero(&ps);
	ngtcp2_pkt_info pi;
	for (;;) {
		int64_t sid = -1;
		int fin = 0;
		nghttp3_vec v[16];
		nghttp3_ssize nv = 0;
		if (c->h != NULL && ngtcp2_conn_get_max_data_left(c->q) > 0)
			nv = nghttp3_conn_writev_stream(c->h, &sid, &fin, v, 16);
		if (nv < 0)
			return;
		ngtcp2_ssize w = -1;
		ngtcp2_ssize n = ngtcp2_conn_writev_stream(c->q, &ps.path, &pi, buf, sizeof buf, &w,
							   NGTCP2_WRITE_STREAM_FLAG_MORE | (fin ? NGTCP2_WRITE_STREAM_FLAG_FIN : 0),
							   sid, (ngtcp2_vec *)v, (size_t)nv, now_ns());
		if (n == NGTCP2_ERR_WRITE_MORE) {
			nghttp3_conn_add_write_offset(c->h, sid, (size_t)w);
			continue;
		}
		if (n == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
			nghttp3_conn_block_stream(c->h, sid);
			continue;
		}
		if (n < 0)
			return;
		if (w >= 0 && sid >= 0)
			nghttp3_conn_add_write_offset(c->h, sid, (size_t)w);
		if (n == 0)
			return;
		sendto(fd, buf, (size_t)n, 0, (struct sockaddr *)ps.path.remote.addr, ps.path.remote.addrlen);
	}
}

static int hexval(char ch) { return ch <= '9' ? ch - '0' : (ch | 32) - 'a' + 10; }

int main(int argc, char **argv)
{
	if (argc < 4) {
		fprintf(stderr, "usage: spike CERT KEY PORT [TICKETKEY_HEX]\n");
		return 2;
	}
	RAND_bytes(static_secret, sizeof static_secret);
	if (argc > 4 && strlen(argv[4]) == 160) {
		for (int i = 0; i < 80; i++)
			tk[i] = (unsigned char)(hexval(argv[4][2 * i]) << 4 | hexval(argv[4][2 * i + 1]));
		fixed_tk = true;
	}
	if (ngtcp2_crypto_ossl_init() != 0)
		return 1;
	sctx = SSL_CTX_new(TLS_server_method());
	SSL_CTX_set_min_proto_version(sctx, TLS1_3_VERSION);
	SSL_CTX_set1_groups_list(sctx, "X25519MLKEM768:X25519:P-256");
	SSL_CTX_set_options(sctx, SSL_OP_NO_ANTI_REPLAY | SSL_OP_CIPHER_SERVER_PREFERENCE);
	SSL_CTX_set_max_early_data(sctx, UINT32_MAX); /* RFC 9001 section 4.6.1: 0xffffffff for QUIC */
	SSL_CTX_set_alpn_select_cb(sctx, alpn_cb, NULL);
	SSL_CTX_set_allow_early_data_cb(sctx, allow_early, NULL);
	if (fixed_tk)
		SSL_CTX_set_tlsext_ticket_key_evp_cb(sctx, ticket_cb);
	if (SSL_CTX_use_certificate_chain_file(sctx, argv[1]) != 1 ||
	    SSL_CTX_use_PrivateKey_file(sctx, argv[2], SSL_FILETYPE_PEM) != 1) {
		ERR_print_errors_fp(stderr);
		return 1;
	}
	struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons((uint16_t)atoi(argv[3])),
				  .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (bind(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
		perror("bind");
		return 1;
	}
	memcpy(&local, &sa, sizeof sa);
	locallen = sizeof sa;
	fprintf(stderr, "spike: listening on %s, OpenSSL %s, ngtcp2 %s, nghttp3 %s\n", argv[3],
		OpenSSL_version(OPENSSL_VERSION), ngtcp2_version(0)->version_str, nghttp3_version(0)->version_str);
	for (;;) {
		uint64_t next = UINT64_MAX, now = now_ns();
		for (int i = 0; i < MAXC; i++)
			if (conns[i].used) {
				uint64_t e = ngtcp2_conn_get_expiry2(conns[i].q);
				next = e < next ? e : next;
			}
		int wait = next == UINT64_MAX ? 1000 : next <= now ? 0 : (int)((next - now) / NGTCP2_MILLISECONDS) + 1;
		struct pollfd pf = { .fd = fd, .events = POLLIN };
		if (poll(&pf, 1, wait) > 0) {
			uint8_t buf[65536];
			struct sockaddr_storage from;
			socklen_t fl = sizeof from;
			ssize_t n;
			while ((n = recvfrom(fd, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl)) > 0) {
				ngtcp2_version_cid vc;
				int rv = ngtcp2_pkt_decode_version_cid(&vc, buf, (size_t)n, SCIDLEN);
				if (rv == NGTCP2_ERR_VERSION_NEGOTIATION) {
					uint8_t out[256];
					uint32_t sv[] = { NGTCP2_PROTO_VER_V1, NGTCP2_PROTO_VER_V2 };
					ngtcp2_ssize k = ngtcp2_pkt_write_version_negotiation(out, sizeof out, 0, vc.scid, vc.scidlen,
											      vc.dcid, vc.dcidlen, sv, 2);
					if (k > 0)
						sendto(fd, out, (size_t)k, 0, (struct sockaddr *)&from, fl);
					fl = sizeof from;
					continue;
				}
				if (rv != 0) {
					fl = sizeof from;
					continue;
				}
				conn *c = find(vc.dcid, vc.dcidlen);
				ngtcp2_pkt_hd hd;
				bool fresh = false;
				if (c == NULL) {
					if (ngtcp2_accept(&hd, buf, (size_t)n) == 0)
						c = accept_conn(&hd, &from, fl), fresh = true;
				}
				if (c != NULL) {
					ngtcp2_path path = { { (struct sockaddr *)&local, locallen }, { (struct sockaddr *)&from, fl }, NULL };
					ngtcp2_pkt_info pi = { 0 };
					rv = ngtcp2_conn_read_pkt(c->q, &path, &pi, buf, (size_t)n, now_ns());
					if (rv == NGTCP2_ERR_RETRY && fresh) {
						/* the first Initial did not start the ClientHello: validate the address first */
						send_retry(&hd, &from, fl);
						conn_free(c);
					} else if (rv != 0) {
						fprintf(stderr, "spike: read_pkt %s\n", ngtcp2_strerror(rv));
						conn_free(c);
					} else {
						flush(c);
					}
				}
				fl = sizeof from;
			}
		}
		for (int i = 0; i < MAXC; i++) {
			if (!conns[i].used)
				continue;
			if (ngtcp2_conn_get_expiry2(conns[i].q) <= now_ns()) {
				if (ngtcp2_conn_handle_expiry(conns[i].q, now_ns()) != 0 ||
				    ngtcp2_conn_in_closing_period2(conns[i].q) || ngtcp2_conn_in_draining_period2(conns[i].q)) {
					conn_free(&conns[i]);
					continue;
				}
				flush(&conns[i]);
			}
		}
	}
}
