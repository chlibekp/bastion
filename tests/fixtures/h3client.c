/* HTTP/3 test client for the QUIC tests (Phase 8), on the pinned ngtcp2 (OpenSSL backend) and
 * nghttp3. One connection, poll(2) loop, JSON lines on stdout:
 *   {"type":"resp","path":...,"status":N,"len":N,"sha256":"..","headers":{..},"trailers":{..},"reset":N|null}
 *   {"type":"conn",...}   last line: handshake, ALPN, group, resumption, 0-RTT, close reason
 *
 *   h3client [options] HOST PORT [PATH...]
 *     --sni NAME            server name (default localhost)
 *     --session FILE        load a TLS session (and FILE.tp transport parameters) if present, save new ones
 *     --early               send the requests as 0-RTT when the session allows it
 *     --version v1|v2       QUIC version of the first Initial (default v1)
 *     --method M            request method (default GET)
 *     --body-size N         request body of N pattern bytes (byte i = (i*31+7) & 0xff)
 *     --header 'n: v'       extra request field, repeatable
 *     --trailer 'n: v'      request trailer field, repeatable
 *     --repeat N            every path N times
 *     --rebind-after N      after N response body bytes, move to a new local port (NAT rebinding)
 *     --rebind-after-handshake  the same, as soon as the handshake is confirmed (HANDSHAKE_DONE)
 *     --cancel-after N      after N body bytes of a response, STOP_SENDING it (H3_REQUEST_CANCELLED)
 *     --rapid-reset N       open N requests and reset each at once, then send the paths normally
 *     --close-control       close our control stream after the handshake (a critical stream)
 *     --max-data N          connection receive window (default 16 MiB)
 *     --timeout MS          give up after MS (default 30000)
 *     --wait-ticket         wait up to 1 s for a session ticket before closing
 *     --print-body          include the body in the response line (text, for small bodies)
 * Exit 0 when the handshake completed and every request got an answer (or was reset by request). */
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdarg.h>
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
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#define MAXREQ 4096
#define MAXHDR 64

typedef struct req {
	int64_t id;
	const char *path;
	int status;
	uint64_t len;
	EVP_MD_CTX *md;
	char hdrs[8192];
	size_t hlen;
	char trls[2048];
	size_t tlen;
	char body[4096];
	size_t blen;
	bool in_trailers, done, cancelled, rapid;
	int64_t reset;
	uint64_t up_off; /* request body bytes handed to nghttp3 */
} req;

static struct {
	const char *host, *port, *sni, *session, *method;
	bool early, close_control, wait_ticket, print_body, rebind_hs;
	uint32_t version;
	uint64_t body_size, rebind_after, cancel_after, max_data;
	unsigned repeat, rapid;
	int timeout_ms;
	const char *hdr[MAXHDR], *trl[MAXHDR];
	int nhdr, ntrl;
	const char *paths[MAXREQ];
	int npaths;
} opt;

static struct {
	int fd;
	struct sockaddr_storage local, remote;
	socklen_t locallen, remotelen;
	SSL_CTX *sctx;
	SSL *ssl;
	ngtcp2_crypto_ossl_ctx *octx;
	ngtcp2_crypto_conn_ref ref;
	ngtcp2_conn *conn;
	nghttp3_conn *h3;
	ngtcp2_ccerr err;
	req reqs[MAXREQ];
	int nreqs, ndone, next_req;
	bool handshake, confirmed, early_sent, ticket, rebound, control_closed, goaway;
	uint64_t body_total;
	int ports[4];
	int nports;
	char close_reason[256];
} C;

static uint64_t now_ns(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (uint64_t)t.tv_sec * NGTCP2_SECONDS + (uint64_t)t.tv_nsec;
}

static void die(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fprintf(stderr, "h3client: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	exit(2);
}

static void json_str(FILE *f, const char *s, size_t n)
{
	fputc('"', f);
	for (size_t i = 0; i < n; i++) {
		unsigned char ch = (unsigned char)s[i];
		if (ch == '"' || ch == '\\')
			fprintf(f, "\\%c", ch);
		else if (ch < 0x20 || ch >= 0x7f)
			fprintf(f, "\\u%04x", ch);
		else
			fputc(ch, f);
	}
	fputc('"', f);
}

static void append_kv(char *buf, size_t cap, size_t *len, const uint8_t *n, size_t nl, const uint8_t *v, size_t vl)
{
	/* stored as JSON object members; a repeated name is joined with ", " by the reader */
	char tmp[1024];
	int k = 0;
	FILE *f = fmemopen(tmp, sizeof tmp, "w");
	if (f == NULL)
		return;
	if (*len > 0)
		fputc(',', f);
	json_str(f, (const char *)n, nl);
	fputc(':', f);
	json_str(f, (const char *)v, vl > 512 ? 512 : vl);
	k = (int)ftell(f);
	fclose(f);
	if (k > 0 && *len + (size_t)k < cap) {
		memcpy(buf + *len, tmp, (size_t)k);
		*len += (size_t)k;
	}
}

/* ---- sockets ---- */

static int new_socket(void)
{
	int fd = socket(C.remote.ss_family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0)
		die("socket: %s", strerror(errno));
	if (connect(fd, (struct sockaddr *)&C.remote, C.remotelen) != 0)
		die("connect: %s", strerror(errno));
	C.locallen = sizeof C.local;
	if (getsockname(fd, (struct sockaddr *)&C.local, &C.locallen) != 0)
		die("getsockname: %s", strerror(errno));
	int port = ntohs(C.local.ss_family == AF_INET ? ((struct sockaddr_in *)&C.local)->sin_port
						     : ((struct sockaddr_in6 *)&C.local)->sin6_port);
	if (C.nports < 4)
		C.ports[C.nports++] = port;
	return fd;
}

static void send_pkt(const uint8_t *p, size_t n)
{
	ssize_t r;
	do
		r = send(C.fd, p, n, 0);
	while (r < 0 && errno == EINTR);
	/* EAGAIN or ECONNREFUSED: QUIC recovers from a lost datagram */
}

/* ---- HTTP/3 ---- */

static req *req_of(void *sud) { return (req *)sud; }

static int cb_recv_header(nghttp3_conn *h, int64_t sid, int32_t tok, nghttp3_rcbuf *name, nghttp3_rcbuf *value,
			  uint8_t flags, void *ud, void *sud)
{
	(void)h, (void)sid, (void)tok, (void)flags, (void)ud;
	req *r = req_of(sud);
	if (r == NULL)
		return 0;
	nghttp3_vec n = nghttp3_rcbuf_get_buf(name), v = nghttp3_rcbuf_get_buf(value);
	if (n.len == 7 && memcmp(n.base, ":status", 7) == 0) {
		int st = 0;
		for (size_t i = 0; i < v.len; i++)
			st = st * 10 + (v.base[i] - '0');
		if (st >= 200 || r->status == 0)
			r->status = st;
		return 0;
	}
	if (r->status >= 100 && r->status < 200)
		return 0; /* interim fields */
	append_kv(r->hdrs, sizeof r->hdrs, &r->hlen, n.base, n.len, v.base, v.len);
	return 0;
}

static int cb_recv_trailer(nghttp3_conn *h, int64_t sid, int32_t tok, nghttp3_rcbuf *name, nghttp3_rcbuf *value,
			   uint8_t flags, void *ud, void *sud)
{
	(void)h, (void)sid, (void)tok, (void)flags, (void)ud;
	req *r = req_of(sud);
	if (r == NULL)
		return 0;
	nghttp3_vec n = nghttp3_rcbuf_get_buf(name), v = nghttp3_rcbuf_get_buf(value);
	append_kv(r->trls, sizeof r->trls, &r->tlen, n.base, n.len, v.base, v.len);
	return 0;
}

static void finish(req *r)
{
	if (r->done)
		return;
	r->done = true;
	C.ndone++;
	unsigned char dg[32];
	unsigned dl = 0;
	EVP_DigestFinal_ex(r->md, dg, &dl);
	if (r->rapid)
		return;
	printf("{\"type\":\"resp\",\"path\":");
	json_str(stdout, r->path, strlen(r->path));
	printf(",\"stream\":%lld,\"status\":%d,\"len\":%llu,\"sha256\":\"", (long long)r->id, r->status,
	       (unsigned long long)r->len);
	for (unsigned i = 0; i < dl; i++)
		printf("%02x", dg[i]);
	printf("\",\"headers\":{%.*s},\"trailers\":{%.*s}", (int)r->hlen, r->hdrs, (int)r->tlen, r->trls);
	if (opt.print_body) {
		printf(",\"body\":");
		json_str(stdout, r->body, r->blen);
	}
	if (r->reset >= 0)
		printf(",\"reset\":%lld", (long long)r->reset);
	else
		printf(",\"reset\":null");
	printf(",\"cancelled\":%s}\n", r->cancelled ? "true" : "false");
	fflush(stdout);
}

static void rebind(void)
{
	int fd = new_socket();
	ngtcp2_addr a;
	ngtcp2_addr_init(&a, (struct sockaddr *)&C.local, C.locallen);
	close(C.fd);
	C.fd = fd;
	ngtcp2_conn_set_local_addr(C.conn, &a); /* NAT rebinding: no PATH_CHALLENGE from our side */
	C.rebound = true;
}

static int cb_recv_data(nghttp3_conn *h, int64_t sid, const uint8_t *data, size_t len, void *ud, void *sud)
{
	(void)h, (void)ud;
	req *r = req_of(sud);
	ngtcp2_conn_extend_max_stream_offset(C.conn, sid, len);
	ngtcp2_conn_extend_max_offset(C.conn, len);
	if (r == NULL)
		return 0;
	r->len += len;
	EVP_DigestUpdate(r->md, data, len);
	if (opt.print_body && r->blen < sizeof r->body) {
		size_t k = len < sizeof r->body - r->blen ? len : sizeof r->body - r->blen;
		memcpy(r->body + r->blen, data, k);
		r->blen += k;
	}
	C.body_total += len;
	if (opt.rebind_after && !C.rebound && C.body_total >= opt.rebind_after)
		rebind();
	if (opt.cancel_after && !r->cancelled && r->len >= opt.cancel_after) {
		r->cancelled = true;
		ngtcp2_conn_shutdown_stream_read(C.conn, 0, sid, NGHTTP3_H3_REQUEST_CANCELLED);
		finish(r);
	}
	return 0;
}

static int cb_deferred_consume(nghttp3_conn *h, int64_t sid, size_t n, void *ud, void *sud)
{
	(void)h, (void)ud, (void)sud;
	ngtcp2_conn_extend_max_stream_offset(C.conn, sid, n);
	ngtcp2_conn_extend_max_offset(C.conn, n);
	return 0;
}

static int cb_end_stream(nghttp3_conn *h, int64_t sid, void *ud, void *sud)
{
	(void)h, (void)sid, (void)ud;
	if (sud != NULL)
		finish(req_of(sud));
	return 0;
}

static int cb_reset_stream(nghttp3_conn *h, int64_t sid, uint64_t code, void *ud, void *sud)
{
	(void)h, (void)ud;
	req *r = req_of(sud);
	if (r != NULL && !r->done)
		r->reset = (int64_t)code;
	ngtcp2_conn_shutdown_stream_write(C.conn, 0, sid, code);
	return 0;
}

static int cb_stop_sending(nghttp3_conn *h, int64_t sid, uint64_t code, void *ud, void *sud)
{
	(void)h, (void)ud, (void)sud;
	ngtcp2_conn_shutdown_stream_read(C.conn, 0, sid, code);
	return 0;
}

static int cb_stream_close(nghttp3_conn *h, int64_t sid, uint64_t code, void *ud, void *sud)
{
	(void)h, (void)sid, (void)ud;
	req *r = req_of(sud);
	if (r != NULL && !r->done) {
		if (r->reset < 0 && code != NGHTTP3_H3_NO_ERROR)
			r->reset = (int64_t)code;
		finish(r);
	}
	return 0;
}

static int cb_acked(nghttp3_conn *h, int64_t sid, uint64_t n, void *ud, void *sud)
{
	(void)h, (void)sid, (void)n, (void)ud, (void)sud;
	return 0;
}

static int cb_shutdown(nghttp3_conn *h, int64_t id, void *ud)
{
	(void)h, (void)id, (void)ud;
	C.goaway = true;
	return 0;
}

static nghttp3_ssize read_body(nghttp3_conn *h, int64_t sid, nghttp3_vec *vec, size_t veccnt, uint32_t *flags,
			       void *ud, void *sud)
{
	(void)h, (void)sid, (void)veccnt, (void)ud;
	req *r = req_of(sud);
	/* nghttp3 keeps the bytes until they are acknowledged, so they come from one immutable
	 * buffer: the pattern has period 256, and the window starting at off & 255 is the bytes. */
	static uint8_t pat[65536];
	if (pat[0] == 0)
		for (size_t i = 0; i < sizeof pat; i++)
			pat[i] = (uint8_t)((i * 31 + 7) & 0xff);
	uint64_t left = opt.body_size - r->up_off;
	size_t k = left < sizeof pat - 256 ? (size_t)left : sizeof pat - 256;
	vec[0].base = pat + (r->up_off & 255);
	vec[0].len = k;
	r->up_off += k;
	if (r->up_off == opt.body_size) {
		*flags |= NGHTTP3_DATA_FLAG_EOF;
		if (opt.ntrl > 0)
			*flags |= NGHTTP3_DATA_FLAG_NO_END_STREAM;
	}
	return 1;
}

static void split_field(const char *s, nghttp3_nv *nv)
{
	const char *c = strchr(s + (s[0] == ':'), ':'); /* ":path: /x" names a pseudo-header */
	if (c == NULL || c == s)
		die("bad field %s", s);
	nv->name = (uint8_t *)s;
	nv->namelen = (size_t)(c - s);
	c++;
	while (*c == ' ')
		c++;
	nv->value = (uint8_t *)c;
	nv->valuelen = strlen(c);
	nv->flags = NGHTTP3_NV_FLAG_NONE;
}

static nghttp3_nv mk(const char *n, const char *v)
{
	return (nghttp3_nv){ (uint8_t *)n, (uint8_t *)v, strlen(n), strlen(v), NGHTTP3_NV_FLAG_NONE };
}

static int submit(req *r)
{
	int64_t sid;
	int rv = ngtcp2_conn_open_bidi_stream(C.conn, &sid, NULL);
	if (rv != 0)
		return rv;
	r->id = sid;
	r->reset = -1;
	r->md = EVP_MD_CTX_new();
	EVP_DigestInit_ex(r->md, EVP_sha256(), NULL);
	static char clen[32];
	nghttp3_nv nva[MAXHDR + 6];
	size_t n = 0;
	char auth[300];
	snprintf(auth, sizeof auth, "%s", opt.sni);
	nva[n++] = mk(":method", opt.method);
	nva[n++] = mk(":scheme", "https");
	nva[n++] = mk(":authority", auth);
	nva[n++] = mk(":path", r->path);
	for (int i = 0; i < opt.nhdr; i++)
		split_field(opt.hdr[i], &nva[n++]);
	if (opt.body_size > 0 && opt.ntrl == 0) {
		snprintf(clen, sizeof clen, "%llu", (unsigned long long)opt.body_size);
		nva[n++] = mk("content-length", clen);
	}
	nghttp3_data_reader dr = { .read_data = read_body };
	rv = nghttp3_conn_submit_request(C.h3, sid, nva, n, opt.body_size > 0 ? &dr : NULL, r);
	if (rv != 0)
		die("submit_request: %s", nghttp3_strerror(rv));
	if (opt.ntrl > 0 && opt.body_size == 0)
		die("--trailer needs --body-size");
	return 0;
}

static void submit_trailers(void)
{
	if (opt.ntrl == 0)
		return;
	for (int i = 0; i < C.nreqs; i++) {
		req *r = &C.reqs[i];
		if (!r->rapid && r->id >= 0 && r->up_off == opt.body_size && !r->in_trailers) {
			nghttp3_nv nva[MAXHDR];
			for (int k = 0; k < opt.ntrl; k++)
				split_field(opt.trl[k], &nva[k]);
			r->in_trailers = true; /* reused as "trailers submitted" on the request side */
			nghttp3_conn_submit_trailers(C.h3, r->id, nva, (size_t)opt.ntrl);
		}
	}
}

static void submit_pending(void)
{
	while (C.next_req < C.nreqs) {
		req *r = &C.reqs[C.next_req];
		if (submit(r) != 0)
			break; /* stream limit: retried when extended */
		C.next_req++;
		if (r->rapid) {
			ngtcp2_conn_shutdown_stream(C.conn, 0, r->id, NGHTTP3_H3_REQUEST_CANCELLED);
			nghttp3_conn_shutdown_stream_write(C.h3, r->id);
			finish(r);
		}
	}
}

static int setup_h3(void)
{
	nghttp3_callbacks cb = {
		.acked_stream_data = cb_acked,
		.stream_close = cb_stream_close,
		.recv_data = cb_recv_data,
		.deferred_consume = cb_deferred_consume,
		.recv_header = cb_recv_header,
		.recv_trailer = cb_recv_trailer,
		.stop_sending = cb_stop_sending,
		.end_stream = cb_end_stream,
		.reset_stream = cb_reset_stream,
		.shutdown = cb_shutdown,
	};
	nghttp3_settings s;
	nghttp3_settings_default(&s);
	s.qpack_max_dtable_capacity = 4096;
	s.qpack_blocked_streams = 100;
	int rv = nghttp3_conn_client_new(&C.h3, &cb, &s, NULL, NULL);
	if (rv != 0)
		return rv;
	int64_t ctrl, qe, qd;
	if (ngtcp2_conn_open_uni_stream(C.conn, &ctrl, NULL) || nghttp3_conn_bind_control_stream(C.h3, ctrl))
		return -1;
	if (ngtcp2_conn_open_uni_stream(C.conn, &qe, NULL) || ngtcp2_conn_open_uni_stream(C.conn, &qd, NULL) ||
	    nghttp3_conn_bind_qpack_streams(C.h3, qe, qd))
		return -1;
	return 0;
}

/* ---- QUIC callbacks ---- */

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *ref)
{
	(void)ref;
	return C.conn;
}

static void rand_cb(uint8_t *d, size_t n, const ngtcp2_rand_ctx *c)
{
	(void)c;
	RAND_bytes(d, (int)n);
}

static int new_cid(ngtcp2_conn *c, ngtcp2_cid *cid, ngtcp2_stateless_reset_token *tok, size_t len, void *ud)
{
	(void)c, (void)ud;
	RAND_bytes(cid->data, (int)len);
	cid->datalen = len;
	RAND_bytes(tok->data, sizeof tok->data);
	return 0;
}

static int recv_stream_data(ngtcp2_conn *c, uint32_t flags, int64_t sid, uint64_t off, const uint8_t *d, size_t n,
			    void *ud, void *sud)
{
	(void)c, (void)off, (void)ud, (void)sud;
	nghttp3_ssize k = nghttp3_conn_read_stream2(C.h3, sid, d, n, flags & NGTCP2_STREAM_DATA_FLAG_FIN, now_ns());
	if (k < 0) {
		ngtcp2_ccerr_set_application_error(&C.err, nghttp3_err_infer_quic_app_error_code((int)k), NULL, 0);
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}
	ngtcp2_conn_extend_max_stream_offset(C.conn, sid, (uint64_t)k);
	ngtcp2_conn_extend_max_offset(C.conn, (uint64_t)k);
	return 0;
}

static int acked_offset(ngtcp2_conn *c, int64_t sid, uint64_t off, uint64_t n, void *ud, void *sud)
{
	(void)c, (void)off, (void)ud, (void)sud;
	return nghttp3_conn_add_ack_offset(C.h3, sid, n) == 0 ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
}

static int stream_close(ngtcp2_conn *c, uint32_t flags, int64_t sid, uint64_t code, void *ud, void *sud)
{
	(void)c, (void)ud, (void)sud;
	if (!(flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET))
		code = NGHTTP3_H3_NO_ERROR;
	int rv = nghttp3_conn_close_stream(C.h3, sid, code);
	return rv == 0 || rv == NGHTTP3_ERR_STREAM_NOT_FOUND ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
}

static int stream_reset(ngtcp2_conn *c, int64_t sid, uint64_t fs, uint64_t code, void *ud, void *sud)
{
	(void)c, (void)fs, (void)code, (void)ud, (void)sud;
	req *r = nghttp3_conn_get_stream_user_data(C.h3, sid);
	if (r != NULL && !r->done && r->reset < 0)
		r->reset = (int64_t)code;
	nghttp3_conn_shutdown_stream_read(C.h3, sid);
	return 0;
}

static int stream_stop_sending(ngtcp2_conn *c, int64_t sid, uint64_t code, void *ud, void *sud)
{
	(void)c, (void)code, (void)ud, (void)sud;
	nghttp3_conn_shutdown_stream_read(C.h3, sid);
	return 0;
}

static int extend_max_stream_data(ngtcp2_conn *c, int64_t sid, uint64_t max, void *ud, void *sud)
{
	(void)c, (void)max, (void)ud, (void)sud;
	nghttp3_conn_unblock_stream(C.h3, sid);
	return 0;
}

static int extend_streams(ngtcp2_conn *c, uint64_t max, void *ud)
{
	(void)c, (void)max, (void)ud;
	if (C.h3 != NULL && (C.handshake || C.early_sent))
		submit_pending();
	return 0;
}

static int handshake_completed(ngtcp2_conn *c, void *ud)
{
	(void)c, (void)ud;
	C.handshake = true;
	return C.h3 == NULL && setup_h3() != 0 ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}

/* HANDSHAKE_DONE arrived: only now may the client move (RFC 9000 section 9). */
static int handshake_confirmed(ngtcp2_conn *c, void *ud)
{
	(void)c, (void)ud;
	C.confirmed = true;
	return 0;
}

static int early_rejected(ngtcp2_conn *c, void *ud)
{
	(void)c, (void)ud;
	/* the 0-RTT requests are lost: start over once the handshake is done */
	nghttp3_conn_del(C.h3);
	C.h3 = NULL;
	for (int i = 0; i < C.nreqs; i++) {
		EVP_MD_CTX_free(C.reqs[i].md);
		C.reqs[i].md = NULL;
		C.reqs[i].id = -1;
		C.reqs[i].done = false;
		C.reqs[i].len = 0;
		C.reqs[i].up_off = 0;
		C.reqs[i].hlen = C.reqs[i].tlen = C.reqs[i].blen = 0;
	}
	C.ndone = 0;
	C.next_req = 0;
	C.early_sent = false;
	return setup_h3() == 0 ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
}

static int new_session(SSL *ssl, SSL_SESSION *sess)
{
	(void)ssl;
	C.ticket = true;
	if (opt.session == NULL)
		return 0;
	BIO *f = BIO_new_file(opt.session, "w");
	if (f != NULL) {
		PEM_write_bio_SSL_SESSION(f, sess);
		BIO_free(f);
	}
	uint8_t tp[256];
	ngtcp2_ssize n = ngtcp2_conn_encode_0rtt_transport_params(C.conn, tp, sizeof tp);
	if (n > 0) {
		char p[1024];
		snprintf(p, sizeof p, "%s.tp", opt.session);
		FILE *ft = fopen(p, "wb");
		if (ft != NULL) {
			fwrite(tp, 1, (size_t)n, ft);
			fclose(ft);
		}
	}
	return 0;
}

static bool load_session(void)
{
	if (opt.session == NULL)
		return false;
	BIO *f = BIO_new_file(opt.session, "r");
	if (f == NULL)
		return false;
	SSL_SESSION *s = PEM_read_bio_SSL_SESSION(f, NULL, NULL, NULL);
	BIO_free(f);
	if (s == NULL || !SSL_set_session(C.ssl, s)) {
		SSL_SESSION_free(s);
		return false;
	}
	bool early = opt.early && SSL_SESSION_get_max_early_data(s) != 0;
	SSL_SESSION_free(s);
	if (early)
		SSL_set_quic_tls_early_data_enabled(C.ssl, 1);
	return early;
}

static void setup_quic(void)
{
	ngtcp2_callbacks cb = {
		.client_initial = ngtcp2_crypto_client_initial_cb,
		.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
		.encrypt = ngtcp2_crypto_encrypt_cb,
		.decrypt = ngtcp2_crypto_decrypt_cb,
		.hp_mask = ngtcp2_crypto_hp_mask_cb,
		.recv_retry = ngtcp2_crypto_recv_retry_cb,
		.rand = rand_cb,
		.update_key = ngtcp2_crypto_update_key_cb,
		.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
		.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
		.version_negotiation = ngtcp2_crypto_version_negotiation_cb,
		.get_new_connection_id2 = new_cid,
		.get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb,
		.handshake_completed = handshake_completed,
		.handshake_confirmed = handshake_confirmed,
		.recv_stream_data = recv_stream_data,
		.acked_stream_data_offset = acked_offset,
		.stream_close = stream_close,
		.stream_reset = stream_reset,
		.stream_stop_sending = stream_stop_sending,
		.extend_max_stream_data = extend_max_stream_data,
		.extend_max_local_streams_bidi = extend_streams,
		.tls_early_data_rejected = early_rejected,
	};
	ngtcp2_cid dcid, scid;
	dcid.datalen = 18;
	RAND_bytes(dcid.data, (int)dcid.datalen);
	scid.datalen = 8;
	RAND_bytes(scid.data, (int)scid.datalen);
	ngtcp2_settings s;
	ngtcp2_settings_default(&s);
	s.initial_ts = now_ns();
	s.handshake_timeout = (uint64_t)opt.timeout_ms * NGTCP2_MILLISECONDS;
	static uint32_t vers[2];
	vers[0] = opt.version;
	vers[1] = opt.version == NGTCP2_PROTO_VER_V1 ? NGTCP2_PROTO_VER_V2 : NGTCP2_PROTO_VER_V1;
	s.available_versions = vers;
	s.available_versionslen = 2;
	s.preferred_versions = vers;
	s.preferred_versionslen = 2;
	ngtcp2_transport_params p;
	ngtcp2_transport_params_default(&p);
	p.initial_max_streams_uni = 3;
	p.initial_max_stream_data_bidi_local = opt.max_data;
	p.initial_max_stream_data_uni = 256 * 1024;
	p.initial_max_data = opt.max_data;
	p.max_idle_timeout = 30 * NGTCP2_SECONDS;
	ngtcp2_path path = { { (struct sockaddr *)&C.local, C.locallen }, { (struct sockaddr *)&C.remote, C.remotelen }, NULL };
	int rv = ngtcp2_conn_client_new(&C.conn, &dcid, &scid, &path, opt.version, &cb, &s, &p, NULL, NULL);
	if (rv != 0)
		die("client_new: %s", ngtcp2_strerror(rv));
}

static void setup_tls(void)
{
	if (ngtcp2_crypto_ossl_init() != 0)
		die("ngtcp2_crypto_ossl_init");
	C.sctx = SSL_CTX_new(TLS_client_method());
	SSL_CTX_set_min_proto_version(C.sctx, TLS1_3_VERSION);
	SSL_CTX_set_session_cache_mode(C.sctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
	SSL_CTX_sess_set_new_cb(C.sctx, new_session);
	SSL_CTX_set1_groups_list(C.sctx, "X25519MLKEM768:X25519:P-256");
	C.ssl = SSL_new(C.sctx);
	if (ngtcp2_crypto_ossl_ctx_new(&C.octx, C.ssl) != 0 || ngtcp2_crypto_ossl_configure_client_session(C.ssl) != 0)
		die("ossl client session");
	C.ref.get_conn = get_conn;
	SSL_set_app_data(C.ssl, &C.ref);
	SSL_set_connect_state(C.ssl);
	static const unsigned char alpn[] = "\x02h3";
	SSL_set_alpn_protos(C.ssl, alpn, sizeof alpn - 1);
	SSL_set_tlsext_host_name(C.ssl, opt.sni);
}

/* ---- I/O ---- */

static int write_out(void)
{
	uint8_t buf[1500 * 10];
	ngtcp2_path_storage ps;
	ngtcp2_path_storage_zero(&ps);
	ngtcp2_pkt_info pi;
	uint64_t ts = now_ns();
	for (int guard = 0; guard < 100000; guard++) {
		int64_t sid = -1;
		int fin = 0;
		nghttp3_vec vec[16];
		nghttp3_ssize nv = 0;
		if (C.h3 != NULL && ngtcp2_conn_get_max_data_left(C.conn) > 0) {
			nv = nghttp3_conn_writev_stream(C.h3, &sid, &fin, vec, 16);
			if (nv < 0)
				die("writev_stream: %s", nghttp3_strerror((int)nv));
		}
		uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE | (fin ? NGTCP2_WRITE_STREAM_FLAG_FIN : 0);
		ngtcp2_ssize wlen = -1;
		ngtcp2_ssize n = ngtcp2_conn_writev_stream(C.conn, &ps.path, &pi, buf, 1452, &wlen, flags, sid,
							   (ngtcp2_vec *)vec, (size_t)nv, ts);
		if (n < 0) {
			if (n == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
				nghttp3_conn_block_stream(C.h3, sid);
				continue;
			}
			if (n == NGTCP2_ERR_STREAM_SHUT_WR) {
				nghttp3_conn_shutdown_stream_write(C.h3, sid);
				continue;
			}
			if (n == NGTCP2_ERR_WRITE_MORE) {
				nghttp3_conn_add_write_offset(C.h3, sid, (size_t)wlen);
				continue;
			}
			ngtcp2_ccerr_set_liberr(&C.err, (int)n, NULL, 0);
			return -1;
		}
		if (wlen >= 0 && sid >= 0)
			nghttp3_conn_add_write_offset(C.h3, sid, (size_t)wlen);
		if (n == 0)
			return 0;
		send_pkt(buf, (size_t)n);
	}
	return 0;
}

static int read_in(void)
{
	uint8_t buf[65536];
	for (;;) {
		struct sockaddr_storage from;
		socklen_t fl = sizeof from;
		ssize_t n = recvfrom(C.fd, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl);
		if (n < 0) {
			if (errno == EAGAIN || errno == EINTR || errno == ECONNREFUSED)
				return 0;
			die("recv: %s", strerror(errno));
		}
		ngtcp2_path path = { { (struct sockaddr *)&C.local, C.locallen }, { (struct sockaddr *)&from, fl }, NULL };
		ngtcp2_pkt_info pi = { 0 };
		int rv = ngtcp2_conn_read_pkt(C.conn, &path, &pi, buf, (size_t)n, now_ns());
		if (rv != 0) {
			if (rv == NGTCP2_ERR_DRAINING || rv == NGTCP2_ERR_CLOSING)
				return -1;
			if (rv == NGTCP2_ERR_CRYPTO)
				ngtcp2_ccerr_set_tls_alert(&C.err, ngtcp2_conn_get_tls_alert2(C.conn), NULL, 0);
			else if (C.err.error_code == 0)
				ngtcp2_ccerr_set_liberr(&C.err, rv, NULL, 0);
			snprintf(C.close_reason, sizeof C.close_reason, "read_pkt: %s", ngtcp2_strerror(rv));
			return -1;
		}
	}
}

static void close_conn(void)
{
	if (ngtcp2_conn_in_closing_period2(C.conn) || ngtcp2_conn_in_draining_period2(C.conn))
		return;
	uint8_t buf[1500];
	ngtcp2_path_storage ps;
	ngtcp2_path_storage_zero(&ps);
	ngtcp2_pkt_info pi;
	if (C.err.error_code == 0 && C.err.type == NGTCP2_CCERR_TYPE_TRANSPORT)
		ngtcp2_ccerr_set_application_error(&C.err, NGHTTP3_H3_NO_ERROR, NULL, 0);
	ngtcp2_ssize n = ngtcp2_conn_write_connection_close(C.conn, &ps.path, &pi, buf, sizeof buf, &C.err, now_ns());
	if (n > 0)
		send_pkt(buf, (size_t)n);
}

static void parse_args(int argc, char **argv)
{
	opt.sni = "localhost";
	opt.method = "GET";
	opt.version = NGTCP2_PROTO_VER_V1;
	opt.repeat = 1;
	opt.timeout_ms = 30000;
	opt.max_data = 16u << 20;
	int i = 1;
	for (; i < argc && strncmp(argv[i], "--", 2) == 0; i++) {
		const char *a = argv[i];
#define ARG() (i + 1 < argc ? argv[++i] : (die("%s needs a value", a), ""))
		if (!strcmp(a, "--sni"))
			opt.sni = ARG();
		else if (!strcmp(a, "--session"))
			opt.session = ARG();
		else if (!strcmp(a, "--early"))
			opt.early = true;
		else if (!strcmp(a, "--version"))
			opt.version = !strcmp(ARG(), "v2") ? NGTCP2_PROTO_VER_V2 : NGTCP2_PROTO_VER_V1;
		else if (!strcmp(a, "--method"))
			opt.method = ARG();
		else if (!strcmp(a, "--body-size"))
			opt.body_size = strtoull(ARG(), NULL, 10);
		else if (!strcmp(a, "--header") && opt.nhdr < MAXHDR)
			opt.hdr[opt.nhdr++] = ARG();
		else if (!strcmp(a, "--trailer") && opt.ntrl < MAXHDR)
			opt.trl[opt.ntrl++] = ARG();
		else if (!strcmp(a, "--repeat"))
			opt.repeat = (unsigned)atoi(ARG());
		else if (!strcmp(a, "--rebind-after-handshake"))
			opt.rebind_hs = true;
		else if (!strcmp(a, "--rebind-after"))
			opt.rebind_after = strtoull(ARG(), NULL, 10);
		else if (!strcmp(a, "--cancel-after"))
			opt.cancel_after = strtoull(ARG(), NULL, 10);
		else if (!strcmp(a, "--rapid-reset"))
			opt.rapid = (unsigned)atoi(ARG());
		else if (!strcmp(a, "--close-control"))
			opt.close_control = true;
		else if (!strcmp(a, "--max-data"))
			opt.max_data = strtoull(ARG(), NULL, 10);
		else if (!strcmp(a, "--timeout"))
			opt.timeout_ms = atoi(ARG());
		else if (!strcmp(a, "--wait-ticket"))
			opt.wait_ticket = true;
		else if (!strcmp(a, "--print-body"))
			opt.print_body = true;
		else
			die("unknown option %s", a);
#undef ARG
	}
	if (argc - i < 2)
		die("usage: h3client [options] HOST PORT [PATH...]");
	opt.host = argv[i++];
	opt.port = argv[i++];
	for (; i < argc && opt.npaths < MAXREQ; i++)
		opt.paths[opt.npaths++] = argv[i];
}

int main(int argc, char **argv)
{
	parse_args(argc, argv);
	struct addrinfo hints = { .ai_socktype = SOCK_DGRAM }, *res;
	if (getaddrinfo(opt.host, opt.port, &hints, &res) != 0)
		die("getaddrinfo %s", opt.host);
	memcpy(&C.remote, res->ai_addr, res->ai_addrlen);
	C.remotelen = res->ai_addrlen;
	freeaddrinfo(res);
	C.fd = new_socket();
	ngtcp2_ccerr_default(&C.err);

	for (unsigned k = 0; k < opt.rapid && C.nreqs < MAXREQ; k++) {
		C.reqs[C.nreqs].path = opt.paths[0] != NULL ? opt.paths[0] : "/";
		C.reqs[C.nreqs].rapid = true;
		C.reqs[C.nreqs++].id = -1;
	}
	for (unsigned rep = 0; rep < opt.repeat; rep++)
		for (int k = 0; k < opt.npaths && C.nreqs < MAXREQ; k++) {
			C.reqs[C.nreqs].path = opt.paths[k];
			C.reqs[C.nreqs++].id = -1;
		}

	setup_tls();
	setup_quic();
	ngtcp2_conn_set_tls_native_handle(C.conn, C.octx);
	bool early = load_session();
	bool early_attempted = false;
	if (early) {
		char p[1024];
		snprintf(p, sizeof p, "%s.tp", opt.session);
		FILE *ft = fopen(p, "rb");
		uint8_t tp[256];
		size_t tn = ft != NULL ? fread(tp, 1, sizeof tp, ft) : 0;
		if (ft != NULL)
			fclose(ft);
		if (tn > 0 && ngtcp2_conn_decode_and_set_0rtt_transport_params(C.conn, tp, tn) == 0) {
			if (setup_h3() != 0)
				die("h3 setup");
			C.early_sent = early_attempted = true;
			submit_pending();
		}
	}

	uint64_t deadline = now_ns() + (uint64_t)opt.timeout_ms * NGTCP2_MILLISECONDS;
	uint64_t ticket_deadline = 0;
	int rc = 0;
	for (;;) {
		if (C.confirmed && opt.rebind_hs && !C.rebound)
			rebind();
		if (C.handshake && C.h3 == NULL) {
			if (setup_h3() != 0)
				die("h3 setup");
		}
		if (C.handshake && C.h3 != NULL) {
			submit_pending();
			submit_trailers();
			if (opt.close_control && !C.control_closed) {
				C.control_closed = true;
				ngtcp2_conn_shutdown_stream_write(C.conn, 0, 2, 0); /* client control stream id 2 */
			}
		}
		if (write_out() != 0)
			break;
		bool all = C.handshake && C.ndone == C.nreqs && C.next_req == C.nreqs;
		if (all && !opt.wait_ticket)
			break;
		if (all && opt.wait_ticket) {
			if (C.ticket)
				break;
			if (ticket_deadline == 0)
				ticket_deadline = now_ns() + NGTCP2_SECONDS;
			else if (now_ns() > ticket_deadline)
				break;
		}
		if (C.goaway && C.next_req == C.nreqs && C.ndone == C.nreqs)
			break;
		uint64_t now = now_ns(), exp = ngtcp2_conn_get_expiry2(C.conn);
		if (now >= deadline) {
			snprintf(C.close_reason, sizeof C.close_reason, "timeout");
			rc = 1;
			break;
		}
		int wait = exp <= now ? 0 : (int)((exp - now) / NGTCP2_MILLISECONDS) + 1;
		int dl = (int)((deadline - now) / NGTCP2_MILLISECONDS) + 1;
		if (wait > dl)
			wait = dl;
		if (wait > 50 && opt.wait_ticket && all)
			wait = 50;
		struct pollfd pf = { .fd = C.fd, .events = POLLIN };
		int pr = poll(&pf, 1, wait);
		if (pr > 0 && read_in() != 0)
			break;
		if (ngtcp2_conn_get_expiry2(C.conn) <= now_ns()) {
			int rv = ngtcp2_conn_handle_expiry(C.conn, now_ns());
			if (rv != 0) {
				snprintf(C.close_reason, sizeof C.close_reason, "expiry: %s", ngtcp2_strerror(rv));
				break;
			}
		}
	}
	const ngtcp2_ccerr *peer = ngtcp2_conn_get_ccerr(C.conn);
	close_conn();
	const unsigned char *alpn = NULL;
	unsigned alen = 0;
	SSL_get0_alpn_selected(C.ssl, &alpn, &alen);
	const char *group = SSL_group_to_name(C.ssl, SSL_get_negotiated_group(C.ssl));
	printf("{\"type\":\"conn\",\"handshake\":%s,\"alpn\":", C.handshake ? "true" : "false");
	json_str(stdout, (const char *)(alpn ? alpn : (const unsigned char *)""), alen);
	printf(",\"group\":");
	json_str(stdout, group ? group : "", group ? strlen(group) : 0);
	printf(",\"resumed\":%s,\"early_attempted\":%s,\"early_accepted\":%s,\"version\":%u,\"ticket\":%s,"
	       "\"rebound\":%s,\"goaway\":%s,\"ports\":[",
	       SSL_session_reused(C.ssl) ? "true" : "false", early_attempted ? "true" : "false",
	       early_attempted && SSL_get_early_data_status(C.ssl) == SSL_EARLY_DATA_ACCEPTED ? "true" : "false",
	       ngtcp2_conn_get_negotiated_version(C.conn), C.ticket ? "true" : "false", C.rebound ? "true" : "false",
	       C.goaway ? "true" : "false");
	for (int i = 0; i < C.nports; i++)
		printf("%s%d", i ? "," : "", C.ports[i]);
	printf("],\"peer_error\":{\"type\":%d,\"code\":%llu},\"done\":%d,\"requests\":%d,\"reason\":", (int)peer->type,
	       (unsigned long long)peer->error_code, C.ndone, C.nreqs);
	json_str(stdout, C.close_reason, strlen(C.close_reason));
	printf("}\n");
	fflush(stdout);
	if (!C.handshake || C.ndone != C.nreqs)
		rc = 1;
	return rc;
}
