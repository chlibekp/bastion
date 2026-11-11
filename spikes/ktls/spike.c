/* kTLS behaviour spike (Phase 6 Task 1). Throwaway: not part of the release build.
 *
 * One process forks a client (blocking user-space OpenSSL) and a server (non-blocking, socket BIO,
 * SSL_OP_ENABLE_KTLS), over loopback TCP, and reports what the server observes.
 *
 *   spike matrix  CERT KEY            kTLS TX/RX activation per version and cipher
 *   spike keyupdate CERT KEY MODE     MODE: tx12|plain|requested : client KeyUpdate, RX/TX on
 *   spike ticket  CERT KEY            NewSessionTicket with kTLS TX, then resumption
 *   spike alert   CERT KEY            client close_notify with RX in the kernel
 *   spike sendfile CERT KEY           SSL_sendfile vs sendfile(2) on a kTLS TX socket
 *   spike bench   CERT KEY MODE       MODE: user|tx|txrx  small and large throughput
 *
 * Build: clang -O1 -D_GNU_SOURCE spike.c $(pkg-config --cflags --libs --static openssl) -o spike
 * Run in the VM tier (modprobe tls first): scripts/vm-run.sh build/spike/ktls matrix CERT KEY */
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <stdbool.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const char *g_cert, *g_key;

static double now(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

static void die(const char *m)
{
	fprintf(stderr, "spike: %s\n", m);
	ERR_print_errors_fp(stderr);
	exit(2);
}

static int listen_sock(int *port)
{
	int s = socket(AF_INET, SOCK_STREAM, 0), one = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
	struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	if (bind(s, (struct sockaddr *)&a, sizeof a) != 0 || listen(s, 4) != 0)
		die("bind");
	socklen_t l = sizeof a;
	getsockname(s, (struct sockaddr *)&a, &l);
	*port = ntohs(a.sin_port);
	return s;
}

/* TLS 1.3 installs the write (application) key with the server Finished and the read key only after
 * the client Finished, so turning SSL_OP_ENABLE_KTLS off once TX is up leaves RX in user space. TLS 1.2
 * installs RX first and OpenSSL 3.5 has no per-direction option: there RX goes to the kernel too. */
static void tx_only_cb(const SSL *cs, int where, int ret)
{
	SSL *ssl = (SSL *)cs;
	(void)ret;
	if ((where & SSL_CB_ACCEPT_LOOP) && SSL_version(ssl) == TLS1_3_VERSION &&
	    BIO_get_ktls_send(SSL_get_wbio(ssl)))
		SSL_clear_options(ssl, SSL_OP_ENABLE_KTLS);
}

static SSL_CTX *server_ctx(int ver, const char *suite12, const char *suite13, bool ktls)
{
	SSL_CTX *c = SSL_CTX_new(TLS_server_method());
	SSL_CTX_set_min_proto_version(c, ver);
	SSL_CTX_set_max_proto_version(c, ver);
	if (suite12)
		SSL_CTX_set_cipher_list(c, suite12);
	if (suite13)
		SSL_CTX_set_ciphersuites(c, suite13);
	if (ktls)
		SSL_CTX_set_options(c, SSL_OP_ENABLE_KTLS);
	if (ktls && getenv("SPIKE_NORX")) { /* kTLS TX only: OpenSSL 3.5 has no per-direction option */
		SSL_CTX_set_info_callback(c, tx_only_cb);
	}
	SSL_CTX_set_mode(c, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
	if (SSL_CTX_use_certificate_chain_file(c, g_cert) != 1 || SSL_CTX_use_PrivateKey_file(c, g_key, SSL_FILETYPE_PEM) != 1)
		die("cert");
	return c;
}

static SSL_CTX *client_ctx(int ver, const char *suite12, const char *suite13)
{
	SSL_CTX *c = SSL_CTX_new(TLS_client_method());
	SSL_CTX_set_min_proto_version(c, ver);
	SSL_CTX_set_max_proto_version(c, ver);
	if (suite12)
		SSL_CTX_set_cipher_list(c, suite12);
	if (suite13)
		SSL_CTX_set_ciphersuites(c, suite13);
	SSL_CTX_set_session_cache_mode(c, SSL_SESS_CACHE_CLIENT);
	return c;
}

static int connect_to(int port)
{
	int s = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons((uint16_t)port),
				 .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	if (connect(s, (struct sockaddr *)&a, sizeof a) != 0)
		die("connect");
	return s;
}

/* Non-blocking server accept + handshake with poll(2): the shape of the real worker. */
static SSL *server_accept(SSL_CTX *ctx, int ls)
{
	int fd = accept(ls, NULL, NULL);
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
	SSL *ssl = SSL_new(ctx);
	SSL_set_fd(ssl, fd);
	for (;;) {
		int rc = SSL_accept(ssl);
		if (rc == 1)
			return ssl;
		int e = SSL_get_error(ssl, rc);
		struct pollfd p = { fd, e == SSL_ERROR_WANT_WRITE ? POLLOUT : POLLIN, 0 };
		if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) {
			fprintf(stderr, "server handshake failed: %d\n", e);
			ERR_print_errors_fp(stderr);
			return NULL;
		}
		poll(&p, 1, 5000);
	}
}

/* returns >0 bytes, 0 closed (ZERO_RETURN), -1 error, with *why set */
static ssize_t srv_read(SSL *ssl, void *b, size_t n, int *why)
{
	int fd = SSL_get_fd(ssl);
	for (;;) {
		int rc = SSL_read(ssl, b, (int)n);
		if (rc > 0)
			return rc;
		int e = SSL_get_error(ssl, rc);
		*why = e;
		if (e == SSL_ERROR_ZERO_RETURN)
			return 0;
		if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE)
			return -1;
		struct pollfd p = { fd, e == SSL_ERROR_WANT_WRITE ? POLLOUT : POLLIN, 0 };
		if (poll(&p, 1, 5000) == 0) {
			*why = -999;
			return -1;
		}
	}
}

static int srv_write_all(SSL *ssl, const char *b, size_t n)
{
	int fd = SSL_get_fd(ssl);
	while (n > 0) {
		int rc = SSL_write(ssl, b, (int)n);
		if (rc > 0) {
			b += rc;
			n -= (size_t)rc;
			continue;
		}
		int e = SSL_get_error(ssl, rc);
		if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE)
			return -e;
		struct pollfd p = { fd, e == SSL_ERROR_WANT_WRITE ? POLLOUT : POLLIN, 0 };
		poll(&p, 1, 5000);
	}
	return 0;
}

static const char *ktls_state(SSL *ssl)
{
	static char b[32];
	snprintf(b, sizeof b, "tx=%d rx=%d", BIO_get_ktls_send(SSL_get_wbio(ssl)),
		 BIO_get_ktls_recv(SSL_get_rbio(ssl)));
	if (getenv("SPIKE_DEBUG")) {
		fprintf(stderr, "opts ktls=%d bio=%s errq=%lu cipher=%s\n", !!(SSL_get_options(ssl) & SSL_OP_ENABLE_KTLS),
			BIO_method_name(SSL_get_wbio(ssl)), ERR_peek_error(), SSL_get_cipher(ssl));
	}
	return b;
}

static void cli_read_exact(SSL *c, size_t n)
{
	char b[65536];
	while (n > 0) {
		int rc = SSL_read(c, b, (int)(n < sizeof b ? n : sizeof b));
		if (rc <= 0)
			die("client read");
		n -= (size_t)rc;
	}
}

/* ---- matrix ---- */
static void do_matrix(void)
{
	struct { const char *name; int ver; const char *s12, *s13; } cases[] = {
		{ "TLS1.2 AES128-GCM", TLS1_2_VERSION, "ECDHE-ECDSA-AES128-GCM-SHA256", NULL },
		{ "TLS1.2 AES256-GCM", TLS1_2_VERSION, "ECDHE-ECDSA-AES256-GCM-SHA384", NULL },
		{ "TLS1.2 CHACHA20", TLS1_2_VERSION, "ECDHE-ECDSA-CHACHA20-POLY1305", NULL },
		{ "TLS1.3 AES128-GCM", TLS1_3_VERSION, NULL, "TLS_AES_128_GCM_SHA256" },
		{ "TLS1.3 AES256-GCM", TLS1_3_VERSION, NULL, "TLS_AES_256_GCM_SHA384" },
		{ "TLS1.3 CHACHA20", TLS1_3_VERSION, NULL, "TLS_CHACHA20_POLY1305_SHA256" },
	};
	for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
		int port, ls = listen_sock(&port);
		pid_t pid = fork();
		if (pid == 0) {
			SSL *c = SSL_new(client_ctx(cases[i].ver, cases[i].s12, cases[i].s13));
			SSL_set_fd(c, connect_to(port));
			if (SSL_connect(c) != 1)
				die("client connect");
			SSL_write(c, "ping", 4);
			char b[8];
			int n = SSL_read(c, b, 4);
			_exit(n == 4 && memcmp(b, "pong", 4) == 0 ? 0 : 3);
		}
		SSL *s = server_accept(server_ctx(cases[i].ver, cases[i].s12, cases[i].s13, true), ls);
		char b[16];
		int why = 0;
		ssize_t n = s ? srv_read(s, b, sizeof b, &why) : -1;
		int w = n > 0 ? srv_write_all(s, "pong", 4) : -1;
		printf("%-20s %s read=%zd write=%d\n", cases[i].name, s ? ktls_state(s) : "handshake-failed", n, w);
		int st;
		waitpid(pid, &st, 0);
		printf("%-20s client exit %d\n", "", WEXITSTATUS(st));
		if (s)
			SSL_free(s);
		close(ls);
	}
}

/* ---- keyupdate ---- */
static void do_keyupdate(const char *mode)
{
	int ver = strcmp(mode, "tx12") == 0 ? TLS1_2_VERSION : TLS1_3_VERSION;
	int port, ls = listen_sock(&port);
	pid_t pid = fork();
	bool requested = strcmp(mode, "requested") == 0;
	if (pid == 0) {
		SSL *c = SSL_new(client_ctx(ver, NULL, NULL));
		SSL_set_fd(c, connect_to(port));
		if (SSL_connect(c) != 1)
			die("client connect");
		SSL_write(c, "one", 3);
		if (ver == TLS1_3_VERSION &&
		    SSL_key_update(c, requested ? SSL_KEY_UPDATE_REQUESTED : SSL_KEY_UPDATE_NOT_REQUESTED) != 1)
			die("key_update");
		int w = SSL_write(c, "two", 3);
		char b[16];
		int n = SSL_read(c, b, sizeof b);
		fprintf(stderr, "client: after KeyUpdate(%s): write=%d read=%d err=%d\n", mode, w, n,
			n > 0 ? 0 : SSL_get_error(c, n));
		_exit(0);
	}
	SSL *s = server_accept(server_ctx(ver, NULL, NULL, true), ls);
	printf("server %s\n", s ? ktls_state(s) : "handshake-failed");
	char b[16];
	int why = 0;
	for (int i = 0; i < 2 && s; i++) {
		ssize_t n = srv_read(s, b, sizeof b, &why);
		printf("server read #%d: %zd (SSL_get_error %d)\n", i + 1, n, why);
		if (n < 0)
			ERR_print_errors_fp(stdout);
		if (n <= 0)
			break;
	}
	int w = s ? srv_write_all(s, "reply", 5) : -1;
	printf("server write after KeyUpdate: %d\n", w);
	if (w != 0)
		ERR_print_errors_fp(stdout);
	waitpid(pid, NULL, 0);
}

/* ---- ticket ---- */
static void do_ticket(void)
{
	SSL_CTX *cc = client_ctx(TLS1_3_VERSION, NULL, NULL);
	SSL_SESSION *sess = NULL;
	for (int round = 0; round < 2; round++) {
		int port, ls = listen_sock(&port);
		pid_t pid = fork();
		if (pid == 0) {
			SSL *c = SSL_new(cc);
			if (sess)
				SSL_set_session(c, sess);
			SSL_set_fd(c, connect_to(port));
			if (SSL_connect(c) != 1)
				die("client connect");
			char b[16];
			SSL_write(c, "x", 1);
			int n = SSL_read(c, b, sizeof b);
			fprintf(stderr, "client round %d: reused=%d read=%d\n", round, SSL_session_reused(c), n);
			FILE *f = fopen("/tmp/spike-sess", "w");
			SSL_SESSION *s2 = SSL_get1_session(c);
			if (f && s2)
				PEM_write_SSL_SESSION(f, s2);
			if (f)
				fclose(f);
			_exit(0);
		}
		SSL_CTX *sc = server_ctx(TLS1_3_VERSION, NULL, NULL, true);
		SSL *s = server_accept(sc, ls);
		char b[8];
		int why;
		srv_read(s, b, sizeof b, &why);
		int w = srv_write_all(s, "ok", 2);
		printf("round %d server %s write=%d reused=%d\n", round, ktls_state(s), w, SSL_session_reused(s));
		waitpid(pid, NULL, 0);
		FILE *f = fopen("/tmp/spike-sess", "r");
		if (f) {
			sess = PEM_read_SSL_SESSION(f, NULL, NULL, NULL);
			fclose(f);
		}
		close(ls);
	}
	puts("note: each round forks a fresh server SSL_CTX, so resumption needs shared ticket keys; "
	     "the number above that matters is the write result with tickets sent under kTLS TX");
}

/* ---- alert ---- */
static void do_alert(void)
{
	int port, ls = listen_sock(&port);
	pid_t pid = fork();
	if (pid == 0) {
		SSL *c = SSL_new(client_ctx(TLS1_3_VERSION, NULL, NULL));
		SSL_set_fd(c, connect_to(port));
		if (SSL_connect(c) != 1)
			die("client connect");
		SSL_write(c, "bye", 3);
		SSL_shutdown(c); /* close_notify */
		_exit(0);
	}
	SSL *s = server_accept(server_ctx(TLS1_3_VERSION, NULL, NULL, true), ls);
	printf("server %s\n", ktls_state(s));
	char b[16];
	int why = 0;
	ssize_t n = srv_read(s, b, sizeof b, &why);
	printf("read #1: %zd\n", n);
	n = srv_read(s, b, sizeof b, &why);
	printf("read #2 after close_notify: %zd SSL_get_error=%d (ZERO_RETURN=%d)\n", n, why, SSL_ERROR_ZERO_RETURN);
	int rc = SSL_shutdown(s);
	printf("server SSL_shutdown: %d\n", rc);
	waitpid(pid, NULL, 0);
}

/* ---- sendfile ---- */
static void do_sendfile(void)
{
	const size_t len = 8u << 20;
	char path[] = "/tmp/spike-fileXXXXXX";
	int fd = mkstemp(path);
	char *buf = malloc(len);
	for (size_t i = 0; i < len; i++)
		buf[i] = (char)(i * 131 + (i >> 8));
	if (write(fd, buf, len) != (ssize_t)len)
		die("write file");
	for (int mode = 0; mode < 2; mode++) {
		int port, ls = listen_sock(&port);
		pid_t pid = fork();
		if (pid == 0) {
			SSL *c = SSL_new(client_ctx(TLS1_3_VERSION, NULL, NULL));
			SSL_set_fd(c, connect_to(port));
			if (SSL_connect(c) != 1)
				die("client connect");
			char *got = malloc(len);
			size_t off = 0;
			while (off < len) {
				int n = SSL_read(c, got + off, (int)(len - off));
				if (n <= 0)
					break;
				off += (size_t)n;
			}
			fprintf(stderr, "client %s: got %zu of %zu bytes, identical=%d\n",
				mode ? "sendfile(2)" : "SSL_sendfile", off, len, off == len && memcmp(got, buf, len) == 0);
			_exit(0);
		}
		SSL *s = server_accept(server_ctx(TLS1_3_VERSION, NULL, NULL, true), ls);
		printf("server %s\n", ktls_state(s));
		double t = now();
		off_t off = 0;
		long long sent = 0;
		int sfd = SSL_get_fd(s);
		if (mode == 0) {
			while ((size_t)sent < len) {
				ossl_ssize_t n = SSL_sendfile(s, fd, off, len - (size_t)sent, 0);
				if (n < 0) {
					int e = SSL_get_error(s, (int)n);
					if (e == SSL_ERROR_WANT_WRITE) {
						struct pollfd p = { sfd, POLLOUT, 0 };
						poll(&p, 1, 5000);
						continue;
					}
					printf("SSL_sendfile error %d errno=%s\n", e, strerror(errno));
					ERR_print_errors_fp(stdout);
					break;
				}
				off += n;
				sent += n;
			}
		} else {
			while ((size_t)sent < len) {
				ssize_t n = sendfile(sfd, fd, &off, len - (size_t)sent);
				if (n < 0) {
					if (errno == EAGAIN) {
						struct pollfd p = { sfd, POLLOUT, 0 };
						poll(&p, 1, 5000);
						continue;
					}
					printf("sendfile(2) error %s\n", strerror(errno));
					break;
				}
				sent += n;
			}
		}
		printf("%s: sent %lld bytes in %.3fs\n", mode ? "sendfile(2)" : "SSL_sendfile", sent, now() - t);
		shutdown(sfd, SHUT_WR);
		waitpid(pid, NULL, 0);
		close(ls);
	}
}

/* ---- bench ---- */
static void do_bench(const char *mode)
{
	bool tx = strcmp(mode, "user") != 0;
	bool rx = strcmp(mode, "txrx") == 0;
	if (tx && !rx)
		setenv("SPIKE_NORX", "1", 1);
	int port, ls = listen_sock(&port);
	const int small_n = 20000, small_len = 1024;
	const size_t big = 64u << 20;
	pid_t pid = fork();
	if (pid == 0) { /* client: reads small responses, then big, then uploads big */
		SSL *c = SSL_new(client_ctx(TLS1_3_VERSION, NULL, NULL));
		SSL_set_fd(c, connect_to(port));
		if (SSL_connect(c) != 1)
			die("client connect");
		for (int i = 0; i < small_n; i++) {
			SSL_write(c, "r", 1);
			cli_read_exact(c, small_len);
		}
		SSL_write(c, "B", 1);
		cli_read_exact(c, big);
		char *blk = calloc(1, 65536);
		for (size_t sent = 0; sent < big; sent += 65536)
			SSL_write(c, blk, 65536);
		SSL_read(c, blk, 1);
		_exit(0);
	}
	SSL *s = server_accept(server_ctx(TLS1_3_VERSION, NULL, NULL, tx), ls);
	/* ENABLE_KTLS covers TX and RX; RX is turned off for `tx` by SSL_OP_NO_RX_KTLS where supported */
	printf("mode %s: %s\n", mode, ktls_state(s));
	(void)rx;
	char b[65536], *resp = calloc(1, 65536);
	int why;
	double t = now();
	for (int i = 0; i < small_n; i++) {
		if (srv_read(s, b, 1, &why) != 1 || srv_write_all(s, resp, small_len) != 0)
			die("small");
	}
	double t_small = now() - t;
	srv_read(s, b, 1, &why);
	t = now();
	for (size_t sent = 0; sent < big; sent += 65536)
		if (srv_write_all(s, resp, 65536) != 0)
			die("big");
	double t_big = now() - t;
	t = now();
	size_t got = 0;
	while (got < big) {
		ssize_t n = srv_read(s, b, sizeof b, &why);
		if (n <= 0)
			break;
		got += (size_t)n;
	}
	double t_up = now() - t;
	srv_write_all(s, "k", 1);
	printf("  small: %d x %d B in %.3fs = %.0f req/s\n", small_n, small_len, t_small, small_n / t_small);
	printf("  download: %zu MiB in %.3fs = %.1f MiB/s\n", big >> 20, t_big, (double)(big >> 20) / t_big);
	printf("  upload:   %zu MiB in %.3fs = %.1f MiB/s\n", got >> 20, t_up, (double)(got >> 20) / t_up);
	waitpid(pid, NULL, 0);
}

int main(int argc, char **argv)
{
	signal(SIGPIPE, SIG_IGN);
	if (argc < 4) {
		fprintf(stderr, "usage: spike matrix|keyupdate|ticket|alert|sendfile|bench CERT KEY [MODE]\n");
		return 2;
	}
	g_cert = argv[2];
	g_key = argv[3];
	const char *m = argv[1];
	if (strcmp(m, "matrix") == 0)
		do_matrix();
	else if (strcmp(m, "keyupdate") == 0 && argc > 4)
		do_keyupdate(argv[4]);
	else if (strcmp(m, "ticket") == 0)
		do_ticket();
	else if (strcmp(m, "alert") == 0)
		do_alert();
	else if (strcmp(m, "sendfile") == 0)
		do_sendfile();
	else if (strcmp(m, "bench") == 0 && argc > 4)
		do_bench(argv[4]);
	else
		return 2;
	return 0;
}
