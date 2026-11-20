/* See http_client.h. */
#include "ops/http_client.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/epoll.h>
#include <time.h>
#include <unistd.h>

static void seterr(char *err, size_t cap, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void seterr(char *err, size_t cap, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(err, cap, fmt, ap);
	va_end(ap);
}

static uint64_t mono_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

bool bst_hc_parse_url(const char *url, bool *tls, char *host, size_t hcap, uint16_t *port,
		      char *path, size_t pcap)
{
	const char *p;
	if (strncmp(url, "https://", 8) == 0) {
		*tls = true;
		*port = 443;
		p = url + 8;
	} else if (strncmp(url, "http://", 7) == 0) {
		*tls = false;
		*port = 80;
		p = url + 7;
	} else {
		return false;
	}
	size_t hl = strcspn(p, "/?#");
	const char *hend = p + hl;
	const char *h = p, *colon = NULL;
	size_t n;
	if (*h == '[') {
		const char *rb = memchr(h, ']', hl);
		if (rb == NULL)
			return false;
		h++;
		n = (size_t)(rb - h);
		if (rb + 1 < hend) {
			if (rb[1] != ':')
				return false;
			colon = rb + 1;
		}
	} else {
		colon = memchr(h, ':', hl);
		n = colon != NULL ? (size_t)(colon - h) : hl;
	}
	if (n == 0 || n >= hcap)
		return false;
	for (size_t i = 0; i < n; i++)
		if (h[i] <= ' ' || h[i] == '@' || (unsigned char)h[i] >= 0x7f)
			return false; /* no userinfo, no spaces, no controls */
	memcpy(host, h, n);
	host[n] = '\0';
	if (colon != NULL) {
		unsigned long v = 0;
		const char *q = colon + 1;
		if (q == hend || hend - q > 5)
			return false;
		for (; q < hend; q++) {
			if (*q < '0' || *q > '9')
				return false;
			v = v * 10 + (unsigned long)(*q - '0');
		}
		if (v == 0 || v > 65535)
			return false;
		*port = (uint16_t)v;
	}
	const char *rest = *hend == '\0' ? "/" : hend;
	if (*rest == '#')
		rest = "/";
	size_t rl = strcspn(rest, "#");
	if (rl + (rest[0] == '?') + 1 > pcap)
		return false;
	size_t o = 0;
	if (rest[0] == '?')
		path[o++] = '/';
	memcpy(path + o, rest, rl);
	path[o + rl] = '\0';
	for (size_t i = 0; path[i] != '\0'; i++)
		if ((unsigned char)path[i] <= ' ' || (unsigned char)path[i] >= 0x7f)
			return false; /* no request splitting */
	return true;
}

int bst_hc_open(bst_hc *c, const char *url, const char *ca_file, int timeout_ms, char *err, size_t ecap)
{
	memset(c, 0, sizeof *c);
	c->ep = -1;
	c->timeout_ms = timeout_ms;
	char longpath[2048];
	if (!bst_hc_parse_url(url, &c->tls, c->host, sizeof c->host, &c->port, longpath, sizeof longpath)) {
		seterr(err, ecap, "not an http(s) URL: %s", url);
		return -1;
	}
	struct addrinfo hints = { .ai_socktype = SOCK_STREAM, .ai_family = AF_UNSPEC }, *res = NULL;
	char port[8];
	snprintf(port, sizeof port, "%u", (unsigned)c->port);
	int rc = getaddrinfo(c->host, port, &hints, &res);
	if (rc != 0 || res == NULL) {
		seterr(err, ecap, "resolving %s: %s", c->host, gai_strerror(rc));
		return -1;
	}
	memcpy(&c->addr, res->ai_addr, res->ai_addrlen);
	c->alen = res->ai_addrlen;
	freeaddrinfo(res);
	c->ep = epoll_create1(EPOLL_CLOEXEC);
	if (c->ep < 0) {
		seterr(err, ecap, "epoll_create1: %s", strerror(errno));
		return -1;
	}
	if (!c->tls)
		return 0;
	SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
	if (ctx == NULL) {
		seterr(err, ecap, "SSL_CTX_new failed");
		bst_hc_close(c);
		return -1;
	}
	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
	SSL_CTX_set_options(ctx, SSL_OP_IGNORE_UNEXPECTED_EOF | SSL_OP_NO_TICKET);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	/* A file, read now: a hashed directory would be read at verify time, inside the sandbox. */
	const char *file = ca_file != NULL ? ca_file : X509_get_default_cert_file();
	if (SSL_CTX_load_verify_file(ctx, file) != 1) {
		seterr(err, ecap, "loading the CA trust file %s failed", file);
		ERR_clear_error();
		SSL_CTX_free(ctx);
		bst_hc_close(c);
		return -1;
	}
	c->ssl_ctx = ctx;
	return 0;
}

void bst_hc_close(bst_hc *c)
{
	if (c->ssl_ctx != NULL)
		SSL_CTX_free(c->ssl_ctx);
	c->ssl_ctx = NULL;
	if (c->ep >= 0)
		close(c->ep);
	c->ep = -1;
}

void bst_hc_sleep(const bst_hc *c, uint64_t ms)
{
	uint64_t end = mono_ms() + ms;
	struct epoll_event ev;
	for (;;) {
		uint64_t now = mono_ms();
		if (now >= end)
			return;
		uint64_t left = end - now;
		(void)epoll_pwait(c->ep, &ev, 1, left > 60000 ? 60000 : (int)left, NULL);
	}
}

/* Waits for fd to be ready for ev until deadline: 0, or -1 with err. */
static int wait_fd(const bst_hc *c, int fd, uint32_t events, uint64_t deadline, char *err, size_t ecap)
{
	struct epoll_event ev = { .events = events, .data.fd = fd };
	if (epoll_ctl(c->ep, EPOLL_CTL_ADD, fd, &ev) != 0) {
		seterr(err, ecap, "epoll_ctl: %s", strerror(errno));
		return -1;
	}
	int rc;
	for (;;) {
		uint64_t now = mono_ms();
		if (now >= deadline) {
			rc = 0;
			break;
		}
		rc = epoll_pwait(c->ep, &ev, 1, (int)(deadline - now), NULL);
		if (rc >= 0 || errno != EINTR)
			break;
	}
	(void)epoll_ctl(c->ep, EPOLL_CTL_DEL, fd, NULL);
	if (rc <= 0) {
		if (rc == 0)
			seterr(err, ecap, "timed out");
		else
			seterr(err, ecap, "epoll_pwait: %s", strerror(errno));
		return -1;
	}
	return 0;
}

static int conn_open(const bst_hc *c, uint64_t deadline, char *err, size_t ecap)
{
	int fd = socket(c->addr.ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		seterr(err, ecap, "socket: %s", strerror(errno));
		return -1;
	}
	if (connect(fd, (const struct sockaddr *)&c->addr, c->alen) != 0) {
		if (errno != EINPROGRESS) {
			seterr(err, ecap, "connect to %s:%u: %s", c->host, (unsigned)c->port, strerror(errno));
			close(fd);
			return -1;
		}
		if (wait_fd(c, fd, EPOLLOUT, deadline, err, ecap) != 0) {
			close(fd);
			return -1;
		}
		int so = 0;
		socklen_t sl = sizeof so;
		if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so, &sl) != 0 || so != 0) {
			seterr(err, ecap, "connect to %s:%u: %s", c->host, (unsigned)c->port, strerror(so ? so : errno));
			close(fd);
			return -1;
		}
	}
	return fd;
}

typedef struct io {
	const bst_hc *c;
	int fd;
	SSL *ssl;
	uint64_t deadline;
} io;

/* SSL_ERROR_WANT_* to an epoll wait. */
static int ssl_wait(io *x, int r, char *err, size_t ecap, const char *what)
{
	int e = SSL_get_error(x->ssl, r);
	if (e == SSL_ERROR_WANT_READ)
		return wait_fd(x->c, x->fd, EPOLLIN, x->deadline, err, ecap);
	if (e == SSL_ERROR_WANT_WRITE)
		return wait_fd(x->c, x->fd, EPOLLOUT, x->deadline, err, ecap);
	unsigned long le = ERR_get_error();
	char buf[160] = "";
	if (le != 0)
		ERR_error_string_n(le, buf, sizeof buf);
	ERR_clear_error();
	seterr(err, ecap, "TLS %s with %s failed: %s", what, x->c->host, buf[0] ? buf : "connection closed");
	return -1;
}

static int io_write(io *x, const char *p, size_t n, char *err, size_t ecap)
{
	while (n > 0) {
		if (x->ssl != NULL) {
			int r = SSL_write(x->ssl, p, n > INT32_MAX ? INT32_MAX : (int)n);
			if (r <= 0) {
				if (ssl_wait(x, r, err, ecap, "write") != 0)
					return -1;
				continue;
			}
			p += r;
			n -= (size_t)r;
		} else {
			ssize_t r = write(x->fd, p, n);
			if (r < 0) {
				if (errno == EINTR)
					continue;
				if (errno != EAGAIN || wait_fd(x->c, x->fd, EPOLLOUT, x->deadline, err, ecap) != 0) {
					if (errno != EAGAIN)
						seterr(err, ecap, "write: %s", strerror(errno));
					return -1;
				}
				continue;
			}
			p += r;
			n -= (size_t)r;
		}
	}
	return 0;
}

/* Reads into p: bytes read, 0 at end, -1 on error. */
static ssize_t io_read(io *x, char *p, size_t n, char *err, size_t ecap)
{
	for (;;) {
		if (x->ssl != NULL) {
			int r = SSL_read(x->ssl, p, n > INT32_MAX ? INT32_MAX : (int)n);
			if (r > 0)
				return r;
			int e = SSL_get_error(x->ssl, r);
			if (e == SSL_ERROR_ZERO_RETURN)
				return 0;
			if (ssl_wait(x, r, err, ecap, "read") != 0)
				return -1;
		} else {
			ssize_t r = read(x->fd, p, n);
			if (r >= 0)
				return r;
			if (errno == EINTR)
				continue;
			if (errno != EAGAIN) {
				seterr(err, ecap, "read: %s", strerror(errno));
				return -1;
			}
			if (wait_fd(x->c, x->fd, EPOLLIN, x->deadline, err, ecap) != 0)
				return -1;
		}
	}
}

static void copy_hdr(char *dst, size_t cap, const char *v, size_t vl)
{
	if (vl >= cap)
		vl = cap - 1;
	memcpy(dst, v, vl);
	dst[vl] = '\0';
}

/* 0: complete, 1: needs more, -1: malformed or too large. */
static int parse(const char *buf, size_t len, bool head_only, bool eof, bst_hc_resp *r, char *err,
		 size_t ecap)
{
	const char *he = NULL;
	for (size_t i = 0; i + 3 < len; i++)
		if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
			he = buf + i + 2;
			break;
		}
	if (he == NULL) {
		if (len > BST_HC_MAX_HEAD) {
			seterr(err, ecap, "response head larger than %u bytes", BST_HC_MAX_HEAD);
			return -1;
		}
		if (eof) {
			seterr(err, ecap, "truncated response head");
			return -1;
		}
		return 1;
	}
	if ((size_t)(he - buf) > BST_HC_MAX_HEAD) {
		seterr(err, ecap, "response head larger than %u bytes", BST_HC_MAX_HEAD);
		return -1;
	}
	if (len < 12 || memcmp(buf, "HTTP/1.", 7) != 0 || buf[8] != ' ' || buf[9] < '1' || buf[9] > '5' ||
	    buf[10] < '0' || buf[10] > '9' || buf[11] < '0' || buf[11] > '9') {
		seterr(err, ecap, "not an HTTP/1.x response");
		return -1;
	}
	r->status = (buf[9] - '0') * 100 + (buf[10] - '0') * 10 + (buf[11] - '0');
	long long clen = -1;
	bool chunked = false;
	const char *line = memchr(buf, '\n', (size_t)(he - buf));
	line = line != NULL ? line + 1 : he;
	while (line < he) {
		const char *eol = memchr(line, '\n', (size_t)(he - line));
		if (eol == NULL)
			break;
		size_t ll = (size_t)(eol - line);
		if (ll > 0 && line[ll - 1] == '\r')
			ll--;
		const char *colon = memchr(line, ':', ll);
		if (colon != NULL) {
			size_t nl = (size_t)(colon - line);
			const char *v = colon + 1;
			size_t vl = ll - nl - 1;
			while (vl > 0 && (*v == ' ' || *v == '\t'))
				v++, vl--;
			while (vl > 0 && (v[vl - 1] == ' ' || v[vl - 1] == '\t'))
				vl--;
#define IS(name) (nl == sizeof(name) - 1 && strncasecmp(line, name, nl) == 0)
			if (IS("Content-Length")) {
				long long n = 0;
				if (vl == 0 || vl > 12) {
					seterr(err, ecap, "bad Content-Length");
					return -1;
				}
				for (size_t i = 0; i < vl; i++) {
					if (v[i] < '0' || v[i] > '9') {
						seterr(err, ecap, "bad Content-Length");
						return -1;
					}
					n = n * 10 + (v[i] - '0');
				}
				if (clen >= 0 && clen != n) {
					seterr(err, ecap, "conflicting Content-Length");
					return -1;
				}
				clen = n;
			} else if (IS("Transfer-Encoding")) {
				chunked = vl >= 7 && strncasecmp(v + vl - 7, "chunked", 7) == 0;
			} else if (IS("Location")) {
				copy_hdr(r->location, sizeof r->location, v, vl);
			} else if (IS("Replay-Nonce")) {
				copy_hdr(r->nonce, sizeof r->nonce, v, vl);
			} else if (IS("Retry-After")) {
				copy_hdr(r->retry_after, sizeof r->retry_after, v, vl);
			} else if (IS("Content-Type")) {
				copy_hdr(r->content_type, sizeof r->content_type, v, vl);
			} else if (IS("Link")) {
				/* <url>;rel="up" (one Link line per value is what CAs send) */
				if (vl > 2 && v[0] == '<' && memmem(v, vl, "rel=\"up\"", 8) != NULL) {
					const char *gt = memchr(v, '>', vl);
					if (gt != NULL)
						copy_hdr(r->link_up, sizeof r->link_up, v + 1, (size_t)(gt - v - 1));
				}
			}
#undef IS
		}
		line = eol + 1;
	}
	const char *b = he + 2;
	size_t avail = len - (size_t)(b - buf);
	bool nobody = head_only || r->status == 204 || r->status == 304 || r->status / 100 == 1;
	size_t blen;
	char *out;
	if (nobody) {
		blen = 0;
		out = malloc(1);
		if (out == NULL)
			goto oom;
	} else if (chunked) {
		out = malloc(avail + 1);
		if (out == NULL)
			goto oom;
		size_t o = 0, i = 0;
		for (;;) {
			const char *nl = memchr(b + i, '\n', avail - i);
			if (nl == NULL) {
				free(out);
				goto more;
			}
			unsigned long long sz = 0;
			size_t k = i, digits = 0;
			for (; b + k < nl; k++) {
				char ch = b[k];
				int d = ch >= '0' && ch <= '9' ? ch - '0' : ch >= 'a' && ch <= 'f' ? ch - 'a' + 10
					: ch >= 'A' && ch <= 'F' ? ch - 'A' + 10 : -1;
				if (d < 0)
					break;
				if (++digits > 8) {
					free(out);
					seterr(err, ecap, "chunk too large");
					return -1;
				}
				sz = sz * 16 + (unsigned)d;
			}
			if (digits == 0) {
				free(out);
				seterr(err, ecap, "bad chunk size");
				return -1;
			}
			i = (size_t)(nl - b) + 1;
			if (sz == 0) {
				/* trailers until an empty line */
				for (;;) {
					const char *tl = memchr(b + i, '\n', avail - i);
					if (tl == NULL) {
						free(out);
						goto more;
					}
					size_t tlen = (size_t)(tl - (b + i));
					i = (size_t)(tl - b) + 1;
					if (tlen == 0 || (tlen == 1 && tl[-1] == '\r'))
						break;
				}
				break;
			}
			if (o + sz > BST_HC_MAX_BODY) {
				free(out);
				seterr(err, ecap, "response body larger than %u bytes", BST_HC_MAX_BODY);
				return -1;
			}
			if (avail - i < sz + 2) {
				free(out);
				goto more;
			}
			memcpy(out + o, b + i, (size_t)sz);
			o += (size_t)sz;
			i += (size_t)sz;
			if (b[i] == '\r')
				i++;
			if (i >= avail || b[i] != '\n') {
				free(out);
				seterr(err, ecap, "bad chunk framing");
				return -1;
			}
			i++;
		}
		blen = o;
	} else if (clen >= 0) {
		if ((unsigned long long)clen > BST_HC_MAX_BODY) {
			seterr(err, ecap, "response body larger than %u bytes", BST_HC_MAX_BODY);
			return -1;
		}
		if (avail < (size_t)clen)
			goto more;
		blen = (size_t)clen;
		out = malloc(blen + 1);
		if (out == NULL)
			goto oom;
		memcpy(out, b, blen);
	} else {
		if (avail > BST_HC_MAX_BODY) {
			seterr(err, ecap, "response body larger than %u bytes", BST_HC_MAX_BODY);
			return -1;
		}
		if (!eof)
			return 1; /* until the connection closes */
		blen = avail;
		out = malloc(blen + 1);
		if (out == NULL)
			goto oom;
		memcpy(out, b, blen);
	}
	out[blen] = '\0';
	free(r->body);
	r->body = out;
	r->len = blen;
	return 0;
more:
	if (eof) {
		seterr(err, ecap, "truncated response body");
		return -1;
	}
	if (avail > BST_HC_MAX_BODY + 65536) {
		seterr(err, ecap, "response body larger than %u bytes", BST_HC_MAX_BODY);
		return -1;
	}
	return 1;
oom:
	seterr(err, ecap, "out of memory");
	return -1;
}

int bst_hc_parse_response(const char *buf, size_t len, bool head_only, bst_hc_resp *r, char *err,
			  size_t ecap)
{
	return parse(buf, len, head_only, true, r, err, ecap) == 0 ? 0 : -1;
}

void bst_hc_resp_free(bst_hc_resp *r)
{
	free(r->body);
	memset(r, 0, sizeof *r);
}

int bst_hc_request(bst_hc *c, const char *method, const char *url, const char *ctype,
		   const char *body, size_t blen, bst_hc_resp *r, char *err, size_t ecap)
{
	memset(r, 0, sizeof *r);
	bool tls;
	char host[256], path[2048];
	uint16_t port;
	if (!bst_hc_parse_url(url, &tls, host, sizeof host, &port, path, sizeof path)) {
		seterr(err, ecap, "not an http(s) URL");
		return -1;
	}
	if (tls != c->tls || port != c->port || strcasecmp(host, c->host) != 0) {
		seterr(err, ecap, "URL on another host than the directory's (%s:%u): refused", c->host,
		       (unsigned)c->port);
		return -1;
	}
	io x = { .c = c, .fd = -1, .deadline = mono_ms() + (uint64_t)c->timeout_ms };
	x.fd = conn_open(c, x.deadline, err, ecap);
	if (x.fd < 0)
		return -1;
	int ret = -1;
	char *buf = NULL;
	if (tls) {
		x.ssl = SSL_new(c->ssl_ctx);
		if (x.ssl == NULL || SSL_set_fd(x.ssl, x.fd) != 1) {
			seterr(err, ecap, "SSL_new failed");
			goto out;
		}
		struct in6_addr a6;
		struct in_addr a4;
		bool ip = inet_pton(AF_INET, host, &a4) == 1 || inet_pton(AF_INET6, host, &a6) == 1;
		if (ip) {
			X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(x.ssl), host);
		} else {
			SSL_set_tlsext_host_name(x.ssl, host);
			SSL_set1_host(x.ssl, host);
		}
		for (;;) {
			int hr = SSL_connect(x.ssl);
			if (hr == 1)
				break;
			if (ssl_wait(&x, hr, err, ecap, "handshake") != 0)
				goto out;
		}
	}
	char head[3072];
	char hostport[300];
	bool dflt = port == (tls ? 443 : 80);
	bool v6 = strchr(host, ':') != NULL;
	if (dflt)
		snprintf(hostport, sizeof hostport, "%s%s%s", v6 ? "[" : "", host, v6 ? "]" : "");
	else
		snprintf(hostport, sizeof hostport, "%s%s%s:%u", v6 ? "[" : "", host, v6 ? "]" : "",
			 (unsigned)port);
	int hl = snprintf(head, sizeof head,
			  "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: bastion-acme\r\nAccept: */*\r\n"
			  "Connection: close\r\n%s%s%s",
			  method, path, hostport, ctype ? "Content-Type: " : "", ctype ? ctype : "",
			  ctype ? "\r\n" : "");
	if (hl < 0 || (size_t)hl >= sizeof head - 64) {
		seterr(err, ecap, "request head too long");
		goto out;
	}
	if (body != NULL || strcmp(method, "POST") == 0)
		hl += snprintf(head + hl, sizeof head - (size_t)hl, "Content-Length: %zu\r\n", blen);
	hl += snprintf(head + hl, sizeof head - (size_t)hl, "\r\n");
	if (io_write(&x, head, (size_t)hl, err, ecap) != 0 ||
	    (blen > 0 && io_write(&x, body, blen, err, ecap) != 0))
		goto out;
	size_t cap = 16384, len = 0;
	buf = malloc(cap);
	if (buf == NULL) {
		seterr(err, ecap, "out of memory");
		goto out;
	}
	bool head_only = strcmp(method, "HEAD") == 0;
	for (;;) {
		if (len == cap) {
			if (cap >= BST_HC_MAX_HEAD + BST_HC_MAX_BODY + 131072) {
				seterr(err, ecap, "response larger than %u bytes", BST_HC_MAX_BODY);
				goto out;
			}
			char *nb = realloc(buf, cap * 2);
			if (nb == NULL) {
				seterr(err, ecap, "out of memory");
				goto out;
			}
			buf = nb;
			cap *= 2;
		}
		ssize_t n = io_read(&x, buf + len, cap - len, err, ecap);
		if (n < 0)
			goto out;
		len += (size_t)n;
		int pr = parse(buf, len, head_only, n == 0, r, err, ecap);
		if (pr < 0)
			goto out;
		if (pr == 0)
			break;
	}
	ret = 0;
out:
	if (ret != 0)
		bst_hc_resp_free(r);
	free(buf);
	if (x.ssl != NULL) {
		(void)SSL_shutdown(x.ssl);
		SSL_free(x.ssl);
	}
	ERR_clear_error();
	close(x.fd);
	return ret;
}
