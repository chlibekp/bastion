/* See proxyproto.h. */
#include "proxy/proxyproto.h"

#include "core/wheel.h"
#include "io/sock.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static const uint8_t v2_sig[12] = { 0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D,
				    0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A };
static const char v1_sig[] = "PROXY ";

/* ---- parsing ---- */

/* A decimal port: 1 to 5 digits, no leading zero (except "0" itself), at most 65535. */
static bool parse_port(const char *p, size_t n, uint16_t *out)
{
	if (n == 0 || n > 5 || (n > 1 && p[0] == '0'))
		return false;
	unsigned v = 0;
	for (size_t i = 0; i < n; i++) {
		if (p[i] < '0' || p[i] > '9')
			return false;
		v = v * 10 + (unsigned)(p[i] - '0');
	}
	if (v > 65535)
		return false;
	*out = (uint16_t)v;
	return true;
}

/* The next space-separated field of [*p, end): never empty. */
static bool field(const char **p, const char *end, const char **f, size_t *fl, bool last)
{
	const char *s = *p;
	const char *e = s;
	while (e < end && *e != ' ')
		e++;
	if (e == s || (last ? e != end : e == end))
		return false;
	*f = s;
	*fl = (size_t)(e - s);
	*p = last ? e : e + 1;
	return true;
}

static int parse_v1(const uint8_t *p, size_t n, bst_pp_info *out)
{
	size_t cmp = n < sizeof v1_sig - 1 ? n : sizeof v1_sig - 1;
	if (memcmp(p, v1_sig, cmp) != 0)
		return -1;
	const uint8_t *lf = NULL;
	size_t lim = n < BST_PP_V1_MAX ? n : BST_PP_V1_MAX;
	for (size_t i = 1; i < lim; i++)
		if (p[i] == '\n') {
			lf = p + i;
			break;
		}
	if (lf == NULL)
		return n >= BST_PP_V1_MAX ? -1 : 0;
	if (lf[-1] != '\r')
		return -1;
	size_t len = (size_t)(lf - p) + 1;
	const char *s = (const char *)p + sizeof v1_sig - 1;
	const char *end = (const char *)lf - 1; /* the CR */
	memset(out, 0, sizeof *out);
	out->version = 1;
	out->len = len;
	if ((size_t)(end - s) >= 7 && memcmp(s, "UNKNOWN", 7) == 0)
		return (int)len; /* whatever follows UNKNOWN is ignored */
	bool v6;
	if ((size_t)(end - s) > 5 && memcmp(s, "TCP4 ", 5) == 0)
		v6 = false;
	else if ((size_t)(end - s) > 5 && memcmp(s, "TCP6 ", 5) == 0)
		v6 = true;
	else
		return -1;
	s += 5;
	const char *f[4];
	size_t fl[4];
	for (int i = 0; i < 4; i++)
		if (!field(&s, end, &f[i], &fl[i], i == 3))
			return -1;
	if (!bst_addr_parse((bst_str){ f[0], (uint32_t)fl[0] }, &out->src.ip) ||
	    !bst_addr_parse((bst_str){ f[1], (uint32_t)fl[1] }, &out->dst.ip) ||
	    !parse_port(f[2], fl[2], &out->src.port) || !parse_port(f[3], fl[3], &out->dst.port))
		return -1;
	uint8_t fam = v6 ? BST_IP_V6 : BST_IP_V4;
	if (out->src.ip.family != fam || out->dst.ip.family != fam)
		return -1;
	out->has_addr = true;
	return (int)len;
}

static int parse_v2(const uint8_t *p, size_t n, bst_pp_info *out)
{
	size_t cmp = n < sizeof v2_sig ? n : sizeof v2_sig;
	if (memcmp(p, v2_sig, cmp) != 0)
		return -1;
	if (n >= 13 && (p[12] & 0xF0) != 0x20)
		return -1; /* version 2 only */
	if (n >= 13 && (p[12] & 0x0F) > 1)
		return -1; /* LOCAL or PROXY */
	if (n < 16)
		return 0;
	size_t body = ((size_t)p[14] << 8) | p[15];
	size_t len = 16 + body;
	if (len > BST_PP_MAX)
		return -1;
	uint8_t fam = p[13];
	size_t need = fam == 0x11 ? 12 : fam == 0x21 ? 36 : fam == 0x31 ? 216 : 0;
	if (fam != 0x00 && fam != 0x11 && fam != 0x21 && fam != 0x31)
		return -1; /* UDP and unix datagram are not a TCP connection */
	if (body < need)
		return -1; /* a length too short for the addresses it declares */
	if (n < len)
		return 0;
	memset(out, 0, sizeof *out);
	out->version = 2;
	out->len = len;
	out->local = (p[12] & 0x0F) == 0;
	if (out->local || (fam != 0x11 && fam != 0x21))
		return (int)len; /* no client address: LOCAL, UNSPEC or a unix socket */
	const uint8_t *a = p + 16;
	if (fam == 0x11) {
		out->src.ip.family = out->dst.ip.family = BST_IP_V4;
		memcpy(out->src.ip.b, a, 4);
		memcpy(out->dst.ip.b, a + 4, 4);
		a += 8;
	} else {
		out->src.ip.family = out->dst.ip.family = BST_IP_V6;
		memcpy(out->src.ip.b, a, 16);
		memcpy(out->dst.ip.b, a + 16, 16);
		a += 32;
	}
	out->src.port = (uint16_t)((a[0] << 8) | a[1]);
	out->dst.port = (uint16_t)((a[2] << 8) | a[3]);
	out->has_addr = true;
	return (int)len;
}

int bst_pp_parse(const uint8_t *p, size_t n, bst_pp_info *out)
{
	if (n == 0)
		return 0;
	if (p[0] == 'P')
		return parse_v1(p, n, out);
	if (p[0] == 0x0D)
		return parse_v2(p, n, out);
	return -1;
}

size_t bst_pp_want(const uint8_t *p, size_t n)
{
	if (n < 8)
		return 8 - n; /* the shortest header of either version is longer */
	if (p[0] == 'P')
		return 1; /* v1 ends at a CRLF: one byte at a time */
	if (n < 16)
		return 16 - n;
	size_t len = 16 + (((size_t)p[14] << 8) | p[15]);
	return len > n ? len - n : 1;
}

/* ---- writing ---- */

static bst_ip mapped(const bst_ip *v4)
{
	bst_ip r;
	memset(&r, 0, sizeof r);
	r.family = BST_IP_V6;
	r.b[10] = r.b[11] = 0xff;
	memcpy(r.b + 12, v4->b, 4);
	return r;
}

/* Both addresses in one family: IPv4 when both are (or map to) IPv4, else IPv6. */
static bool same_family(const bst_sockaddr *src, const bst_sockaddr *dst, bst_sockaddr *s,
			bst_sockaddr *d)
{
	if (src == NULL || dst == NULL)
		return false;
	*s = *src;
	*d = *dst;
	s->ip = bst_ip_canon(&src->ip);
	d->ip = bst_ip_canon(&dst->ip);
	if (s->ip.family != BST_IP_V4 && s->ip.family != BST_IP_V6)
		return false;
	if (d->ip.family != BST_IP_V4 && d->ip.family != BST_IP_V6)
		return false;
	if (s->ip.family == d->ip.family)
		return true;
	if (s->ip.family == BST_IP_V4)
		s->ip = mapped(&s->ip);
	else
		d->ip = mapped(&d->ip);
	return true;
}

size_t bst_pp_write_v1(const bst_sockaddr *src, const bst_sockaddr *dst, char *buf, size_t cap)
{
	bst_sockaddr s, d;
	int n;
	if (!same_family(src, dst, &s, &d)) {
		n = snprintf(buf, cap, "PROXY UNKNOWN\r\n");
	} else {
		char sa[BST_ADDR_STRLEN], da[BST_ADDR_STRLEN];
		if (bst_addr_format(&s.ip, sa, sizeof sa) == 0 || bst_addr_format(&d.ip, da, sizeof da) == 0)
			return 0;
		n = snprintf(buf, cap, "PROXY %s %s %s %u %u\r\n", s.ip.family == BST_IP_V4 ? "TCP4" : "TCP6",
			     sa, da, (unsigned)s.port, (unsigned)d.port);
	}
	return n > 0 && (size_t)n < cap ? (size_t)n : 0;
}

size_t bst_pp_write_v2(const bst_sockaddr *src, const bst_sockaddr *dst, uint8_t *buf, size_t cap)
{
	bst_sockaddr s, d;
	bool have = same_family(src, dst, &s, &d);
	size_t alen = !have ? 0 : s.ip.family == BST_IP_V4 ? 12 : 36;
	if (cap < 16 + alen)
		return 0;
	memcpy(buf, v2_sig, sizeof v2_sig);
	buf[12] = 0x21; /* version 2, PROXY */
	buf[13] = !have ? 0x00 : s.ip.family == BST_IP_V4 ? 0x11 : 0x21;
	buf[14] = (uint8_t)(alen >> 8);
	buf[15] = (uint8_t)alen;
	if (have) {
		size_t al = s.ip.family == BST_IP_V4 ? 4 : 16;
		uint8_t *w = buf + 16;
		memcpy(w, s.ip.b, al);
		memcpy(w + al, d.ip.b, al);
		w += 2 * al;
		w[0] = (uint8_t)(s.port >> 8);
		w[1] = (uint8_t)s.port;
		w[2] = (uint8_t)(d.port >> 8);
		w[3] = (uint8_t)d.port;
	}
	return 16 + alen;
}

/* ---- reading on accept ---- */

typedef struct pp_reader {
	bst_sock *sk; /* borrowed: closing it leaves fd open */
	int fd;
	bst_timer timer;
	bst_pp_ready_cb cb;
	void *ud;
	size_t n;
	uint8_t buf[BST_PP_MAX];
} pp_reader;

static void finish(pp_reader *r, const bst_pp_info *info)
{
	bst_timer_cancel(&r->timer);
	bst_sock_close(r->sk);
	int fd = r->fd;
	if (info == NULL)
		close(fd);
	bst_pp_ready_cb cb = r->cb;
	void *ud = r->ud;
	free(r);
	cb(ud, info != NULL ? fd : -1, info);
}

static void on_timeout(void *ud)
{
	finish(ud, NULL);
}

static void on_readable(void *ud, uint32_t events, int err)
{
	pp_reader *r = ud;
	(void)events;
	if (err != 0) {
		finish(r, NULL);
		return;
	}
	for (;;) {
		size_t want = bst_pp_want(r->buf, r->n);
		if (want > sizeof r->buf - r->n)
			want = sizeof r->buf - r->n;
		if (want == 0) {
			finish(r, NULL);
			return;
		}
		ssize_t got = recv(r->fd, r->buf + r->n, want, MSG_DONTWAIT);
		if (got < 0 && errno == EINTR)
			continue;
		if (got < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			if (bst_io_poll(r->sk, POLLIN | POLLRDHUP, on_readable, r) != 0)
				finish(r, NULL);
			return;
		}
		if (got <= 0) { /* the peer closed or failed before the header ended */
			finish(r, NULL);
			return;
		}
		r->n += (size_t)got;
		bst_pp_info info;
		int rc = bst_pp_parse(r->buf, r->n, &info);
		if (rc < 0) {
			finish(r, NULL);
			return;
		}
		if (rc > 0) {
			finish(r, &info);
			return;
		}
	}
}

int bst_pp_accept(bst_loop *l, int fd, uint64_t timeout_ms, bst_pp_ready_cb cb, void *ud)
{
	pp_reader *r = malloc(sizeof *r);
	bst_sock *sk = r != NULL ? bst_sock_wrap_borrowed(l, fd) : NULL;
	if (sk == NULL) {
		free(r);
		close(fd);
		return -1;
	}
	r->sk = sk;
	r->fd = fd;
	r->cb = cb;
	r->ud = ud;
	r->n = 0;
	bst_timer_init(&r->timer);
	/* Re-arming reports readiness that already exists, so bytes already queued are not lost;
	 * the callback never runs from inside this call. */
	if (bst_io_poll(sk, POLLIN | POLLRDHUP, on_readable, r) != 0) {
		bst_sock_close(sk);
		close(fd);
		free(r);
		return -1;
	}
	bst_loop_timer_arm(l, &r->timer, timeout_ms, on_timeout, r);
	return 0;
}
