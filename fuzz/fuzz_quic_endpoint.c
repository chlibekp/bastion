/* libFuzzer harness for the QUIC endpoint's datagram path (src/http/h3/quic.c): connection ID
 * lookup, Version Negotiation, Retry and token checks, stateless reset, refusal and the first
 * packets of a connection inside ngtcp2. The input is a sequence of datagrams, each a 1-byte
 * source port selector, a 2-byte length and that many bytes, fed to one endpoint that lives across
 * inputs (rebuilt every RESET_EVERY inputs), so connections made by one datagram see the next.
 *
 * Properties: no crash, leak or hang; nothing sent is larger than BST_QUIC_PKT_MAX; and the endpoint
 * never sends more than 3x what it received, over the whole run. No address is ever validated here
 * (a token cannot be forged and no handshake completes: the context has no certificate), so every
 * byte out is either a stateless answer smaller than its trigger or under ngtcp2's 3x
 * anti-amplification budget (RFC 9000 section 8). */
#include "http/h3/quic.h"

#include "io/loop.h"

#include <openssl/ssl.h>
#include <string.h>

#define RESET_EVERY 2000u

static bst_loop *loop;
static SSL_CTX *ctx;
static bst_cfg_quic q;
static bst_quic_endpoint *ep;
static unsigned runs;
static uint64_t rx_total, tx_total;

static void sink(void *ud, const bst_udp_pkt *p)
{
	(void)ud;
	if (p->len == 0 || p->len > BST_QUIC_PKT_MAX)
		__builtin_trap();
	tx_total += p->len;
}

static void setup(void)
{
	bst_err e = {.msg = ""};
	bst_quic_init();
	bst_loop_cfg lc;
	memset(&lc, 0, sizeof lc);
	lc.backend = BST_BACKEND_EPOLL;
	loop = bst_loop_new(&lc, &e);
	ctx = SSL_CTX_new(TLS_server_method());
	if (loop == NULL || ctx == NULL)
		__builtin_trap();
	SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
	SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
	q = (bst_cfg_quic){ .max_connections = 16, .idle_timeout_ms = 30000, .handshake_timeout_ms = 10000,
			    .max_streams_bidi = 100, .max_streams_uni = 3, .initial_max_data = 1 << 20,
			    .initial_max_stream_data = 256 << 10, .cc = BST_QUIC_CC_CUBIC,
			    .retry = BST_QUIC_RETRY_AUTO, .retry_threshold = 4,
			    .versions = { 0x00000001u, 0x6b3343cfu }, .nversions = 2,
			    .stateless_reset = true, .ssl_ctx = ctx };
}

static void new_endpoint(void)
{
	bst_quic_ep_cfg c;
	memset(&c, 0, sizeof c);
	c.loop = loop;
	c.q = &q;
	c.slot = 3;
	c.local.ip.family = BST_IP_V4;
	c.local.ip.b[0] = 127, c.local.ip.b[3] = 1;
	c.local.port = 443;
	memset(&c.secrets, 0x5c, sizeof c.secrets);
	c.sink = sink;
	bst_err e = {.msg = ""};
	ep = bst_quic_endpoint_new(&c, &e);
	if (ep == NULL)
		__builtin_trap();
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t len)
{
	if (loop == NULL)
		setup();
	if (ep == NULL || ++runs % RESET_EVERY == 0) {
		bst_quic_endpoint_free(ep);
		new_endpoint();
	}
	bst_sockaddr src, dst;
	memset(&src, 0, sizeof src);
	src.ip.family = BST_IP_V4;
	src.ip.b[0] = 192, src.ip.b[1] = 0, src.ip.b[2] = 2, src.ip.b[3] = 7;
	dst = src;
	dst.ip.b[0] = 127, dst.ip.b[1] = 0, dst.ip.b[2] = 0, dst.ip.b[3] = 1;
	dst.port = 443;
	size_t off = 0;
	while (off + 3 <= len) {
		src.port = (uint16_t)(40000 + (d[off] & 7));
		size_t n = (size_t)d[off + 1] << 8 | d[off + 2];
		off += 3;
		if (n > len - off)
			n = len - off;
		if (n == 0)
			continue;
		rx_total += n;
		bst_quic_endpoint_input(ep, d + off, n, &src, &dst, 0);
		if (tx_total > 3 * rx_total)
			__builtin_trap();
		off += n;
	}
	return 0;
}
