/* QUIC Retry and address tokens (http/h3/token.h). */
#include "tap.h"

#include "http/h3/token.h"

#include <string.h>
#include <time.h>

static uint64_t now_ns(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (uint64_t)t.tv_sec * NGTCP2_SECONDS + (uint64_t)t.tv_nsec;
}

static bst_sockaddr v4(uint8_t last, uint16_t port)
{
	bst_sockaddr a;
	memset(&a, 0, sizeof a);
	a.ip.family = BST_IP_V4;
	a.ip.b[0] = 192, a.ip.b[1] = 0, a.ip.b[2] = 2, a.ip.b[3] = last;
	a.port = port;
	return a;
}

static ngtcp2_cid cid(uint8_t fill, size_t len)
{
	ngtcp2_cid c;
	memset(&c, 0, sizeof c);
	c.datalen = len;
	memset(c.data, fill, len);
	return c;
}

/* A Retry token validates for the address and IDs it was made for, and gives back the original
 * destination ID; another address or port, another version, an expired token, a token sealed under
 * other secrets, and any changed byte all fail. */
TEST(token_roundtrip)
{
	bst_quic_secrets s, other;
	memset(&s, 0x11, sizeof s);
	memset(&other, 0x22, sizeof other);
	bst_sockaddr peer = v4(7, 4433), moved_ip = v4(8, 4433), moved_port = v4(7, 4434);
	ngtcp2_cid scid = cid(0xaa, 16), odcid = cid(0xbb, 8), out;
	uint8_t tok[BST_TOKEN_MAX];
	uint64_t t0 = now_ns();
	ngtcp2_ssize n = bst_token_retry(tok, &s, NGTCP2_PROTO_VER_V1, &peer, &scid, &odcid, t0);
	ASSERT(n > 0 && n <= BST_TOKEN_MAX);
	size_t len = (size_t)n;

	ASSERT_EQ(bst_token_retry_check(&out, tok, len, &s, NGTCP2_PROTO_VER_V1, &peer, &scid, t0), 0);
	ASSERT_EQ(out.datalen, odcid.datalen);
	ASSERT(memcmp(out.data, odcid.data, odcid.datalen) == 0);

	ASSERT_EQ(bst_token_retry_check(&out, tok, len, &s, NGTCP2_PROTO_VER_V1, &moved_ip, &scid, t0), -1);
	ASSERT_EQ(bst_token_retry_check(&out, tok, len, &s, NGTCP2_PROTO_VER_V1, &moved_port, &scid, t0), -1);
	ASSERT_EQ(bst_token_retry_check(&out, tok, len, &s, NGTCP2_PROTO_VER_V2, &peer, &scid, t0), -1);
	ngtcp2_cid wrong = cid(0xab, 16);
	ASSERT_EQ(bst_token_retry_check(&out, tok, len, &s, NGTCP2_PROTO_VER_V1, &peer, &wrong, t0), -1);
	ASSERT_EQ(bst_token_retry_check(&out, tok, len, &other, NGTCP2_PROTO_VER_V1, &peer, &scid, t0), -1);
	uint64_t late = t0 + (uint64_t)(BST_TOKEN_RETRY_TTL_MS + 1) * NGTCP2_MILLISECONDS;
	ASSERT_EQ(bst_token_retry_check(&out, tok, len, &s, NGTCP2_PROTO_VER_V1, &peer, &scid, late), -1);
	ASSERT_EQ(bst_token_retry_check(&out, tok, 0, &s, NGTCP2_PROTO_VER_V1, &peer, &scid, t0), -1);
	ASSERT_EQ(bst_token_retry_check(&out, tok, len - 1, &s, NGTCP2_PROTO_VER_V1, &peer, &scid, t0), -1);
	for (size_t i = 0; i < len; i++) { /* every single flipped bit is caught */
		tok[i] ^= 0x01;
		ASSERT_EQ(bst_token_retry_check(&out, tok, len, &s, NGTCP2_PROTO_VER_V1, &peer, &scid, t0), -1);
		tok[i] ^= 0x01;
	}
	ASSERT_EQ(bst_token_retry_check(&out, tok, len, &s, NGTCP2_PROTO_VER_V1, &peer, &scid, t0), 0);
}

/* A NEW_TOKEN token is bound to the address, expires, and is never taken for a Retry token. */
TEST(token_regular)
{
	bst_quic_secrets s;
	memset(&s, 0x33, sizeof s);
	bst_sockaddr peer = v4(9, 1000), other = v4(10, 1000);
	uint8_t tok[BST_TOKEN_MAX];
	uint64_t t0 = now_ns();
	ngtcp2_ssize n = bst_token_regular(tok, &s, &peer, t0);
	ASSERT(n > 0);
	ASSERT_EQ(bst_token_regular_check(tok, (size_t)n, &s, &peer, t0), 0);
	ASSERT_EQ(bst_token_regular_check(tok, (size_t)n, &s, &other, t0), -1);
	uint64_t late = t0 + (uint64_t)(BST_TOKEN_REGULAR_TTL_MS + 1) * NGTCP2_MILLISECONDS;
	ASSERT_EQ(bst_token_regular_check(tok, (size_t)n, &s, &peer, late), -1);
	ngtcp2_cid odcid, scid = cid(1, 16);
	ASSERT_EQ(bst_token_retry_check(&odcid, tok, (size_t)n, &s, NGTCP2_PROTO_VER_V1, &peer, &scid, t0), -1);
}

/* The stateless reset token depends on the connection ID and the secret only: every worker
 * derives the same one. */
TEST(token_reset)
{
	bst_quic_secrets s, o;
	memset(&s, 0x44, sizeof s);
	memset(&o, 0x55, sizeof o);
	ngtcp2_cid a = cid(1, 16), b = cid(2, 16);
	uint8_t ta[16], ta2[16], tb[16], to[16];
	ASSERT_EQ(bst_token_reset(ta, &s, &a), 0);
	ASSERT_EQ(bst_token_reset(ta2, &s, &a), 0);
	ASSERT_EQ(bst_token_reset(tb, &s, &b), 0);
	ASSERT_EQ(bst_token_reset(to, &o, &a), 0);
	ASSERT(memcmp(ta, ta2, 16) == 0);
	ASSERT(memcmp(ta, tb, 16) != 0);
	ASSERT(memcmp(ta, to, 16) != 0);
}

TAP_MAIN()
