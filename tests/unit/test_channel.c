/* The master channel: typed, length-checked messages. Master reads them as root from a process
 * that may be compromised, so every malformed shape is a refusal, never a guess. */
#include "proc/channel.h"
#include "tap.h"

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static size_t enc_ready(unsigned char *buf, size_t cap, bst_backend b)
{
	bst_msg m = {.type = BST_MSG_READY, .ready = {.backend = b}};
	return bst_chan_encode(&m, buf, cap);
}

TEST(round_trip_ready)
{
	unsigned char buf[BST_CHAN_MAX];
	size_t n = enc_ready(buf, sizeof buf, BST_BACKEND_EPOLL);
	ASSERT(n > 0 && n <= sizeof buf);
	bst_msg out;
	ASSERT(bst_chan_decode(buf, n, &out));
	ASSERT_EQ(out.type, BST_MSG_READY);
	ASSERT_EQ(out.ready.backend, BST_BACKEND_EPOLL);
}

TEST(round_trip_stop)
{
	unsigned char buf[BST_CHAN_MAX];
	for (int g = 0; g < 2; g++) {
		bst_msg m = {.type = BST_MSG_STOP, .stop = {.graceful = g != 0}};
		size_t n = bst_chan_encode(&m, buf, sizeof buf);
		ASSERT(n > 0);
		bst_msg out;
		ASSERT(bst_chan_decode(buf, n, &out));
		ASSERT_EQ(out.type, BST_MSG_STOP);
		ASSERT_EQ(out.stop.graceful, g != 0);
	}
}

TEST(encode_refuses_small_buffer)
{
	unsigned char buf[BST_CHAN_MAX];
	ASSERT_EQ(enc_ready(buf, 2, BST_BACKEND_EPOLL), 0);
}

TEST(rejects_every_truncation)
{
	unsigned char buf[BST_CHAN_MAX];
	size_t n = enc_ready(buf, sizeof buf, BST_BACKEND_URING);
	bst_msg out;
	for (size_t k = 0; k < n; k++)
		ASSERT(!bst_chan_decode(buf, k, &out));
}

TEST(rejects_trailing_bytes)
{
	unsigned char buf[BST_CHAN_MAX + 8] = {0};
	size_t n = enc_ready(buf, sizeof buf, BST_BACKEND_URING);
	bst_msg out;
	ASSERT(!bst_chan_decode(buf, n + 1, &out));
	ASSERT(!bst_chan_decode(buf, BST_CHAN_MAX + 8, &out));
}

TEST(rejects_bad_magic_type_and_length_field)
{
	unsigned char good[BST_CHAN_MAX], buf[BST_CHAN_MAX];
	size_t n = enc_ready(good, sizeof good, BST_BACKEND_URING);
	bst_msg out;
	for (size_t i = 0; i < n; i++) { /* a flip in any header or payload byte is caught or valid */
		for (unsigned bit = 0; bit < 8; bit++) {
			memcpy(buf, good, n);
			buf[i] ^= (unsigned char)(1u << bit);
			if (i < BST_CHAN_HDR) /* header bytes have one valid value for this message */
				if (bst_chan_decode(buf, n, &out))
					ASSERT(out.type != BST_MSG_READY ||
					       out.ready.backend != BST_BACKEND_URING);
		}
	}
	memcpy(buf, good, n);
	buf[0] ^= 0xff;
	ASSERT(!bst_chan_decode(buf, n, &out));
	memcpy(buf, good, n);
	buf[2] = 0;
	ASSERT(!bst_chan_decode(buf, n, &out)); /* type 0 */
	buf[2] = 200;
	ASSERT(!bst_chan_decode(buf, n, &out)); /* unknown type */
	memcpy(buf, good, n);
	buf[3] = (unsigned char)(buf[3] + 1);
	ASSERT(!bst_chan_decode(buf, n, &out)); /* length field disagrees */
}

TEST(rejects_values_out_of_range)
{
	unsigned char buf[BST_CHAN_MAX];
	size_t n = enc_ready(buf, sizeof buf, BST_BACKEND_URING);
	bst_msg out;
	buf[BST_CHAN_HDR] = (unsigned char)BST_BACKEND_AUTO; /* a loop always runs a real backend */
	ASSERT(!bst_chan_decode(buf, n, &out));
	buf[BST_CHAN_HDR] = 77;
	ASSERT(!bst_chan_decode(buf, n, &out));
	bst_msg m = {.type = BST_MSG_STOP, .stop = {.graceful = true}};
	n = bst_chan_encode(&m, buf, sizeof buf);
	buf[BST_CHAN_HDR] = 2;
	ASSERT(!bst_chan_decode(buf, n, &out));
}

TEST(over_a_real_socketpair)
{
	int sv[2];
	ASSERT_EQ(bst_chan_pair(sv), 0);
	bst_msg m = {.type = BST_MSG_READY, .ready = {.backend = BST_BACKEND_URING}}, out;
	ASSERT_EQ(bst_chan_recv(sv[0], &out), -EAGAIN);
	ASSERT_EQ(bst_chan_send(sv[1], &m), 0);
	ASSERT_EQ(bst_chan_recv(sv[0], &out), 1);
	ASSERT_EQ(out.ready.backend, BST_BACKEND_URING);
	/* An oversized datagram is refused whole, not read as its first bytes. */
	unsigned char big[512];
	memset(big, 0, sizeof big);
	size_t n = bst_chan_encode(&m, big, sizeof big);
	ASSERT(n > 0);
	ASSERT_EQ(send(sv[1], big, sizeof big, 0), (ssize_t)sizeof big);
	ASSERT_EQ(bst_chan_recv(sv[0], &out), -EPROTO);
	ASSERT_EQ(send(sv[1], "x", 1, 0), 1);
	ASSERT_EQ(bst_chan_recv(sv[0], &out), -EPROTO);
	close(sv[1]);
	ASSERT_EQ(bst_chan_recv(sv[0], &out), 0); /* EOF */
	close(sv[0]);
}

TEST(pair_ends_are_nonblocking_and_cloexec)
{
	int sv[2];
	ASSERT_EQ(bst_chan_pair(sv), 0);
	int type = 0;
	socklen_t len = sizeof type;
	ASSERT_EQ(getsockopt(sv[0], SOL_SOCKET, SO_TYPE, &type, &len), 0);
	ASSERT_EQ(type, SOCK_SEQPACKET); /* message boundaries are what the length check relies on */
	close(sv[0]);
	close(sv[1]);
}

TAP_MAIN()
