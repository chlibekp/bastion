/* The QUIC send queue's batching rules (http/h3/txq.h), through its sink: what joins a GSO batch,
 * what ends one, and that every packet comes out once, whole and in order. */
#include "tap.h"

#include "http/h3/txq.h"

#include <string.h>

typedef struct got {
	size_t n;
	size_t len[64];
	uint8_t first[64];
	uint16_t port[64];
} got;

static void sink(void *ud, const bst_udp_pkt *p)
{
	got *g = ud;
	if (g->n < 64) {
		g->len[g->n] = p->len;
		g->first[g->n] = ((const uint8_t *)p->data)[0];
		g->port[g->n] = p->dst.port;
	}
	g->n++;
}

static bst_sockaddr to(uint16_t port)
{
	bst_sockaddr a;
	memset(&a, 0, sizeof a);
	a.ip.family = BST_IP_V4;
	a.ip.b[0] = 127;
	a.ip.b[3] = 1;
	a.port = port;
	return a;
}

static void add(bst_txq *q, uint8_t tag, size_t len, uint16_t port, bool alone)
{
	uint8_t *b = bst_txq_scratch(q);
	memset(b, tag, len);
	bst_sockaddr d = to(port);
	bst_txq_add(q, b, len, &d, NULL, 0, alone);
}

/* Same-size packets to one peer become one batch; a shorter one is its last segment. */
TEST(txq_batches_same_size)
{
	bst_txq q;
	got g = { 0 };
	ASSERT_EQ(bst_txq_init(&q, NULL, true, sink, &g, NULL, NULL), 0);
	for (uint8_t i = 0; i < 5; i++)
		add(&q, i, 1200, 443, false);
	add(&q, 5, 700, 443, false); /* short: ends the batch */
	add(&q, 6, 1200, 443, false); /* a new one */
	bst_txq_end(&q);
	bst_txq_kick(&q);
	ASSERT_EQ(q.st.pkts, 7);
	ASSERT_EQ(q.st.batches, 2);
	ASSERT_EQ(q.st.multi, 1);
	ASSERT_EQ(g.n, 7);
	for (size_t i = 0; i < 7; i++)
		ASSERT_EQ(g.first[i], i);
	ASSERT_EQ(g.len[5], 700);
	ASSERT_EQ(g.len[6], 1200);
	bst_txq_free(&q);
}

/* Another destination, a larger packet, an `alone` probe, or a full batch start a new batch. */
TEST(txq_batch_boundaries)
{
	bst_txq q;
	got g = { 0 };
	ASSERT_EQ(bst_txq_init(&q, NULL, true, sink, &g, NULL, NULL), 0);
	add(&q, 0, 1200, 443, false);
	add(&q, 1, 1200, 444, false);  /* other port */
	add(&q, 2, 1300, 444, false);  /* larger than the segment size */
	add(&q, 3, 1400, 444, true);   /* a probe: alone */
	add(&q, 4, 1400, 444, false);  /* cannot join the probe */
	for (unsigned i = 0; i < BST_TXQ_SEGS; i++)
		add(&q, 5, 1000, 445, false); /* exactly full */
	add(&q, 6, 1000, 445, false);  /* the next batch */
	bst_txq_end(&q);
	ASSERT(bst_txq_room(&q));
	bst_txq_kick(&q);
	ASSERT_EQ(q.st.batches, 7);
	ASSERT_EQ(g.n, 6 + BST_TXQ_SEGS);
	ASSERT_EQ(g.port[1], 444);
	bst_txq_free(&q);
}

/* quic_gso off: every packet is a batch of its own; the open batch is not sent before it ends. */
TEST(txq_gso_off)
{
	bst_txq q;
	got g = { 0 };
	ASSERT_EQ(bst_txq_init(&q, NULL, false, sink, &g, NULL, NULL), 0);
	for (uint8_t i = 0; i < 4; i++)
		add(&q, i, 1200, 443, false);
	bst_txq_kick(&q);
	ASSERT_EQ(g.n, 4);
	ASSERT_EQ(q.st.batches, 4);
	ASSERT_EQ(q.st.multi, 0);
	bst_txq_free(&q);

	got h = { 0 };
	ASSERT_EQ(bst_txq_init(&q, NULL, true, sink, &h, NULL, NULL), 0);
	add(&q, 0, 1200, 443, false);
	bst_txq_kick(&q); /* still open: held */
	ASSERT_EQ(h.n, 0);
	bst_txq_end(&q);
	bst_txq_kick(&q);
	ASSERT_EQ(h.n, 1);
	bst_txq_free(&q);
}

TAP_MAIN()
