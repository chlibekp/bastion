/* The QUIC send queue: GSO batches over bst_udp_send (txq.h). */
#include "http/h3/txq.h"

#include "core/log.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

int bst_txq_init(bst_txq *q, bst_sock *sock, bool gso, bst_txq_sink sink, void *sink_ud,
		 void (*on_room)(void *), void *room_ud)
{
	memset(q, 0, sizeof *q);
	q->slots = malloc(BST_TXQ_SLOTS * sizeof *q->slots); /* pages are touched as batches fill */
	if (q->slots == NULL)
		return -1;
	q->sock = sock;
	q->sink = sink;
	q->sink_ud = sink_ud;
	q->on_room = on_room;
	q->room_ud = room_ud;
	q->max_segs = gso ? BST_TXQ_SEGS : 1;
	return 0;
}

void bst_txq_free(bst_txq *q)
{
	free(q->slots);
	q->slots = NULL;
}

bool bst_txq_room(const bst_txq *q)
{
	return q->count < BST_TXQ_SLOTS;
}

uint8_t *bst_txq_scratch(bst_txq *q)
{
	return q->scratch;
}

static bst_txq_batch *slot(const bst_txq *q, size_t i)
{
	return &q->slots[(q->head + i) % BST_TXQ_SLOTS];
}

static bool same_ip(const bst_ip *a, const bst_ip *b)
{
	if (a->family != b->family)
		return false;
	return a->family == 0 || bst_ip_eq(a, b);
}

/* The packet may join batch b: same addressing and marks, and it keeps the UDP_SEGMENT shape. */
static bool fits(const bst_txq *q, const bst_txq_batch *b, size_t len, const bst_sockaddr *dst,
		 const bst_ip *src, uint8_t ecn)
{
	return !b->closed && !b->alone && b->nseg < q->max_segs && len <= b->seg &&
	       b->meta.ecn == ecn && b->meta.dst.port == dst->port && same_ip(&b->meta.dst.ip, &dst->ip) &&
	       same_ip(&b->meta.src, src);
}

void bst_txq_add(bst_txq *q, const uint8_t *data, size_t len, const bst_sockaddr *dst, const bst_ip *src,
		 uint8_t ecn, bool alone)
{
	static const bst_ip none = { 0 };
	if (src == NULL)
		src = &none;
	if (len == 0 || len > BST_TXQ_PKT_MAX)
		return;
	bst_txq_batch *b = q->open ? slot(q, q->count - 1) : NULL;
	if (b != NULL && !alone && fits(q, b, len, dst, src, ecn)) {
		memcpy(b->data + b->meta.len, data, len);
		b->meta.len += len;
		b->nseg++;
		b->meta.gso_size = b->seg; /* len > gso_size now: one GSO send (io/udp.h) */
		if (len < b->seg || b->nseg == q->max_segs)
			b->closed = true; /* a short packet must be the last segment */
		q->st.pkts++;
		return;
	}
	if (b != NULL)
		b->closed = true;
	if (q->count >= BST_TXQ_SLOTS) /* the caller asked bst_txq_room: never here */
		return;
	b = slot(q, q->count);
	q->count++;
	q->open = true;
	memset(&b->meta, 0, sizeof b->meta);
	memcpy(b->data, data, len);
	b->meta.data = b->data;
	b->meta.len = len;
	b->meta.dst = *dst;
	b->meta.src = *src;
	b->meta.ecn = ecn & 3;
	b->seg = (uint16_t)len;
	b->nseg = 1;
	b->alone = alone;
	b->closed = alone || q->max_segs == 1;
	q->st.pkts++;
}

void bst_txq_end(bst_txq *q)
{
	if (q->open)
		slot(q, q->count - 1)->closed = true;
	q->open = false;
}

static void retire(bst_txq *q, size_t n)
{
	q->head = (q->head + n) % BST_TXQ_SLOTS;
	q->count -= n;
	if (q->count == 0)
		q->open = false;
}

static void on_sent(void *ud, size_t bytes, int err)
{
	bst_txq *q = ud;
	(void)bytes;
	if (err < 0 && err != -ECANCELED) {
		q->st.send_errors++;
		bst_log(BST_LOG_DEBUG, "quic: send: %s", strerror(-err));
	}
	size_t n = q->inflight;
	q->inflight = 0;
	retire(q, n);
	bst_txq_kick(q);
	if (q->on_room != NULL)
		q->on_room(q->room_ud);
}

static void to_sink(bst_txq *q, const bst_txq_batch *b)
{
	bst_udp_pkt p = b->meta;
	p.gso_size = 0;
	for (size_t off = 0; off < b->meta.len; off += b->seg) {
		p.data = b->data + off;
		p.len = b->meta.len - off < b->seg ? b->meta.len - off : b->seg;
		q->sink(q->sink_ud, &p);
	}
}

void bst_txq_kick(bst_txq *q)
{
	if (q->inflight > 0)
		return;
	/* The closed batches, in order: the open one is the last and still filling. */
	size_t ready = q->count - (q->open && !slot(q, q->count - 1)->closed ? 1 : 0);
	if (q->sink != NULL || q->sock == NULL) {
		for (size_t i = 0; i < ready; i++) {
			const bst_txq_batch *b = slot(q, i);
			q->st.batches++;
			q->st.multi += b->nseg > 1;
			if (q->sink != NULL)
				to_sink(q, b);
		}
		retire(q, ready);
		return;
	}
	if (ready == 0)
		return;
	/* A batch sent alone goes in a call of its own, so that its failure ends nothing else. */
	size_t n = 0;
	while (n < ready && n < BST_UDP_BATCH) {
		const bst_txq_batch *b = slot(q, n);
		if (b->alone && n > 0)
			break;
		q->sendv[n] = b->meta;
		if (b->nseg == 1)
			q->sendv[n].gso_size = 0;
		q->st.batches++;
		q->st.multi += b->nseg > 1;
		n++;
		if (b->alone)
			break;
	}
	q->inflight = n;
	int rc = bst_udp_send(q->sock, q->sendv, (int)n, on_sent, q);
	if (rc != 0) { /* not started, or a bad packet: drop them, never stall the queue */
		q->st.send_errors++;
		bst_log(BST_LOG_DEBUG, "quic: send: %s", strerror(-rc));
		q->inflight = 0;
		retire(q, n);
		bst_txq_kick(q); /* the next group; at most BST_TXQ_SLOTS deep */
	}
}
