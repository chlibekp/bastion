/* HTTP/2 with prior knowledge on a cleartext listener (`listen 8080 h2c`; RFC 9113 section 3.3).
 *
 * The client sends the 24-byte preface first. So the first bytes decide: while what has arrived
 * is still a prefix of the preface the sniffer waits; the moment one byte differs the connection
 * is HTTP/1.1, and once all 24 match it is HTTP/2. Either way the bytes read so far are handed
 * to the protocol, which processes them first. */
#include "http/h1/conn.h"
#include "http/h2/conn.h"
#include "io/loop.h"
#include "route/vhost.h"

#include <stdlib.h>
#include <string.h>

typedef struct sniff {
	bst_worker *w;
	bst_loop *loop;
	bst_transport *t;
	const bst_listener_set *set;
	bst_sockaddr peer;
	bool has_peer, syn_data;
	uint8_t *buf;
	size_t len, cap;
	bst_timer timer;
} sniff;

static void sniff_free(sniff *s)
{
	bst_timer_cancel(&s->timer);
	free(s->buf);
	free(s);
}

static void on_timeout(void *ud)
{
	sniff *s = ud; /* the client said nothing, or too slowly: the same as an idle HTTP/1.1 connection */
	s->t->ops->close(s->t);
	sniff_free(s);
}

static void decide(sniff *s, bool h2)
{
	s->t->ops->recv_stop(s->t);
	bst_transport *t = s->t;
	const bst_sockaddr *peer = s->has_peer ? &s->peer : NULL;
	if (h2)
		(void)bst_conn_h2_start(s->w, t, s->set, peer, s->buf, s->len, s->syn_data);
	else
		(void)bst_conn_h1_start_prefix(s->w, t, s->set, peer, s->buf, s->len, s->syn_data);
	sniff_free(s);
}

static void on_recv(void *ud, bst_buf *data, int err)
{
	sniff *s = ud;
	if (data == NULL || err != 0) { /* closed or failed before saying anything */
		if (data != NULL)
			bst_buf_unref(data);
		s->t->ops->close(s->t);
		sniff_free(s);
		return;
	}
	if (s->len + data->len > s->cap) {
		size_t cap = s->len + data->len;
		uint8_t *nb = realloc(s->buf, cap);
		if (nb == NULL) {
			bst_buf_unref(data);
			s->t->ops->close(s->t);
			sniff_free(s);
			return;
		}
		s->buf = nb;
		s->cap = cap;
	}
	memcpy(s->buf + s->len, data->data, data->len);
	s->len += data->len;
	bst_buf_unref(data);
	size_t cmp = s->len < BST_H2_PREFACE_LEN ? s->len : BST_H2_PREFACE_LEN;
	if (memcmp(s->buf, BST_H2_PREFACE, cmp) != 0)
		decide(s, false);
	else if (s->len >= BST_H2_PREFACE_LEN)
		decide(s, true);
	/* else: a still-matching prefix of the preface; wait for the rest */
}

void bst_h2c_sniff(bst_worker *w, bst_transport *t, const bst_listener_set *set, const bst_sockaddr *peer,
		   bool syn_data)
{
	sniff *s = calloc(1, sizeof *s);
	const bst_cfg_server *def = bst_vhost_default(set);
	if (s == NULL || def == NULL) {
		free(s);
		t->ops->close(t);
		return;
	}
	s->w = w;
	s->loop = bst_worker_loop(w);
	s->t = t;
	s->set = set;
	s->syn_data = syn_data;
	if (peer != NULL) {
		s->peer = *peer;
		s->has_peer = true;
	}
	bst_timer_init(&s->timer);
	bst_loop_timer_arm(s->loop, &s->timer, def->common.http.client_header_timeout_ms, on_timeout, s);
	if (t->ops->recv_start(t, on_recv, s) != 0) {
		t->ops->close(t);
		sniff_free(s);
	}
}
