#include "http/stream.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

bst_arena *bst_stream_arena(bst_stream *s)
{
	return s->arena;
}

bst_req *bst_stream_req(bst_stream *s)
{
	return &s->req;
}

void bst_stream_set_handler(bst_stream *s, const bst_handler_ops *h, void *hctx)
{
	s->handler = h;
	s->hctx = hctx;
	if (h->on_request != NULL)
		h->on_request(s);
}

int bst_stream_send_head(bst_stream *s, const bst_resp_head *h, bool end_stream)
{
	return s->ops->send_head(s, h, end_stream);
}

int bst_stream_send_interim(bst_stream *s, int status, const bst_headers *h)
{
	return s->ops->send_interim(s, status, h);
}

int bst_stream_send_body(bst_stream *s, bst_chain *c, bool end_stream, bst_done_cb cb, void *ud)
{
	return s->ops->send_body(s, c, end_stream, cb, ud);
}

int bst_stream_send_trailers(bst_stream *s, const bst_headers *h)
{
	return s->ops->send_trailers(s, h);
}

void bst_stream_read_body(bst_stream *s, size_t credit)
{
	s->ops->read_body(s, credit);
}

/* ---- virtual servers ---- */

bst_cfg_server_set *bst_server_set_new(const bst_config *cfg, const bst_cfg_listen *l)
{
	const bst_cfg_global *g = &cfg->global;
	bst_cfg_server_set *set = calloc(1, sizeof *set);
	if (set == NULL)
		return NULL;
	set->servers = calloc(g->nservers ? g->nservers : 1, sizeof *set->servers);
	if (set->servers == NULL) {
		free(set);
		return NULL;
	}
	for (size_t i = 0; i < g->nservers; i++) {
		const bst_cfg_server *s = g->servers[i];
		for (size_t j = 0; j < s->nlistens; j++) {
			const bst_sockaddr *a = &s->listens[j].addr;
			if (a->port == l->addr.port && bst_ip_eq(&a->ip, &l->addr.ip)) {
				set->servers[set->n++] = s;
				break;
			}
		}
	}
	for (size_t i = 0; i < set->n && set->dflt == NULL; i++)
		if (set->servers[i]->nnames == 0)
			set->dflt = set->servers[i];
	if (set->dflt == NULL && set->n > 0)
		set->dflt = set->servers[0];
	return set;
}

const bst_cfg_server *bst_server_match(const bst_cfg_server_set *set, bst_str host)
{
	/* Strip the port, and the brackets of an IPv6 literal. */
	if (host.p == NULL || host.len == 0)
		return set->dflt;
	const char *p = host.p;
	size_t len = host.len;
	if (len > 0 && p[0] == '[') {
		const char *rb = memchr(p, ']', len);
		if (rb != NULL) {
			len = (size_t)(rb - p) - 1;
			p++;
		}
	} else {
		const char *colon = memchr(p, ':', len);
		if (colon != NULL)
			len = (size_t)(colon - p);
	}
	for (size_t i = 0; len > 0 && i < set->n; i++) {
		const bst_cfg_server *s = set->servers[i];
		for (size_t k = 0; k < s->nnames; k++) {
			const char *name = s->names[k];
			if (name[0] != '~' && strlen(name) == len) {
				size_t j = 0;
				while (j < len && tolower((unsigned char)p[j]) == (unsigned char)name[j])
					j++;
				if (j == len)
					return s;
			}
		}
	}
	return set->dflt;
}

/* Phase 5 replaces this with vhost, location and rewrite. For now a server answers with its
 * `return`, or 404. */
void bst_stream_dispatch(bst_stream *s)
{
	if (s->cfg != NULL && s->cfg->http.ret.set)
		bst_stream_set_handler(s, &bst_return_handler, NULL);
	else
		(void)bst_send_error(s, 404);
}
