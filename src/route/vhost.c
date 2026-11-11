#include "route/vhost.h"

#include "core/addr.h"
#include "route/regex.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define HOST_MAX 253 /* the longest DNS name; a longer Host matches nothing */

typedef struct ent {
	const char *key;
	uint32_t len;
	const bst_cfg_server *srv;
} ent;

typedef struct tab {
	ent *e;
	size_t mask; /* size - 1, size a power of two; 0 when the table is empty */
} tab;

typedef struct rx_ent {
	const bst_regex *re;
	const bst_cfg_server *srv;
} rx_ent;

struct bst_listener_set {
	const bst_cfg_server **servers;
	size_t n;
	const bst_cfg_server *dflt;
	tab exact;
	tab lead;  /* `*.example.com` under "example.com" */
	tab trail; /* `example.*` under "example" */
	rx_ent *rx; /* `~regex` names in file order */
	size_t nrx;
};

static uint64_t fnv(const char *p, size_t n)
{
	uint64_t h = 1469598103934665603ull;
	for (size_t i = 0; i < n; i++)
		h = (h ^ (unsigned char)p[i]) * 1099511628211ull;
	return h;
}

static bool tab_init(tab *t, size_t names)
{
	if (names == 0)
		return true;
	size_t sz = 16;
	while (sz < names * 2)
		sz <<= 1;
	t->e = calloc(sz, sizeof *t->e);
	t->mask = sz - 1;
	return t->e != NULL;
}

/* The first server to claim a key keeps it: file order decides. */
static void tab_put(tab *t, const char *key, size_t len, const bst_cfg_server *srv)
{
	size_t i = fnv(key, len) & t->mask;
	while (t->e[i].key != NULL) {
		if (t->e[i].len == len && memcmp(t->e[i].key, key, len) == 0)
			return;
		i = (i + 1) & t->mask;
	}
	t->e[i] = (ent){ key, (uint32_t)len, srv };
}

static const bst_cfg_server *tab_get(const tab *t, const char *key, size_t len)
{
	if (t->e == NULL)
		return NULL;
	size_t i = fnv(key, len) & t->mask;
	while (t->e[i].key != NULL) {
		if (t->e[i].len == len && memcmp(t->e[i].key, key, len) == 0)
			return t->e[i].srv;
		i = (i + 1) & t->mask;
	}
	return NULL;
}

static bool is_lead(const char *nm, size_t len)
{
	return len > 2 && nm[0] == '*' && nm[1] == '.';
}

static bool is_trail(const char *nm, size_t len)
{
	return len > 2 && nm[len - 1] == '*' && nm[len - 2] == '.';
}

bst_listener_set *bst_vhost_set_from(const bst_cfg_server *const *servers, size_t n,
				     const bst_cfg_server *dflt)
{
	bst_listener_set *s = calloc(1, sizeof *s);
	if (s == NULL)
		return NULL;
	s->servers = calloc(n ? n : 1, sizeof *s->servers);
	if (s->servers == NULL) {
		free(s);
		return NULL;
	}
	size_t nex = 0, nlead = 0, ntrail = 0, nrx = 0;
	for (size_t i = 0; i < n; i++) {
		s->servers[i] = servers[i];
		for (size_t k = 0; servers[i]->name_res != NULL && k < servers[i]->nnames; k++)
			nrx += servers[i]->name_res[k] != NULL;
		for (size_t k = 0; k < servers[i]->nnames; k++) {
			const char *nm = servers[i]->names[k];
			size_t len = strlen(nm);
			if (nm[0] == '~')
				continue;
			if (is_lead(nm, len))
				nlead++;
			else if (is_trail(nm, len))
				ntrail++;
			else
				nex++;
		}
	}
	s->n = n;
	s->rx = calloc(nrx ? nrx : 1, sizeof *s->rx);
	if (s->rx == NULL || !tab_init(&s->exact, nex) || !tab_init(&s->lead, nlead) || !tab_init(&s->trail, ntrail)) {
		bst_vhost_set_free(s);
		return NULL;
	}
	for (size_t i = 0; i < n; i++)
		for (size_t k = 0; k < servers[i]->nnames; k++) {
			const char *nm = servers[i]->names[k];
			size_t len = strlen(nm);
			if (nm[0] == '~') {
				if (servers[i]->name_res != NULL && servers[i]->name_res[k] != NULL)
					s->rx[s->nrx++] = (rx_ent){ servers[i]->name_res[k], servers[i] };
				continue;
			}
			if (is_lead(nm, len))
				tab_put(&s->lead, nm + 2, len - 2, servers[i]);
			else if (is_trail(nm, len))
				tab_put(&s->trail, nm, len - 2, servers[i]);
			else
				tab_put(&s->exact, nm, len, servers[i]);
		}
	s->dflt = dflt;
	for (size_t i = 0; s->dflt == NULL && i < n; i++)
		if (servers[i]->nnames == 0)
			s->dflt = servers[i];
	if (s->dflt == NULL && n > 0)
		s->dflt = servers[0];
	return s;
}

bst_listener_set *bst_vhost_set_new(const bst_config *cfg, const bst_cfg_listen *l)
{
	const bst_cfg_global *g = &cfg->global;
	const bst_cfg_server **list = calloc(g->nservers ? g->nservers : 1, sizeof *list);
	if (list == NULL)
		return NULL;
	size_t n = 0;
	const bst_cfg_server *dflt = NULL;
	for (size_t i = 0; i < g->nservers; i++) {
		const bst_cfg_server *s = g->servers[i];
		for (size_t j = 0; j < s->nlistens; j++) {
			const bst_sockaddr *a = &s->listens[j].addr;
			if (a->port != l->addr.port || !bst_ip_eq(&a->ip, &l->addr.ip))
				continue;
			list[n++] = s;
			if (s->listens[j].default_server && dflt == NULL)
				dflt = s;
			break;
		}
	}
	bst_listener_set *set = bst_vhost_set_from(list, n, dflt);
	free(list);
	return set;
}

void bst_vhost_set_free(bst_listener_set *s)
{
	if (s == NULL)
		return;
	free(s->exact.e);
	free(s->lead.e);
	free(s->trail.e);
	free(s->rx);
	free(s->servers);
	free(s);
}

const bst_cfg_server *bst_vhost_default(const bst_listener_set *s)
{
	return s->dflt;
}

/* Host header value to a lower-case name in buf: port, IPv6 brackets and one trailing dot go.
 * 0 when there is nothing to match. */
static size_t host_name(bst_str host, char *buf)
{
	const char *p = host.p;
	size_t len = host.len;
	if (p == NULL || len == 0)
		return 0;
	if (p[0] == '[') {
		const char *rb = memchr(p, ']', len);
		if (rb == NULL)
			return 0;
		len = (size_t)(rb - p) - 1;
		p++;
	} else {
		const char *colon = memchr(p, ':', len);
		if (colon != NULL)
			len = (size_t)(colon - p);
	}
	if (len > 0 && p[len - 1] == '.')
		len--;
	if (len == 0 || len > HOST_MAX)
		return 0;
	for (size_t i = 0; i < len; i++) {
		char c = p[i];
		buf[i] = c >= 'A' && c <= 'Z' ? (char)(c + 32) : c;
	}
	return len;
}

const bst_cfg_server *bst_vhost_lookup(const bst_listener_set *s, bst_str host, bool *matched)
{
	char buf[HOST_MAX + 1];
	size_t len = host_name(host, buf);
	const bst_cfg_server *hit = NULL;
	if (len > 0) {
		hit = tab_get(&s->exact, buf, len);
		for (size_t i = 0; hit == NULL && i < len; i++) /* "a.b.c": try "b.c", then "c" */
			if (buf[i] == '.')
				hit = tab_get(&s->lead, buf + i + 1, len - i - 1);
		for (size_t i = len; hit == NULL && i > 0; i--) /* "a.b.c": try "a.b", then "a" */
			if (buf[i - 1] == '.')
				hit = tab_get(&s->trail, buf, i - 1);
	}
	for (size_t i = 0; hit == NULL && len > 0 && i < s->nrx; i++)
		if (bst_regex_match(s->rx[i].re, (bst_str){ buf, (uint32_t)len }, NULL) == BST_RE_MATCH)
			hit = s->rx[i].srv; /* a limit counts as no match: the default answers */
	if (matched != NULL)
		*matched = hit != NULL;
	return hit != NULL ? hit : s->dflt;
}

const bst_cfg_server *bst_vhost_select(const bst_listener_set *s, bst_str host)
{
	return bst_vhost_lookup(s, host, NULL);
}
