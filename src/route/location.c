#include "route/location.h"

#include "config/errfmt.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* A node of the compressed trie: the bytes of its edge, its children ordered by first byte, and
 * the location whose pattern ends here. Edges point into the pattern strings of the config. */
typedef struct tnode {
	const char *edge;
	uint32_t elen;
	struct tnode **kids;
	uint32_t nkids, kcap;
	const bst_cfg_location *loc;
} tnode;

struct bst_loc_level {
	tnode *prefix, *exact;
	const bst_cfg_location **re; /* file order */
	size_t nre;
};

static tnode *node_new(const char *edge, uint32_t elen)
{
	tnode *n = calloc(1, sizeof *n);
	if (n != NULL) {
		n->edge = edge;
		n->elen = elen;
	}
	return n;
}

static void node_free(tnode *n)
{
	if (n == NULL)
		return;
	for (uint32_t i = 0; i < n->nkids; i++)
		node_free(n->kids[i]);
	free(n->kids);
	free(n);
}

static tnode *find_kid(const tnode *n, unsigned char c)
{
	uint32_t lo = 0, hi = n->nkids;
	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2;
		unsigned char k = (unsigned char)n->kids[mid]->edge[0];
		if (k == c)
			return n->kids[mid];
		if (k < c)
			lo = mid + 1;
		else
			hi = mid;
	}
	return NULL;
}

static bool add_kid(tnode *n, tnode *kid)
{
	if (n->nkids == n->kcap) {
		uint32_t cap = n->kcap ? n->kcap * 2 : 2;
		tnode **v = realloc(n->kids, cap * sizeof *v);
		if (v == NULL)
			return false;
		n->kids = v;
		n->kcap = cap;
	}
	uint32_t i = n->nkids;
	while (i > 0 && (unsigned char)n->kids[i - 1]->edge[0] > (unsigned char)kid->edge[0]) {
		n->kids[i] = n->kids[i - 1];
		i--;
	}
	n->kids[i] = kid;
	n->nkids++;
	return true;
}

enum { INS_OK, INS_DUP, INS_OOM };

static int trie_insert(tnode *root, const char *key, size_t len, const bst_cfg_location *loc)
{
	tnode *node = root;
	size_t i = 0;
	while (i < len) {
		tnode *kid = find_kid(node, (unsigned char)key[i]);
		if (kid == NULL) {
			kid = node_new(key + i, (uint32_t)(len - i));
			if (kid == NULL || !add_kid(node, kid)) {
				node_free(kid);
				return INS_OOM;
			}
			kid->loc = loc;
			return INS_OK;
		}
		size_t c = 0;
		while (c < kid->elen && c < len - i && kid->edge[c] == key[i + c])
			c++;
		if (c < kid->elen) { /* split the edge: kid keeps the first c bytes, `low` the rest */
			tnode *low = node_new(kid->edge + c, kid->elen - (uint32_t)c);
			if (low == NULL)
				return INS_OOM;
			low->kids = kid->kids;
			low->nkids = kid->nkids;
			low->kcap = kid->kcap;
			low->loc = kid->loc;
			kid->kids = NULL;
			kid->nkids = kid->kcap = 0;
			kid->loc = NULL;
			kid->elen = (uint32_t)c;
			if (!add_kid(kid, low)) {
				/* undo: give everything back to kid so it frees cleanly */
				kid->kids = low->kids;
				kid->nkids = low->nkids;
				kid->kcap = low->kcap;
				kid->loc = low->loc;
				kid->elen += low->elen;
				free(low);
				return INS_OOM;
			}
		}
		node = kid;
		i += c;
	}
	if (node->loc != NULL)
		return INS_DUP;
	node->loc = loc;
	return INS_OK;
}

/* The location of the longest pattern that is a prefix of uri (exact: equal to uri). */
static const bst_cfg_location *trie_find(const tnode *root, bst_str uri, bool exact)
{
	const tnode *node = root;
	const bst_cfg_location *best = NULL;
	size_t i = 0;
	while (i < uri.len) {
		const tnode *kid = find_kid(node, (unsigned char)uri.p[i]);
		if (kid == NULL || uri.len - i < kid->elen || memcmp(kid->edge, uri.p + i, kid->elen) != 0)
			break;
		i += kid->elen;
		node = kid;
		if (node->loc != NULL)
			best = node->loc;
	}
	return exact ? (i == uri.len ? node->loc : NULL) : best;
}

void bst_loc_level_free(struct bst_loc_level *lv)
{
	if (lv == NULL)
		return;
	node_free(lv->prefix);
	node_free(lv->exact);
	free(lv->re);
	free(lv);
}

struct bst_loc_level *bst_loc_level_new(bst_cfg_location *const *locs, size_t n,
					const bst_cfg_location **bad, bst_err *err)
{
	if (bad != NULL)
		*bad = NULL;
	struct bst_loc_level *lv = calloc(1, sizeof *lv);
	if (lv != NULL) {
		lv->prefix = node_new("", 0);
		lv->exact = node_new("", 0);
		lv->re = calloc(n ? n : 1, sizeof *lv->re);
	}
	if (lv == NULL || lv->prefix == NULL || lv->exact == NULL || lv->re == NULL) {
		bst_loc_level_free(lv);
		bst_err_set(err, "out of memory");
		return NULL;
	}
	for (size_t i = 0; i < n; i++) {
		const bst_cfg_location *l = locs[i];
		int rc = INS_OK;
		if (l->mod == BST_LOC_REGEX || l->mod == BST_LOC_REGEX_I)
			lv->re[lv->nre++] = l;
		else
			rc = trie_insert(l->mod == BST_LOC_EXACT ? lv->exact : lv->prefix, l->pattern,
					 strlen(l->pattern), l);
		if (rc != INS_OK) {
			if (rc == INS_DUP) {
				char t[BST_SCHEMA_MAX_TOKEN_SHOWN + 8];
				bst_cfg_shown(l->pattern, strlen(l->pattern), t, sizeof t);
				bst_err_set(err, "duplicate location \"%s\"", t);
				if (bad != NULL)
					*bad = l;
			} else {
				bst_err_set(err, "out of memory");
			}
			bst_loc_level_free(lv);
			return NULL;
		}
	}
	return lv;
}

/* One level of nginx's search. NULL with caps->limit_hit set when a regex gave up. */
static const bst_cfg_location *level_pick(const struct bst_loc_level *lv, bst_str uri,
					  bst_captures *caps)
{
	const bst_cfg_location *hit = trie_find(lv->exact, uri, true);
	if (hit != NULL)
		return hit;
	const bst_cfg_location *best = trie_find(lv->prefix, uri, false);
	if (best != NULL && best->mod == BST_LOC_PREFIX_STOP)
		return best;
	for (size_t i = 0; i < lv->nre; i++) {
		int rc = bst_regex_match(lv->re[i]->re, uri, caps);
		if (rc == BST_RE_MATCH)
			return lv->re[i];
		if (rc == BST_RE_LIMIT) {
			caps->limit_hit = true;
			return NULL;
		}
	}
	return best;
}

const bst_cfg_location *bst_location_find(const bst_cfg_server *srv, bst_str uri,
					  bst_captures *caps)
{
	memset(caps, 0, sizeof *caps);
	caps->subject = uri;
	const bst_cfg_location *cur = NULL;
	for (const struct bst_loc_level *lv = srv->lvl; lv != NULL;) {
		const bst_cfg_location *pick = level_pick(lv, uri, caps);
		if (caps->limit_hit)
			return NULL;
		if (pick == NULL)
			break;
		cur = pick;
		lv = pick->lvl;
	}
	return cur;
}

/* ---- building, once, after the configuration compiled ---- */

static void free_regex(void *p)
{
	bst_regex_free(p);
}

static void free_level(void *p)
{
	bst_loc_level_free(p);
}

static int own(bst_config *cfg, void (*fn)(void *), void *p, bst_err *err)
{
	if (bst_config_on_free(cfg, fn, p, err) != 0) {
		fn(p);
		return -1;
	}
	return 0;
}

static bool is_regex(const bst_cfg_location *l)
{
	return l->mod == BST_LOC_REGEX || l->mod == BST_LOC_REGEX_I;
}

/* A nested prefix or exact location has to lie inside its parent's prefix, as in nginx. */
static int check_nesting(const bst_cfg_location *par, const bst_cfg_location *kid, bst_cfg_ctx *c,
			 bst_err *err)
{
	if (par == NULL || is_regex(par) || is_regex(kid))
		return 0;
	size_t pl = strlen(par->pattern);
	if (par->mod != BST_LOC_EXACT && strncmp(kid->pattern, par->pattern, pl) == 0)
		return 0;
	if (par->mod == BST_LOC_EXACT && strcmp(kid->pattern, par->pattern) == 0)
		return 0;
	char a[BST_SCHEMA_MAX_TOKEN_SHOWN + 8], b[BST_SCHEMA_MAX_TOKEN_SHOWN + 8];
	bst_cfg_shown(kid->pattern, strlen(kid->pattern), a, sizeof a);
	bst_cfg_shown(par->pattern, strlen(par->pattern), b, sizeof b);
	bst_err_set(err, "location \"%s\" is outside location \"%s\"", a, b);
	bst_cfg_err_at(err, bst_cfg_src(c, &kid->loc));
	return -1;
}

/* The rewrite rules of one scope. A list a scope inherits holds the very same rules as its
 * parent's, which are compiled already. */
static int prepare_rewrites(bst_config *cfg, bst_cfg_ctx *c, const bst_cfg_common *cm, bst_err *err)
{
	for (size_t i = 0; i < cm->rewrites.n; i++) {
		bst_cfg_rewrite *r = (bst_cfg_rewrite *)(uintptr_t)cm->rewrites.items[i];
		if (r->re != NULL)
			continue;
		r->re = bst_regex_compile((bst_str){ r->pattern, (uint32_t)strlen(r->pattern) }, false, err);
		if (r->re == NULL) {
			bst_cfg_err_at(err, bst_cfg_src(c, &r->loc));
			return -1;
		}
		if (own(cfg, free_regex, r->re, err) != 0)
			return -1;
	}
	return 0;
}

static int prepare_level(bst_config *cfg, bst_cfg_ctx *c, bst_cfg_location *parent,
			 bst_cfg_location **locs, size_t n, struct bst_loc_level **out,
			 bst_err *err)
{
	for (size_t i = 0; i < n; i++) {
		bst_cfg_location *l = locs[i];
		if (check_nesting(parent, l, c, err) != 0)
			return -1;
		if (is_regex(l)) {
			l->re = bst_regex_compile((bst_str){ l->pattern, (uint32_t)strlen(l->pattern) },
						  l->mod == BST_LOC_REGEX_I, err);
			if (l->re == NULL) {
				bst_cfg_err_at(err, bst_cfg_src(c, &l->loc));
				return -1;
			}
			if (own(cfg, free_regex, l->re, err) != 0)
				return -1;
		}
		if (prepare_rewrites(cfg, c, &l->common, err) != 0)
			return -1;
		if (l->nchildren > 0 &&
		    prepare_level(cfg, c, l, l->children, l->nchildren, &l->lvl, err) != 0)
			return -1;
	}
	const bst_cfg_location *bad;
	*out = bst_loc_level_new(locs, n, &bad, err);
	if (*out == NULL) {
		if (bad != NULL)
			bst_cfg_err_at(err, bst_cfg_src(c, &bad->loc));
		return -1;
	}
	return own(cfg, free_level, *out, err);
}

int bst_route_prepare(bst_config *cfg, bst_cfg_ctx *c, bst_err *err)
{
	if (prepare_rewrites(cfg, c, &cfg->global.common, err) != 0)
		return -1;
	for (size_t i = 0; i < cfg->global.nservers; i++) {
		bst_cfg_server *s = cfg->global.servers[i];
		if (prepare_rewrites(cfg, c, &s->common, err) != 0)
			return -1;
		if (s->nnames > 0) {
			s->name_res = bst_arena_alloc(cfg->arena, s->nnames * sizeof *s->name_res);
			if (s->name_res == NULL) {
				bst_err_set(err, "out of memory");
				return -1;
			}
			memset(s->name_res, 0, s->nnames * sizeof *s->name_res);
		}
		for (size_t k = 0; k < s->nnames; k++) {
			if (s->names[k][0] != '~')
				continue;
			/* host names are case-insensitive, so are the patterns that match them */
			s->name_res[k] = bst_regex_compile(
				(bst_str){ s->names[k] + 1, (uint32_t)strlen(s->names[k] + 1) }, true, err);
			if (s->name_res[k] == NULL) {
				bst_cfg_err_at(err, bst_cfg_src(c, &s->name_locs[k]));
				return -1;
			}
			if (own(cfg, free_regex, s->name_res[k], err) != 0)
				return -1;
		}
		if (s->nlocations > 0 &&
		    prepare_level(cfg, c, NULL, s->locations, s->nlocations, &s->lvl, err) != 0)
			return -1;
	}
	return 0;
}
