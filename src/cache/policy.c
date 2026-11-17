/* See policy.h. */
#include "cache/policy.h"

#include "http/accept_encoding.h"
#include "http/conditional.h"

#include <string.h>

static bool resp_cc(const bst_headers *resp, const bst_cache_policy_cfg *cfg, bst_cache_control *cc)
{
	if (cfg->ignore & BST_CACHE_IGN_CACHE_CONTROL) {
		bst_cc_init(cc);
		return false;
	}
	return bst_cc_parse(resp, cc);
}

/* Section 4.2.2: statuses whose responses are heuristically cacheable. Only the non-error
 * ones are used here (see policy.h). */
static bool heuristic_status(int st)
{
	return st == 200 || st == 203 || st == 204 || st == 300 || st == 301 || st == 308;
}

static const bst_cache_valid *valid_rule(const bst_cache_policy_cfg *cfg, int status)
{
	for (size_t i = 0; i < cfg->nvalid; i++)
		if (cfg->valid[i].status == status || cfg->valid[i].status == 0)
			return &cfg->valid[i];
	return NULL;
}

static bool date_of(const bst_headers *h, bst_hdr_id id, int64_t *out)
{
	const bst_header *f = bst_headers_get(h, id);
	time_t t;
	if (f == NULL || bst_headers_count(h, id) != 1 || !bst_http_date_parse(f->value, &t))
		return false;
	*out = (int64_t)t;
	return true;
}

void bst_cache_resp_times(const bst_headers *resp, int64_t *date, int64_t *age)
{
	*date = BST_CC_NONE;
	*age = BST_CC_NONE;
	int64_t d;
	if (date_of(resp, BST_H_DATE, &d))
		*date = d;
	const bst_header *a = bst_headers_get(resp, BST_H_AGE);
	uint64_t v;
	if (a != NULL && bst_str_to_u64(a->value, &v))
		*age = v > 2147483648ull ? 2147483648ll : (int64_t)v;
}

void bst_cache_freshness(int status, const bst_headers *resp, const bst_cache_policy_cfg *cfg,
			 int64_t now, bst_freshness *out)
{
	memset(out, 0, sizeof *out);
	out->swr = out->sie = BST_CC_NONE;
	out->source = "none";
	bst_cache_control cc, cdn;
	resp_cc(resp, cfg, &cc);
	bool has_cdn = !(cfg->ignore & BST_CACHE_IGN_CDN_CACHE_CONTROL) &&
		       bst_cc_parse_name(resp, BST_S("cdn-cache-control"), &cdn);
	/* RFC 9213 section 2.2: a targeted field replaces Cache-Control */
	const bst_cache_control *c = has_cdn ? &cdn : &cc;
	out->no_cache = c->no_cache || (has_cdn && cc.no_cache);
	out->must_revalidate = c->must_revalidate || c->proxy_revalidate ||
			       c->s_maxage != BST_CC_NONE;
	out->immutable = c->immutable;
	out->swr = c->swr;
	out->sie = c->sie;
	if (c->invalid) { /* section 4.2.1: stale */
		out->lifetime = 0;
		out->source = "invalid";
		return;
	}
	if (has_cdn && (cdn.max_age != BST_CC_NONE || cdn.s_maxage != BST_CC_NONE)) {
		out->lifetime = cdn.s_maxage != BST_CC_NONE ? cdn.s_maxage : cdn.max_age;
		out->source = "cdn-cache-control";
		return;
	}
	if (cc.s_maxage != BST_CC_NONE) {
		out->lifetime = cc.s_maxage;
		out->source = "s-maxage";
		return;
	}
	if (cc.max_age != BST_CC_NONE) {
		out->lifetime = cc.max_age;
		out->source = "max-age";
		return;
	}
	if (!(cfg->ignore & BST_CACHE_IGN_EXPIRES) && bst_headers_get(resp, BST_H_EXPIRES) != NULL) {
		int64_t exp, date;
		if (!date_of(resp, BST_H_EXPIRES, &exp)) {
			out->lifetime = 0; /* an invalid Expires means already expired (5.3) */
			out->source = "expires";
			return;
		}
		if (!date_of(resp, BST_H_DATE, &date))
			date = now;
		out->lifetime = exp - date;
		out->source = "expires";
		return;
	}
	const bst_cache_valid *v = valid_rule(cfg, status);
	if (v != NULL) {
		out->lifetime = v->secs;
		out->source = "cache_valid";
		return;
	}
	int64_t lm, date;
	if (cfg->heuristic_max > 0 && heuristic_status(status) && date_of(resp, BST_H_LAST_MODIFIED, &lm)) {
		if (!date_of(resp, BST_H_DATE, &date))
			date = now;
		int64_t h = date > lm ? (date - lm) / 10 : 0; /* 10 % of the age (4.2.2) */
		out->lifetime = h > cfg->heuristic_max ? cfg->heuristic_max : h;
		out->source = "heuristic";
	}
}

int64_t bst_cache_age(int64_t date, int64_t age_value, int64_t req_time, int64_t resp_time,
		      int64_t now)
{
	if (age_value == BST_CC_NONE)
		age_value = 0;
	int64_t apparent = date == BST_CC_NONE ? 0 : resp_time - date;
	if (apparent < 0)
		apparent = 0; /* a clock ahead of ours never makes a response younger */
	int64_t delay = resp_time - req_time;
	if (delay < 0)
		delay = 0;
	int64_t corrected_age = age_value + delay;
	int64_t initial = apparent > corrected_age ? apparent : corrected_age;
	int64_t resident = now - resp_time;
	if (resident < 0)
		resident = 0;
	return initial + resident;
}

bool bst_cache_req_no_store(const bst_headers *req)
{
	bst_cache_control cc;
	bst_cc_parse(req, &cc);
	return cc.no_store;
}

bool bst_cache_req_revalidate(const bst_headers *req, const bst_cache_policy_cfg *cfg)
{
	if (!cfg->honor_request_cc)
		return false;
	bst_cache_control cc;
	if (bst_cc_parse(req, &cc))
		return cc.no_cache || cc.max_age == 0;
	return bst_headers_list_has(req, BST_H_PRAGMA, BST_S("no-cache")); /* 5.4 */
}

bool bst_cache_storable(const bst_req_head *req, int status, const bst_headers *resp,
			const bst_cache_policy_cfg *cfg, const char **reason)
{
	const char *why = NULL;
	bst_cache_control cc;
	resp_cc(resp, cfg, &cc);
	bst_freshness fr;
	if (req->method != BST_M_GET)
		why = "method";
	else if (status < 200 || status == 206 || status == 304 || status > 599)
		why = status == 206 ? "partial" : "status"; /* 206 is not stored in this version */
	else if (bst_cache_req_no_store(&req->headers))
		why = "request no-store";
	else if (cc.no_store)
		why = "no-store";
	else if (cc.priv)
		why = "private";
	else if (!(cfg->ignore & BST_CACHE_IGN_SET_COOKIE) &&
		 bst_headers_get(resp, BST_H_SET_COOKIE) != NULL &&
		 cfg->cookies == BST_CACHE_COOKIES_NO_STORE)
		why = "set-cookie";
	else if (bst_headers_get(&req->headers, BST_H_AUTHORIZATION) != NULL && !cc.pub &&
		 cc.s_maxage == BST_CC_NONE && !cc.must_revalidate)
		why = "authorization"; /* 3.5 */
	if (why == NULL && !(cfg->ignore & BST_CACHE_IGN_VARY)) {
		char buf[BST_CACHE_VARY_MAX];
		int vn = bst_cache_vary_data(resp, &req->headers, cfg->vary_limit, buf, sizeof buf);
		if (vn == -1)
			why = "vary *";
		else if (vn == -2)
			why = "vary limit";
	}
	if (why == NULL) {
		bst_cache_freshness(status, resp, cfg, 0, &fr);
		bool explicit_fresh = strcmp(fr.source, "none") != 0;
		bool revalidatable = (fr.no_cache || cc.no_cache) &&
				     (bst_headers_get(resp, BST_H_ETAG) != NULL ||
				      bst_headers_get(resp, BST_H_LAST_MODIFIED) != NULL);
		if (!explicit_fresh && !revalidatable && !cc.pub)
			why = "no freshness";
		else if (status >= 400 && strcmp(fr.source, "heuristic") == 0)
			why = "no freshness";
	}
	if (reason != NULL)
		*reason = why;
	return why == NULL;
}

/* Appends v with whitespace runs folded and both ends trimmed. */
static size_t fold(bst_str v, char *out, size_t k, size_t cap, bool *over)
{
	bool space = false, any = false;
	for (uint32_t i = 0; i < v.len; i++) {
		char c = v.p[i];
		if (c == ' ' || c == '\t') {
			space = any;
			continue;
		}
		if (space) {
			if (k < cap)
				out[k] = ' ';
			k++;
			space = false;
		}
		if (k < cap)
			out[k] = c;
		k++;
		any = true;
	}
	if (k > cap)
		*over = true;
	return k;
}

/* The codings of zstd, br, gzip that the request's Accept-Encoding lines accept, as letters
 * "z", "b", "g" in that order ("" for none). A key on this set instead of the negotiated coding
 * stays right when the stored body was encoded by the upstream with a coding of its choice. */
static size_t ae_set(const bst_headers *req, char out[4])
{
	char joined[1024];
	size_t o = 0;
	for (const bst_header *h = bst_headers_next(req, NULL, BST_H_ACCEPT_ENCODING); h != NULL;
	     h = bst_headers_next(req, h, BST_H_ACCEPT_ENCODING)) {
		if (o + h->value.len + 2 > sizeof joined)
			break; /* the rest is ignored, as by the compress filter's own reading */
		if (o > 0) {
			joined[o++] = ',';
			joined[o++] = ' ';
		}
		memcpy(joined + o, h->value.p, h->value.len);
		o += h->value.len;
	}
	bst_str ae = { joined, (uint32_t)o };
	static const struct { bst_encoding e; char c; } codings[] = {
		{ BST_ENC_ZSTD, 'z' }, { BST_ENC_BR, 'b' }, { BST_ENC_GZIP, 'g' }
	};
	size_t n = 0;
	for (size_t i = 0; i < 3; i++)
		if (o > 0 && bst_negotiate_encoding(ae, BST_ENC_BIT(codings[i].e)) == codings[i].e)
			out[n++] = codings[i].c;
	return n;
}

int bst_cache_vary_data(const bst_headers *resp, const bst_headers *req, unsigned limit, char *out,
			size_t cap)
{
	size_t k = 0;
	unsigned names = 0;
	bool over = false;
	for (const bst_header *f = bst_headers_next(resp, NULL, BST_H_VARY); f != NULL;
	     f = bst_headers_next(resp, f, BST_H_VARY)) {
		bst_str v = f->value;
		uint32_t i = 0;
		while (i < v.len) {
			while (i < v.len && (v.p[i] == ' ' || v.p[i] == '\t' || v.p[i] == ','))
				i++;
			uint32_t s = i;
			while (i < v.len && v.p[i] != ',' && v.p[i] != ' ' && v.p[i] != '\t')
				i++;
			bst_str name = { v.p + s, i - s };
			while (i < v.len && v.p[i] != ',')
				i++; /* junk after the name: ignored */
			if (name.len == 0)
				continue;
			if (name.len == 1 && name.p[0] == '*')
				return -1;
			if (limit > 0 && ++names > limit)
				return -2;
			for (uint32_t j = 0; j < name.len; j++, k++)
				if (k < cap)
					out[k] = (char)(name.p[j] >= 'A' && name.p[j] <= 'Z' ? name.p[j] + 32
											: name.p[j]);
			if (k < cap)
				out[k] = ':';
			k++;
			if (bst_str_ieq(name, BST_S("accept-encoding"))) {
				/* never the raw field: the set of codings it accepts (at most 8 values) */
				char set[4];
				size_t sn = ae_set(req, set);
				for (size_t j = 0; j < sn; j++, k++)
					if (k < cap)
						out[k] = set[j];
				if (k < cap)
					out[k] = '\n';
				k++;
				continue;
			}
			bool first = true;
			for (const bst_header *r = bst_headers_next_name(req, NULL, name); r != NULL;
			     r = bst_headers_next_name(req, r, name)) {
				if (!first) {
					if (k < cap)
						out[k] = ',';
					k++;
				}
				first = false;
				k = fold(r->value, out, k, cap, &over);
			}
			if (k < cap)
				out[k] = '\n';
			k++;
		}
	}
	if (k > cap || over || k > BST_CACHE_VARY_MAX)
		return -2;
	return (int)k;
}

bool bst_cache_key_vary_match(bst_str stored_vary, const bst_headers *stored_resp,
			      const bst_headers *req)
{
	char buf[BST_CACHE_VARY_MAX];
	int n = bst_cache_vary_data(stored_resp, req, 0, buf, sizeof buf);
	if (n < 0)
		return false; /* Vary: * never matches (4.1), nor does data too long to compare */
	return (uint32_t)n == stored_vary.len && memcmp(buf, stored_vary.p, (size_t)n) == 0;
}

bool bst_cache_invalidates(bst_method m, int status)
{
	bool unsafe = m != BST_M_GET && m != BST_M_HEAD && m != BST_M_OPTIONS && m != BST_M_TRACE;
	return unsafe && status >= 200 && status < 400;
}

static bool keep_stored(bst_hdr_id id)
{
	switch (id) {
	case BST_H_CONTENT_LENGTH:
	case BST_H_TRANSFER_ENCODING:
	case BST_H_CONTENT_RANGE:
	case BST_H_CONNECTION:
	case BST_H_KEEP_ALIVE:
	case BST_H_TE:
	case BST_H_TRAILER:
	case BST_H_UPGRADE:
	case BST_H_PROXY_CONNECTION:
		return true;
	default:
		return false;
	}
}

int bst_cache_merge_304(bst_headers *stored, const bst_headers *r)
{
	for (uint32_t i = 0; i < r->n; i++) {
		const bst_header *f = &r->v[i];
		if (keep_stored(f->id))
			continue;
		bool first = true; /* the first line of this name in the 304 replaces the stored ones */
		for (uint32_t j = 0; j < i; j++)
			if (bst_str_ieq(r->v[j].name, f->name))
				first = false;
		char *b = bst_arena_alloc(stored->arena, (size_t)f->name.len + f->value.len + 1);
		if (b == NULL)
			return -1;
		memcpy(b, f->name.p, f->name.len);
		if (f->value.len > 0)
			memcpy(b + f->name.len, f->value.p, f->value.len);
		bst_str nm = { b, f->name.len }, val = { b + f->name.len, f->value.len };
		if (first)
			(void)bst_headers_remove_name(stored, f->name);
		if (bst_headers_add(stored, nm, val) != 0)
			return -1;
	}
	return 0;
}
