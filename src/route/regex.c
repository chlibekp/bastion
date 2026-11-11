#define PCRE2_CODE_UNIT_WIDTH 8
#include "route/regex.h"

#include <pcre2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct bst_regex {
	pcre2_code *code;
};

static uint32_t g_match_limit = BST_REGEX_MATCH_LIMIT_DEFAULT;
static uint32_t g_depth_limit = BST_REGEX_DEPTH_LIMIT_DEFAULT;
static pcre2_match_context *g_ctx;
static pcre2_match_data *g_data;

bst_str bst_captures_get(const bst_captures *c, unsigned i)
{
	if (i >= c->n || c->g[i].len == 0)
		return (bst_str){ c->subject.p != NULL ? c->subject.p : "", 0 };
	return (bst_str){ c->subject.p + c->g[i].off, c->g[i].len };
}

bst_regex *bst_regex_compile(bst_str pattern, bool icase, bst_err *err)
{
	int code = 0;
	PCRE2_SIZE off = 0;
	pcre2_code *c = pcre2_compile((PCRE2_SPTR)pattern.p, pattern.len,
				      icase ? PCRE2_CASELESS : 0, &code, &off, NULL);
	if (c == NULL) {
		PCRE2_UCHAR msg[120];
		if (pcre2_get_error_message(code, msg, sizeof msg) < 0)
			snprintf((char *)msg, sizeof msg, "error %d", code);
		bst_err_set(err, "invalid regular expression: %s (at offset %zu of the pattern)",
			    (const char *)msg, (size_t)off);
		return NULL;
	}
	bst_regex *re = malloc(sizeof *re);
	if (re == NULL) {
		pcre2_code_free(c);
		bst_err_set(err, "out of memory");
		return NULL;
	}
	re->code = c;
	return re;
}

void bst_regex_free(bst_regex *re)
{
	if (re == NULL)
		return;
	pcre2_code_free(re->code);
	free(re);
}

void bst_regex_set_limits(uint32_t match_limit, uint32_t depth_limit)
{
	g_match_limit = match_limit != 0 ? match_limit : BST_REGEX_MATCH_LIMIT_DEFAULT;
	g_depth_limit = depth_limit != 0 ? depth_limit : BST_REGEX_DEPTH_LIMIT_DEFAULT;
	if (g_ctx != NULL) {
		pcre2_set_match_limit(g_ctx, g_match_limit);
		pcre2_set_depth_limit(g_ctx, g_depth_limit);
	}
}

static bool ensure_state(void)
{
	if (g_ctx == NULL) {
		g_ctx = pcre2_match_context_create(NULL);
		if (g_ctx == NULL)
			return false;
		pcre2_set_match_limit(g_ctx, g_match_limit);
		pcre2_set_depth_limit(g_ctx, g_depth_limit);
	}
	if (g_data == NULL) {
		g_data = pcre2_match_data_create(BST_RE_MAX_CAPTURES, NULL);
		if (g_data == NULL)
			return false;
	}
	return true;
}

int bst_regex_match(const bst_regex *re, bst_str subject, bst_captures *caps)
{
	if (!ensure_state())
		return BST_RE_LIMIT;
	int rc = pcre2_match(re->code, (PCRE2_SPTR)(subject.p != NULL ? subject.p : ""), subject.len, 0,
			     0, g_data, g_ctx);
	if (rc == PCRE2_ERROR_NOMATCH)
		return BST_RE_NOMATCH;
	if (rc < 0)
		return BST_RE_LIMIT; /* match limit, depth limit, heap limit, bad offsets: fail closed */
	if (caps != NULL) {
		const PCRE2_SIZE *ov = pcre2_get_ovector_pointer(g_data);
		unsigned n = rc == 0 ? BST_RE_MAX_CAPTURES : (unsigned)rc; /* 0: ovector too small */
		caps->subject = subject;
		caps->n = n;
		caps->limit_hit = false;
		for (unsigned i = 0; i < BST_RE_MAX_CAPTURES; i++) {
			bool set = i < n && ov[2 * i] != PCRE2_UNSET && ov[2 * i + 1] >= ov[2 * i];
			caps->g[i].off = set ? (uint32_t)ov[2 * i] : 0;
			caps->g[i].len = set ? (uint32_t)(ov[2 * i + 1] - ov[2 * i]) : 0;
		}
	}
	return BST_RE_MATCH;
}
