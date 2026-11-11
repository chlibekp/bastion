/* PCRE2 behind a small, bounded interface. Every pattern in the configuration (location, server
 * name, rewrite) goes through here, and every match runs under a match limit and a depth limit:
 * a pattern such as (a+)+$ against a long URI ends in BST_RE_LIMIT instead of holding the worker.
 *
 * No JIT. PCRE2's JIT maps executable memory, which the worker's sandbox forbids on purpose
 * (mmap and mprotect never get PROT_EXEC), so the interpreter runs and the limits are what bound
 * the cost. Patterns are matched as bytes (no UTF mode): a request path is whatever bytes the
 * client percent-encoded.
 *
 * Matching uses one match-data block and one context per process and is for the loop thread only.
 * Compiled patterns are immutable and shared by the forked workers. */
#ifndef BST_ROUTE_REGEX_H
#define BST_ROUTE_REGEX_H

#include "core/err.h"
#include "core/str.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BST_RE_MAX_CAPTURES 10 /* the whole match and $1..$9 */

/* What the regex_match_limit and regex_depth_limit directives set when a process does not call
 * bst_regex_set_limits (unit tests): the directives' own defaults. */
#define BST_REGEX_MATCH_LIMIT_DEFAULT 100000u
#define BST_REGEX_DEPTH_LIMIT_DEFAULT 1000u

typedef struct bst_regex bst_regex;

/* The groups of the last successful match as offsets into the subject, which this holds a view
 * of (valid as long as the subject is). n counts the groups that exist, group 0 included; one
 * that did not take part has len 0. */
typedef struct bst_captures {
	bst_str subject;
	unsigned n;
	struct {
		uint32_t off, len;
	} g[BST_RE_MAX_CAPTURES];
	bool limit_hit; /* a regex of the search hit its limit: the search was abandoned */
} bst_captures;

/* The text of capture i, empty when it does not exist. */
bst_str bst_captures_get(const bst_captures *c, unsigned i);

enum { BST_RE_NOMATCH = 0, BST_RE_MATCH = 1, BST_RE_LIMIT = -1 };

/* NULL with err set ("... at offset N") for a pattern that does not compile. The result is
 * malloc'd: free it with bst_regex_free. */
bst_regex *bst_regex_compile(bst_str pattern, bool icase, bst_err *err);
void bst_regex_free(bst_regex *re);

/* Process-wide limits for every match from now on; 0 keeps the default of the macros above. */
void bst_regex_set_limits(uint32_t match_limit, uint32_t depth_limit);

/* Searches subject. BST_RE_MATCH fills caps (when not NULL) with the groups, BST_RE_NOMATCH
 * leaves it alone, BST_RE_LIMIT means the match or depth limit ended the attempt (or the
 * subject is too long for PCRE2's offsets): the caller must treat that as a failure, never as
 * "no match", where a regex guards something. */
int bst_regex_match(const bst_regex *re, bst_str subject, bst_captures *caps);

#endif
