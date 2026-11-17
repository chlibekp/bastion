/* WAF-lite (Phase 12, Task 4): small request rules, checked between routing and the handler.
 *
 *   waf_rule wp_admin {
 *       match path prefix /wp-admin;
 *       match method != POST;
 *       action deny 403;
 *   }
 *   server { waf wp_admin bad_bots; rule_mode enforce; }
 *
 * A rule is one or more `match <subject> <op> [value]` lines that all have to hold (AND), and one
 * action: allow (stop checking, let the request through), deny [status] (403 by default), log
 * (log the match and go on to the next rule), challenge (the proof-of-work page, sec/challenge.h)
 * or limit <zone> (charge the request to that limit_zone). Rules run in the order `waf` names
 * them and the first rule that matches with a deciding action (all but log) wins.
 * `rule_mode log` logs what would have happened and acts on nothing.
 *
 * Subjects: path (the normalized, percent-decoded path, so /%77p-admin is /wp-admin), uri (the
 * request target as sent), query, arg:<name>, header:<name>, cookie:<name>, method, host, ip (the
 * client address after real_ip), ja4 (TLS only), content_type, content_length, user_agent,
 * protocol (HTTP/1.0, HTTP/1.1, HTTP/2, HTTP/3), tls_version (TLS only).
 *
 * Operators: = != ~ !~ (PCRE2, with the regex_match_limit) prefix suffix contains in_cidr
 * in_file (a file of CIDRs for ip, else of exact values, one per line) > < (numbers) missing
 * exists. A subject with several values (a repeated header, argument or cookie) matches a
 * positive operator when any value does, and != or !~ when any value does not match the value.
 * A subject with no value (a missing header, ja4 over cleartext) matches only `missing`. Values
 * compare case-sensitively, as sent (header names ignore case); arg: names and values are
 * percent-decoded first. A regex that hits its limit counts as a match for a deny or challenge
 * rule (fail closed) and as no match otherwise; so does a subject with more than 128 values.
 *
 * No request body inspection and no scoring: deliberately small. Rules compile at load into flat
 * arrays, with each rule's cheap tests ordered before its regexes. */
#ifndef BST_SEC_WAF_H
#define BST_SEC_WAF_H

#include "config/compile.h"
#include "core/cidr.h"
#include "core/str.h"
#include "http/stream.h"
#include "route/regex.h"

#include <stdbool.h>
#include <stdint.h>

typedef enum bst_waf_subject {
	BST_WAF_PATH = 0, BST_WAF_URI, BST_WAF_QUERY, BST_WAF_ARG, BST_WAF_HEADER, BST_WAF_COOKIE,
	BST_WAF_METHOD, BST_WAF_HOST, BST_WAF_IP, BST_WAF_JA4, BST_WAF_CONTENT_TYPE,
	BST_WAF_CONTENT_LENGTH, BST_WAF_USER_AGENT, BST_WAF_PROTOCOL, BST_WAF_TLS_VERSION,
	BST_WAF_SUBJECTS
} bst_waf_subject;

typedef enum bst_waf_op {
	BST_WAF_EQ = 0, BST_WAF_NE, BST_WAF_RE, BST_WAF_NRE, BST_WAF_PREFIX, BST_WAF_SUFFIX,
	BST_WAF_CONTAINS, BST_WAF_IN_CIDR, BST_WAF_IN_FILE, BST_WAF_GT, BST_WAF_LT, BST_WAF_MISSING,
	BST_WAF_EXISTS, BST_WAF_OPS
} bst_waf_op;

typedef enum bst_waf_verdict {
	BST_WAF_NONE = 0,  /* no rule decided: carry on */
	BST_WAF_ALLOW,	   /* an allow rule matched: skip the remaining rules */
	BST_WAF_DENY,	   /* refuse with status */
	BST_WAF_CHALLENGE, /* answer with the challenge (sec/challenge.h) */
	BST_WAF_LIMIT,	   /* charge the request to zone */
} bst_waf_verdict;

typedef struct bst_waf_match {
	uint8_t subject, op;
	bst_str name;		  /* arg:, header:, cookie: */
	bst_str value;
	int64_t num;		  /* > < and content_length = */
	bst_regex *re;		  /* ~ !~ */
	bst_cidr cidr;		  /* in_cidr */
	const bst_cidrset *cidrs; /* in_file of ip */
	const bst_str *words;	  /* in_file of anything else: sorted */
	size_t nwords;
} bst_waf_match;

struct bst_limit_zone;

typedef struct bst_waf_rule {
	const char *name;
	bst_cfg_loc loc;
	bst_waf_match *m; /* cheap first, regexes last */
	size_t nm, cap_;
	bst_waf_verdict action; /* BST_WAF_NONE: log */
	bool action_set;
	unsigned status;	/* deny */
	const char *zone_name;	/* limit */
	struct bst_limit_zone *zone;
	bst_escalate_cfg esc;	/* `escalate`: a deny is a strike */
	uint64_t hits_id;	/* bastion_waf_matches_total{rule} counter id */
} bst_waf_rule;

/* `waf <rule>...`: the names as written, resolved by a post hook. */
typedef struct bst_waf_ref {
	const char *name;
	bst_cfg_loc loc;
	bst_waf_rule *rule;
} bst_waf_ref;

/* What evaluating a set of rules decided. */
typedef struct bst_waf_action {
	bst_waf_verdict verdict;
	const bst_waf_rule *rule; /* the deciding rule, or NULL */
	unsigned status;
	bool regex_limit;	  /* a regex hit its limit on the way */
} bst_waf_action;

/* Called for each rule that matched (logs, counters), in order; may be NULL. */
typedef void (*bst_waf_on_match)(const bst_waf_rule *r, const bst_stream *s, void *ud);

/* Evaluates the rules (const bst_waf_ref *) of a scope against a request whose client address
 * (sec_ip) is set. */
bst_waf_action bst_waf_eval(const bst_cfg_list *rules, const bst_stream *s, bst_waf_on_match cb, void *ud);

/* One match line against a request (for tests). True when it holds; *limit set when a regex hit
 * its limit. */
bool bst_waf_match_eval(const bst_waf_match *m, const bst_stream *s, bool *limit);

/* Parses `<subject> <op> [value]` into m (the regex compiled, the file loaded). 0, or -1 with why
 * set (cap bytes). */
int bst_waf_match_parse(bst_waf_match *m, bst_str subject, bst_str op, const bst_str *value,
			bst_arena *a, char *why, size_t cap);
/* Sorts the matches of a rule: cheap subjects and operators first, regexes last. */
void bst_waf_rule_order(bst_waf_rule *r);
/* Frees what a match owns outside the arena (regex, file sets). */
void bst_waf_match_free(bst_waf_match *m);

#endif
