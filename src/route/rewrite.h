/* `rewrite` rules, run by the router (route/router.c) in two phases: the rules of the server
 * before the location is chosen, those of the location after. See the directive's text in
 * config/rewrite_directives.c for the language. */
#ifndef BST_ROUTE_REWRITE_H
#define BST_ROUTE_REWRITE_H

#include "config/compile.h"
#include "http/stream.h"

/* Runs rules (a list of bst_cfg_rewrite) in order on s->uri. A matching rule replaces the path
 * (and the query when the replacement has a '?'), and the rules after it see the new path, until
 * one carries a flag: *flag is then that flag, else BST_REWRITE_NONE. 0, or the status to
 * answer with (500: a regex over its limit, a result that is not an absolute path). */
int bst_rewrite_run(bst_stream *s, const bst_cfg_list *rules, bst_rewrite_flag *flag);

/* The built-in `redirect` and `redirect_https` handler (answers with the location). */
extern const bst_handler_ops bst_redirect_handler;

/* Applies the request header operations of s->cfg to the request (route/router.c calls it once
 * the location is final). */
void bst_apply_request_headers(bst_stream *s);

#endif
