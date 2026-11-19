/* Template variables of the request layer (config/template.h defines the machinery, this file
 * defines what `$host`, `$uri`, `$arg_NAME`, `$1` and the others mean for a bst_stream).
 *
 * Values are views into the request or its arena and live as long as the stream. What is
 * decoded and what is not matters in a Location or a header:
 *   $uri          the normalized path, percent-decoded: it can hold any byte, CR and LF too
 *   $request_uri  the target as the client sent it, path and query, still encoded: use this
 *                 one to build a redirect
 *   $args, $arg_NAME, $cookie_NAME   as sent, not decoded
 *   $http_NAME    a request header ("_" stands for "-", case ignored)
 *   $host         the Host without port
 *   $remote_addr, $remote_port, $scheme, $request_method, $request_id
 *   $status       the status of the response being sent (empty before one exists)
 *   $1 .. $9      the groups of the regex that chose the location, or of the rewrite running
 * A header template that evaluates to a line break is refused whole (header_tpl, not stripped). */
#ifndef BST_ROUTE_VARS_H
#define BST_ROUTE_VARS_H

#include "config/template.h"
#include "http/stream.h"

/* What an access log must not show (ops/logger.h): with a ctx's redact set, $http_NAME of a
 * listed header and $cookie_NAME (when `cookie` is listed) read "[REDACTED]", and so do the
 * values of listed query parameters in $arg_NAME, $args and $request_uri. Names are lower case;
 * header names compare case-insensitively, parameter names after percent-decoding. */
typedef struct bst_var_redact {
	const char *const *headers;
	size_t nheaders;
	const char *const *params;
	size_t nparams;
} bst_var_redact;

#define BST_REDACTED "[REDACTED]"

struct bst_var_ctx {
	bst_stream *s;
	const bst_captures *caps; /* what $1..$9 read: the stream's, or a rewrite's */
	int status;		  /* $status */
	const bst_var_redact *redact; /* NULL except when rendering a log line */
};

static inline void bst_var_ctx_init(bst_var_ctx *c, bst_stream *s)
{
	c->s = s;
	c->caps = &s->caps;
	c->status = 0;
	c->redact = NULL;
}

/* True for a variable whose value is the client's own input (arguments, headers, cookies,
 * captures of a path): a redirect that begins with one lets the client choose where it goes. */
bool bst_var_is_request_input(bst_var_fn fn);

#endif
