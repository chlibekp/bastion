/* Protocol-independent request and response model (architecture section 5). HTTP/1.1 fills a
 * bst_req_head from bytes, HTTP/2 and HTTP/3 from decoded fields; handlers read the same
 * struct on every protocol. Every bst_str here points into an arena or buffer that outlives
 * the request. */
#ifndef BST_HTTP_HTTP_H
#define BST_HTTP_HTTP_H

#include "core/str.h"
#include "http/headers.h"

#include <stdbool.h>
#include <stdint.h>

typedef enum bst_method {
	BST_M_UNKNOWN = 0, /* a valid token that is none of the others */
	BST_M_GET,
	BST_M_HEAD,
	BST_M_POST,
	BST_M_PUT,
	BST_M_DELETE,
	BST_M_CONNECT,
	BST_M_OPTIONS,
	BST_M_TRACE,
	BST_M_PATCH,
} bst_method;

bst_method bst_method_from(bst_str s);
const char *bst_method_name(bst_method m); /* "GET"; "" for BST_M_UNKNOWN */

/* RFC 9112 section 3.2: the four shapes of a request-target. */
typedef enum bst_target_form {
	BST_TARGET_ORIGIN,    /* /path?query */
	BST_TARGET_ABSOLUTE,  /* http://host/path?query */
	BST_TARGET_AUTHORITY, /* host:port, CONNECT only */
	BST_TARGET_ASTERISK,  /* *, OPTIONS only */
} bst_target_form;

typedef struct bst_req_head {
	bst_method method;
	bst_str method_str; /* as received, also for BST_M_UNKNOWN */
	bst_target_form form;
	bst_str target;    /* the request-target exactly as received */
	bst_str scheme;    /* absolute form: lower or upper case as written */
	bst_str authority; /* absolute and authority form: host[:port] */
	bst_str path;      /* origin and absolute form, not decoded; "/" for an absolute form with none */
	bst_str query;     /* without the '?'; check has_query to tell "" from none */
	bool has_query;
	uint8_t version_minor; /* 0 or 1; HTTP/1.2 and later minors count as 1 (RFC 9112 section 2.3) */
	bst_headers headers;
} bst_req_head;

/* A response head as handlers give it to a protocol. content_length < 0 means unknown (the
 * protocol then chunks or closes). headers carry no framing or connection headers: the
 * protocol adds Content-Length, Transfer-Encoding, Connection, Date and Server itself. */
typedef struct bst_resp_head {
	int status;
	int64_t content_length;
	bool close; /* end the connection after this response (HTTP/1.x: Connection: close) */
	bst_headers headers;
} bst_resp_head;

/* Why a stream is reset: given to bst_stream_ops.reset and bst_handler_ops.on_reset. */
typedef enum bst_stream_err {
	BST_STREAM_ERR_NONE = 0,
	BST_STREAM_ERR_CANCEL,   /* the peer went away or gave up */
	BST_STREAM_ERR_TIMEOUT,  /* a deadline ran out */
	BST_STREAM_ERR_PROTOCOL, /* the peer broke the protocol */
	BST_STREAM_ERR_INTERNAL, /* our side failed */
} bst_stream_err;

#endif
