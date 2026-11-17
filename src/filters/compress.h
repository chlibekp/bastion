/* On-the-fly response compression (zstd, brotli, gzip): a response filter (bst_filter_ops) set
 * up at the response head when the scope's `compress` allows it and the response qualifies, so
 * it applies the same to every handler and protocol.
 *
 * Skipped (sent as it is): HEAD; statuses other than 200, 201, 202, 203; a request with Range;
 * a response that is already encoded, has Content-Range, says Cache-Control: no-transform, is
 * not of a compress_types type, or is known to be shorter than compress_min_size; with
 * compress_sensitive off, a request with Cookie or Authorization or a response with Set-Cookie
 * (BREACH); past compress_max_concurrent streams in the worker, or when the compressor's memory
 * does not fit the worker budget.
 *
 * A compressed response gets Content-Encoding, Vary: Accept-Encoding and a weak ETag, and loses
 * Content-Length and Accept-Ranges. Every body piece is flushed through the compressor, so
 * streamed responses (SSE) reach the client without waiting. File segments are read with pread
 * on the loop. */
#ifndef BST_FILTERS_COMPRESS_H
#define BST_FILTERS_COMPRESS_H

#include "http/stream.h"

#include <stdbool.h>

/* Called by bst_stream_send_head with the response head (already through the header
 * operations): when compression applies, edits h and adds the filter to s. When the response
 * could have been compressed for another client, adds Vary: Accept-Encoding even when not. */
void bst_compress_attach(bst_stream *s, bst_resp_head *h, bool end_stream);

/* The request's Accept-Encoding lines joined into one value (arena copy when there are
 * several), "" when absent. */
bst_str bst_compress_accept(bst_stream *s);

/* Compressed streams running in this worker (tests and stats). */
unsigned bst_compress_active(void);

#endif
