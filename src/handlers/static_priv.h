/* What static.c and static_send.c share: a response body is a list of pieces, memory (the part
 * headers of multipart/byteranges) or a range of the open file. */
#ifndef BST_HANDLERS_STATIC_PRIV_H
#define BST_HANDLERS_STATIC_PRIV_H

#include "handlers/ofcache.h"
#include "http/stream.h"

typedef struct bst_piece {
	bst_buf *mem; /* non-NULL: the buffer's bytes (0..len) */
	off_t foff, flen; /* else: bytes of the file */
} bst_piece;

/* Sends the pieces as the body (end_stream on the last byte) with every file segment sendfile
 * or splice can move: one chain, file segments cut at max_chunk. 0, or -1 when out of memory
 * (nothing sent). */
int bst_static_send_chain(bst_stream *s, bst_file *f, const bst_piece *p, int n, uint64_t max_chunk);

/* Sends the pieces by reading the file on the aio pool, chunk bytes at a time, one send in
 * flight: for `sendfile off`. Takes a reference of f and of each mem piece. *slot is set to the
 * state until it ends, so on_reset can abort it: bst_static_stream_abort(*slot). 0, or -1 out of
 * memory (nothing sent). */
struct bst_static_rd;
int bst_static_send_read(bst_stream *s, bst_file *f, const bst_piece *p, int n, size_t chunk,
			 struct bst_static_rd **slot);
void bst_static_stream_abort(struct bst_static_rd *rd);

#endif
