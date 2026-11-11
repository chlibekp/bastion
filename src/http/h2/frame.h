/* HTTP/2 frame codec (RFC 9113 section 4 and 6, RFC 9218 section 7). Pure functions over bytes:
 * no sockets, no allocation in the parser, so it is fuzzed on its own (fuzz/fuzz_h2_frame.c).
 *
 * The parser checks everything a frame can be judged on without connection state: its length
 * against the peer's limit before the payload is read, the fixed sizes of the small frames, the
 * stream-id rules (SETTINGS and PING only on stream 0, DATA and HEADERS never on it) and padding.
 * Whatever needs state (stream states, header-block sequencing, window sums) is the connection's. */
#ifndef BST_HTTP_H2_FRAME_H
#define BST_HTTP_H2_FRAME_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define BST_H2_FRAME_HDR 9u
#define BST_H2_MIN_FRAME 16384u      /* RFC 9113 section 4.2: the smallest SETTINGS_MAX_FRAME_SIZE */
#define BST_H2_MAX_FRAME 16777215u   /* and the largest */
#define BST_H2_MAX_WINDOW 2147483647u /* 2^31-1 */

typedef enum bst_h2_type {
	BST_H2_DATA = 0x0,
	BST_H2_HEADERS = 0x1,
	BST_H2_PRIORITY = 0x2,
	BST_H2_RST_STREAM = 0x3,
	BST_H2_SETTINGS = 0x4,
	BST_H2_PUSH_PROMISE = 0x5,
	BST_H2_PING = 0x6,
	BST_H2_GOAWAY = 0x7,
	BST_H2_WINDOW_UPDATE = 0x8,
	BST_H2_CONTINUATION = 0x9,
	BST_H2_PRIORITY_UPDATE = 0x10, /* RFC 9218 section 7.1 */
} bst_h2_type;

enum { /* flags */
	BST_H2_F_END_STREAM = 0x1,
	BST_H2_F_ACK = 0x1,
	BST_H2_F_END_HEADERS = 0x4,
	BST_H2_F_PADDED = 0x8,
	BST_H2_F_PRIORITY = 0x20,
};

typedef enum bst_h2_code { /* RFC 9113 section 7 */
	BST_H2_NO_ERROR = 0x0,
	BST_H2_PROTOCOL_ERROR = 0x1,
	BST_H2_INTERNAL_ERROR = 0x2,
	BST_H2_FLOW_CONTROL_ERROR = 0x3,
	BST_H2_SETTINGS_TIMEOUT = 0x4,
	BST_H2_STREAM_CLOSED = 0x5,
	BST_H2_FRAME_SIZE_ERROR = 0x6,
	BST_H2_REFUSED_STREAM = 0x7,
	BST_H2_CANCEL = 0x8,
	BST_H2_COMPRESSION_ERROR = 0x9,
	BST_H2_CONNECT_ERROR = 0xa,
	BST_H2_ENHANCE_YOUR_CALM = 0xb,
	BST_H2_INADEQUATE_SECURITY = 0xc,
	BST_H2_HTTP_1_1_REQUIRED = 0xd,
} bst_h2_code;

enum { /* SETTINGS identifiers (RFC 9113 section 6.5.2, RFC 8441 section 3) */
	BST_H2_S_HEADER_TABLE_SIZE = 0x1,
	BST_H2_S_ENABLE_PUSH = 0x2,
	BST_H2_S_MAX_CONCURRENT_STREAMS = 0x3,
	BST_H2_S_INITIAL_WINDOW_SIZE = 0x4,
	BST_H2_S_MAX_FRAME_SIZE = 0x5,
	BST_H2_S_MAX_HEADER_LIST_SIZE = 0x6,
	BST_H2_S_ENABLE_CONNECT_PROTOCOL = 0x8,
	BST_H2_S_NO_RFC7540_PRIORITIES = 0x9,
};

/* Why a frame was refused. stream == 0: a connection error (GOAWAY with code); else a stream error
 * (RST_STREAM with code on that stream). */
typedef struct bst_h2_err {
	uint32_t code;
	uint32_t stream;
} bst_h2_err;

/* A parsed frame. Pointers point into the input of bst_h2_frame_parse and are valid while it is. */
typedef struct bst_h2_frame {
	uint8_t type, flags;
	uint32_t stream_id; /* the reserved bit cleared */
	uint32_t length;    /* the whole payload, padding included: what flow control counts */
	const uint8_t *data; /* DATA: the data. HEADERS, CONTINUATION: the header block fragment.
			      * SETTINGS: the entries. PRIORITY_UPDATE: the field value. unknown: payload */
	uint32_t data_len;
	/* HEADERS (with the PRIORITY flag) and PRIORITY */
	bool has_priority, exclusive;
	uint32_t dep;
	uint8_t weight;
	uint32_t value; /* RST_STREAM, GOAWAY: error code. WINDOW_UPDATE: increment.
			 * PRIORITY_UPDATE: the prioritized stream id */
	uint32_t last_stream; /* GOAWAY */
	uint8_t ping[8];      /* PING */
} bst_h2_frame;

/* Parses one frame from buf[0..n). Returns the bytes it used (> 0), 0 when more input is needed, or
 * -1 with *err set. A frame longer than max_frame is refused as soon as its 9-byte head is
 * there, before any payload is read. Unknown frame types parse (the caller ignores them). A
 * PUSH_PROMISE is always refused: a client never may send one to a server. */
ssize_t bst_h2_frame_parse(const uint8_t *buf, size_t n, uint32_t max_frame, bst_h2_frame *out,
			   bst_h2_err *err);

/* The next SETTINGS entry of a SETTINGS frame; *pos starts at 0. False at the end. */
bool bst_h2_settings_next(const bst_h2_frame *f, size_t *pos, uint16_t *id, uint32_t *val);

/* ---- writers: append to a growable byte vector ---- */

typedef struct bst_h2_wr {
	uint8_t *p;
	size_t len, cap;
} bst_h2_wr;

void bst_h2_wr_free(bst_h2_wr *w);
/* Room for n more bytes; 0, or -1 on exhaustion. */
int bst_h2_wr_reserve(bst_h2_wr *w, size_t n);

/* The 9-byte head of any frame. */
void bst_h2_put_head(uint8_t out[BST_H2_FRAME_HDR], uint32_t len, uint8_t type, uint8_t flags,
		     uint32_t stream);

/* All return 0, or -1 on exhaustion. */
/* HEADERS, then CONTINUATION frames when block is longer than max_frame. */
int bst_h2_write_headers(bst_h2_wr *w, uint32_t stream, const uint8_t *block, size_t n,
			 bool end_stream, uint32_t max_frame);
/* Only the 9-byte head of a DATA frame of n payload bytes: the payload follows it on the wire, and
 * the caller supplies it (often straight from a file). */
int bst_h2_write_data(bst_h2_wr *w, uint32_t stream, uint32_t n, bool end_stream);
/* entries: pairs of (id, value). nentries may be 0; ack sends an empty SETTINGS with ACK. */
int bst_h2_write_settings(bst_h2_wr *w, const uint32_t (*entries)[2], size_t nentries, bool ack);
int bst_h2_write_ping(bst_h2_wr *w, const uint8_t data[8], bool ack);
int bst_h2_write_goaway(bst_h2_wr *w, uint32_t last_stream, uint32_t code);
int bst_h2_write_rst(bst_h2_wr *w, uint32_t stream, uint32_t code);
int bst_h2_write_window_update(bst_h2_wr *w, uint32_t stream, uint32_t increment);
int bst_h2_write_priority_update(bst_h2_wr *w, uint32_t prioritized, const char *field, size_t n);

#endif
