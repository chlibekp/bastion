/* HPACK header compression (RFC 7541). Pure code over bytes, an arena and a header list: no sockets,
 * fuzzed on its own (fuzz/fuzz_hpack.c).
 *
 * Decoder. Everything it keeps is bounded before it is allocated: the dynamic table by the table
 * size the connection advertised (RFC 7541 accounting, 32 bytes per entry on top of name and
 * value), and the decoded header list by max_header_list_size, checked for each field BEFORE its
 * bytes are copied, so a small block that references a large table entry thousands of times
 * (an HPACK bomb) is cut after the first few. Huffman strings are decoded under the same
 * remaining budget. Any error leaves the compression state undefined: the connection is closed
 * (COMPRESSION_ERROR, RFC 9113 section 4.3).
 *
 * Encoder. The policy is the server's: static and dynamic entries are used for what repeats
 * (status, server, content-type, cache-control ...); the headers that change every response
 * (date, content-length, etag ...) are sent as literals that do not enter the table; Set-Cookie,
 * Cookie and Authorization are sent as never-indexed literals, so an intermediary re-encoding them
 * cannot turn the table into a compression oracle (CRIME-style secret recovery). */
#ifndef BST_HTTP_H2_HPACK_H
#define BST_HTTP_H2_HPACK_H

#include "core/arena.h"
#include "http/h2/frame.h"
#include "http/headers.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct bst_hpack_entry {
	char *data; /* name, then value */
	uint32_t nlen, vlen;
} bst_hpack_entry;

/* The dynamic table: a ring of entries, newest at head. size and max count 32 bytes per entry. */
typedef struct bst_hpack_table {
	bst_hpack_entry *ring;
	uint32_t cap; /* a power of two, or 0 */
	uint32_t head, n;
	size_t size, max;
} bst_hpack_table;

#define BST_HPACK_STATIC_COUNT 61u
#define BST_HPACK_ENTRY_OVERHEAD 32u

typedef struct bst_hpack_dec {
	bst_hpack_table t;
	uint32_t limit; /* the largest table size an update may name: what the connection advertised */
} bst_hpack_dec;

typedef struct bst_hpack_limits {
	uint32_t max_header_list_size; /* decoded size of a block: name + value + 32 per field */
} bst_hpack_limits;

#define BST_HPACK_OK 0
#define BST_HPACK_ERR (-1)       /* a malformed or illegal block: COMPRESSION_ERROR */
#define BST_HPACK_TOO_LARGE (-2) /* the decoded list would exceed max_header_list_size */
#define BST_HPACK_NOMEM (-3)

/* limit: SETTINGS_HEADER_TABLE_SIZE as advertised to the peer. The table starts at the protocol
 * default of 4096 or limit, whichever is smaller. */
void bst_hpack_dec_init(bst_hpack_dec *d, uint32_t limit);
void bst_hpack_dec_free(bst_hpack_dec *d);

/* Decodes one complete header block (HEADERS and its CONTINUATIONs joined) and appends the fields
 * to out (which uses its own arena for the list; names and values are copied into arena unless
 * they are static-table strings). Returns BST_HPACK_OK or one of the errors above. */
int bst_hpack_decode(bst_hpack_dec *d, const uint8_t *in, size_t n, bst_arena *arena,
		     bst_headers *out, const bst_hpack_limits *lim);

typedef enum bst_hpack_policy {
	BST_HPACK_POLICY_SERVER = 0,   /* see the file comment */
	BST_HPACK_POLICY_INDEX_ALL,    /* RFC 7541 Appendix C: index everything, Huffman when shorter */
	BST_HPACK_POLICY_INDEX_ALL_RAW /* the same without Huffman */
} bst_hpack_policy;

typedef struct bst_hpack_enc {
	bst_hpack_table t;
	bool pending; /* a size update must open the next block */
	uint32_t pending_min, pending_cur;
	bst_hpack_policy policy;
} bst_hpack_enc;

/* max: the dynamic table size to start at (the peer's SETTINGS_HEADER_TABLE_SIZE, at most 4096
 * until it says otherwise). */
void bst_hpack_enc_init(bst_hpack_enc *e, uint32_t max);
void bst_hpack_enc_free(bst_hpack_enc *e);
/* The peer changed SETTINGS_HEADER_TABLE_SIZE (or we cap it lower): the next block begins with a
 * dynamic table size update. */
void bst_hpack_enc_set_max(bst_hpack_enc *e, uint32_t max);
/* Appends the block for h to out. Names are lower-cased. 0, or -1 on exhaustion. */
int bst_hpack_encode(bst_hpack_enc *e, const bst_headers *h, bst_h2_wr *out);

/* Test seams: HPACK integers (RFC 7541 section 5.1) and the table's current size. */
int bst_hpack_int_encode(bst_h2_wr *w, uint8_t first_bits, unsigned prefix, uint32_t v);
int bst_hpack_int_decode(const uint8_t **p, const uint8_t *end, unsigned prefix, uint32_t *out);
size_t bst_hpack_table_size(const bst_hpack_table *t);
uint32_t bst_hpack_table_count(const bst_hpack_table *t);

#endif
