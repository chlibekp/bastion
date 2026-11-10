/* The header model every protocol and handler shares: an ordered list of (name, value, id)
 * with the id of the names Bastion knows (known_headers.def) resolved once, by a generated
 * perfect hash. Names and values are views, never copied: whoever adds an entry keeps the bytes
 * alive as long as the list, normally by taking both from the arena the list was made with.
 * Order and repeated names are kept exactly as they came, because Set-Cookie and friends depend
 * on it. Not thread-safe. */
#ifndef BST_HTTP_HEADERS_H
#define BST_HTTP_HEADERS_H

#include "core/arena.h"
#include "core/str.h"
#include "http/token.h"

#include <stddef.h>
#include <stdint.h>

typedef uint16_t bst_hdr_id;

enum bst_hdr_ids {
	BST_H_UNKNOWN = 0,
#define X(id, name) BST_H_##id,
#include "http/known_headers.def"
#undef X
	BST_H_COUNT_ /* one past the last known id */
};

typedef struct bst_header {
	bst_str name; /* as received: case is kept for the wire, compare with the id or ieq */
	bst_str value;
	bst_hdr_id id; /* BST_H_UNKNOWN for a name Bastion has no id for */
} bst_header;

typedef struct bst_headers {
	bst_header *v;
	uint32_t n, cap;
	bst_arena *arena; /* storage for v */
} bst_headers;

/* The id of a name in any letter case, or BST_H_UNKNOWN. */
bst_hdr_id bst_hdr_lookup(const char *name, size_t len);
/* The canonical lower-case name of a known id; an empty string for BST_H_UNKNOWN. */
bst_str bst_hdr_name(bst_hdr_id id);

void bst_headers_init(bst_headers *h, bst_arena *arena);
/* Appends; the name's id is looked up. 0, or -1 when the arena is exhausted (the list is then
 * unchanged). Does not validate: parsers and filters do, with bst_is_token and
 * bst_is_field_value_clean. */
int bst_headers_add(bst_headers *h, bst_str name, bst_str value);

/* The first entry with this id or name (any letter case), or NULL. */
const bst_header *bst_headers_get(const bst_headers *h, bst_hdr_id id);
const bst_header *bst_headers_get_name(const bst_headers *h, bst_str name);
/* The next entry after `after` with that id (or name), in order; `after` NULL gives the first.
 * Walks repeated headers: Set-Cookie, Via. */
const bst_header *bst_headers_next(const bst_headers *h, const bst_header *after, bst_hdr_id id);
const bst_header *bst_headers_next_name(const bst_headers *h, const bst_header *after,
					bst_str name);
size_t bst_headers_count(const bst_headers *h, bst_hdr_id id);

/* Removes every entry with the id (or name); returns how many went. Order of the rest is kept. */
size_t bst_headers_remove(bst_headers *h, bst_hdr_id id);
size_t bst_headers_remove_name(bst_headers *h, bst_str name);
/* Replaces the first entry of that name with this value and drops any others, or appends.
 * 0, or -1 on exhaustion (unchanged). */
int bst_headers_set(bst_headers *h, bst_str name, bst_str value);

#endif
