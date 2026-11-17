/* Accept-Encoding negotiation (RFC 9110 section 12.5.3): which content coding a response may be
 * sent with. Pure: no allocation, no state. */
#ifndef BST_HTTP_ACCEPT_ENCODING_H
#define BST_HTTP_ACCEPT_ENCODING_H

#include "core/str.h"

#include <stdint.h>

typedef enum bst_encoding {
	BST_ENC_IDENTITY = 0,
	BST_ENC_ZSTD,
	BST_ENC_BR,
	BST_ENC_GZIP,
	BST_ENC_COUNT_
} bst_encoding;

#define BST_ENC_BIT(e) (1u << (e))
#define BST_ENC_ALL (BST_ENC_BIT(BST_ENC_ZSTD) | BST_ENC_BIT(BST_ENC_BR) | BST_ENC_BIT(BST_ENC_GZIP))

/* The coding to send for a request whose Accept-Encoding is accept_encoding (all its lines
 * joined with ", "; empty when absent), choosing only among the codings in allowed
 * (BST_ENC_BIT mask). The client's highest q wins; ties go to the server's order zstd, br,
 * gzip; a coding is used only when its q is at least identity's. Identity for an absent or
 * malformed field, and when nothing allowed is acceptable. */
bst_encoding bst_negotiate_encoding(bst_str accept_encoding, uint32_t allowed);

/* The token for Content-Encoding ("zstd", "br", "gzip"; "identity" for identity). */
bst_str bst_encoding_name(bst_encoding e);

#endif
