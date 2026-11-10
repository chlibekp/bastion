/* Byte-class scans for the HTTP/1.1 parser: the length of the leading run of bytes that may
 * appear in a header value or a request-target. SSE2 and AVX2 (x86_64, AVX2 chosen at run
 * time) and NEON (arm64) vector paths; a scalar path is the reference every vector path is
 * tested against (tests/unit/test_h1_parser.c), and the only one elsewhere. */
#ifndef BST_HTTP_H1_SCAN_H
#define BST_HTTP_H1_SCAN_H

#include <stdbool.h>
#include <stddef.h>

/* Leading bytes valid in a field value: HTAB, SP, VCHAR and obs-text, so not 0x00-0x08,
 * 0x0a-0x1f or 0x7f. Returns n when all are. */
size_t bst_h1_scan_value(const char *p, size_t n);
/* Leading bytes valid in a request-target: 0x21-0x7e. Returns n when all are. */
size_t bst_h1_scan_target(const char *p, size_t n);

typedef enum bst_h1_scan_kind {
	BST_SCAN_SCALAR = 1,
	BST_SCAN_SSE2 = 2,
	BST_SCAN_AVX2 = 4,
	BST_SCAN_NEON = 8,
} bst_h1_scan_kind;

/* Bit set of the kinds this build and CPU can run (always includes SCALAR). */
unsigned bst_h1_scan_available(void);
/* Name of the kind in use. */
const char *bst_h1_scan_name(void);
/* Forces one kind, or 0 to go back to the best available. False when it is not available. For
 * tests: not thread-safe. */
bool bst_h1_scan_select(bst_h1_scan_kind kind);

#endif
