/* Character classes of RFC 9110 section 5: the token and field-value rules shared by every
 * protocol's parser. */
#ifndef BST_HTTP_TOKEN_H
#define BST_HTTP_TOKEN_H

#include "core/str.h"

#include <stdbool.h>

/* tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
 *         / DIGIT / ALPHA. One byte of the table is 1 for a tchar, else 0. */
extern const unsigned char bst_tchar_tab[256];

static inline bool bst_is_tchar(unsigned char c)
{
	return bst_tchar_tab[c] != 0;
}

/* True when every byte of a header field value is allowed: VCHAR, SP, HTAB and obs-text (0x80-0xff).
 * NUL, CR, LF and every other control byte are not, so a value can not smuggle a line break
 * into a header block, a log line or a proxied request. */
bool bst_is_field_value_clean(bst_str v);

/* True for a non-empty string made only of tchars. */
bool bst_is_token(bst_str s);

#endif
