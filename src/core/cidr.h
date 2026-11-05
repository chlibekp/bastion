/* CIDR parsing and longest-prefix matching.
 *
 * Family rule: a lookup address is first canonicalised with bst_ip_canon, so
 * ::ffff:10.0.0.1 is matched as IPv4 10.0.0.1 and cannot slip past an IPv4 rule.
 * Likewise bst_cidr_parse canonicalises an IPv4-mapped prefix of length >= 96
 * ("::ffff:10.0.0.0/104" becomes 10.0.0.0/8). Consequences:
 *   - 0.0.0.0/0 matches every IPv4 address (including mapped ones) and no IPv6 one.
 *   - ::/0 matches every native IPv6 address and NO IPv4 address, mapped or not.
 *   - an IPv6 prefix shorter than 96 never matches a mapped address, since that
 *     address is looked up as IPv4.
 * bst_cidrset_add applies the same normalisation, so a hand-built bst_cidr
 * (v6 ::ffff:10.0.0.0, prefix 104) is stored as IPv4 10.0.0.0/8 and is the same rule
 * as that IPv4 prefix (adding either replaces the other). A hand-built IPv6 rule with
 * prefix < 96 is stored as given and likewise never matches mapped addresses.
 *
 * The set is a path-compressed binary trie, one per family. Matching never mutates
 * it, so after loading it is safe to share read-only between threads or by COW. */
#ifndef BST_CIDR_H
#define BST_CIDR_H

#include "core/addr.h"

typedef struct bst_cidr {
	bst_ip ip; /* host bits are zero */
	uint8_t prefix;
} bst_cidr;

/* "addr/len". The slash and prefix are mandatory. The prefix is 1-3 decimal digits
 * without sign, space or leading zeros, at most 32 (IPv4) or 128 (IPv6). Host bits set
 * below the prefix are an error ("10.0.0.1/8"). Returns false on any error. */
bool bst_cidr_parse(bst_str s, bst_cidr *out);

typedef struct bst_cidrset bst_cidrset;

bst_cidrset *bst_cidrset_new(void);
void bst_cidrset_free(bst_cidrset *set);

/* Inserts cidr -> value. value must be non-NULL (NULL means "no match" on lookup).
 * Adding a prefix already present REPLACES its value (last add wins) and succeeds.
 * Returns 0 on success, -1 on invalid arguments or allocation failure. */
int bst_cidrset_add(bst_cidrset *set, const bst_cidr *cidr, void *value);

/* Value of the longest matching prefix, or NULL if none matches. */
void *bst_cidrset_match(const bst_cidrset *set, const bst_ip *ip);

#endif
