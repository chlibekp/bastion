/* IP access lists (Phase 12, Task 2): `allow`, `deny`, `allow_file`, `deny_file`, `acl_default`.
 *
 * Rule: the first rule that matches decides, in the order the scope wrote them (as nginx); a
 * file is one rule that matches any CIDR it lists (a prefix tree, so a million entries match in
 * about the time of one). No rule matching: `acl_default` (allow). A scope that writes its own
 * rules replaces the inherited list. IPv4-mapped IPv6 addresses match as IPv4.
 *
 * The server scope's list is enforced at accept, before TLS (the connection is closed), and the
 * effective list of the request's location in the router (403). So a location can not reopen an
 * address its server denies. */
#ifndef BST_SEC_ACL_H
#define BST_SEC_ACL_H

#include "config/compile.h"
#include "core/addr.h"
#include "core/cidr.h"

#include <stdbool.h>

typedef struct bst_acl_rule {
	bool allow;
	bst_cidr cidr;		 /* when set is NULL */
	const bst_cidrset *set;	 /* allow_file / deny_file */
} bst_acl_rule;

/* True when the rules (const bst_acl_rule *) let ip in. */
bool bst_acl_check(const bst_cfg_list *rules, bool default_deny, const bst_ip *ip);

/* Loads a file of CIDRs or addresses, one per line, '#' comments. NULL with why set. */
bst_cidrset *bst_acl_load_file(const char *path, size_t *n, char *why, size_t cap);

#endif
