/* libFuzzer harness for IP/CIDR parsing. The input is copied to an exact-size heap
 * block so ASan flags any read past len. Properties: anything bst_addr_parse accepts
 * formats and re-parses to an equal address; canon is idempotent; anything
 * bst_cidr_parse accepts can be added to a set and matches its own network address. */
#include "core/cidr.h"

#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t size)
{
	if (size > 4096)
		return 0;
	char *copy = malloc(size ? size : 1);
	if (!copy)
		abort();
	memcpy(copy, d, size);
	bst_str s = { copy, (uint32_t)size };

	bst_ip ip;
	if (bst_addr_parse(s, &ip)) {
		char buf[BST_ADDR_STRLEN];
		size_t n = bst_addr_format(&ip, buf, sizeof buf);
		if (n == 0)
			abort();
		bst_ip back;
		if (!bst_addr_parse((bst_str){ buf, (uint32_t)n }, &back) || !bst_ip_eq(&ip, &back))
			abort();
		bst_ip c = bst_ip_canon(&ip), cc = bst_ip_canon(&c);
		if (!bst_ip_eq(&c, &cc))
			abort();
	}

	bst_cidr cidr;
	if (bst_cidr_parse(s, &cidr)) {
		bst_cidrset *set = bst_cidrset_new();
		if (!set || bst_cidrset_add(set, &cidr, set) != 0)
			abort();
		if (bst_cidrset_match(set, &cidr.ip) != set)
			abort();
		bst_cidrset_free(set);
	}
	free(copy);
	return 0;
}
