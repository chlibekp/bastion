/* See acl.h. */
#include "sec/acl.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

static bool cidr_has(const bst_cidr *c, const bst_ip *ip)
{
	if (c->ip.family != ip->family)
		return false;
	unsigned p = c->prefix, n = ip->family == BST_IP_V4 ? 4 : 16;
	for (unsigned i = 0; i < n && p > 0; i++, p = p > 8 ? p - 8 : 0) {
		uint8_t m = p >= 8 ? 0xff : (uint8_t)(0xff00u >> p);
		if ((ip->b[i] & m) != c->ip.b[i])
			return false;
	}
	return true;
}

bool bst_acl_check(const bst_cfg_list *rules, bool default_deny, const bst_ip *ip)
{
	bst_ip c = bst_ip_canon(ip);
	for (size_t i = 0; i < rules->n; i++) {
		const bst_acl_rule *r = rules->items[i];
		bool hit = r->set != NULL ? bst_cidrset_match(r->set, &c) != NULL : cidr_has(&r->cidr, &c);
		if (hit)
			return r->allow;
	}
	return !default_deny;
}

bst_cidrset *bst_acl_load_file(const char *path, size_t *n, char *why, size_t cap)
{
	FILE *f = fopen(path, "re");
	if (f == NULL) {
		snprintf(why, cap, "%s", strerror(errno));
		return NULL;
	}
	bst_cidrset *set = bst_cidrset_new();
	static int mark; /* any non-NULL value: a match */
	char line[256];
	size_t lineno = 0;
	*n = 0;
	while (set != NULL && fgets(line, sizeof line, f) != NULL) {
		lineno++;
		char *h = strchr(line, '#');
		if (h != NULL)
			*h = '\0';
		char *p = line, *e;
		while (*p == ' ' || *p == '\t')
			p++;
		e = p + strlen(p);
		while (e > p && (e[-1] == '\n' || e[-1] == '\r' || e[-1] == ' ' || e[-1] == '\t'))
			e--;
		if (e == p)
			continue;
		bst_str s = { p, (uint32_t)(e - p) };
		bst_cidr c;
		if (!bst_cidr_parse(s, &c)) {
			bst_ip ip;
			if (!bst_addr_parse(s, &ip)) {
				snprintf(why, cap, "line %zu: not an address or CIDR", lineno);
				bst_cidrset_free(set);
				fclose(f);
				return NULL;
			}
			c.ip = bst_ip_canon(&ip);
			c.prefix = c.ip.family == BST_IP_V4 ? 32 : 128;
		}
		if (bst_cidrset_add(set, &c, &mark) != 0) {
			snprintf(why, cap, "out of memory");
			bst_cidrset_free(set);
			fclose(f);
			return NULL;
		}
		(*n)++;
	}
	fclose(f);
	if (set == NULL)
		snprintf(why, cap, "out of memory");
	return set;
}
