#include "route/vhost.h"
#include "tap.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static bst_cfg_server mk(const char *const *names, size_t n)
{
	bst_cfg_server s;
	memset(&s, 0, sizeof s);
	s.names = (const char **)(uintptr_t)names;
	s.nnames = n;
	return s;
}

#define SEL(set, h) bst_vhost_select(set, (bst_str){ h, (uint32_t)strlen(h) })

TEST(exact_beats_wildcard)
{
	const char *n1[] = { "*.example.com" }, *n2[] = { "www.example.com" };
	bst_cfg_server wild = mk(n1, 1), exact = mk(n2, 1);
	const bst_cfg_server *l[] = { &wild, &exact };
	bst_listener_set *s = bst_vhost_set_from(l, 2, NULL);
	ASSERT(s != NULL);
	ASSERT(SEL(s, "www.example.com") == &exact);
	ASSERT(SEL(s, "api.example.com") == &wild);
	ASSERT(SEL(s, "a.b.example.com") == &wild); /* any depth below */
	bst_vhost_set_free(s);
}

TEST(wildcard_needs_a_label)
{
	const char *n1[] = { "*.example.com" };
	bst_cfg_server wild = mk(n1, 1), other = mk(NULL, 0);
	const bst_cfg_server *l[] = { &wild, &other };
	bst_listener_set *s = bst_vhost_set_from(l, 2, NULL);
	bool matched = true;
	ASSERT(bst_vhost_lookup(s, BST_S("example.com"), &matched) == &other);
	ASSERT(!matched);
	ASSERT(bst_vhost_lookup(s, BST_S("notexample.com"), &matched) == &other);
	ASSERT(!matched);
	bst_vhost_set_free(s);
}

TEST(longest_wildcard_wins)
{
	const char *n1[] = { "*.example.com" }, *n2[] = { "*.a.example.com" },
		   *n3[] = { "www.*" }, *n4[] = { "www.example.*" };
	bst_cfg_server shortw = mk(n1, 1), longw = mk(n2, 1), tr = mk(n3, 1), trlong = mk(n4, 1);
	const bst_cfg_server *l[] = { &shortw, &longw, &tr, &trlong };
	bst_listener_set *s = bst_vhost_set_from(l, 4, NULL);
	ASSERT(SEL(s, "x.a.example.com") == &longw);
	ASSERT(SEL(s, "x.b.example.com") == &shortw);
	ASSERT(SEL(s, "q.x.a.example.com") == &longw);
	/* leading wildcards come before trailing ones, and the longer trailing one wins */
	ASSERT(SEL(s, "www.example.org") == &trlong);
	ASSERT(SEL(s, "www.other.org") == &tr);
	bst_vhost_set_free(s);
}

TEST(case_insensitive)
{
	const char *n1[] = { "example.com" };
	bst_cfg_server a = mk(n1, 1), b = mk(NULL, 0);
	const bst_cfg_server *l[] = { &b, &a };
	bst_listener_set *s = bst_vhost_set_from(l, 2, NULL);
	ASSERT(SEL(s, "EXAMPLE.com") == &a);
	ASSERT(SEL(s, "ExAmPlE.CoM") == &a);
	bst_vhost_set_free(s);
}

TEST(trailing_dot)
{
	const char *n1[] = { "example.com" };
	bst_cfg_server a = mk(n1, 1), b = mk(NULL, 0);
	const bst_cfg_server *l[] = { &b, &a };
	bst_listener_set *s = bst_vhost_set_from(l, 2, NULL);
	ASSERT(SEL(s, "example.com.") == &a);
	ASSERT(SEL(s, "example.com..") == &b); /* one dot only */
	ASSERT(SEL(s, ".") == &b);
	bst_vhost_set_free(s);
}

TEST(port_stripped)
{
	const char *n1[] = { "example.com" };
	bst_cfg_server a = mk(n1, 1), b = mk(NULL, 0);
	const bst_cfg_server *l[] = { &b, &a };
	bst_listener_set *s = bst_vhost_set_from(l, 2, NULL);
	ASSERT(SEL(s, "example.com:8080") == &a);
	ASSERT(SEL(s, "example.com:") == &a);
	ASSERT(SEL(s, "other.com:80") == &b);
	bst_vhost_set_free(s);
}

TEST(ipv6_literal_host)
{
	const char *n1[] = { "::1" };
	bst_cfg_server a = mk(n1, 1), b = mk(NULL, 0);
	const bst_cfg_server *l[] = { &b, &a };
	bst_listener_set *s = bst_vhost_set_from(l, 2, NULL);
	ASSERT(SEL(s, "[::1]:8080") == &a);
	ASSERT(SEL(s, "[::1]") == &a);
	ASSERT(SEL(s, "[::2]:80") == &b);
	ASSERT(SEL(s, "[::1") == &b); /* unterminated: no match, no read past the end */
	bst_vhost_set_free(s);
}

TEST(default_server)
{
	const char *n1[] = { "a.example" }, *n2[] = { "b.example" };
	bst_cfg_server a = mk(n1, 1), b = mk(n2, 1);
	const bst_cfg_server *l[] = { &a, &b };
	/* no match and nothing designated: the first server of the listener */
	bst_listener_set *s = bst_vhost_set_from(l, 2, NULL);
	ASSERT(SEL(s, "zzz") == &a);
	ASSERT(bst_vhost_default(s) == &a);
	bst_vhost_set_free(s);
	/* a configured default wins over file order */
	s = bst_vhost_set_from(l, 2, &b);
	ASSERT(SEL(s, "zzz") == &b);
	ASSERT(SEL(s, "a.example") == &a);
	ASSERT(SEL(s, "") == &b);
	bst_vhost_set_free(s);
	/* a server with no name is the default unless one is designated */
	bst_cfg_server any = mk(NULL, 0);
	const bst_cfg_server *l2[] = { &a, &any, &b };
	s = bst_vhost_set_from(l2, 3, NULL);
	ASSERT(SEL(s, "zzz") == &any);
	bst_vhost_set_free(s);
}

TEST(regex_names_are_not_exact)
{
	const char *n1[] = { "~^www\\d+\\.example\\.com$" };
	bst_cfg_server a = mk(n1, 1), b = mk(NULL, 0);
	const bst_cfg_server *l[] = { &b, &a };
	bst_listener_set *s = bst_vhost_set_from(l, 2, NULL);
	/* the regex form is Task 3's; until it is compiled in it must never match literally */
	ASSERT(SEL(s, "~^www\\d+\\.example\\.com$") == &b);
	bst_vhost_set_free(s);
}

TEST(many_names)
{
	enum { N = 5000 };
	static char names[N][32];
	static const char *ptr[N];
	for (int i = 0; i < N; i++) {
		snprintf(names[i], sizeof names[i], "*.h%d.example.org", i);
		ptr[i] = names[i];
	}
	bst_cfg_server a = mk(ptr, N), b = mk(NULL, 0);
	const bst_cfg_server *l[] = { &b, &a };
	bst_listener_set *s = bst_vhost_set_from(l, 2, NULL);
	ASSERT(s != NULL);
	ASSERT(SEL(s, "x.h4999.example.org") == &a);
	ASSERT(SEL(s, "x.h5000.example.org") == &b);
	bst_vhost_set_free(s);
}

TAP_MAIN()
