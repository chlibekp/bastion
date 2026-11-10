#include "http/http.h"

#include <string.h>

static const struct {
	const char *name;
	bst_method m;
} methods[] = {
	{ "GET", BST_M_GET },	      { "HEAD", BST_M_HEAD },	{ "POST", BST_M_POST },
	{ "PUT", BST_M_PUT },	      { "DELETE", BST_M_DELETE }, { "CONNECT", BST_M_CONNECT },
	{ "OPTIONS", BST_M_OPTIONS }, { "TRACE", BST_M_TRACE }, { "PATCH", BST_M_PATCH },
};

/* Methods are case-sensitive (RFC 9110 section 9.1): "get" is a method nobody defined. */
bst_method bst_method_from(bst_str s)
{
	for (size_t i = 0; i < sizeof methods / sizeof methods[0]; i++)
		if (s.len == strlen(methods[i].name) && memcmp(s.p, methods[i].name, s.len) == 0)
			return methods[i].m;
	return BST_M_UNKNOWN;
}

const char *bst_method_name(bst_method m)
{
	for (size_t i = 0; i < sizeof methods / sizeof methods[0]; i++)
		if (methods[i].m == m)
			return methods[i].name;
	return "";
}
