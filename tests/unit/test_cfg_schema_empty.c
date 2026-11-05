/* A binary with no registered directive tables must still link and work: the linker
 * section does not exist, and the weak __start_/__stop_ symbols resolve to NULL. */
#include "config/parser.h"
#include "config/schema.h"
#include "core/arena.h"
#include "tap.h"

#include <string.h>

TEST(zero_tables)
{
	size_t n = 99;
	(void)bst_dirtabs(&n);
	ASSERT_EQ(n, 0);

	bst_err e;
	const bst_schema *s = bst_schema_registry(&e);
	ASSERT(s != NULL);
	ASSERT(bst_schema_find(s, "root", 4, BST_CTX_GLOBAL) == NULL);

	bst_arena *a = bst_arena_new(1 << 12);
	const char *ok = "";
	bst_ast *ast = bst_cfg_parse_string(ok, 0, "e.conf", NULL, a, &e);
	ASSERT(ast != NULL);
	ASSERT_EQ(bst_cfg_validate(ast, &e), 0);
	const char *bad = "root /x;";
	ast = bst_cfg_parse_string(bad, strlen(bad), "e.conf", NULL, a, &e);
	ASSERT(ast != NULL);
	ASSERT_EQ(bst_cfg_validate(ast, &e), -1);
	ASSERT(strstr(e.msg, "unknown directive \"root\"") != NULL);
	bst_arena_free(a);
}

TAP_MAIN()
