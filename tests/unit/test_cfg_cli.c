#include "config/cli.h"
#include "config/compile.h"
#include "core/arena.h"
#include "tap.h"

#include <string.h>

/* serve and proxy build the AST directly: a hostile argument is one argument, never text
 * that gets re-lexed. */
TEST(serve_ast_holds_hostile_dir_as_one_arg)
{
	bst_arena *a = bst_arena_new(4096);
	bst_err e;
	const char *dir = "a;b {\n} server { listen 1; ";
	bst_ast *ast = bst_cli_build_ast("serve", dir, 8080, a, &e);
	ASSERT(ast != NULL);
	ASSERT_EQ(ast->root.nchildren, 1);
	const bst_ast_node *srv = ast->root.children;
	ASSERT_STR(srv->name, "server");
	ASSERT(srv->has_block);
	ASSERT_EQ(srv->nchildren, 2);
	const bst_ast_node *listen = srv->children, *root = listen->next;
	ASSERT_STR(listen->name, "listen");
	ASSERT_STR(listen->args[0].text, "8080");
	ASSERT_STR(root->name, "root");
	ASSERT_EQ(root->nargs, 1);
	ASSERT_EQ(root->args[0].len, strlen(dir));
	ASSERT_STR(root->args[0].text, dir);
	ASSERT_STR(root->args[0].tpl, "a;b {\n} server { listen 1; "); /* no `$` here */
	ASSERT(root->parent == srv && srv->parent == &ast->root);
	bst_arena_free(a);
}

TEST(proxy_ast_and_dollar_is_literal)
{
	bst_arena *a = bst_arena_new(4096);
	bst_err e;
	bst_ast *ast = bst_cli_build_ast("proxy", "http://h/$host", 3000, a, &e);
	ASSERT(ast != NULL);
	const bst_ast_node *p = ast->root.children->children->next;
	ASSERT_STR(p->name, "proxy");
	ASSERT_STR(p->args[0].text, "http://h/$host");
	ASSERT_STR(p->args[0].tpl, "http://h/$$host");
	bst_arena_free(a);
}

TAP_MAIN()
