/* The registry schema: built once from the linker section. */
#include "config/schema.h"
#include "config/template.h"

#include <pthread.h>

static pthread_once_t reg_once = PTHREAD_ONCE_INIT;
static bst_schema *reg_schema;
static bst_err reg_err;

static void reg_init(void)
{
	size_t n;
	const bst_dirtab *const *tabs = bst_dirtabs(&n);
	reg_schema = bst_schema_build(tabs, n, &reg_err);
	/* The real schema checks templates against the real variable registry, so an unknown
	 * variable fails at -t. This file is the one place schema code meets template code. */
	if (reg_schema != NULL)
		bst_schema_set_tpl_check(reg_schema, bst_tpl_check_arg);
}

const bst_schema *bst_schema_registry(bst_err *e)
{
	pthread_once(&reg_once, reg_init);
	if (reg_schema == NULL && e != NULL)
		*e = reg_err;
	return reg_schema;
}
