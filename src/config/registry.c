/* The registry schema: built once from the linker section. */
#include "config/schema.h"

#include <pthread.h>

static pthread_once_t reg_once = PTHREAD_ONCE_INIT;
static bst_schema *reg_schema;
static bst_err reg_err;

static void reg_init(void)
{
	size_t n;
	const bst_dirtab *const *tabs = bst_dirtabs(&n);
	reg_schema = bst_schema_build(tabs, n, &reg_err);
}

const bst_schema *bst_schema_registry(bst_err *e)
{
	pthread_once(&reg_once, reg_init);
	if (reg_schema == NULL && e != NULL)
		*e = reg_err;
	return reg_schema;
}
