#include "core/err.h"

#include <stdarg.h>
#include <stdio.h>

void bst_err_set(bst_err *e, const char *fmt, ...)
{
	if (!e)
		return;
	e->file = NULL;
	e->line = 0;
	e->col = 0;
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(e->msg, sizeof e->msg, fmt, ap);
	va_end(ap);
	if (n < 0)
		e->msg[0] = '\0';
}
