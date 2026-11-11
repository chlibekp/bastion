#include "handlers/roots.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int bst_roots_open(bst_config *cfg, bst_err *err)
{
	bst_cfg_global *g = &cfg->global;
	for (size_t i = 0; i < g->nroots; i++) {
		bst_cfg_root *r = g->roots[i];
		if (r->fd >= 0)
			continue;
		r->fd = open(r->path, O_PATH | O_DIRECTORY | O_CLOEXEC);
		if (r->fd < 0) {
			bst_err_set(err, "root \"%s\": %s", r->path, strerror(errno));
			return -1;
		}
	}
	return 0;
}

void bst_roots_close(bst_config *cfg)
{
	for (size_t i = 0; i < cfg->global.nroots; i++) {
		bst_cfg_root *r = cfg->global.roots[i];
		if (r->fd >= 0)
			close(r->fd);
		r->fd = -1;
	}
}

size_t bst_roots_paths(const bst_config *cfg, const char ***out)
{
	size_t n = cfg->global.nroots;
	*out = NULL;
	if (n == 0)
		return 0;
	const char **a = malloc(n * sizeof *a);
	if (a == NULL)
		return 0;
	for (size_t i = 0; i < n; i++)
		a[i] = cfg->global.roots[i]->path;
	*out = a;
	return n;
}
