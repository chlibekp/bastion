/* 103 Early Hints (RFC 8297): the configured Link values, sent before the handler runs. The
 * protocols refuse an interim response where it can not go (HTTP/1.0, a head already sent). */
#include "filters/extras.h"

#include "core/log.h"

#include <string.h>

void bst_early_hints_send(bst_stream *s)
{
	const bst_cfg_extras *x = &s->cfg->extras;
	if (!x->early_hints || x->early_links.n == 0)
		return;
	if (s->req.head.version_minor < 1)
		return; /* HTTP/1.0 has no interim responses (h2 and h3 count as 1) */
	bst_headers hs;
	bst_headers_init(&hs, s->arena);
	for (size_t i = 0; i < x->early_links.n; i++) {
		const char *v = (const char *)x->early_links.items[i];
		if (bst_headers_add(&hs, BST_S("Link"), (bst_str){ v, (uint32_t)strlen(v) }) != 0)
			return; /* out of memory: the hints are only a hint */
	}
	(void)bst_stream_send_interim(s, 103, &hs);
}
