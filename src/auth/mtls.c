/* auth_mtls as an auth_require mechanism: a verified client certificate (Phase 6 checks it in
 * the handshake), optionally one whose subject DN or a DNS SAN is in the configured list.
 * Anything else is 403. */
#include "auth/auth_common.h"

#include "tls/conn.h"

#include <string.h>

bool bst_auth_mtls_configured(const bst_stream *s)
{
	return s->cfg->auth_mtls;
}

static bool in_san_list(const char *sans, const char *want)
{
	size_t wl = strlen(want);
	const char *p = sans;
	while (p != NULL && *p != '\0') {
		const char *c = strchr(p, ',');
		size_t l = c ? (size_t)(c - p) : strlen(p);
		if (l == wl && memcmp(p, want, l) == 0)
			return true;
		p = c ? c + 1 : NULL;
	}
	return false;
}

void bst_auth_mtls_start(bst_auth_run *r)
{
	bst_stream *s = bst_auth_stream(r);
	const bst_cfg_list *allow = &s->cfg->auth_mtls_allow;
	if (!bst_tls_client_verified(s->transport)) {
		bst_auth_step(r, 403, (bst_str){ NULL, 0 }, (bst_str){ NULL, 0 });
		return;
	}
	if (allow->n == 0) {
		bst_auth_step(r, 0, (bst_str){ NULL, 0 }, (bst_str){ NULL, 0 });
		return;
	}
	const char *dn = bst_tls_var(s->transport, "client_s_dn");
	const char *san = bst_tls_var(s->transport, "client_san_dns");
	for (size_t i = 0; i < allow->n; i++) {
		const char *w = allow->items[i];
		if ((dn != NULL && strcmp(dn, w) == 0) || (san != NULL && in_san_list(san, w))) {
			if (dn != NULL && s->auth_user.p == NULL)
				s->auth_user = (bst_str){ dn, (uint32_t)strlen(dn) };
			bst_auth_step(r, 0, (bst_str){ NULL, 0 }, (bst_str){ NULL, 0 });
			return;
		}
	}
	bst_auth_step(r, 403, (bst_str){ NULL, 0 }, (bst_str){ NULL, 0 });
}
