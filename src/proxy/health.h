/* Active health checks (`health_check` in an upstream block). They run in the helper, never in a
 * worker, so each peer gets one probe per interval for the whole server however many workers
 * there are. A probe connects, sends `GET <path>` with Connection: close and reads the status
 * line: a status in the expected range within the timeout passes, anything else fails. `fails`
 * consecutive failures mark the peer down in the shared upstream_state (every worker sees it at
 * its next pick); `passes` consecutive passes bring it back. Peers start up.
 *
 * Probes speak plain HTTP/1.1; for an upstream with TLS the TCP connect alone is the check. */
#ifndef BST_PROXY_HEALTH_H
#define BST_PROXY_HEALTH_H

#include "config/compile.h"
#include "io/loop.h"

/* Starts the probes of every upstream with a health_check on the helper's loop. */
void bst_health_check_run(bst_loop *l, const bst_config *cfg);

/* Parses `200` or `200-399` into a range; false when malformed. */
bool bst_health_parse_expect(const char *s, size_t n, unsigned *lo, unsigned *hi);

#endif
