/* Alt-Svc (RFC 7838) on TCP responses, so a client that reached a server over TCP learns the
 * server's HTTP/3 address (Phase 8 Task 6). Directive `alt_svc auto|off|<value>`, server context:
 *   auto  `h3=":<port>"; ma=86400` when the server has a `listen ... http3`, else nothing;
 *   off   nothing;
 *   other that field value as written.
 * A handler that sets Alt-Svc itself keeps its own. HTTP/3 responses carry none. */
#ifndef BST_HTTP_H3_ALTSVC_H
#define BST_HTTP_H3_ALTSVC_H

#include "config/compile.h"
#include "core/str.h"

#include <stdbool.h>
#include <stddef.h>

#define BST_ALT_SVC_MAX 256 /* room for the `auto` value; a written value is used in place */

/* The Alt-Svc value for a response of srv, or an empty string for none. buf (BST_ALT_SVC_MAX bytes)
 * holds an `auto` value; the result points into buf or into the configuration. */
bst_str bst_alt_svc(const bst_cfg_server *srv, char *buf);

#endif
