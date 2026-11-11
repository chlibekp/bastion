/* Virtual host selection (config-language.md "name"). The servers that share a listener's
 * address form one set; the Host of a request picks one of them.
 *
 * Order, as nginx does it: an exact name, then the longest leading wildcard (`*.example.com`,
 * any host below it), then the longest trailing wildcard (`example.*`), then the regular
 * expressions (`~re`) in file order, then the default. The default is the server of a
 * `listen ... default_server`, else the server with no name, else the first.
 *
 * Exact names sit in a hash table. A leading wildcard is stored under its suffix
 * ("example.com") and found by stripping labels from the left of the host until one is a key
 * (the first hit is the longest); a trailing wildcard is the same walk from the right on its
 * prefix. Looking up is therefore a few probes whatever the number of names, and building is
 * linear. The host is lower-cased into a stack buffer and never allocated for. */
#ifndef BST_ROUTE_VHOST_H
#define BST_ROUTE_VHOST_H

#include "config/compile.h"
#include "core/str.h"

#include <stdbool.h>
#include <stddef.h>

typedef struct bst_listener_set bst_listener_set;

/* The servers of cfg that listen on l's address. NULL on exhaustion. */
bst_listener_set *bst_vhost_set_new(const bst_config *cfg, const bst_cfg_listen *l);
/* The same for an explicit list (tests): servers is copied; dflt NULL picks the default as
 * above. */
bst_listener_set *bst_vhost_set_from(const bst_cfg_server *const *servers, size_t n,
				     const bst_cfg_server *dflt);
void bst_vhost_set_free(bst_listener_set *s);

/* The default server of the set (never NULL for a set with a server). */
const bst_cfg_server *bst_vhost_default(const bst_listener_set *s);

/* The server for host (Host header value: port, IPv6 brackets and one trailing dot are
 * ignored, letter case too). *matched, when not NULL, says a name matched (false: it is the
 * default that answers). */
const bst_cfg_server *bst_vhost_lookup(const bst_listener_set *s, bst_str host, bool *matched);
const bst_cfg_server *bst_vhost_select(const bst_listener_set *s, bst_str host);

#endif
