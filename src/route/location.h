/* Location matching, nginx's rules (config-language.md "Location precedence"), on one level of
 * siblings at a time:
 *   1. `=` exact: the whole URI equals the pattern. It wins at once.
 *   2. The longest prefix among `pattern` and `^~ pattern`. If it is a `^~`, it wins at once.
 *   3. The regexes (`~`, `~*`) in file order: the first that matches wins.
 *   4. Otherwise the longest prefix of step 2, or no location at all.
 * Once a location is chosen its children (nested locations) are searched the same way against
 * the same URI; a match among them replaces the parent, none keeps it. The captures of a regex
 * stay available to the children that do not replace them (`$1` in a nested rewrite).
 *
 * The prefixes of a level are a compressed trie, so the cost of a lookup follows the length of
 * the URI and not the number of locations. A regex that hits its limit ends the whole search:
 * where a regex guards something, "did not match" would be the wrong answer, so the caller
 * answers 500 (caps->limit_hit). The indexes are built once after the configuration compiles
 * (route_directives.c) and freed with it. */
#ifndef BST_ROUTE_LOCATION_H
#define BST_ROUTE_LOCATION_H

#include "config/compile.h"
#include "route/regex.h"

struct bst_loc_level;

/* The server's top level, or a location's children. NULL on exhaustion or for a pattern two
 * siblings both claim, with err set and *bad the offending location (NULL when it is not one).
 * Free with bst_loc_level_free. */
struct bst_loc_level *bst_loc_level_new(bst_cfg_location *const *locs, size_t n,
					const bst_cfg_location **bad, bst_err *err);
void bst_loc_level_free(struct bst_loc_level *lv);

/* Compiles every regex location and name, builds the index of every level and registers their
 * cleanup with the config. 0, or -1 with err set to a positioned message. */
int bst_route_prepare(bst_config *cfg, bst_cfg_ctx *c, bst_err *err);

/* The location for the normalized path uri (no query), or NULL for the server's own
 * configuration. caps is cleared first; on a regex match it holds the groups. */
const bst_cfg_location *bst_location_find(const bst_cfg_server *srv, bst_str uri,
					  bst_captures *caps);

/* The configuration in force for that location, or the server's. */
static inline const bst_cfg_common *bst_location_cfg(const bst_cfg_server *srv,
						     const bst_cfg_location *loc)
{
	return loc != NULL ? &loc->common : &srv->common;
}

#endif
