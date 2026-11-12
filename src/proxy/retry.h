/* The retry budget of one upstream in one worker (`retry budget=`). Every request deposits
 * budget_pct/100 of a token, every retry takes a whole one, and the reserve is capped at
 * BST_RETRY_RESERVE: during a total outage retries add at most budget_pct of the requests (plus
 * that small reserve), so retries never multiply the load on a failing upstream. */
#ifndef BST_PROXY_RETRY_H
#define BST_PROXY_RETRY_H

#include "proxy/upstream.h"

#include <stdbool.h>

#define BST_RETRY_RESERVE 3.0

/* A request to u started. */
void bst_retry_note_request(const bst_cfg_upstream *u);
/* May one more retry go out? true takes a token. */
bool bst_retry_take(const bst_cfg_upstream *u);

#ifdef BST_TEST
void bst_retry_test_reset(void);
#endif

#endif
