# Phase 10: HTTP Cache

**Goal:** An RFC 9111 shared cache with RAM and disk tiers, stampede protection, stale serving, and fast purging with tags.

**Architecture:** RAM tier is per-worker with no locks, so popular objects may exist once per worker in exchange for no cross-process pointers and no crash-recovery problem. Disk tier is shared: a CAS-updated index in shm plus one file per object. Purge uses timestamps checked at lookup, so purging a tag is O(1).

**Spec:** RFC 9111, RFC 5861, RFC 9211, RFC 9213.

## Review Focus

1. Cache poisoning: unkeyed `X-Forwarded-Host`, Host variants, `Vary: *`, responses with `Set-Cookie`, and error responses → no user receives another user's content or a poisoned page. (Tasks 1, 5)
2. Authenticated requests: `Authorization` with cacheable responses → stored only as RFC 9111 section 3.5 allows. (Task 1)
3. Worker crash or `kill -9` during a fill → no partial object is ever served, temp files are cleaned, and no stale lock remains. (Tasks 2, 6)
4. Disk full, read-only cache directory, or corrupted cache file → falls back to the upstream with a logged error. (Task 2)
5. Thousands of concurrent requests for one uncached URL → few upstream fetches and bounded waiters. (Task 6)

---

### Task 1: Freshness and storability policy

**Files:**
- Create: `src/cache/policy.{c,h}`, `src/http/cache_control.{c,h}`
- Test: `tests/unit/test_cache_policy.c`, `fuzz/fuzz_cache_control.c`

**Interfaces:**
- Produces: Pure functions. `bst_cc_parse(bst_headers *, bst_cache_control *)`, `bst_cache_storable(req, resp, cfg, &reason)`, `bst_cache_freshness(resp, cfg, now, bst_freshness *)`, `bst_cache_age(...)`, `bst_cache_key_vary_match(...)`, `bst_cache_merge_304(stored, resp304)`.

- [ ] **Step 1: Write failing tests**, table-driven with RFC section numbers:
  - `no_store_either_side`, `private_not_stored`, `set_cookie_default_not_stored`.
  - `authorization_rule`: stored only with `public`, `s-maxage` or `must-revalidate`.
  - `freshness_order`: `CDN-Cache-Control`, then `s-maxage`, `max-age`, `Expires`, config `cache_valid`, heuristics.
  - `age_calc`: RFC 9111 section 4.2.3 with `Age` and clock skew.
  - `no_cache_requires_revalidation`, `must_revalidate_forbids_stale`, `immutable`.
  - `request_no_cache`: obeyed only with `cache_honor_request_cc on`, default off, so clients can't force origin load.
  - `vary_star`: never matches.
  - `vary_normalized`: value whitespace normalized in comparison.
  - `unsafe_invalidates`: successful POST, PUT or DELETE invalidates the target URI.
  - `partial_not_stored`: 206 isn't stored in this version.
  - `malformed_cc`: invalid `max-age=abc`, negative, overflow → treated as stale.
  - `merge_304`: updates headers, retains the body, and doesn't take framing headers.
- [ ] **Step 2: Run** `./dev make test-unit T=cache_policy` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** same → PASS, fuzz 60 seconds → no crash.
- [ ] **Step 5: Commit** `feat(cache): add RFC 9111 storage and freshness policy`

### Task 2: Disk object store

**Files:**
- Create: `src/cache/store.{c,h}`
- Test: `tests/unit/test_cache_store.c`, `fuzz/fuzz_cache_header.c`

**Interfaces:**
- Produces: `bst_key` (SHA-256), `bst_store_open_read(store, key, cb)`, `bst_store_begin_write`, `bst_store_write`, `bst_store_commit`, `bst_store_abort`, `bst_store_delete`. On-disk: `<root>/ab/cd/<hex key>`. Header holds magic, format version, key copy, timing, status, response headers, tags, Vary data, body length and an xxHash or SHA-256 of the header.

- [ ] **Step 1: Write failing tests**
  - `roundtrip`: write, commit, open and read match.
  - `atomic_publish`: not visible before commit; temp file renamed into place.
  - `abort_removes_temp`.
  - `corrupt_header`: flipped bytes, wrong magic, short file, or body shorter than declared → treated as a miss and deleted, with a counter.
  - `key_mismatch`: a file whose stored key differs from the request → miss.
  - `old_version`: older format version → miss, safely.
  - `enospc`: simulated full disk → commit fails cleanly, and the response still reaches the client.
- [ ] **Step 2: Run** `./dev make test-unit T=cache_store` → FAIL.
- [ ] **Step 3: Implement.** All operations run through the loop's disk path, never blocking. Directories are created in the helper at startup, so workers need fewer syscalls.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(cache): add crash-safe disk object store`

### Task 3: Shared index and eviction

**Files:**
- Create: `src/cache/index.{c,h}`, `src/cache/eviction.c`
- Test: `tests/unit/test_cache_index.c`, `tests/integration/test_cache_eviction.py`

**Interfaces:**
- Produces: `bst_cindex_lookup(idx, key, bst_centry *out)`, `bst_cindex_insert`, `bst_cindex_touch`, `bst_cindex_remove`. Lock-free open-addressed table in `cache_index` shm. Helper job `bst_cache_scan` (rebuild at startup) and `bst_cache_evict` (sampled LRU). Directives in `cache_store`: `disk path size=`, `max_object`, `min_uses`, `inactive`, `evict_batch`, `scan_rate`.

- [ ] **Step 1: Write failing tests**
  - `insert_lookup_remove`, `collision_probe`, `concurrent_threads` (TSan, 8 threads).
  - `full_table`: insert when full → false, counted, and server continues uncached.
  - `test_size_limit`: disk usage stays at or below `size` under fill load.
  - `test_lru_prefers_cold`: hot objects survive eviction.
  - `test_restart_survives`: objects are served after restart without upstream calls.
  - `test_scan_background`: startup serves traffic during a slow scan, with not-yet-indexed files treated as misses.
  - `test_expired_inactive`: `inactive` removes unused entries.
- [ ] **Step 2: Run** `./dev make test-unit T=cache_index` → FAIL.
- [ ] **Step 3: Implement.** `last_access` writes are relaxed and rate-limited to one per second per entry, avoiding cache-line contention. Workers don't delete during eviction; helper unlinks.
- [ ] **Step 4: Run** same plus `./dev make test-int K=cache_eviction` → PASS.
- [ ] **Step 5: Commit** `feat(cache): add shared index and background eviction`

### Task 4: RAM tier

**Files:**
- Create: `src/cache/ram.{c,h}`
- Test: `tests/unit/test_cache_ram.c`

**Interfaces:**
- Produces: `bst_ram_get(ram, key) → bst_robj *` (refcounted), `bst_ram_put(ram, key, head, chain)`, S3-FIFO or similar scan-resistant eviction. Directives `ram <size>`, split evenly per worker, and `ram_max_object`. Uses huge pages when `huge_pages` allows.

- [ ] **Step 1: Write failing tests**
  - `hit_returns_same`, `size_limit_enforced`.
  - `evict_while_referenced`: an object being sent stays valid until unref, under ASan.
  - `scan_resistance`: a one-time scan of many objects doesn't evict a repeatedly used small set.
  - `oversize_skipped`: objects over `ram_max_object` stay disk only.
- [ ] **Step 2: Run** `./dev make test-unit T=cache_ram` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(cache): add per-worker RAM tier`

### Task 5: Cache filter

**Files:**
- Create: `src/cache/filter.{c,h}`, `src/cache/cache_directives.c`
- Test: `tests/integration/test_cache.py`

**Interfaces:**
- Consumes: policy, store, index, ram, `bst_filter_ops`, `bst_proxy_handler`, range and conditional functions.
- Produces: Lookup before the handler and a response tee. Directives: `cache <store>`, `cache_key <template>` (default `$scheme$host$request_uri`), `cache_valid`, `cache_methods`, `cache_bypass`, `cache_no_store_if`, `cache_ignore_headers`, `cache_vary_limit`, `cache_status_header`, `cache_cookies_policy`, `cache_honor_request_cc`, `cache_background_fill`.

- [ ] **Step 1: Write failing tests**
  - `test_hit_miss`: second request served without an upstream call, `Cache-Status` per RFC 9211.
  - `test_age_header`: `Age` correct.
  - `test_host_in_key`: same path on 2 hosts stays separate.
  - `test_unkeyed_header_poison`: `X-Forwarded-Host` variant can't change cached output for others, in a test whose upstream reflects it.
  - `test_vary`: `Accept-Language` variants are separate, and `Vary: *` isn't reused.
  - `test_set_cookie_not_cached`, `test_authorization_not_shared`.
  - `test_head_from_get`: HEAD served from a stored GET.
  - `test_range_from_cache`: Range on a cached full object → 206 without upstream.
  - `test_revalidate_304`: stale + `If-None-Match` to upstream, 304 refreshes the entry and the client gets a full response.
  - `test_client_conditional`: client's `If-None-Match` on a hit gives 304.
  - `test_invalidate_post`: POST invalidates GET's entry.
  - `test_client_abort_fill`: client abort mid-fill → the fill completes or aborts, as `cache_background_fill` says, and no partial entry is served.
  - `test_upstream_truncated`: truncated upstream body is never committed.
  - `test_across_protocols`: stored on HTTP/1.1, served on HTTP/2 and HTTP/3, identical.
  - `test_cache_disabled_when_broken`: read-only cache dir → serving continues with warning.
- [ ] **Step 2: Run** `./dev make test-int K=test_cache` → FAIL.
- [ ] **Step 3: Implement.** Disk hits use file segments, so zero-copy works when possible. The stored response head sits in the header, and the body offset in the file is page-aligned.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(cache): add cache filter for proxied responses`

### Task 6: Stampede lock and stale serving

**Files:**
- Create: `src/cache/lock.{c,h}`
- Test: `tests/unit/test_cache_lock.c`, `tests/integration/test_cache_stale.py`

**Interfaces:**
- Produces: `bst_cachelock_try(table, key, slot, deadline)`, `bst_cachelock_release`, `bst_cachelock_expired`. Directives: `lock on|off`, `lock_timeout`, `lock_max_waiters`, `stale_while_revalidate`, `stale_if_error`, `background_revalidate on|off`.

- [ ] **Step 1: Write failing tests**
  - `lock_cas`: only one winner across threads.
  - `lock_expires`: an owner that died releases after the deadline.
  - `test_stampede`: 5,000 concurrent misses → 1 upstream fetch across all workers.
  - `test_lock_timeout`: slow fill → waiters pass through after `lock_timeout`, and the overall request count remains bounded.
  - `test_lock_owner_crash`: `kill -9` the fill worker → others recover within `lock_timeout`.
  - `test_uncacheable_after_lock`: a private response releases waiters immediately, and they each fetch, never sharing a private body.
  - `test_swr`: stale served immediately, exactly one background revalidation.
  - `test_stale_if_error`: 5xx or connection failure → stale with `Cache-Status`, until `stale_if_error` expires.
  - `test_must_revalidate_no_stale`: never served stale.
- [ ] **Step 2: Run** `./dev make test-unit T=cache_lock && ./dev make test-int K=cache_stale` → FAIL.
- [ ] **Step 3: Implement.** Waiters poll with backoff between 5 ms and 50 ms using timers. A background revalidation is a detached internal request with its own arena.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(cache): add stampede lock and stale serving`

### Task 7: Purge

**Files:**
- Create: `src/cache/purge.{c,h}`
- Test: `tests/unit/test_cache_purge.c`, `tests/integration/test_cache_purge.py`

**Interfaces:**
- Produces: `bst_purge_url(store, key)`, `bst_purge_tag(store, bst_str tag)`, `bst_purge_host(store, bst_str host)`, `bst_purge_all(store)`. Fixed-size shm table `tag hash → purged_at`, plus a store-wide `purged_at`. Lookup compares `entry.stored_at` to tag timestamps. The table is saved to disk regularly by the helper, and read at startup. Directives: `cache_tag_header` (default `Cache-Tag`), `cache_max_tags`, `purge_table_size`, `purge_method_allow <cidr>`. Admin endpoints follow in Phase 14.

- [ ] **Step 1: Write failing tests**
  - `test_purge_url`: next request misses.
  - `test_purge_tag`: 1,000 objects with a shared tag → all miss after one O(1) call; other objects still hit.
  - `test_purge_host`.
  - `test_purge_all_workers`: RAM copies on every worker are also invalid.
  - `test_purge_survives_restart`: purged entries don't reappear after restart.
  - `test_refill_after_purge`: a new fill after purge is served, because `stored_at > purged_at`.
  - `test_purge_race`: a fill started before the purge and finishing after isn't served, which requires comparing fill **start** time.
  - `tag_collision_safe` unit: hash collisions cause only extra misses.
  - `test_tag_header_stripped`: tag header isn't forwarded to clients by default.
- [ ] **Step 2: Run** `./dev make test-int K=cache_purge` → FAIL.
- [ ] **Step 3: Implement.** `stored_at` records when the request began rather than when the response arrived.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(cache): add O(1) purge by URL, tag and host`
