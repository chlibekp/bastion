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

- [x] **Step 1: Write failing tests**, table-driven with RFC section numbers:
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
- [x] **Step 2: Run** `./dev make test-unit T=cache_policy` → FAIL.
- [x] **Step 3: Implement.**
- [x] **Step 4: Run** same → PASS, fuzz 60 seconds → no crash.
- [x] **Step 5: Commit** `feat(cache): add RFC 9111 storage and freshness policy`
  - Deviations: tests were written after the implementation (the intent's test-after posture), so the Step 2 FAIL run was not observed. `bst_cc_parse` has two siblings: `bst_cc_parse_value` (one field line) and `bst_cc_parse_name` (CDN-Cache-Control). A delta-seconds above 2^31, malformed or repeated with another value makes the field invalid (stale), as this plan says, rather than RFC 9111's clamp. Heuristic freshness is used only for non-error statuses and is capped at one day, a constant rather than a directive. A response is storable only with explicit freshness, a `cache_valid` rule, heuristic freshness, `public`, or (for no-cache) a validator. Vary data is limited to 4 KiB.

### Task 2: Disk object store

**Files:**
- Create: `src/cache/store.{c,h}`
- Test: `tests/unit/test_cache_store.c`, `fuzz/fuzz_cache_header.c`

**Interfaces:**
- Produces: `bst_key` (SHA-256), `bst_store_open_read(store, key, cb)`, `bst_store_begin_write`, `bst_store_write`, `bst_store_commit`, `bst_store_abort`, `bst_store_delete`. On-disk: `<root>/ab/cd/<hex key>`. Header holds magic, format version, key copy, timing, status, response headers, tags, Vary data, body length and an xxHash or SHA-256 of the header.

- [x] **Step 1: Write failing tests**
  - `roundtrip`: write, commit, open and read match.
  - `atomic_publish`: not visible before commit; temp file renamed into place.
  - `abort_removes_temp`.
  - `corrupt_header`: flipped bytes, wrong magic, short file, or body shorter than declared → treated as a miss and deleted, with a counter.
  - `key_mismatch`: a file whose stored key differs from the request → miss.
  - `old_version`: older format version → miss, safely.
  - `enospc`: simulated full disk → commit fails cleanly, and the response still reaches the client.
- [x] **Step 2: Run** `./dev make test-unit T=cache_store` → FAIL.
- [x] **Step 3: Implement.** All operations run through the loop's disk path, never blocking. Directories are created in the helper at startup, so workers need fewer syscalls.
- [x] **Step 4: Run** same → PASS.
- [x] **Step 5: Commit** `feat(cache): add crash-safe disk object store`
  - Deviations: header reads (open, check, the hash) run on the aio pool, but writes are synchronous `pwrite` on the loop thread into the page cache, as `proxy/spool.c` does, and commit is one `renameat2`. Directories (`ab/cd`, `tmp`) are made by the worker on first use with `mkdirat`, not by the helper at startup. There is no fsync: a power loss may lose recent objects, and the SHA-256 header hash and length check keep a torn one from being served. The header hash is SHA-256. Full disk is tested with the `test_space` field and the `BST_TEST_CACHE_ENOSPC` hook. Worker allowlist rows added: `unlinkat`, `renameat2`, `mkdirat`, `ftruncate` (an empty-body object such as a Vary marker).

### Task 3: Shared index and eviction

**Files:**
- Create: `src/cache/index.{c,h}`, `src/cache/eviction.c`
- Test: `tests/unit/test_cache_index.c`, `tests/integration/test_cache_eviction.py`

**Interfaces:**
- Produces: `bst_cindex_lookup(idx, key, bst_centry *out)`, `bst_cindex_insert`, `bst_cindex_touch`, `bst_cindex_remove`. Lock-free open-addressed table in `cache_index` shm. Helper job `bst_cache_scan` (rebuild at startup) and `bst_cache_evict` (sampled LRU). Directives in `cache_store`: `disk path size=`, `max_object`, `min_uses`, `inactive`, `evict_batch`, `scan_rate`.

- [x] **Step 1: Write failing tests**
  - `insert_lookup_remove`, `collision_probe`, `concurrent_threads` (TSan, 8 threads).
  - `full_table`: insert when full → false, counted, and server continues uncached.
  - `test_size_limit`: disk usage stays at or below `size` under fill load.
  - `test_lru_prefers_cold`: hot objects survive eviction.
  - `test_restart_survives`: objects are served after restart without upstream calls.
  - `test_scan_background`: startup serves traffic during a slow scan, with not-yet-indexed files treated as misses.
  - `test_expired_inactive`: `inactive` removes unused entries.
- [x] **Step 2: Run** `./dev make test-unit T=cache_index` → FAIL.
- [x] **Step 3: Implement.** `last_access` writes are relaxed and rate-limited to one per second per entry, avoiding cache-line contention. Workers don't delete during eviction; helper unlinks.
- [x] **Step 4: Run** same plus `./dev make test-int K=cache_eviction` → PASS.
- [x] **Step 5: Commit** `feat(cache): add shared index and background eviction`
  - Deviations: `test_cache_eviction.py` needs the filter and landed with Task 5. Every field of a slot is an atomic and the state word carries a generation, so readers detect reuse (TSan-clean). A directive `max_entries` sizes the index (default one slot per 8 KiB of `size`, 1024 to 16M). Eviction samples 16 live slots per removal; an entry's size is its body plus one 4 KiB header page. `inactive` is swept 4096 slots per round. The scan also removes temp files older than the helper's start and broken or misplaced objects. Test hooks: `BST_TEST_CACHE_EVICT_MS`, `BST_TEST_CACHE_SCAN_DELAY_MS`. Helper allowlist rows extended (were worker only): `openat2`, `statx`, `fstat`, `getdents64`, `pread64`; `unlinkat` added for both roles.

### Task 4: RAM tier

**Files:**
- Create: `src/cache/ram.{c,h}`
- Test: `tests/unit/test_cache_ram.c`

**Interfaces:**
- Produces: `bst_ram_get(ram, key) → bst_robj *` (refcounted), `bst_ram_put(ram, key, head, chain)`, S3-FIFO or similar scan-resistant eviction. Directives `ram <size>`, split evenly per worker, and `ram_max_object`. Uses huge pages when `huge_pages` allows.

- [x] **Step 1: Write failing tests**
  - `hit_returns_same`, `size_limit_enforced`.
  - `evict_while_referenced`: an object being sent stays valid until unref, under ASan.
  - `scan_resistance`: a one-time scan of many objects doesn't evict a repeatedly used small set.
  - `oversize_skipped`: objects over `ram_max_object` stay disk only.
- [x] **Step 2: Run** `./dev make test-unit T=cache_ram` → FAIL.
- [x] **Step 3: Implement.**
- [x] **Step 4: Run** same → PASS.
- [x] **Step 5: Commit** `feat(cache): add per-worker RAM tier`
  - Deviations: `bst_ram_put` takes the object's meta and a contiguous body (the filter collects up to `ram_max_object` while filling), not a chain. Huge pages are not used: no `huge_pages` directive exists yet. The RAM tier is filled on fills only, not on disk hits. A RAM copy is served only while the shared index holds the same fill time and no purge covers it, so eviction, invalidation and purges elsewhere reach every worker's RAM.

### Task 5: Cache filter

**Files:**
- Create: `src/cache/filter.{c,h}`, `src/cache/cache_directives.c`
- Test: `tests/integration/test_cache.py`

**Interfaces:**
- Consumes: policy, store, index, ram, `bst_filter_ops`, `bst_proxy_handler`, range and conditional functions.
- Produces: Lookup before the handler and a response tee. Directives: `cache <store>`, `cache_key <template>` (default `$scheme$host$request_uri`), `cache_valid`, `cache_methods`, `cache_bypass`, `cache_no_store_if`, `cache_ignore_headers`, `cache_vary_limit`, `cache_status_header`, `cache_cookies_policy`, `cache_honor_request_cc`, `cache_background_fill`.

- [x] **Step 1: Write failing tests**
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
- [x] **Step 2: Run** `./dev make test-int K=test_cache` → FAIL.
- [x] **Step 3: Implement.** Disk hits use file segments, so zero-copy works when possible. The stored response head sits in the header, and the body offset in the file is page-aligned.
- [x] **Step 4: Run** same → PASS.
- [x] **Step 5: Commit** `feat(cache): add cache filter for proxied responses`
  - Deviations: the response filter chain (`bst_filter_ops`) does not exist yet (Phase 11), so the cache is a set of hooks the proxy handler calls (`cache/filter.h`): lookup before the exchange, a tee of the body, commit on a clean end only. A Vary response is stored under the key plus its Vary data, with a marker object under the key. A Range request that misses is passed through uncached; a multi-range request on a hit gets the whole 200; a HEAD that misses is passed through. A 304 revalidation refreshes the entry's times in the shared index and serves the merged fields, but does not rewrite the stored file's fields. `cache_background_fill on` fetches the response again in a detached internal request rather than continuing the abandoned exchange. The client's validators and Range are removed from a fill's upstream request. `min_uses` is counted per worker. Extra directive `cache_tag_header_pass`. A broken store directory is tested with a path below a regular file (tests run as root, which ignores modes), and write failures with `BST_TEST_CACHE_ENOSPC` (`test_cache_write_failure`).

### Task 6: Stampede lock and stale serving

**Files:**
- Create: `src/cache/lock.{c,h}`
- Test: `tests/unit/test_cache_lock.c`, `tests/integration/test_cache_stale.py`

**Interfaces:**
- Produces: `bst_cachelock_try(table, key, slot, deadline)`, `bst_cachelock_release`, `bst_cachelock_expired`. Directives: `lock on|off`, `lock_timeout`, `lock_max_waiters`, `stale_while_revalidate`, `stale_if_error`, `background_revalidate on|off`.

- [x] **Step 1: Write failing tests**
  - `lock_cas`: only one winner across threads.
  - `lock_expires`: an owner that died releases after the deadline.
  - `test_stampede`: 5,000 concurrent misses → 1 upstream fetch across all workers.
  - `test_lock_timeout`: slow fill → waiters pass through after `lock_timeout`, and the overall request count remains bounded.
  - `test_lock_owner_crash`: `kill -9` the fill worker → others recover within `lock_timeout`.
  - `test_uncacheable_after_lock`: a private response releases waiters immediately, and they each fetch, never sharing a private body.
  - `test_swr`: stale served immediately, exactly one background revalidation.
  - `test_stale_if_error`: 5xx or connection failure → stale with `Cache-Status`, until `stale_if_error` expires.
  - `test_must_revalidate_no_stale`: never served stale.
- [x] **Step 2: Run** `./dev make test-unit T=cache_lock && ./dev make test-int K=cache_stale` → FAIL.
- [x] **Step 3: Implement.** Waiters poll with backoff between 5 ms and 50 ms using timers. A background revalidation is a detached internal request with its own arena.
- [x] **Step 4: Run** same → PASS.
- [x] **Step 5: Commit** `feat(cache): add stampede lock and stale serving`
  - Deviations: the lock word holds a 23-bit tag, a pass flag and a 40-bit deadline, so `bst_cachelock_try` also takes the clock and `bst_cachelock_release` the deadline it was taken with. A lock is taken on misses only; a stale entry outside stale-while-revalidate is revalidated by each request. Background revalidation is a full (unconditional) fetch through the same detached request as `cache_background_fill`; its uniqueness comes from a lock left to expire after `lock_timeout`. A full aio queue (a crowd of waiters waking at once) makes a request wait and retry instead of fetching. The lock table has `max_entries / 8` slots (1024 to 1M). `stale_while_revalidate` and `stale_if_error` default to 0 (only the response's own directives apply); a longer configured window wins. `test_stampede` runs 5,000 concurrent requests over two workers.

### Task 7: Purge

**Files:**
- Create: `src/cache/purge.{c,h}`
- Test: `tests/unit/test_cache_purge.c`, `tests/integration/test_cache_purge.py`

**Interfaces:**
- Produces: `bst_purge_url(store, key)`, `bst_purge_tag(store, bst_str tag)`, `bst_purge_host(store, bst_str host)`, `bst_purge_all(store)`. Fixed-size shm table `tag hash → purged_at`, plus a store-wide `purged_at`. Lookup compares `entry.stored_at` to tag timestamps. The table is saved to disk regularly by the helper, and read at startup. Directives: `cache_tag_header` (default `Cache-Tag`), `cache_max_tags`, `purge_table_size`, `purge_method_allow <cidr>`. Admin endpoints follow in Phase 14.

- [x] **Step 1: Write failing tests**
  - `test_purge_url`: next request misses.
  - `test_purge_tag`: 1,000 objects with a shared tag → all miss after one O(1) call; other objects still hit.
  - `test_purge_host`.
  - `test_purge_all_workers`: RAM copies on every worker are also invalid.
  - `test_purge_survives_restart`: purged entries don't reappear after restart.
  - `test_refill_after_purge`: a new fill after purge is served, because `stored_at > purged_at`.
  - `test_purge_race`: a fill started before the purge and finishing after isn't served, which requires comparing fill **start** time.
  - `tag_collision_safe` unit: hash collisions cause only extra misses.
  - `test_tag_header_stripped`: tag header isn't forwarded to clients by default.
- [x] **Step 2: Run** `./dev make test-int K=cache_purge` → FAIL.
- [x] **Step 3: Implement.** `stored_at` records when the request began rather than when the response arrived.
- [x] **Step 4: Run** same → PASS.
- [x] **Step 5: Commit** `feat(cache): add O(1) purge by URL, tag and host`
  - Deviations: the `bst_purge_*` functions take the table (`bst_purge_mark`, `bst_purge_mark_all`, `bst_purge_valid`), and the URL, tag, host and all purges are made by a `PURGE` request from `purge_method_allow` addresses (`Purge-Scope: host|all`, `Purge-Tag: a, b`). PURGE became a known method (`BST_M_PURGE`); the router answers 501 where no cache is, as before, and `test_h1_framing`/`test_h1_parser` use `BREW` for the unknown-method case. A slot keeps the latest time of every hash in it, so collisions only add misses. A fill that begins in the purge's own millisecond counts as purged. Extra directive `purge_save_interval` (default 1s); the helper saves only when the table changed; a table saved with another size, or an unreadable one, folds into the store-wide time. A URL purge also removes the index entry and the file. Helper allowlist extended (were worker only): `pwrite64`, `renameat2`.
