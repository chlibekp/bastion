# Phase 5: Routing and Static Files (Milestone M1)

**Goal:** Virtual hosts, nginx-style locations, rewrites and complete static file serving. At the end of this phase, Bastion can serve a real site over HTTP/1.1.

**Architecture:** Router selects `bst_cfg_location` from compiled structures, then assigns a handler. File access goes through `openat2` with `RESOLVE_BENEATH`, so path bugs cannot escape the root, even if URI normalization were wrong.

**Spec:** [config-language.md](config-language.md), RFC 3986 section 5.2.4, RFC 9110 sections 13 and 14.

## Review Focus

1. Path traversal variants: `/../`, `/%2e%2e/`, `/%2f`, `/..%5c`, double encoding, NUL bytes, and symlinks out of root → 400 or 404, with no file disclosed. (Tasks 1, 5)
2. Catastrophic regex against a long URI → stopped by match limits, returning 500 or no match, with the worker still responsive. (Task 3)
3. Range abuse: `bytes=0-0,1-1,...` thousands of ranges, overlaps, unsatisfiable ranges → bounded CPU and memory. (Task 6)
4. File changed or deleted while being served, or open-file cache stale after an edit → error handled, change visible within the TTL. (Tasks 5, 7)
5. File names with HTML, quotes, or non-UTF-8 bytes in directory listing → escaped, with no injection. (Task 8)

---

### Task 1: URI normalization

**Files:**
- Create: `src/route/uri.{c,h}`
- Test: `tests/unit/test_uri.c`, `fuzz/fuzz_uri.c`

**Interfaces:**
- Produces: `int bst_uri_normalize(bst_str raw_path, char *out, size_t cap, bst_uri_flags, size_t *out_len)` applying percent-decoding, dot-segment removal and optional slash merge. `bst_uri_encode_path`, `bst_query_get(bst_str query, bst_str name, bst_str *value)`.

- [ ] **Step 1: Write failing tests**
  - `dot_segments`: RFC 3986 section 5.2.4 examples.
  - `above_root`: `/../../x` → `/x`, never negative depth.
  - `encoded_dots`: `/%2e%2e/x` → `/x`.
  - `encoded_slash`: `/a%2fb` → error by default, 400.
  - `nul`: `%00` → error.
  - `bad_percent`: `%zz`, `%1` → error.
  - `backslash`: `/a\b` is preserved, not treated as a separator.
  - `double_encoding`: `%252e` decodes once to `%2e` literal.
  - `merge_slashes`: `//a///b` → `/a/b` when enabled.
  - `idempotent`: normalizing twice equals normalizing once, also asserted by the fuzz harness.
- [ ] **Step 2: Run** `./dev make test-unit T=uri` → FAIL.
- [ ] **Step 3: Implement** in place into a caller-provided buffer.
- [ ] **Step 4: Run** same → PASS, fuzz 60 seconds → no crash.
- [ ] **Step 5: Commit** `feat(route): add URI normalization`

### Task 2: Virtual host selection

**Files:**
- Create: `src/route/vhost.{c,h}`
- Test: `tests/unit/test_vhost.c`, `tests/integration/test_vhost.py`

**Interfaces:**
- Produces: `const bst_cfg_server *bst_vhost_select(const bst_listener_set *, bst_str host)`. Directive `name` is already registered by Phase 2 (`src/config/core_directives.c`; it lower-cases names except `~regex` ones and rejects duplicates in a server): extend it, adding validation of the wildcard and regex forms, rather than registering it again. It accepts exact, `*.example.com`, `example.*`, and `~regex`. Directive `default_server` on `listen`. `unknown_host` directive: `default | 421 | close`.

- [ ] **Step 1: Write failing tests**
  - `exact_beats_wildcard`, `longest_wildcard_wins`, `case_insensitive`, `trailing_dot`, `port_stripped`, `ipv6_literal_host`.
  - `default_server`: no match → configured default, else first server for the listener.
  - `test_unknown_host_close`: `unknown_host close` closes without a response.
- [ ] **Step 2: Run** `./dev make test-unit T=vhost` → FAIL.
- [ ] **Step 3: Implement** with a hash map for exact names and a reversed-label trie for wildcards.
- [ ] **Step 4: Run** same → PASS, also `./dev make test-int K=vhost`.
- [ ] **Step 5: Commit** `feat(route): add virtual host selection`

### Task 3: Location matching with PCRE2

**Files:**
- Create: `src/route/location.{c,h}`, `src/route/regex.{c,h}`
- Test: `tests/unit/test_location.c`

**Interfaces:**
- Produces: `bst_regex *bst_regex_compile(bst_str, bool icase, bst_err *)`, `int bst_regex_match(const bst_regex *, bst_str, bst_captures *)` with per-worker JIT stacks; `const bst_cfg_location *bst_location_find(const bst_cfg_server *, bst_str uri, bst_captures *)`. Directives: `location` is already registered by Phase 2 (valid in `server` and `location`, nested locations with `parent` and `children` in `bst_cfg_location`, modifier and pattern stored): add pattern validation and matching, do not register it again; `client_max_body_size` is likewise already core. New directives: `regex_match_limit`, `regex_depth_limit`.

- [ ] **Step 1: Write failing tests**, following nginx precedence:
  - `exact_first`, `longest_prefix`, `caret_tilde_stops_regex`, `regex_order_first_match`, `regex_beats_prefix`, `case_insensitive`.
  - `nested_location`: nested block matches inside the parent's prefix.
  - `captures_available`: `$1` is available to children.
  - `redos`: pattern `(a+)+$` with 100,000 `a` characters and a trailing `b` finishes in less than 50 ms and returns the configured limit result.
  - `invalid_regex`: compile error with file position.
- [ ] **Step 2: Run** `./dev make test-unit T=location` → FAIL.
- [ ] **Step 3: Implement** prefix lookup with a compressed trie. The match limit is enforced through `pcre2_set_match_limit` and `pcre2_set_depth_limit`.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(route): add location matching with bounded regex`

### Task 4: Rewrites, redirects and header operations

**Files:**
- Create: `src/route/rewrite.{c,h}`, `src/filters/headers.{c,h}`
- Test: `tests/integration/test_rewrite.py`

**Interfaces:**
- Consumes: `bst_tpl`, `bst_filter_ops`.
- Produces: Directives `rewrite <regex> <replacement> [last|break]`, `redirect <code> <target>`, `redirect_https`, `return <code> [body]`, `header_add`, `header_set`, `header_remove`, `request_header_set`, `request_header_remove`, `expires`, `rewrite_max_cycles`, all merged from `global → server → location`.

- [ ] **Step 1: Write failing tests**
  - `test_rewrite_last_rematches`: `last` restarts location search.
  - `test_rewrite_loop`: self-rewrite → 500 after `rewrite_max_cycles`, default 10.
  - `test_redirect_captures`: `$1` substitution and query preserved.
  - `test_header_crlf_injection`: a template that expands to CR/LF from `%0d%0a` in input → header dropped, logged, and no split.
  - `test_open_redirect_scheme`: `redirect 301 $arg_x` is warned about in `-t` output.
  - `test_expires_immutable`: `expires 1y immutable` sets the expected `Cache-Control`.
  - `test_header_on_errors`: `header_add ... always` applies to error responses, otherwise only 2xx and 3xx.
- [ ] **Step 2: Run** `./dev make test-int K=rewrite` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(route): add rewrites, redirects and header operations`

### Task 5: Safe file resolution and open-file cache

**Files:**
- Create: `src/handlers/resolve.{c,h}`, `src/handlers/ofcache.{c,h}`
- Test: `tests/unit/test_ofcache.c`, `tests/integration/test_file_safety.py`

**Interfaces:**
- Produces: `void bst_file_open(bst_worker *, int root_fd, bst_str rel, bst_file_policy, bst_file_cb, void *ud)`. `bst_file { fd, size, mtime_ns, ino, refcount }`, `bst_file_unref`. Directives: `root`, `alias`, `symlinks on|off|owner_match`, `dotfiles deny|allow`, `open_file_cache max=n ttl=d errors=on`.

- [ ] **Step 1: Write failing tests**
  - `test_traversal_corpus`: all variants in `tests/corpus/traversal.txt` → 400 or 404, and canary file outside the root is never returned.
  - `test_symlink_off`: symlink inside root → 404 under `symlinks off`.
  - `test_symlink_escape`: under `symlinks on`, symlink to `/etc/passwd` is denied through `RESOLVE_BENEATH`.
  - `test_dotfile_denied`: `/.env`, `/.git/config` → 404 by default.
  - `test_dir_is_not_file`: `/dir` → 301 `/dir/`.
  - `test_special_files`: FIFO or device in root → 403 without hanging the worker.
  - `ofcache_ttl`, `ofcache_lru`, and `ofcache_error_cached` unit tests.
  - `ofcache_deleted_while_held`: held file stays readable and closes after the final unref.
- [ ] **Step 2: Run** `./dev make test-unit T=ofcache && ./dev make test-int K=file_safety` → FAIL.
- [ ] **Step 3: Implement.** `root_fd` is opened before the sandbox. Opens use `openat2` with `O_NONBLOCK`, `RESOLVE_BENEATH`, `RESOLVE_NO_MAGICLINKS`, plus `RESOLVE_NO_SYMLINKS` under `symlinks off`; through `IORING_OP_OPENAT2` on io_uring and the aio pool on epoll.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(handlers): add safe file resolution and open-file cache`

### Task 6: Conditional and range logic

**Files:**
- Create: `src/handlers/range.{c,h}`, `src/http/conditional.{c,h}`
- Test: `tests/unit/test_conditional.c`, `tests/unit/test_range.c`, `fuzz/fuzz_range.c`

**Interfaces:**
- Produces: `bst_cond_result bst_evaluate_preconditions(const bst_headers *, const bst_validators *, method)` returning `PROCEED`, `304`, `412`. `int bst_range_parse(bst_str, off_t size, bst_range *out, int max, int *n)` returning satisfiable, none, or `416`. `bst_etag_for_file`. Directives: `max_ranges`, `etag on|off`. Both are pure functions so that Phase 10 reuses them.

- [ ] **Step 1: Write failing tests**
  - `precedence`: RFC 9110 section 13.2.2 order for every combination of the four headers.
  - `if_none_match_weak`: weak comparison; `*` handled.
  - `if_match_strong`: weak validator fails.
  - `invalid_date_ignored`: unparsable `If-Modified-Since` ignored.
  - `range_forms`: `0-0`, `-5`, `5-`, past the end clamped.
  - `range_416`: `bytes=100-` on a 50-byte file → 416 with `Content-Range: bytes */50`.
  - `range_malformed_ignored`: `bytes=abc`, other units → full response.
  - `range_abuse`: 10,000 ranges → full response or 416, bounded by `max_ranges`.
  - `range_overlap_coalesced`: overlapping and adjacent ranges merge.
  - `range_overflow`: values past 2^63 are treated safely.
  - `if_range_mismatch`: full response if the validator differs.
- [ ] **Step 2: Run** `./dev make test-unit T='conditional,range'` → FAIL.
- [ ] **Step 3: Implement** with ETag format `"<hex mtime_ns>-<hex size>"`.
- [ ] **Step 4: Run** same → PASS, fuzz 60 seconds → no crash.
- [ ] **Step 5: Commit** `feat(http): add conditional request and range logic`

### Task 7: Static handler

**Files:**
- Create: `src/handlers/static.{c,h}`, `src/handlers/mime.c`, `src/handlers/mime_table.def`
- Test: `tests/integration/test_static.py`

**Interfaces:**
- Consumes: `bst_file_open`, range and conditional functions, `bst_stream`.
- Produces: `extern const bst_handler_ops bst_static_handler`. Directives: `types`, `default_type`, `sendfile on|off`, `sendfile_max_chunk`, `read_chunk_size`. Multi-range responses use `multipart/byteranges` with a random boundary.

- [ ] **Step 1: Write failing tests**
  - `test_get_identical`: small, 1 MiB, 1 GiB sparse files return byte-identical data, checked by hash.
  - `test_head`, `test_mime`, `test_options_allow`, `test_post_405` with `Allow`.
  - `test_range_single`, `test_range_multi` validated by a multipart parser, `test_range_head`.
  - `test_304`, `test_412`.
  - `test_zero_byte_file`, `test_large_file_offset_above_4g`.
  - `test_file_replaced_during_send`: rename over a file in flight → client gets consistent old content, since the fd is held.
  - `test_truncated_during_send`: connection aborted rather than length mismatched silently.
  - `test_slow_clients_no_buffering`: 1,000 slow readers of a big file keep RSS bounded.
  - `test_zero_copy_used`: debug counter confirms sendfile or splice for HTTP/1.1 cleartext.
- [ ] **Step 2: Run** `./dev make test-int K=static` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** same → PASS on both backends.
- [ ] **Step 5: Commit** `feat(handlers): add static file handler with range support`

### Task 8: Index, try_files, listing, error pages

**Files:**
- Create: `src/handlers/autoindex.{c,h}`, `src/handlers/try_files.c`, `src/handlers/error_page.c`
- Test: `tests/integration/test_static_extras.py`

**Interfaces:**
- Produces: Directives `index`, `try_files`, `autoindex on|off`, `autoindex_format html|json`, `error_page <codes> <uri>`, and `internal`. `error_page` re-enters the router with a fixed recursion limit of one.

- [ ] **Step 1: Write failing tests**
  - `test_index`: `/dir/` → `index.html`, else 403 unless listing is on.
  - `test_spa_fallback`: `try_files $uri $uri/ /index.html` serves index for unknown routes with 200, and real files as themselves.
  - `test_try_files_code`: final argument `=404` works.
  - `test_autoindex_default_off`.
  - `test_autoindex_escaping`: filename `<script>"'&.txt` and a non-UTF-8 name are safely encoded in both formats, and dotfiles remain hidden.
  - `test_autoindex_huge_dir`: 100,000 entries streams with bounded memory and doesn't stall the worker.
  - `test_error_page`: custom 404 returned with status 404; loop in the error page → default error body.
  - `test_internal_location`: direct client access to an `internal` location → 404.
- [ ] **Step 2: Run** `./dev make test-int K=static_extras` → FAIL.
- [ ] **Step 3: Implement.** Directory reads run in the aio pool in batches.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(handlers): add index, try_files, listing and error pages`

### Task 9: Milestone M1 check

**Files:**
- Create: `scripts/bench.sh`, `bench/README.md`, `bench/nginx.conf`, `bench/bastion.conf`, `docs/quickstart.md`

**Interfaces:**
- Produces: `scripts/bench.sh --target host --scenario static-small|static-large|tls|h2|h3|proxy|cache` driving `wrk`, `h2load` and later tools, against Bastion and nginx with matching settings. Writes `bench/results/<date>-<scenario>.json`.

- [ ] **Step 1: Run** the whole suite `./dev make test-unit test-int conformance fuzz-smoke` → PASS on both backends.
- [ ] **Step 2: Run** `./dev scripts/bench.sh --target local --scenario static-small` to validate that the harness works. Label these results `docker-not-comparable`.
- [ ] **Step 3: Write** `docs/quickstart.md`, verifying each config example by feeding it through `bastion -t` in a test.
- [ ] **Step 4: Run** `./dev make test-int K=quickstart` → PASS. Also add `test_serve_end_to_end` in `tests/integration/test_cli.py`: `bastion serve <dir> --port <p>` serves a file over HTTP. Phase 2 left `serve` building an AST with a `root` directive that does not exist yet (`test_serve_unknown_directive_until_phase5`); this phase registers `root`, so replace that pinning test. Amendment (Phase 2 final review): every test that pins `root` as unknown carries the marker `until_phase5` (and passes `-t`, so it checks the configuration instead of starting a server once `root` exists): `test_serve_unknown_directive_until_phase5`, `test_serve_hostile_dir_cannot_inject` (keep its point: the hostile directory name stays one argument, so `-t` never reports a syntax error) and `test_port_bounds_accepted` (keep: ports 1, 8080 and 65535 are accepted by `serve`) in `tests/integration/test_cli.py`. Rewrite or delete each as this phase closes; `grep -rn until_phase5 tests/` finds them all.
- [ ] **Step 5: Commit** `docs: add quickstart and benchmark harness`, then merge the phase branches.
