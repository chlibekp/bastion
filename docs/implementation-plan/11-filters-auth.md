# Phase 11: Compression, HTTP Extras and Authentication (Milestone M4)

**Goal:** Response compression with cached variants, small HTTP features, and per-location authentication.

**Architecture:** All are stream filters or early-phase checks over `bst_stream`, so they apply equally to every protocol and handler. CPU-heavy work (password hashing, high-level compression of big files) runs off the event loop.

**Spec:** RFC 9110 section 12.5.3, RFC 8297, RFC 7617, RFC 7519, RFC 7515.

## Review Focus

1. BREACH-style exposure: secrets reflected in compressed bodies → compression off by default for responses to credentialed requests and for responses with `Set-Cookie`. (Task 1)
2. JWT with `alg: none`, HS256 signed using a public RSA key, expired, wrong audience, or duplicate claims → rejected. (Task 5)
3. Password hashing flood → concurrency bounded, so an auth endpoint can't take down the worker. (Task 4)
4. Forward-auth service down or slow → fails closed, never lets the request through. (Task 6)
5. Compressed response with a Range request, or `no-transform`, or an already-encoded body → bytes stay correct, with correct `ETag`, `Vary`, and `Content-Length`. (Task 1)

---

### Task 1: On-the-fly compression

**Files:**
- Create: `src/filters/compress.{c,h}`, `src/http/accept_encoding.{c,h}`
- Test: `tests/unit/test_accept_encoding.c`, `tests/integration/test_compress.py`

**Interfaces:**
- Consumes: zstd, brotli, zlib-ng streaming APIs, `bst_filter_ops`.
- Produces: `bst_encoding bst_negotiate_encoding(bst_str accept_encoding, uint32_t allowed)`. Directives: `compress <list>|off`, `compress_types`, `compress_min_size`, `compress_level_zstd`, `compress_level_br`, `compress_level_gzip`, `compress_window`, `compress_sensitive off|on`, `compress_max_concurrent`.

- [ ] **Step 1: Write failing tests**
  - `q_values`: `br;q=0, gzip` → gzip; `*;q=0` → identity; `identity;q=0` honoured; server preference breaks ties.
  - `malformed_ae`: invalid values → identity.
  - `test_each_encoding`: zstd, br and gzip decompress to the original for all sizes, including 0 and 10 GiB-stream sparse.
  - `test_vary_added`, `test_content_length_removed`, `test_etag_weakened`.
  - `test_skip_rules`: no compression for small bodies, already-encoded, wrong type, `no-transform`, HEAD, 204 and 304.
  - `test_range_identity`: Range requests are served without on-the-fly compression.
  - `test_sensitive_default_off`: request with `Cookie` or `Authorization`, and responses with `Set-Cookie` → not compressed unless `compress_sensitive on`.
  - `test_streaming_flush`: SSE and flush events reach the client without buffering.
  - `test_memory_per_stream`: 10,000 concurrent compressed streams stay within the worker budget, and over `compress_max_concurrent` falls back to identity.
  - `test_all_protocols`: identical bytes on HTTP/1.1, HTTP/2, HTTP/3.
- [ ] **Step 2: Run** `./dev make test-unit T=accept_encoding && ./dev make test-int K=test_compress` → FAIL.
- [ ] **Step 3: Implement.** Allocators are hooked to charge the worker memory budget. Defaults favour speed: zstd 3, brotli 4, gzip 5.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(filters): add zstd, brotli and gzip compression`

### Task 2: Precompressed files and cached variants

**Files:**
- Modify: `src/handlers/static.c`, `src/cache/filter.c`, `src/filters/compress.c`
- Test: `tests/integration/test_compress_variants.py`

**Interfaces:**
- Produces: Directive `precompressed on|off` looking up `.zst`, `.br`, `.gz`, zero-copy. Filter order `upstream → compress → cache store`, with a normalized Vary dimension on the negotiated encoding, never the raw `Accept-Encoding`. Directive `cache_compressed_variants on|off`.

- [ ] **Step 1: Write failing tests**
  - `test_precompressed_served`: `.br` sent with `Content-Encoding: br` and `Vary`, using the original file's MIME type.
  - `test_precompressed_stale`: `.br` older than the original is ignored.
  - `test_precompressed_direct_request`: `/app.js.br` by URL follows normal rules, without confusing type.
  - `test_precompressed_range`: Range on a precompressed variant has correct `Content-Range`, or the identity file is used, based on `If-Range` rules.
  - `test_variant_cardinality`: 1,000 distinct `Accept-Encoding` strings → at most 4 cache entries.
  - `test_variant_cached`: second request doesn't recompress, by counter.
  - `test_identity_client`: `Accept-Encoding` absent → identity.
  - `test_upstream_encoded`: upstream that's already compressed passes through as received.
  - `test_purge_all_variants`: URL purge removes every encoding.
- [ ] **Step 2: Run** `./dev make test-int K=compress_variants` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(filters): add precompressed files and cached compressed variants`

### Task 3: HTTP extras

**Files:**
- Create: `src/filters/early_hints.c`, `src/filters/request_id.c`, `src/filters/security_headers.c`, `src/filters/maintenance.c`
- Test: `tests/integration/test_http_extras.py`

**Interfaces:**
- Produces: Directives: `early_hints on|off` and `early_hint <link value>`, `request_id on|off`, `request_id_header`, `request_id_trust <cidr>`, `security_headers off|basic|strict` plus overrides `hsts`, `csp`, `frame_options`, `referrer_policy`, `permissions_policy`, `content_type_options`; `maintenance on|off|<file>`, `maintenance_allow <cidr>`, `maintenance_retry_after`. Variable `$request_id`. Body size control `client_max_body_size` already exists, and this adds per-location `upstream_max_response_size`, plus `client_max_body_size 0` as unlimited with a warning.

- [ ] **Step 1: Write failing tests**
  - `test_103_h2_h3`: 103 arrives before the final response on HTTP/1.1, HTTP/2 and HTTP/3; it is skipped for HTTP/1.0.
  - `test_103_from_upstream`: forwarded.
  - `test_request_id_unique`: unique across workers, 128-bit, and forwarded upstream.
  - `test_request_id_spoof`: incoming ID replaced unless the peer is in `request_id_trust`.
  - `test_security_presets`: exact header sets for `basic` and `strict`; HSTS only sent over TLS.
  - `test_security_no_overwrite`: an upstream's own CSP kept unless `force`.
  - `test_maintenance`: 503 with `Retry-After`; allowed CIDR bypasses; runtime toggle by admin API comes in Phase 14.
  - `test_upstream_response_limit`: larger than limit → 502, connection aborted when already started.
- [ ] **Step 2: Run** `./dev make test-int K=http_extras` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(filters): add Early Hints, request IDs, security presets and maintenance mode`

### Task 4: Basic auth

**Files:**
- Create: `src/auth/basic.{c,h}`, `src/auth/auth_common.{c,h}`
- Test: `tests/unit/test_basic_auth.c`, `tests/integration/test_auth_basic.py`

**Interfaces:**
- Consumes: OpenSSL `EVP_KDF` Argon2id (3.2+), `bst_aio_submit`.
- Produces: Early-phase hook `bst_auth_check(stream, cb)`, shared by all auth types. Directives: `auth_basic <realm>`, `auth_basic_file <path>`, `auth_max_concurrent`, `auth_cache_ttl`, and `bastion passwd [user]` CLI writing PHC-format Argon2id entries. `auth_require any|all` combines mechanisms. Variable `$auth_user`.

- [ ] **Step 1: Write failing tests**
  - `phc_parse`: valid and invalid Argon2id strings; weak parameters warn.
  - `decode_rules`: invalid base64, missing colon, over-length → 401, no crash.
  - `constant_time_unknown_user`: unknown users run a dummy hash, so timing doesn't reveal them.
  - `test_correct_wrong`: 200 and 401 with `WWW-Authenticate`.
  - `test_flood_bounded`: 10,000 wrong password attempts → event loop latency stays low, excess gets 429 or 503, and other locations stay responsive.
  - `test_cached_verification`: repeated valid credentials don't rehash, and the cache key isn't the plaintext.
  - `test_auth_header_not_logged`: `Authorization` never appears in logs.
  - `test_file_unreadable_at_load`: load error, and a 401 is never replaced by an open door.
- [ ] **Step 2: Run** `./dev make test-unit T=basic_auth && ./dev make test-int K=auth_basic` → FAIL.
- [ ] **Step 3: Implement.** Credentials file is parsed by master at load; secrets are `MADV_DONTDUMP`.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(auth): add Basic auth with Argon2id`

### Task 5: JWT

**Files:**
- Create: `src/auth/jwt.{c,h}`, `src/auth/jwks.{c,h}`
- Test: `tests/unit/test_jwt.c`, `fuzz/fuzz_jwt.c`, `tests/integration/test_auth_jwt.py`

**Interfaces:**
- Consumes: `bst_json`, OpenSSL.
- Produces: `bst_jwt_verify(token, const bst_jwt_cfg *, now, bst_jwt_claims *out)`. Directives: `auth_jwt keys=<file|url> alg=<list> iss= aud= leeway= header=|cookie=`, `auth_jwt_claim_header <claim> <header>`, `auth_jwt_required_claim`. Algorithms allowed: ES256, ES384, RS256, PS256, EdDSA, and HS256 only with a secret file explicitly configured. Variable `$jwt_claim_NAME`.

- [ ] **Step 1: Write failing tests**
  - `rfc_vectors`: RFC 7515 and 7519 examples.
  - `alg_none`: rejected in every capitalization.
  - `alg_confusion`: HS256 token signed with an RSA public key → rejected.
  - `alg_not_allowed`: valid signature with an algorithm outside the allowlist → rejected.
  - `kid_lookup`: picks the key by `kid`; unknown `kid` → rejected, and doesn't refetch unbounded.
  - `exp_nbf_iat`: exact boundaries with `leeway`.
  - `iss_aud`: wrong values; `aud` as a string and an array.
  - `duplicate_claims`: rejected through the strict JSON parser.
  - `malformed`: wrong segment count, invalid base64url, padding, 1 MiB token → 401 with bounded work.
  - `crit_header`: unknown `crit` → rejected.
  - `claim_header_injection`: claim values with CR or LF never become a header; spoofed client copies of the mapped header are removed.
  - `test_jwks_rotation`: helper refetches keys, and new `kid` works without reload.
  - `test_jwks_url_down`: previous keys stay in use; empty key set at start → all rejected.
- [ ] **Step 2: Run** `./dev make test-unit T=jwt && ./dev make test-int K=auth_jwt` → FAIL.
- [ ] **Step 3: Implement.** RSA and ECDSA verification are fast enough to run on the loop, with a small per-worker verified-token cache that respects `exp`.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(auth): add JWT validation with safe algorithm allowlist`

### Task 6: Forward auth and mTLS enforcement

**Files:**
- Create: `src/auth/forward.{c,h}`, `src/auth/mtls.c`
- Test: `tests/integration/test_auth_forward.py`

**Interfaces:**
- Consumes: `bst_upstream`, pool, `bst_auth_check`, Phase 6 client cert variables.
- Produces: Directives `auth_forward <upstream> path= timeout= pass_headers= response_headers= fail=closed`, `auth_forward_cache_ttl`, `auth_mtls required|<dn or san list>`. No `fail=open` option exists.

- [ ] **Step 1: Write failing tests**
  - `test_allow`: 2xx proceeds, and listed response headers are copied to the upstream request.
  - `test_deny`: 401, 403 and redirects return to the client with their body.
  - `test_timeout_fails_closed`: slow service → 503, no upstream call.
  - `test_down_fails_closed`: connection refused → 503.
  - `test_original_uri_passed`: `X-Original-*` values are present and are not spoofable by the client.
  - `test_response_header_spoof`: client-supplied versions of the auth response headers are stripped.
  - `test_body_not_sent`: request body isn't forwarded to the auth service, and the upstream later still gets it.
  - `test_mtls_location`: correct DN passes, others 403.
  - `test_auth_combination`: `auth_require all` with JWT plus mTLS requires both.
  - `test_auth_before_cache`: an authenticated location's cached response is never served before auth passes.
- [ ] **Step 2: Run** `./dev make test-int K=auth_forward` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `./dev make test-unit test-int conformance fuzz-smoke` → PASS.
- [ ] **Step 5: Commit** `feat(auth): add forward auth and location mTLS enforcement`
