# Phase 4: HTTP Core and HTTP/1.1

**Goal:** Protocol-independent request and response model, and a strict, fast HTTP/1.1 implementation per RFC 9110 and RFC 9112.

**Architecture:** See [architecture.md](architecture.md) section 5. The parser is zero-copy over receive buffers. `bst_stream` is the boundary every later protocol and handler uses.

**Spec:** [architecture.md](architecture.md), RFC 9110, RFC 9112.

## Review Focus

1. Request smuggling inputs: `Content-Length` with `Transfer-Encoding`, duplicated or comma-list CL, `Transfer-Encoding: xchunked`, obs-fold, bare CR, whitespace before colon → all rejected with 400 and closed. (Task 3)
2. Slowloris, slow body, and slow reader clients → each is cut by a total deadline or minimum rate, not reset by each byte. (Task 5)
3. Pipelined requests whose handlers finish out of order → responses in request order. (Task 5)
4. Client disconnect during a handler → `on_reset` called exactly once, with all resources released. (Task 5)
5. Request split at every possible byte boundary → same parse result as when delivered whole. (Task 2)
6. The SSE and AVX2 parser paths exist only on x86_64 → run the unit tests once under `./dev --platform linux/amd64` before the phase is accepted.
7. The amd64 binary has never run, and Phase 3 proved its seccomp table offline only (ruling N in `03-io-process.md`, Task 8) → at the end of this phase, run `./dev --platform linux/amd64 make test-int K=sandbox`, which needs the x86_64 deps built first: every worker sandboxed on a real x86_64 syscall path. If emulation cannot run it, this acceptance line is raised with the user, not dropped.

---

### Task 1: Header model

**Files:**
- Create: `src/http/headers.{c,h}`, `src/http/known_headers.def`, `scripts/gen-known-headers.py`, `src/http/token.h`
- Test: `tests/unit/test_headers.c`

**Interfaces:**
- Produces: `bst_headers` (array of `{bst_str name; bst_str value; uint16_t id;}`), `bst_hdr_id bst_hdr_lookup(const char *, size_t)` using a generated perfect hash, `bst_headers_add`, `bst_headers_get(h, id)`, `bst_headers_get_name(h, bst_str)` (case-insensitive), `bst_headers_remove`, `bst_headers_set`, `bst_is_tchar`, `bst_is_field_value_clean(bst_str)`.

- [ ] **Step 1: Write failing tests**
  - `lookup_known`: all known headers resolve in any case; unknown → 0.
  - `multi_get`: multiple `Set-Cookie` entries iterate in order.
  - `tchar_table`: every byte 0-255 matches the RFC 9110 token definition.
  - `field_value`: NUL, CR and LF are rejected; HTAB and obs-text are accepted.
- [ ] **Step 2: Run** `./dev make test-unit T=headers` → FAIL.
- [ ] **Step 3: Implement** with a generated table committed alongside its generator.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(http): add header model with known header table`

### Task 2: Request line and header parser

**Files:**
- Create: `src/http/h1/parser.{c,h}`
- Test: `tests/unit/test_h1_parser.c`, `fuzz/fuzz_h1_parser.c`, `tests/corpus/h1/`

**Interfaces:**
- Produces: `bst_h1_result bst_h1_parse_head(bst_h1_parser *, const char *buf, size_t len, const bst_h1_limits *, bst_req_head *out)` returning `DONE`, `NEED_MORE` or `ERROR(status)`, resumable with no rescans of already-validated bytes. `bst_req_head { method, target forms, version, headers }`. Directives: `client_max_uri_size`, `client_max_header_count`, `http1_allow_bare_lf` (default off).

- [ ] **Step 1: Write failing tests**
  - `all_splits`: every corpus request, split at each byte offset → same result as whole input.
  - `target_forms`: origin, absolute, authority (only with CONNECT), asterisk (only with OPTIONS).
  - `method_token`: invalid token → 400; unknown valid method parses and yields 501 or 405 later.
  - `version`: `HTTP/2.0` → 505; `HTTP/1.1` ok; `HTTP/1.2` treated as 1.1 per RFC 9112; `http/1.1` → 400.
  - `leading_crlf`: one leading empty line tolerated; more than the limit → 400.
  - `limits`: URI above the limit → 414; headers above the limit → 431; too many headers → 431.
  - `control_chars`: NUL or CTL in the target or a value → 400; bare LF → 400 unless `http1_allow_bare_lf on`.
- Receive buffers: the parser copies a partial request into a per-connection header buffer capped by the header-size directive, unrefs every recv buffer before returning to the loop, and relies on the header timeout for slow clients. It never keeps a recv buffer across reads (Phase 3 makes holding cost memory rather than stall other sockets, but a parser that holds buffers still pins up to 16 KiB per connection).
- [ ] **Step 2: Run** `./dev make test-unit T=h1_parser` → FAIL.
- [ ] **Step 3: Implement** with SIMD scans (SSE4.2 or AVX2 on x86_64, NEON on arm64, chosen at runtime or compile time) and a scalar path tested for identical results by `all_splits`.
- [ ] **Step 4: Run** same → PASS. `./dev make fuzz T=fuzz_h1_parser SECS=120` → no crash.
- [ ] **Step 5: Commit** `feat(h1): add resumable request parser`

### Task 3: Message framing and smuggling defences

**Files:**
- Create: `src/http/h1/framing.c`, `src/http/semantics.{c,h}`
- Test: `tests/unit/test_h1_framing.c`, `tests/corpus/smuggling/`

**Interfaces:**
- Produces: `bst_framing bst_h1_message_framing(const bst_req_head *, int *status)` giving `NONE`, `LENGTH(n)` or `CHUNKED`. `bst_validate_request_semantics(bst_req *)` for Host rules and connection tokens, shared with HTTP/2 and HTTP/3.

- [ ] **Step 1: Write failing tests**, table-driven, each → expected status and "close":
  - `cl_te_both` → 400.
  - `cl_list_same` (`5, 5`) and `cl_dup_same` → 400 by strict default. `cl_dup_diff`, `cl_plus` (`+5`), `cl_hex`, `cl_overflow`, and `cl_space_before_colon` → 400.
  - `te_identity`, `te_xchunked`, `te_chunked_gzip`, and `te_chunked_chunked` → 501 or 400 as RFC 9112 specifies.
  - `te_http10` → 400 and close.
  - `obs_fold` → 400.
  - `host_missing`, `host_dup`, `host_invalid`, `host_mismatch_absolute_uses_target`.
  - All of the published HTTP desync variants stored in `tests/corpus/smuggling/`.
- [ ] **Step 2: Run** `./dev make test-unit T=h1_framing` → FAIL.
- [ ] **Step 3: Implement.** No leniency directives for CL or TE; an ambiguous message is always rejected.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(h1): reject ambiguous framing and smuggling vectors`

### Task 4: Body decoding

**Files:**
- Create: `src/http/h1/body.{c,h}`
- Test: `tests/unit/test_h1_body.c`, `fuzz/fuzz_h1_chunked.c`

**Interfaces:**
- Produces: `bst_h1_body_feed(bst_h1_body *, bst_buf *in, bst_chain *out, bst_headers *trailers, int *status)`, outputting decoded data without copies. Directives: `chunk_ext_limit`, `client_max_trailer_size`.

- [ ] **Step 1: Write failing tests**
  - `chunk_splits`: valid chunked at all split points gives the same decode.
  - `chunk_size_overflow`: `FFFFFFFFFFFFFFFFF` → 400.
  - `chunk_ext`: valid extensions ignored; bare LF or CR inside → 400; over `chunk_ext_limit` → 400.
  - `trailers`: forbidden trailer names (framing, routing, auth) dropped; size limit enforced.
  - `missing_crlf_after_data`: → 400.
  - `pipelined_after_body`: bytes after the final chunk are returned unconsumed.
  - `max_body`: above `client_max_body_size` → 413.
- [ ] **Step 2: Run** `./dev make test-unit T=h1_body` → FAIL.
- [ ] **Step 3: Implement** as a byte-level state machine for chunk metadata with spans for data.
- [ ] **Step 4: Run** same → PASS, and 120 seconds of fuzz → no crash.
- [ ] **Step 5: Commit** `feat(h1): add body decoder`

### Task 5: Stream core and connection state machine

**Note from Phase 3 Task 7:** this task sets `bst_worker_on_conn` (`src/proc/worker.h`), which replaces `BST_TEST_RAW_MODE` as the worker's protocol; the raw mode is removed once Task 9's overload tests use the `return` handler. A connection brackets itself with `bst_worker_conn_opened` and `bst_worker_conn_closed`, and a stopping worker exits on the last close. A keep-alive connection sitting idle would hold a graceful stop until `shutdown_timeout`, so this task also needs a way to close idle connections when a worker starts stopping (`stop_accepting` in `src/proc/worker.c`).

**Files:**
- Create: `src/http/stream.{c,h}`, `src/http/h1/conn.{c,h}`, `src/http/h1/serialize.c`, `src/http/date.c`, `src/http/errors.c`
- Test: `tests/integration/test_h1_conn.py`, `tests/unit/test_h1_serialize.c`

**Interfaces:**
- Consumes: parser, framing, body, `bst_io_*`, `bst_timer`.
- Produces: `bst_stream`, `bst_stream_ops`, `bst_handler_ops`, `bst_filter_ops`, `bst_transport_ops` (architecture.md section 5), `bst_transport *bst_transport_plain(bst_sock *)`, `bst_stream_set_handler`, `bst_stream_arena`, `bst_stream_req`, `bst_conn_h1_start(bst_worker *, bst_transport *, const bst_cfg_server_set *)`, `bst_send_error(bst_stream *, int status)`, and the built-in `return` handler. Directives: `client_header_timeout`, `client_body_timeout`, `client_body_min_rate`, `send_timeout`, `send_min_rate`, `keepalive_timeout`, `keepalive_requests`, `client_header_buffer_size`, `large_client_header_buffers`, `client_max_body_size` (already registered as a core directive in `src/config/core_directives.c`, with its `bst_cfg_common` field and default `1m`: consume it, do not register it again), `http1_max_pipeline`, `lingering_close`, `lingering_timeout`, `server_tokens`, `return`.

- [ ] **Step 1: Write failing tests**
  - `test_keepalive_reuse`: two requests on one connection.
  - `test_http10_closes`: HTTP/1.0 without keep-alive closes; with `Connection: keep-alive`, stays open and uses correct framing.
  - `test_connection_close`: response carries `Connection: close`, then the socket closes.
  - `test_pipeline_order`: 100 pipelined requests with different handler delays → in order.
  - `test_pipeline_limit`: excessive pipeline depth pauses reads, without unbounded memory.
  - `test_expect_100`: `Expect: 100-continue` → 100 once the handler requests the body; an over-limit length → 413 with no 100.
  - `test_head_no_body`: HEAD has the same headers as GET and no body.
  - `test_204_304_no_body`: no body, no `Content-Length` on 204.
  - `test_date_server`: `Date` is valid and `Server` obeys `server_tokens`.
  - `test_slowloris_header`: one header byte per second → 408 at `client_header_timeout`, total rather than per read.
  - `test_slow_body`: under `client_body_min_rate` → 408.
  - `test_slow_reader`: reader below `send_min_rate` → closed, memory bounded.
  - `test_abort_during_handler`: disconnect → `on_reset` exactly once, ASan clean.
  - `test_lingering_close`: error response with unread body doesn't cause an RST before the client reads the response.
  - `test_trace_connect`: TRACE → 405; CONNECT → 405 with `Allow`.
- [ ] **Step 2: Run** `./dev make test-int K=h1_conn` → FAIL.
- [ ] **Step 3: Implement.** The connection state lives in a slab object. Only the head of the pipeline may write. Other responses wait with back-pressure on their handlers. Writes coalesce head and first body chunk into one `writev`. Date string cached per second.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(h1): add stream core and connection state machine`

### Task 6: HTTP/1.1 conformance corpus

**Files:**
- Create: `tests/conformance/h1_rfc_requirements.yaml`, `tests/conformance/test_h1_rfc.py`, `docs/conformance.md`
- Modify: `Makefile`

**Interfaces:**
- Produces: `make conformance` target that later phases extend. A YAML corpus: raw request bytes, expected status or close behaviour, and RFC section reference.

- [ ] **Step 1: Write the corpus** covering the MUST and MUST NOT requirements for servers in RFC 9110 and RFC 9112, one entry per requirement, section number in each.
- [ ] **Step 2: Run** `./dev make conformance K=h1` → fix any failures in earlier code; a deliberate deviation goes in `docs/conformance.md` with reasoning.
- [ ] **Step 3: Run** differential check `tests/conformance/h1_vs_nginx.py` comparing status against nginx for the whole corpus, printing differences for manual review, with no pass or fail effect.
- [ ] **Step 4: Run** `./dev make conformance K=h1` → PASS.
- [ ] **Step 5: Commit** `test(h1): add RFC requirement corpus and conformance report`
