# Phase 7: HTTP/2 (Milestone M2)

**Goal:** Hand-written, h2spec-clean HTTP/2 per RFC 9113, with HPACK per RFC 7541, RFC 9218 priorities, and defences against all published abuse patterns.

**Architecture:** Frame codec and HPACK are pure, independently fuzzed libraries. `h2/conn.c` owns connection and stream state and exposes each stream as a `bst_stream`.

**Spec:** RFC 9113, RFC 7541, RFC 9218, RFC 8441, [architecture.md](architecture.md) section 5.

## Review Focus

1. HPACK bomb: small input expanding into huge headers, and table-size updates beyond settings → bounded memory, compression error. (Task 2)
2. Rapid Reset and MadeYouReset patterns, where the client causes resets through HEADERS/RST or invalid frames → GOAWAY once a budget is exceeded, with little handler work wasted. (Task 6)
3. CONTINUATION flood with no END_HEADERS → cut at the header limit before any large buffering. (Task 6)
4. Client that never opens its flow-control window while many files are pending → bounded memory and an eventual timeout. (Tasks 4, 6)
5. HTTP/2 values containing CR, LF, NUL or uppercase names → stream error, so nothing can be smuggled into an HTTP/1.1 upstream in Phase 9. (Task 5)

---

### Task 1: Frame codec

**Files:**
- Create: `src/http/h2/frame.{c,h}`
- Test: `tests/unit/test_h2_frame.c`, `fuzz/fuzz_h2_frame.c`

**Interfaces:**
- Produces: `bst_h2_frame_parse(const uint8_t *, size_t, uint32_t max_frame, bst_h2_frame *out, bst_h2_err *)` and writers `bst_h2_write_{headers,data,settings,ping,goaway,rst,window_update,priority_update}`.

- [ ] **Step 1: Write failing tests**
  - `all_frames_roundtrip`: each frame type survives write and parse.
  - `size_rules`: PING not 8 bytes, SETTINGS not a multiple of 6, RST_STREAM not 4, WINDOW_UPDATE not 4 → `FRAME_SIZE_ERROR`.
  - `stream_rules`: SETTINGS on stream ≠ 0, DATA on stream 0 → `PROTOCOL_ERROR`.
  - `padding_too_long`: padding ≥ payload → `PROTOCOL_ERROR`.
  - `over_max_frame`: rejected before reading the payload.
  - `unknown_type_ignored`: unknown frames ignored.
  - `reserved_bit_ignored`: ignored and cleared.
- [ ] **Step 2: Run** `./dev make test-unit T=h2_frame` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** same → PASS, fuzz 120 seconds → no crash.
- [ ] **Step 5: Commit** `feat(h2): add frame codec`

### Task 2: Huffman and HPACK

**Files:**
- Create: `src/http/h2/huffman.{c,h}`, `src/http/h2/hpack.{c,h}`, `src/http/h2/hpack_static.def`, `scripts/gen-huffman.py`
- Test: `tests/unit/test_hpack.c`, `fuzz/fuzz_hpack.c`

**Interfaces:**
- Produces: `bst_hpack_decode(bst_hpack_dec *, const uint8_t *, size_t, bst_arena *, bst_headers *out, const bst_hpack_limits *)`, `bst_hpack_encode(bst_hpack_enc *, const bst_headers *, bst_buf *)`. Encoder policy: index common response headers, never index `Set-Cookie`, `Authorization` or `Cookie` values below a length threshold, to limit CRIME-style leakage.

- [ ] **Step 1: Write failing tests**
  - `rfc7541_c_vectors`: all of Appendix C vectors for decoding and encoding.
  - `huffman_all_symbols`: round trip for each byte value.
  - `huffman_bad_padding`: padding over 7 bits or not all ones → error; EOS symbol → error.
  - `int_overflow`: varint overflow → error, including continuation bytes that wrap.
  - `table_eviction`: entries bigger than the table clear it; sizes match RFC accounting (+32 each).
  - `dyn_table_update_rules`: update larger than the SETTINGS limit, or update not at block start → error.
  - `decoded_size_limit`: 4 KiB input expanding beyond `http2_max_header_list_size` → error with bounded memory.
  - `index_zero_and_past_end`: → error.
- [ ] **Step 2: Run** `./dev make test-unit T=hpack` → FAIL.
- [ ] **Step 3: Implement** using a generated nibble-based decode table, and a ring-buffer dynamic table.
- [ ] **Step 4: Run** same → PASS, 300 seconds fuzz → no crash.
- [ ] **Step 5: Commit** `feat(h2): add Huffman and HPACK`

### Task 3: Connection and stream state

**Files:**
- Create: `src/http/h2/conn.{c,h}`, `src/http/h2/stream.{c,h}`
- Test: `tests/unit/test_h2_conn.c`, `tests/integration/test_h2_basic.py`

**Interfaces:**
- Consumes: frame, HPACK, `bst_stream_ops`.
- Produces: `bst_conn_h2_start(bst_worker *, bst_transport *, const bst_cfg_server_set *)`. Directives: `http2_max_concurrent_streams`, `http2_initial_window`, `http2_connection_window`, `http2_max_frame_size`, `http2_max_header_list_size`, `http2_idle_timeout`, `http2_header_table_size`. A unit test driver feeds frames through a memory transport with no sockets.

- [ ] **Step 1: Write failing tests**
  - `preface_required`: wrong preface → connection close.
  - `settings_ack`: SETTINGS exchanged and acknowledged; missing ACK times out.
  - `state_machine`: all RFC 9113 section 5.1 transitions, including frames on closed and idle streams.
  - `stream_id_rules`: even, or decreasing ID → `PROTOCOL_ERROR`.
  - `max_concurrent`: over limit → `RST_STREAM(REFUSED_STREAM)`.
  - `headers_while_continuation`: any other frame between HEADERS and CONTINUATION → `PROTOCOL_ERROR`.
  - `graceful_goaway`: two-phase GOAWAY, with in-flight streams finishing.
  - `test_h2_alpn_get`: curl and nghttp GET with ALPN h2.
  - `test_multiplex_100`: 100 concurrent streams return the right bodies.
- [ ] **Step 2: Run** `./dev make test-unit T=h2_conn && ./dev make test-int K=h2_basic` → FAIL.
- [ ] **Step 3: Implement.** Closed stream IDs are tracked with a compact window, so frames racing an RST are handled without retaining stream objects.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(h2): add connection and stream state machine`

### Task 4: Flow control and scheduling

**Files:**
- Create: `src/http/h2/flow.{c,h}`, `src/http/h2/sched.{c,h}`
- Test: `tests/unit/test_h2_flow.c`, `tests/integration/test_h2_flow.py`

**Interfaces:**
- Produces: Stream and connection windows, RFC 9218 urgency and incremental scheduler with `Priority` header and PRIORITY_UPDATE frames, `bst_h2_write_pump(conn)`. Uses `TCP_NOTSENT_LOWAT` from the listener profile, so little data sits in kernel buffers and priority takes effect. Directives: `http2_priorities on|off`, `http2_write_chunk`, `http2_recv_window_policy`.

- [ ] **Step 1: Write failing tests**
  - `window_overflow`: WINDOW_UPDATE above 2^31−1 → `FLOW_CONTROL_ERROR` (stream or connection as applicable).
  - `zero_increment`: → error as specified.
  - `initial_window_change`: SETTINGS change applies to existing streams, and can go negative.
  - `client_exceeds_window`: DATA over window → `FLOW_CONTROL_ERROR`.
  - `urgency_order`: urgency 0 beats 7; incremental round-robins.
  - `test_big_file_small_window`: 16 KiB window, 100 MiB file → identical, with no stall.
  - `test_zero_window_timeout`: window never opened → stream reset after `send_timeout`.
  - `test_memory_bound`: 256 streams on a zero window hold bounded memory because handlers aren't asked for more data.
- [ ] **Step 2: Run** `./dev make test-unit T=h2_flow && ./dev make test-int K=h2_flow` → FAIL.
- [ ] **Step 3: Implement.** Stream scheduling is O(log n) or better; file-backed chains read through `bst_io` at most `http2_write_chunk` at a time.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(h2): add flow control and RFC 9218 priorities`

### Task 5: Bridge to HTTP semantics

**Files:**
- Create: `src/http/h2/bridge.c`
- Test: `tests/unit/test_h2_validate.c`, `tests/integration/test_h2_semantics.py`

**Interfaces:**
- Consumes: `bst_validate_request_semantics`, static handler.
- Produces: The `bst_stream_ops` implementation for h2. `bst_h2_validate_headers(...)`, shared with Phase 8 validation rules through `src/http/validate_pseudo.c`.

- [ ] **Step 1: Write failing tests**
  - `pseudo_rules`: missing, duplicate, unknown, or after-regular-field pseudo-headers → malformed (stream `PROTOCOL_ERROR`).
  - `name_rules`: uppercase, space, or colon in a name → malformed.
  - `value_rules`: CR, LF, NUL, or leading or trailing whitespace in a value → malformed.
  - `connection_headers`: `Connection`, `Keep-Alive`, `Upgrade`, `Transfer-Encoding`, `Proxy-Connection`; `TE` other than `trailers` → malformed.
  - `content_length_mismatch`: DATA total differing from CL → malformed.
  - `cookie_crumbs`: split cookies are joined for handlers.
  - `authority_vs_host`: both present and different → 400.
  - `test_static_h2`: Range, conditional, HEAD and error pages match HTTP/1.1 results for the same corpus.
  - `test_trailers`: request and response trailers pass.
- [ ] **Step 2: Run** `./dev make test-unit T=h2_validate && ./dev make test-int K=h2_semantics` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(h2): connect HTTP/2 streams to HTTP semantics`

### Task 6: Abuse guards

**Files:**
- Create: `src/http/h2/guard.{c,h}`
- Test: `tests/integration/test_h2_abuse.py`, `tests/tools/h2_attack.py`

**Interfaces:**
- Produces: Per-connection budgets in a leaky bucket style. `bst_h2_guard_charge(conn, kind)` returning whether to `GOAWAY(ENHANCE_YOUR_CALM)`. Directives under `http2_abuse {}`: `rst_rate`, `server_reset_rate`, `settings_rate`, `ping_rate`, `empty_frame_rate`, `priority_rate`, `window_update_rate`, `continuation_max`, `control_queue_max`. Metric `bastion_h2_abuse_total{kind}`. Each guard hit reports to the Phase 12 escalation hook, a no-op until then.

- [ ] **Step 1: Write failing tests**, each using `h2_attack.py`, with CPU and RSS bounds asserted and with a parallel legitimate client still served:
  - `test_rapid_reset` (CVE-2023-44487): HEADERS then RST at high speed → GOAWAY, and the number of handler starts is limited.
  - `test_made_you_reset` (CVE-2025-8671): client-triggered server resets, such as invalid WINDOW_UPDATE on open streams → also charged.
  - `test_continuation_flood` (CVE-2024-27983 family): endless CONTINUATION → closed at `continuation_max` without big allocation.
  - `test_settings_flood`, `test_ping_flood`, `test_reset_flood` (CVE-2019-9512, -9514, -9515): queued control responses are bounded, then closed.
  - `test_empty_frames` (CVE-2019-9516, -9518): zero-length headers or data floods → closed.
  - `test_dependency_flood` (CVE-2019-9513): PRIORITY frames ignored, and charged.
  - `test_window_drip` (CVE-2019-9511, -9517): data drip attack is bounded.
  - `test_hpack_pressure`: repeated table churn at the limit stays bounded.
  - `test_legitimate_browser_load`: 200 streams with normal cancellation never trigger guards.
- [ ] **Step 2: Run** `./dev make test-int K=h2_abuse` → FAIL.
- [ ] **Step 3: Implement.** Handler dispatch for a new stream occurs only after header validation and the guard check, keeping reset attacks cheap.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(h2): add protocol abuse guards`

### Task 7: Extended CONNECT, h2c and h2spec gate

**Files:**
- Modify: `src/http/h2/conn.c`, `src/http/h1/conn.c`
- Create: `tests/conformance/test_h2spec.py`
- Test: `tests/integration/test_h2_extras.py`

**Interfaces:**
- Produces: `SETTINGS_ENABLE_CONNECT_PROTOCOL` with `:protocol`, consumed in Phase 9 by the WebSocket tunnel. `listen ... h2c` for prior-knowledge cleartext HTTP/2, detecting the preface on a listener and otherwise treating it as HTTP/1.1.

- [ ] **Step 1: Write failing tests**
  - `test_h2c_prior_knowledge`: `curl --http2-prior-knowledge` on an h2c listener.
  - `test_h1_on_h2c_listener`: plain HTTP/1.1 on that listener still works.
  - `test_no_h1_upgrade`: `Upgrade: h2c` is ignored.
  - `test_ext_connect_setting`: advertised only when a location can use it.
  - `test_h2spec`: the pinned `h2spec` strict run, both with and without TLS, has 0 failures.
- [ ] **Step 2: Run** `./dev make conformance K=h2spec` → FAIL.
- [ ] **Step 3: Implement** and fix any failures.
- [ ] **Step 4: Run** `./dev make test-unit test-int test-vm conformance fuzz-smoke` → PASS.
- [ ] **Step 5: Commit** `feat(h2): add extended CONNECT and h2c, enforce h2spec`
