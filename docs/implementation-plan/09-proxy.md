# Phase 9: Reverse Proxy

**Goal:** A streaming reverse proxy with upstream pools, balancing, health checks, retries, circuit breaking, WebSocket, gRPC, SSE, PROXY protocol and upstream TLS.

**Architecture:** A protocol-independent `proxy` handler over `bst_stream`. Request framing always regenerates, so nothing from the client's bytes passes unparsed. Per-worker connection pools, with shared health state published by the helper through `upstream_state`.

**Spec:** RFC 9110 section 7, RFC 9112, RFC 9113, RFC 6455, RFC 7239, RFC 8441, RFC 9220.

## Review Focus

1. Upstream dies mid-response → client connection aborted so a truncated body can't look complete. Never retried once response bytes have gone to the client. (Tasks 3, 5)
2. Hop-by-hop abuse: `Connection: X-Forwarded-For`, spoofed `X-Forwarded-*`, or `Connection: Authorization` from a client → trusted forwarding headers survive, spoofed ones are replaced. (Task 3)
3. HTTP/2 or HTTP/3 client request translated into HTTP/1.1 upstream → no smuggling, as strict validation plus regeneration applies. (Task 3)
4. Stale pooled connection closed by the upstream as a request is sent → retried on a fresh connection only when safe. (Task 2)
5. All upstreams unhealthy → 503 quickly and deterministically, with `panic` behaviour documented, no spin. (Task 5)

---

### Task 1: Upstream model and DNS

**Files:**
- Create: `src/proxy/upstream.{c,h}`, `src/proxy/dns.{c,h}`, `src/proxy/proxy_directives.c`
- Test: `tests/unit/test_dns.c`, `fuzz/fuzz_dns.c`, `tests/integration/test_upstream_dns.py`

**Interfaces:**
- Produces: `bst_upstream`, `bst_peer { bst_sockaddr addr; weight; state index }`. Helper-run `bst_dns_query`, a small stub resolver, parsing A, AAAA. `upstream_state` publication with a generation counter so workers pick up changes without locks. Directives: `upstream`, `server` with `weight=`, `backup`, `resolve`, `max_conns=`; `resolver`, `resolver_ttl_min`, `resolver_ttl_max`, `resolver_timeout`.

- [ ] **Step 1: Write failing tests**
  - `dns_parse`: real captures of A, AAAA, CNAME chains.
  - `dns_compression_loop`: pointer loop → error.
  - `dns_txid_mismatch`: wrong ID or source → ignored.
  - `dns_truncated`, `dns_oversize`: handled safely.
  - `test_resolve_changes`: address change on a test DNS server → traffic moves within TTL with no reload.
  - `test_resolver_down`: old addresses stay in use past TTL with a warning.
  - `test_startup_unresolvable`: `resolve` at startup with failing DNS → starts, with 502 until resolved; no `resolve` → load error.
- [ ] **Step 2: Run** `./dev make test-unit T=dns` → FAIL.
- [ ] **Step 3: Implement.** Query IDs and source ports use a CSPRNG. Name resolution is not used in workers at all.
- [ ] **Step 4: Run** same plus `./dev make test-int K=upstream_dns` → PASS.
- [ ] **Step 5: Commit** `feat(proxy): add upstream model and async DNS`

### Task 2: HTTP/1.1 client and connection pool

**Files:**
- Create: `src/proxy/client_h1.{c,h}`, `src/proxy/pool.{c,h}`, `src/http/h1/resp_parser.{c,h}`
- Test: `tests/unit/test_h1_resp_parser.c`, `fuzz/fuzz_h1_resp.c`, `tests/integration/test_pool.py`

**Interfaces:**
- Produces: `bst_upconn`. `bst_pool_get(worker, peer, cb)`, `bst_pool_put`. Response parser `bst_h1_parse_resp_head` with framing rules from RFC 9112 section 6.3, including 1xx, 204, 304 and close-delimited. Directives: `keepalive`, `keepalive_timeout`, `keepalive_requests`, `connect_timeout`, `send_timeout`, `read_timeout`.

- [ ] **Step 1: Write failing tests**
  - `resp_framing`: table of status and framing header combinations.
  - `resp_cl_te_both`: rejected as 502, never forwarded.
  - `resp_splitting`: CR/LF injection in upstream values → 502.
  - `resp_excess_after_body`: extra bytes → connection not reused.
  - `test_pool_reuse`: 1,000 sequential requests use few connections.
  - `test_pool_idle_timeout`: closes idle connections.
  - `test_pool_stale_detect`: an upstream-closed idle connection → detected by read notification and not used.
  - `test_pool_race`: upstream closes as the request is sent, before any bytes returned → retried only for idempotent methods, otherwise 502.
- [ ] **Step 2: Run** `./dev make test-unit T=h1_resp_parser` → FAIL.
- [ ] **Step 3: Implement.** Sets `IP_BIND_ADDRESS_NO_PORT`, `TCP_NODELAY`, and optional `TCP_FASTOPEN_CONNECT` on upstream sockets.
- [ ] **Step 4: Run** same plus `./dev make test-int K=pool` → PASS.
- [ ] **Step 5: Commit** `feat(proxy): add HTTP/1.1 upstream client and connection pool`

### Task 3: Proxy handler

**Files:**
- Create: `src/proxy/handler.{c,h}`, `src/proxy/forward_headers.c`, `src/proxy/real_ip.c`
- Test: `tests/integration/test_proxy.py`, `tests/integration/test_proxy_translation.py`

**Interfaces:**
- Consumes: `bst_stream`, pool, `bst_chain`.
- Produces: `extern const bst_handler_ops bst_proxy_handler`. Directives: `proxy <url|upstream>`, `proxy_uri pass|strip_prefix`, `proxy_host $host|upstream|<value>`, `forwarded_headers xff|forwarded|off`, `trusted_proxies <cidr...>`, `real_ip_header`, `real_ip_from`, `proxy_pass_header`, `proxy_hide_header`, `intercept_errors`, `response_buffering`, `request_buffering`, `max_upstream_header_size`. Variables `$upstream_addr`, `$upstream_status`, `$upstream_response_time`.

- [ ] **Step 1: Write failing tests**
  - `test_streaming`: 10 GiB through without RSS growth, slow client back-pressures to the upstream.
  - `test_upload_streaming`: upstream sees first bytes before the upload completes when `request_buffering off`.
  - `test_hop_by_hop`: `Connection`-listed names and hop-by-hop headers dropped both ways.
  - `test_connection_header_abuse`: `Connection: X-Forwarded-For` cannot remove forwarding headers.
  - `test_xff`: untrusted client's XFF replaced, trusted proxy's appended.
  - `test_real_ip_spoof`: `real_ip_header` honoured only from `real_ip_from`.
  - `test_mid_response_failure`: upstream dies → HTTP/1.1 connection closed, HTTP/2 RST, HTTP/3 stream reset, never a clean end.
  - `test_upstream_timeouts`: connect → 504 or 502; first byte → 504.
  - `test_h2_to_h1_smuggling`: corpus of h2 and h3 requests with CL/TE tricks → upstream sees exactly one well-formed request per client request.
  - `test_uri_passthrough`: encoded path bytes reach the upstream as sent, unless a rewrite applied.
  - `test_client_abort`: client disconnect closes the upstream request, and connection is not returned to the pool mid-body.
  - `test_1xx`: 100 consumed and 103 forwarded.
  - `test_early_data_flag`: 0-RTT requests carry `Early-Data: 1`; upstream 425 is forwarded.
- [ ] **Step 2: Run** `./dev make test-int K='proxy'` → FAIL.
- [ ] **Step 3: Implement.** Streaming is the default, with credit passed from client to upstream and back. Request head is always serialized anew from the parsed form, with no raw byte forwarding.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(proxy): add streaming reverse proxy handler`

### Task 4: Balancing

**Files:**
- Create: `src/proxy/balance.{c,h}`
- Test: `tests/unit/test_balance.c`

**Interfaces:**
- Produces: `const bst_peer *bst_balance_pick(bst_upstream *, const bst_pick_ctx *)`. Algorithms: `round_robin` (smooth weighted), `least_conn`, `hash <tpl> [consistent]` using a bounded-load ring, and `peak_ewma` with power-of-two choices. Directive: `balance`, plus `slow_start` on `server`.

- [ ] **Step 1: Write failing tests**
  - `rr_weights`: 2:1 weights → 2:1 within 1 in a smooth sequence.
  - `least_conn_prefers_idle`.
  - `hash_stable`: same key maps to same peer.
  - `hash_minimal_movement`: removing 1 of 10 peers remaps about 10% of keys, within bounds.
  - `ewma_avoids_slow`: slow peer gets a smaller share in a simulation.
  - `slow_start_ramp`: recovered peer's share ramps up over the window.
  - `skips_unhealthy`, `backup_only_when_needed`, `no_peer_returns_null`.
- [ ] **Step 2: Run** `./dev make test-unit T=balance` → FAIL.
- [ ] **Step 3: Implement** with per-worker balancing state; only health is shared.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(proxy): add load balancing algorithms`

### Task 5: Health, retries and circuit breaking

**Files:**
- Create: `src/proxy/health.{c,h}`, `src/proxy/breaker.{c,h}`, `src/proxy/retry.{c,h}`
- Test: `tests/unit/test_breaker.c`, `tests/integration/test_upstream_resilience.py`

**Interfaces:**
- Produces: Helper job `bst_health_check_run`. Directives: `health_check path= interval= timeout= fails= passes= expect=`, `passive_eject fails= window= for=`, `retry attempts= budget= on= timeout=`, `circuit_breaker max_pending= max_active= max_retries=`, `panic_threshold`.

- [ ] **Step 1: Write failing tests**
  - `test_active_eject_recover`: failing health path removes a peer; recovery restores it after `passes`.
  - `test_passive_eject`: 5xx or connect errors within `window` eject the peer, and shared state reaches all workers.
  - `test_no_retry_post`: POST never retried after any bytes reached the upstream.
  - `test_retry_get_connect_error`: GET retried on another peer.
  - `test_retry_budget`: a total outage produces retries within `budget`, with no amplification.
  - `test_no_retry_after_client_bytes`: failure after response start → abort, no retry.
  - `test_circuit_open`: `max_pending` reached → immediate 503 with `Retry-After`, no queue growth.
  - `test_all_down`: fast 503, no spin; `panic_threshold` behaviour routes to all peers when configured.
  - `test_health_probe_count`: one probe per interval globally, not per worker.
  - `breaker_states` unit test: closed, open, half-open transitions.
- [ ] **Step 2: Run** `./dev make test-int K=upstream_resilience` → FAIL.
- [ ] **Step 3: Implement.** Active checks run in the helper. Passive observations are written by workers with atomics.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(proxy): add health checks, retries and circuit breaking`

### Task 6: Upstream TLS

**Files:**
- Create: `src/proxy/up_tls.{c,h}`
- Test: `tests/integration/test_upstream_tls.py`

**Interfaces:**
- Consumes: Phase 6 non-blocking TLS.
- Produces: `tls verify on|off`, `tls ca`, `tls sni`, `tls cert`, `tls key`, `tls versions` inside `upstream`. Default for `https://` upstreams: verification on using the system CA, with SNI and hostname checks.

- [ ] **Step 1: Write failing tests**
  - `test_verify_default`: self-signed upstream → 502 and an error log.
  - `test_hostname_mismatch`: valid CA, wrong name → 502.
  - `test_verify_off_warns`: `-t` warns.
  - `test_upstream_mtls`: client certificate is presented.
  - `test_session_reuse`: upstream session resumption reduces full handshakes.
  - `test_sni_sent`: expected SNI seen by the test server.
- [ ] **Step 2: Run** `./dev make test-int K=upstream_tls` → FAIL.
- [ ] **Step 3: Implement.** CA bundles load in master before the sandbox.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(proxy): add upstream TLS and mTLS`

### Task 7: WebSocket and SSE

**Files:**
- Create: `src/proxy/tunnel.{c,h}`
- Test: `tests/integration/test_websocket.py`, `tests/integration/test_sse.py`

**Interfaces:**
- Consumes: `bst_stream`, Phase 7 and 8 extended CONNECT.
- Produces: Directives `websocket on|off` (default on where `proxy` is set), `tunnel_idle_timeout`, `tunnel_max_duration`, `tunnel_drain_timeout`, `max_tunnels`. WebSocket frames are relayed as opaque bytes, with both TLS-free ends using `splice`. HTTP/2 and HTTP/3 extended CONNECT is translated to an HTTP/1.1 Upgrade.

- [ ] **Step 1: Write failing tests**
  - `test_ws_h1`: echo with text, binary, ping and close.
  - `test_ws_over_h2`, `test_ws_over_h3`: RFC 8441 and RFC 9220 clients reach an HTTP/1.1 WebSocket upstream.
  - `test_ws_bad_upgrade`: missing key, wrong version, or upstream that doesn't answer 101 → relayed as a normal response, not a tunnel.
  - `test_ws_smuggle_failed_upgrade`: upstream answering non-101 cannot leave a raw tunnel open, per the known WebSocket smuggling pattern.
  - `test_ws_idle_timeout`, `test_ws_half_close`.
  - `test_ws_backpressure`: slow client slows the upstream, memory bounded.
  - `test_sse_no_buffering`: each event reaches the client within 50 ms, on HTTP/1.1, HTTP/2 and HTTP/3.
- [ ] **Step 2: Run** `./dev make test-int K='websocket or sse'` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(proxy): add WebSocket tunnels and SSE streaming`

### Task 8: HTTP/2 upstream and gRPC

**Files:**
- Create: `src/proxy/client_h2.{c,h}`
- Test: `tests/integration/test_grpc.py`

**Interfaces:**
- Consumes: Phase 7 frame, HPACK and flow modules, reused in client mode.
- Produces: `protocol http1|http2` in `upstream`. `grpc_pass` detection by `Content-Type: application/grpc`. Directive `max_upstream_h2_streams`. Upstream failures translate to `grpc-status` trailers instead of an HTTP error page when the client request is gRPC.

- [ ] **Step 1: Write failing tests**
  - `test_unary`, `test_server_stream`, `test_client_stream`, `test_bidi`: real gRPC test server and client, in Python.
  - `test_trailers_forwarded`: `grpc-status` and `grpc-message` arrive.
  - `test_upstream_down_grpc`: client receives `UNAVAILABLE`, status 14.
  - `test_deadline_cancel`: client cancel → upstream `RST_STREAM`.
  - `test_multiplexing`: many client streams share few upstream connections.
  - `test_upstream_goaway`: GOAWAY drains in-flight and opens a new connection.
  - `test_upstream_settings_limit`: honours peer `MAX_CONCURRENT_STREAMS`.
  - `test_flow_control_bidirectional`: large streams, no deadlock.
- [ ] **Step 2: Run** `./dev make test-int K=grpc` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(proxy): add HTTP/2 upstream and gRPC`

### Task 9: PROXY protocol

**Files:**
- Create: `src/proxy/proxyproto.{c,h}`
- Modify: `src/http/h1/conn.c`, `src/tls/conn.c`, `src/proxy/client_h1.c`, `src/proxy/client_h2.c`
- Test: `tests/unit/test_proxyproto.c`, `fuzz/fuzz_proxyproto.c`, `tests/integration/test_proxyproto.py`

**Interfaces:**
- Produces: `bst_pp_parse(const uint8_t *, size_t, bst_pp_info *)`, `bst_pp_write_v1`, `bst_pp_write_v2`. Directives: `listen ... proxy_protocol`, `proxy_protocol_from <cidr>` (required when accepting), `proxy_protocol_timeout`, `send_proxy_protocol v1|v2` on upstreams. `bst_conn.client_addr_from_header = true`, which Phase 12 reads to stop XDP escalation.

- [ ] **Step 1: Write failing tests**
  - `v1_v2_vectors`: spec examples, TCP4, TCP6, UNKNOWN, LOCAL.
  - `malformed`: truncated, bad signature, length overflow, v1 line above 107 bytes.
  - `test_untrusted_source`: PROXY header from outside `proxy_protocol_from` → closed.
  - `test_trusted_sets_remote`: `$remote_addr` reflects the header.
  - `test_no_header_required`: listener with `proxy_protocol` closes on missing header.
  - `test_before_tls`: header precedes the ClientHello.
  - `test_send_to_upstream`: test upstream receives correct v1 and v2 headers.
- [ ] **Step 2: Run** `./dev make test-unit T=proxyproto` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** same plus `./dev make test-int K=proxyproto` → PASS.
- [ ] **Step 5: Commit** `feat(proxy): add PROXY protocol v1 and v2`

### Task 10: Disk spooling

**Files:**
- Create: `src/proxy/spool.{c,h}`
- Test: `tests/integration/test_spool.py`

**Interfaces:**
- Produces: `bst_spool *bst_spool_open(worker, limit)`, `bst_spool_write`, `bst_spool_read`, with `O_TMPFILE` in `temp_path`. Directives: `temp_path`, `spool_memory_limit`, `retry_buffered_body`. Backs `request_buffering on` and `response_buffering on`, both with memory limits before spilling to disk.

- [ ] **Step 1: Write failing tests**
  - `test_request_buffered`: upstream sees no bytes until the upload finishes.
  - `test_spill`: over the memory threshold spills to disk; content identical.
  - `test_disk_full`: `ENOSPC` → 507 or fallback, with a logged error.
  - `test_no_temp_leak`: abort mid-upload leaves no file on disk, verified by listing `temp_path`.
  - `test_retry_with_buffered_body`: a buffered POST that failed before sending can be retried when configured, and is never replayed by default.
- [ ] **Step 2: Run** `./dev make test-int K=spool` → FAIL.
- [ ] **Step 3: Implement** through `bst_aio_submit` or io_uring file ops.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(proxy): add request and response disk spooling`
