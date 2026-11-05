# Phase 8: QUIC and HTTP/3 (Milestone M3)

**Goal:** HTTP/3 over QUIC v1 and v2, using ngtcp2 and nghttp3, with worker-aware packet routing, address validation under attack, and GSO/GRO.

**Architecture:** See [architecture.md](architecture.md) section 4. Each worker owns its QUIC connections. An `sk_reuseport` BPF program routes packets to the owning worker using the slot inside the connection ID, and this also makes connection migration work.

**Spec:** RFC 9000, RFC 9001, RFC 9002, RFC 9114, RFC 9204, RFC 9220, RFC 9369.

## Review Focus

1. Flood of Initial packets with spoofed sources → Retry tokens keep per-connection state from being allocated, and amplification stays within 3×. (Tasks 3, 6)
2. Client changes IP or port mid-download (NAT rebinding, Wi-Fi to cellular) → packets still reach the same worker, the path is validated, and the transfer finishes. (Task 2)
3. Datagrams smaller than 1200 bytes in an Initial, unknown versions, and garbage UDP → dropped cheaply or Version Negotiation, with no connection state. (Task 3)
4. Thousands of idle connections → timers scale and idle timeout frees them. (Task 3)
5. MTU smaller than GSO batch, or GSO `EIO` → falls back without losing the connection. (Task 5)

---

### Task 1: OpenSSL backend and 0-RTT spike

**Files:**
- Create: `spikes/quic/spike.c`, `spikes/quic/README.md`

**Interfaces:**
- Produces: A findings record deciding the approach used in Tasks 3 and 6. Throwaway code, excluded from release builds.

- [ ] **Step 1:** Build the pinned ngtcp2 with `ngtcp2_crypto_ossl` against pinned OpenSSL, static under both glibc and musl. If that fails, record the error and stop to discuss with the user before proceeding.
- [ ] **Step 2:** Run a minimal server against `curl --http3` and ngtcp2's example client. Confirm handshake, ALPN `h3`, X25519MLKEM768 and ticket resumption.
- [ ] **Step 3:** Test whether 0-RTT works on this backend. Record the result. If unsupported, Task 6 ships without HTTP/3 0-RTT and the limit goes in `docs/conformance.md`.
- [ ] **Step 4:** Check how ticket keys from Phase 6 Task 6 can be shared with QUIC sessions, so resumption works across workers.
- [ ] **Step 5: Commit** `docs(spike): record QUIC backend findings`

### Task 2: Connection IDs and reuseport routing

**Files:**
- Create: `src/http/h3/cid.{c,h}`, `src/xdp/reuseport_quic.bpf.c`, `src/xdp/reuseport.{c,h}`
- Test: `tests/unit/test_cid.c`, `tests/unit/test_reuseport_bpf.c`, `tests/integration/test_quic_routing.py`

**Interfaces:**
- Produces: `bst_cid_generate(uint16_t slot, uint8_t *out, size_t len)`, `uint16_t bst_cid_slot(const uint8_t *, size_t)`. `bst_reuseport_attach(int *fds, int nfds, const bst_slot_map *)`, `bst_reuseport_set_active(generation_slots)`. Directive `quic_routing ebpf|hash`. Fallback when BPF is unavailable: `hash`, logged, migration then unsupported across workers.

- [ ] **Step 1: Write failing tests**
  - `cid_roundtrip`: slot survives generate and read for every slot.
  - `cid_random`: remaining bytes are from a CSPRNG and distinct over 1M.
  These `bpf_*` tests use a real UDP reuseport group on loopback and assert which socket receives each crafted datagram, because `sk_reuseport` programs can't be driven through `BPF_PROG_TEST_RUN`.
  - `bpf_short_header`: crafted packet reaches the socket for the encoded slot.
  - `bpf_initial_hash`: long-header Initial with a client-chosen DCID reaches an active slot.
  - `bpf_invalid_slot`: slot out of range or empty → active generation hash, never a drop.
  - `bpf_truncated`: 1-byte datagram is delivered safely. Separately, `make test-vm KERNEL=floor` confirms the verifier accepts the program on Linux 6.1.
  - `test_migration_same_worker`: `ngtcp2` client rebinding its port mid-transfer finishes, with a server debug counter showing one worker handled all packets.
- [ ] **Step 2: Run** `./dev make test-unit T='cid,reuseport_bpf'` → FAIL.
- [ ] **Step 3: Implement.** Build the BPF object with clang and embed it in the binary through `tools/embed.mk`, which Phase 13 reuses. `sk_reuseport` needs master privileges to attach, so master attaches before the sandbox applies.
- [ ] **Step 4: Run** same plus `./dev make test-int K=quic_routing` → PASS.
- [ ] **Step 5: Commit** `feat(quic): route packets to owning worker by connection ID`

### Task 3: QUIC endpoint

**Files:**
- Create: `src/http/h3/quic.{c,h}`, `src/http/h3/token.{c,h}`, `src/http/h3/quic_directives.c`
- Test: `tests/unit/test_quic_token.c`, `tests/integration/test_quic_endpoint.py`, `fuzz/fuzz_quic_endpoint.c`

**Interfaces:**
- Consumes: `bst_udp_*`, `bst_cid_*`, ngtcp2, TLS ctx from Phase 6.
- Produces: `bst_quic_endpoint_start(bst_worker *, bst_sock *, const bst_cfg_quic *)`. `bst_quic_conn`. Directives: `quic_max_connections`, `quic_idle_timeout`, `quic_handshake_timeout`, `quic_max_streams_bidi`, `quic_max_streams_uni`, `quic_initial_max_data`, `quic_initial_max_stream_data`, `quic_cc cubic|bbr|reno`, `quic_retry auto|always|never`, `quic_retry_threshold`, `quic_versions`, `quic_stateless_reset on`. Token and stateless reset secrets live in the `tickets` shm region.

- [ ] **Step 1: Write failing tests**
  - `token_roundtrip`: Retry token validates for the same address, and fails for other addresses, expired tokens, or tampered bytes.
  - `test_handshake`: `curl --http3` connects.
  - `test_version_negotiation`: unknown version → VN packet, with no state and no amplification.
  - `test_small_initial_dropped`: Initial under 1200 bytes → dropped.
  - `test_retry_always`: `quic_retry always` requires token echo.
  - `test_retry_auto`: exceeding `quic_retry_threshold` half-open → Retry begins, and stops when pressure ends.
  - `test_amplification_limit`: unvalidated client receives at most 3× received bytes, measured on the wire.
  - `test_idle_timeout`: connection freed after timeout, and counters return to 0.
  - `test_stateless_reset`: packet for an unknown short-header CID yields a valid reset, smaller than the trigger packet.
  - `test_max_connections`: over the limit → `CONNECTION_REFUSED`.
- [ ] **Step 2: Run** `./dev make test-unit T=quic_token && ./dev make test-int K=quic_endpoint` → FAIL.
- [ ] **Step 3: Implement.** A per-worker CID hash table holds connections. All connection timers share the Phase 1 wheel, and per-connection state is created only after address validation or within the configured unvalidated budget.
- [ ] **Step 4: Run** same → PASS, on both backends.
- [ ] **Step 5: Commit** `feat(quic): add QUIC endpoint with Retry and stateless reset`

### Task 4: HTTP/3 streams

**Files:**
- Create: `src/http/h3/h3_bridge.{c,h}`
- Test: `tests/integration/test_h3_semantics.py`

**Interfaces:**
- Consumes: nghttp3, `bst_stream_ops`, `src/http/validate_pseudo.c`.
- Produces: the h3 `bst_stream_ops`. Directives: `http3_max_field_section_size`, `http3_qpack_table_size`, `http3_qpack_blocked_streams`. File segments are read into buffers with the loop, with back-pressure tied to stream and connection credit.

- [ ] **Step 1: Write failing tests**
  - `test_static_h3`: same corpus as HTTP/2 Task 5 returns equal results for Range, conditional, HEAD and error pages.
  - `test_large_download`: 1 GiB identical, RSS bounded.
  - `test_large_upload`: 1 GiB POST through a test echo handler, identical.
  - `test_malformed_request`: pseudo-header and value rules → `H3_MESSAGE_ERROR`.
  - `test_cancel`: client STOP_SENDING → handler `on_reset` exactly once.
  - `test_trailers`: both directions.
  - `test_goaway`: graceful stop sends GOAWAY and in-flight streams finish.
  - `test_multiplex`: 100 concurrent streams with `h2load --alpn-list=h3`.
- [ ] **Step 2: Run** `./dev make test-int K=h3_semantics` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(h3): connect HTTP/3 to HTTP semantics`

### Task 5: UDP send path

**Files:**
- Modify: `src/http/h3/quic.c`
- Create: `src/http/h3/txq.{c,h}`
- Test: `tests/integration/test_quic_udp.py`, `tests/vm/test_quic_udp_vm.py`

**Interfaces:**
- Consumes: `bst_udp_send`.
- Produces: Per-connection send batching with GSO, ECN reporting to ngtcp2, and pacing using ngtcp2's `tx_time`. Directives: `quic_gso`, `quic_gro`, `quic_ecn`, `quic_pacing`, `quic_mtu_discovery`, `quic_max_udp_payload`.

- [ ] **Step 1: Write failing tests**
  - `test_gso_counter`: bulk transfer shows packets-per-send above 1.
  - `test_gso_eio`: injected `EIO` → retried without GSO, and the connection survives.
  - `test_ecn_echo`: ECN-capable peer gets ECT marks, and counters reach ngtcp2.
  - `test_loss_recovery`: `tc netem loss 5%` in a netns (VM tier if netem is absent) → transfer completes.
  - `test_reorder`: 25% reorder → completes.
  - `test_low_mtu`: 1280 MTU path → PMTUD stays at or below the path.
- [ ] **Step 2: Run** `./dev make test-int K=quic_udp && ./dev make test-vm K=quic_udp` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(quic): add batched sending, ECN and pacing`

### Task 6: Alt-Svc, 0-RTT and conformance gate

**Files:**
- Create: `src/http/h3/altsvc.c`, `tests/conformance/test_h3spec.py`, `tests/conformance/test_quic_interop.py`
- Modify: `src/http/h3/quic.c`, `docs/conformance.md`
- Test: `tests/integration/test_h3_extras.py`

**Interfaces:**
- Consumes: Phase 6 `early` policy.
- Produces: Automatic `Alt-Svc: h3=":port"; ma=86400` on TCP responses for servers with `listen ... http3`. Directive `alt_svc auto|off|<value>`. 0-RTT follows `early_data` directives, if the Task 1 spike allows. H3 guards use the shared `bst_h2_guard` kinds extended with `stream_reset`, `qpack`, `control_stream`.

- [ ] **Step 1: Write failing tests**
  - `test_alt_svc`: TCP response advertises h3; `curl --http3` reached via a discovered Alt-Svc.
  - `test_h3_early_get` and `test_h3_early_post_425`: same assertions as TCP, only if the spike supports 0-RTT.
  - `test_h3_rapid_reset`: stream open-and-cancel flood → closed with `H3_EXCESSIVE_LOAD`.
  - `test_h3_critical_stream_close`: closing the control stream → connection error per RFC 9114.
  - `test_h3spec`: pinned `h3spec` → 0 failures against QUIC and HTTP/3 suites.
  - `test_quic_interop`: scenarios handshake, transfer, retry, resumption, multiplexing, against at least 2 other client implementations using pinned quic-interop-runner images (manual marker, as it needs nested Docker).
- [ ] **Step 2: Run** `./dev make conformance K=h3` → FAIL.
- [ ] **Step 3: Implement** and fix failures, with any unfixed item recorded in `docs/conformance.md`.
- [ ] **Step 4: Run** `./dev make test-unit test-int test-vm conformance fuzz-smoke` → PASS.
- [ ] **Step 5: Commit** `feat(h3): add Alt-Svc and abuse guards, enforce h3spec`
