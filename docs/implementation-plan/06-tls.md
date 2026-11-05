# Phase 6: TLS and kTLS

**Goal:** Hardened TLS 1.2 and 1.3 with kTLS, SNI, session resumption, OCSP stapling, client certificates, JA4 fingerprints and optional 0-RTT.

**Architecture:** See [architecture.md](architecture.md) section 6. Public OpenSSL API only, using the socket BIO. kTLS tests run in the VM tier, because Docker Desktop's kernel is built without `CONFIG_TLS`.

**Spec:** [architecture.md](architecture.md), RFC 8446, RFC 8470, RFC 6066.

## Review Focus

1. Client that opens TCP and never finishes the handshake, or stalls mid-handshake → closed at `handshake_timeout`, no CPU spin. (Task 3)
2. kTLS requested but unavailable, cipher unsupported, or module not loaded → user-space TLS with a once-per-startup warning, unless `require`. (Task 4)
3. Client sending TLS 1.3 KeyUpdate while kTLS is active → defined behaviour measured in Task 1, never a hang or plaintext leak. (Task 4)
4. Host header or `:authority` not matching SNI → 421 and never another site's content. (Task 5)
5. Replayed 0-RTT POST, or GET with a body → `425 Too Early`, without reaching the handler. (Task 10)

---

### Task 1: kTLS behaviour spike

**Files:**
- Create: `spikes/ktls/spike.c`, `spikes/ktls/README.md`

**Interfaces:**
- Produces: A written findings record in `spikes/ktls/README.md`, which decides the defaults used by Task 4. Throwaway code, excluded from the release build.

- [ ] **Step 1:** In the VM tier, write a small non-blocking OpenSSL server using `SSL_OP_ENABLE_KTLS` with a socket BIO. Record whether kTLS TX and RX activate for TLS 1.2 and TLS 1.3, for AES-128-GCM, AES-256-GCM and CHACHA20-POLY1305.
- [ ] **Step 2:** Record the actual behaviour under: client KeyUpdate with kTLS RX on, client KeyUpdate with `update_requested` while kTLS TX is on, NewSessionTicket sending, TLS alerts, and `SSL_sendfile` compared with `sendfile(2)` directly.
- [ ] **Step 3:** Measure small-response and large-file throughput with TLS user-space, kTLS TX, and kTLS TX+RX on the VM. Note that these numbers show only relative trends.
- [ ] **Step 4:** Record decisions: default modes, KeyUpdate handling, and whether RX can be recommended. Update architecture.md section 6 if results contradict it.
- [ ] **Step 5: Commit** `docs(spike): record kTLS behaviour findings`

### Task 2: Context builder and hardened defaults

**Files:**
- Create: `src/tls/ctx.{c,h}`, `src/tls/tls_directives.c`
- Test: `tests/unit/test_tls_ctx.c`, `tests/fixtures/certs/gen.sh`

**Interfaces:**
- Produces: `SSL_CTX *bst_tls_ctx_build(const bst_cfg_tls *, bst_err *)`. `tls_profile` directives: `versions`, `groups`, `ciphers_tls12`, `ciphersuites_tls13`, `sigalgs`, `prefer_server_ciphers`, `dh_none`, `renegotiation` (always off), `handshake_timeout`. Server directives: `tls_cert <crt> <key>` (repeatable for RSA plus ECDSA), `tls_profile`.

- [ ] **Step 1: Write failing tests**
  - `defaults`: TLS 1.2 minimum; 1.0 and 1.1 rejected; only ECDHE-AEAD on 1.2.
  - `group_order`: X25519MLKEM768 first.
  - `compression_off`, `renegotiation_off`.
  - `key_mismatch`: mismatched cert and key → load error naming both files.
  - `expired_cert_warns`: expired certificate warns during `-t`.
  - `unreadable_key`: load error, and the error text doesn't include key contents.
  - `dual_cert`: RSA and ECDSA certs both served by client preference.
- [ ] **Step 2: Run** `./dev make test-unit T=tls_ctx` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(tls): add context builder with hardened defaults`

### Task 3: TLS connections

**Files:**
- Create: `src/tls/conn.{c,h}`
- Modify: `src/http/h1/conn.c`, `src/io/listener.c`
- Test: `tests/integration/test_tls_conn.py`

**Interfaces:**
- Produces: `bst_tls_conn *bst_tls_accept(bst_worker *, bst_sock *, SSL_CTX *, bst_tls_ready_cb, void *ud)`, `bst_transport *bst_tls_transport(bst_tls_conn *)`, `bst_tls_write_chain` (behind the transport's `send`), `bst_tls_alpn`, `$ssl_protocol`, `$ssl_cipher`, `$ssl_session_reused` variables. Protocol dispatch from ALPN: `http/1.1` → h1, `h2` → Phase 7. Readiness through `bst_io_poll` on both backends. `listen ... tls`. Directive `http_on_tls_port close|respond`.

- [ ] **Step 1: Write failing tests**
  - `test_tls_get`: curl GET over TLS 1.2 and 1.3.
  - `test_large_download_and_upload`: 1 GiB both directions, byte-identical, in user-space TLS.
  - `test_handshake_timeout`: stalled handshake closed at the deadline.
  - `test_garbage_clienthello`: random bytes → closed with no crash.
  - `test_http_on_https_port`: plaintext HTTP → close, or optional `400` page with `http_on_tls_port respond`.
  - `test_close_notify`: clean shutdown; a truncated client doesn't get reported as success.
  - `test_slow_client_no_spin`: slow reader keeps CPU idle during WANT_WRITE.
  - `test_sandbox_holds`: TLS works with the seccomp filter active.
- [ ] **Step 2: Run** `./dev make test-int K=tls_conn` → FAIL.
- [ ] **Step 3: Implement.** Limit per-connection OpenSSL memory with `SSL_MODE_RELEASE_BUFFERS`, and clear the OpenSSL error queue on each call. SSL objects are freed only after pending callbacks are cancelled.
- [ ] **Step 4: Run** same → PASS on both backends.
- [ ] **Step 5: Commit** `feat(tls): add non-blocking TLS connections`

### Task 4: kTLS data path

**Files:**
- Create: `src/tls/ktls.{c,h}`
- Modify: `src/tls/conn.c`
- Test: `tests/vm/test_ktls.py`, `tests/integration/test_ktls_fallback.py`

**Interfaces:**
- Produces: `bool bst_tls_ktls_tx_active(const bst_tls_conn *)`. Directive `ktls off|tx|tx+rx [require]`. Metrics `bastion_tls_ktls_connections{mode}`. With TX active, `bst_tls_write_chain` calls `bst_io_send`, so files go through `sendfile`/splice.

- [ ] **Step 1: Write failing tests**
  - VM tier `test_ktls_tx_active`: `ss -tie` or the metric shows active TX for each supported cipher.
  - VM tier `test_ktls_download_identical`: 1 GiB file via kTLS and sendfile → byte-identical.
  - VM tier `test_ktls_rx_upload`: `ktls tx+rx`, upload identical (only if Task 1 supports it).
  - VM tier `test_key_update`: client KeyUpdate → the behaviour selected in Task 1, asserting no plaintext on the wire with a packet capture check.
  - VM tier `test_alert_close`: close_notify from the client recognized when RX is in the kernel.
  - `test_ktls_fallback_warns`: under LinuxKit or `ktls` forced with an unsupported cipher → works in user space with one warning.
  - `test_ktls_require_fails`: `ktls tx require` where unavailable → startup error.
- [ ] **Step 2: Run** `./dev make test-vm K=ktls && ./dev make test-int K=ktls_fallback` → FAIL.
- [ ] **Step 3: Implement** using Task 1's findings. `setsockopt(SOL_TCP, TCP_ULP)` must happen before the sandbox forbids anything needed, so the required calls join the allowlist with a justification.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(tls): add kTLS TX and RX data paths`

### Task 5: SNI

**Files:**
- Create: `src/tls/sni.{c,h}`
- Test: `tests/integration/test_sni.py`

**Interfaces:**
- Consumes: `bst_vhost_select` logic.
- Produces: `SSL_CTX_set_client_hello_cb`-based selection. Directives: `tls_default_cert`, `sni_required on|off`, `sni_mismatch default|reject`, and `host_sni_mismatch 421|allow`.

- [ ] **Step 1: Write failing tests**
  - `test_sni_selects_cert`: per-name certificates; wildcard names; per-server `tls_profile`.
  - `test_no_sni_default`: no SNI → default cert, or handshake failure with `sni_required on`.
  - `test_unknown_sni_reject`: `unrecognized_name` alert.
  - `test_host_sni_mismatch`: SNI `a` with Host `b` → 421 by default on a client-cert-protected server and on `host_sni_mismatch 421`.
  - `test_sni_case_trailing_dot`: normalized.
  - `test_oversized_sni`: oversized or invalid hostname → rejected.
- [ ] **Step 2: Run** `./dev make test-int K=sni` → FAIL.
- [ ] **Step 3: Implement.** `client_hello_cb` also feeds Task 9.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(tls): add SNI selection and host mismatch policy`

### Task 6: Ticket keys

**Files:**
- Create: `src/tls/tickets.{c,h}`
- Test: `tests/unit/test_tickets.c`, `tests/integration/test_tickets.py`

**Interfaces:**
- Produces: `bst_tickets_init(shm)`, `bst_tickets_rotate(shm)` (called by helper), and an `SSL_CTX_set_tlsext_ticket_key_evp_cb` callback. Directive `tickets off | rotate=<dur> keep=<n> [file=<path>]`. Key material lives only in the `tickets` shm region, using a seqlock for reads.

- [ ] **Step 1: Write failing tests**
  - `test_resume_across_workers`: a session from one worker resumes on another.
  - `test_resume_after_rotation`: old ticket works within `keep`, full handshake after it ages out.
  - `test_keys_not_dumpable`: mapping marked `MADV_DONTDUMP`, verified via `/proc/<pid>/smaps` `dd` flag.
  - `test_ticket_file_cluster`: two instances sharing a key file resume each other's tickets.
  - `seqlock_consistency` unit test: concurrent reader during rotation never sees a torn key.
- [ ] **Step 2: Run** `./dev make test-int K=tickets` → FAIL.
- [ ] **Step 3: Implement** per-RFC 5077 key name, AES-256-GCM or CBC-HMAC as OpenSSL's callback supports.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(tls): add shared ticket keys with rotation`

### Task 7: OCSP stapling

**Files:**
- Create: `src/tls/ocsp.{c,h}`
- Test: `tests/integration/test_ocsp.py`

**Interfaces:**
- Produces: helper job `bst_ocsp_refresh`, a staple in shm, and a status callback in workers. Directives: `ocsp_stapling on|off`, `ocsp_responder_override`, `ocsp_file`.

- [ ] **Step 1: Write failing tests** with an `openssl ocsp` responder in the test
  - `test_staple_served`: `openssl s_client -status` shows `good`.
  - `test_no_ocsp_url`: a certificate without an OCSP URL, as current Let's Encrypt certificates have → no fetch attempts, no warning loop, handshake fine.
  - `test_invalid_response_rejected`: a bad signature or wrong serial → not stapled.
  - `test_responder_down`: old staple retained until expiry, then omitted.
- [ ] **Step 2: Run** `./dev make test-int K=ocsp` → FAIL.
- [ ] **Step 3: Implement.** Fetches run in helper with `OCSP_basic_verify` validation, never on workers.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(tls): add OCSP stapling`

### Task 8: Client certificates

**Files:**
- Modify: `src/tls/ctx.c`, `src/tls/conn.c`
- Test: `tests/integration/test_mtls.py`

**Interfaces:**
- Produces: Directives `tls_client_auth off|optional|required`, `tls_client_ca`, `tls_client_crl`, `tls_client_verify_depth`. Variables `$ssl_client_verify`, `$ssl_client_s_dn`, `$ssl_client_san_dns`, `$ssl_client_fingerprint`. The location-level `auth_mtls` directive enforces it.

- [ ] **Step 1: Write failing tests**
  - `test_required_no_cert`: handshake rejected.
  - `test_optional_location_required`: no cert accepted at the TLS layer, `auth_mtls` location → 403.
  - `test_wrong_ca`, `test_revoked_crl`, `test_expired_client_cert` → rejected.
  - `test_session_resumption_keeps_identity`: resumed sessions retain client identity, and tickets from a non-mTLS server are not valid on an mTLS server, using separate session ID contexts.
  - `test_cross_vhost_cert_bypass`: connect with SNI of a non-mTLS server, then Host of an mTLS server → 421.
- [ ] **Step 2: Run** `./dev make test-int K=mtls` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(tls): add client certificate authentication`

### Task 9: JA4

**Files:**
- Create: `src/tls/ja4.{c,h}`
- Test: `tests/unit/test_ja4.c`, `fuzz/fuzz_ja4.c`, `tests/fixtures/ja4_vectors.json`

**Interfaces:**
- Produces: `int bst_ja4_compute(const bst_client_hello *, char transport, char out[40])` where transport is `t` or `q`. A pure function called only from the ClientHello callback, and only when config uses it, so cost is nil otherwise. Variable `$ja4`. Rules consume it in Phase 12.

- [ ] **Step 1: Write failing tests**
  - `vectors`: published JA4 examples from captures produce the published fingerprints. At Task start, take vectors from the FoxIO JA4 repository and record their source commit.
  - `grease_ignored`: GREASE values never affect the output.
  - `sorted_lists`: ciphers and extensions are sorted before hashing; SNI and ALPN excluded from the extension hash per spec.
  - `no_alpn`, `no_sni`, `empty_ciphers`, `non_ascii_alpn` encoding.
  - Integration `test_ja4_var`: `$ja4` logged for curl matches a value computed from a captured ClientHello.
- [ ] **Step 2: Run** `./dev make test-unit T=ja4` → FAIL.
- [ ] **Step 3: Implement** only the JA4 TLS client fingerprint, which is the BSD-licensed part. Check the license text at Task start and record it in `docs/third-party.md`. Do not implement the separately licensed JA4+ methods.
- [ ] **Step 4: Run** same → PASS, fuzz 60 seconds → no crash.
- [ ] **Step 5: Commit** `feat(tls): add JA4 client fingerprints`

### Task 10: 0-RTT over TCP

**Files:**
- Create: `src/tls/early.{c,h}`
- Test: `tests/integration/test_early_data.py`

**Interfaces:**
- Produces: Directive `early_data on|off` (default off), `early_data_methods` (default `GET HEAD`), `early_data_max_size`. Anti-replay through a shm table of ticket hash fingerprints with a time window, so the policy applies across workers. Request flag `bst_req.early_data`. `Early-Data: 1` to upstream in Phase 9. `425 Too Early` via `bst_send_error`.

- [ ] **Step 1: Write failing tests**
  - `test_off_by_default`: `max_early_data=0` advertised.
  - `test_early_get`: resumed GET in 0-RTT succeeds, and the handler sees the flag.
  - `test_early_post_425`: POST in 0-RTT → 425, and a retry post-handshake succeeds.
  - `test_replay_rejected`: captured 0-RTT flight replayed → rejected or treated as a full handshake, on any worker.
  - `test_early_never_for_mtls`: never accepted on mTLS servers.
  - `test_fastopen_policy`: with TFO enabled, a request delivered in SYN data follows the same safe-method handling documented on `fastopen`.
- [ ] **Step 2: Run** `./dev make test-int K=early_data` → FAIL.
- [ ] **Step 3: Implement** using OpenSSL's `SSL_read_early_data` flow and `SSL_CTX_set_allow_early_data_cb`.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(tls): add restricted 0-RTT with anti-replay`

### Task 11: TLS scan gate

**Files:**
- Create: `tests/conformance/test_testssl.py`
- Modify: `Makefile`, `docs/conformance.md`

**Interfaces:**
- Produces: `make conformance K=tls` runs testssl.sh against the default config, and fails on any finding at `HIGH` or `CRITICAL` or on any protocol or cipher outside the allowed list.

- [ ] **Step 1: Write the test** that parses testssl.sh JSON output, with the pinned tool version from `deps/versions.env`.
- [ ] **Step 2: Run** `./dev make conformance K=tls` → fix any findings.
- [ ] **Step 3: Benchmark** kTLS modes in the VM to update `docs/tuning.md`, and record the comparison with Task 1.
- [ ] **Step 4: Run** the whole `./dev make test-unit test-int test-vm conformance fuzz-smoke` → PASS.
- [ ] **Step 5: Commit** `test(tls): add testssl.sh conformance gate`
