# Phase 14: Operations (Milestone M6)

**Goal:** Reload and upgrade with no failed requests, logs, metrics, tracing, admin API, automatic certificates, hardware tuning and packages.

**Architecture:** See [architecture.md](architecture.md) sections 1 and 4. Workers never block on logging or metrics. Admin functionality runs in the helper and reaches master via typed messages.

**Spec:** [architecture.md](architecture.md), [config-language.md](config-language.md), RFC 8555, RFC 8737, W3C Trace Context.

## Review Focus

1. Bad config during reload, or bad new binary during upgrade → old version keeps serving, the error is visible, and rollback works. (Tasks 1, 2)
2. Disk full, log directory deleted, or logrotate moving files → logging drops are counted, serving continues, and `USR1` reopens. (Task 3)
3. Log injection through paths, headers, or user agents → valid JSON on one line. (Task 3)
4. ACME failures: rate limits, DNS not pointing here yet, or a CA outage → site still serves through a temporary cert, retries back off, and an existing cert stays in use until expiry. (Task 7)
5. Admin socket access from an unauthorized local user → denied by permissions, and the admin API has no network listener unless explicitly configured. (Task 6)

---

### Task 1: Hot reload

**Files:**
- Create: `src/proc/reload.{c,h}`
- Modify: `src/proc/master.c`, `src/proc/worker.c`
- Test: `tests/integration/test_reload.py`

**Interfaces:**
- Produces: `SIGHUP` on master and `bst_master_reload(bst_master *)`. Sequence: parse and compile → reconcile listeners, keeping existing fds → update XDP → fork new generation → health ready signal → old generation stops accepting and drains under `shutdown_timeout`. Reports result through log, the admin API, and `sd_notify`.

- [ ] **Step 1: Write failing tests**, each with an HTTP/1.1, HTTP/2 and HTTP/3 load generator running throughout and asserting **0 failed requests**:
  - `test_reload_under_load`: 20 consecutive reloads with no failure.
  - `test_invalid_config_keeps_running`: error logged, old workers unchanged, status reports failure.
  - `test_add_remove_listener`: new port works, removed port closes, unchanged port never stops accepting.
  - `test_long_download_survives`: a transfer spanning the reload finishes on the old generation.
  - `test_websocket_drain`: tunnels last until `tunnel_drain_timeout`.
  - `test_quic_across_reload`: existing QUIC connection continues, new connection reaches new generation, via slot routing.
  - `test_h2_goaway_on_drain`: old generation sends graceful GOAWAY.
  - `test_shm_state_kept`: rate limit counters, ticket keys, cache index and blocks persist.
  - `test_rapid_reloads`: 5 reloads within a second coalesce, and generations don't pile up without limit.
  - `test_cert_change`: new certificate served for new connections.
  - `test_cache_size_change`: incompatible shm size change handled with a documented reset.
- [ ] **Step 2: Run** `./dev make test-int K=reload` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** same → PASS on both backends.
- [ ] **Step 5: Commit** `feat(proc): add zero-downtime config reload`

### Task 2: Live binary upgrade

**Files:**
- Create: `src/proc/upgrade.{c,h}`
- Test: `tests/integration/test_upgrade.py`

**Interfaces:**
- Produces: `SIGUSR2` on master → `execve` of the on-disk binary, passing listener, shm, and pinned-BPF references in `BASTION_INHERIT`. `WINCH` drains old workers, `QUIT` finishes, `HUP` rolls back. A state blob version check handles format mismatch by refusing and keeping the old process.

- [ ] **Step 1: Write failing tests**, with the same load generators and **0 failed requests**:
  - `test_upgrade_happy`: new binary takes over, the old master exits, and the new PID file is correct.
  - `test_upgrade_rollback`: `HUP` before `QUIT` restores old workers; new master exits.
  - `test_bad_binary`: new binary that crashes at start or fails config → old process keeps serving, with an error reported.
  - `test_state_version_mismatch`: incompatible state → refused safely.
  - `test_xdp_continuity`: the XDP program remains attached and block map entries survive.
  - `test_quic_across_upgrade`: QUIC connections survive.
  - `test_tickets_across_upgrade`: TLS resumption works after upgrade.
  - `test_systemd_mainpid`: `sd_notify` announces the new `MAINPID`.
- [ ] **Step 2: Run** `./dev make test-int K=upgrade` → FAIL.
- [ ] **Step 3: Implement.** `bastionctl upgrade` wraps the signal sequence and watches health, rolling back automatically on failure.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(proc): add live binary upgrade with rollback`

### Task 3: Logging pipeline

**Files:**
- Create: `src/ops/logger.{c,h}`, `src/ops/log_format.{c,h}`
- Test: `tests/unit/test_log_format.c`, `tests/integration/test_access_log.py`

**Interfaces:**
- Consumes: SPSC rings, `bst_tpl`, `bst_jw_*`.
- Produces: `bst_access_log(bst_stream *)`. Directives: `log_format <name> json {…}|text "<template>"`, `access_log <path|off|stdout> <format> sample= errors_only= if=`, `log_buffer`, `log_flush_interval`, `log_redact_query_params`, `log_redact_headers`. `USR1` reopens files. Metric `bastion_log_dropped_total`.

- [ ] **Step 1: Write failing tests**
  - `json_escaping`: control bytes, quotes and invalid UTF-8 produce valid JSON.
  - `text_escaping`: CR and LF can't split a line.
  - `test_every_protocol`: fields correct for HTTP/1.1, HTTP/2 and HTTP/3.
  - `test_sampling`: `sample=0.1` near 10%, with `errors_only` always logged.
  - `test_ring_overflow`: stalled writer → drops counted, serving latency unaffected.
  - `test_logrotate`: rename and `USR1` → new file.
  - `test_disk_full`: `/dev/full` as target → counted drops and no crash.
  - `test_secrets_redacted`: `Authorization`, `Cookie`, and listed query params never logged by default.
  - `test_reload_flush`: no lines lost during reload.
- [ ] **Step 2: Run** `./dev make test-unit T=log_format && ./dev make test-int K=access_log` → FAIL.
- [ ] **Step 3: Implement.** Workers format into the ring. Helper writes files, batching with `writev`.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(ops): add non-blocking structured access logs`

### Task 4: Prometheus metrics

**Files:**
- Create: `src/ops/metrics.{c,h}`
- Modify: `src/core/counters.c`
- Test: `tests/integration/test_metrics.py`

**Interfaces:**
- Produces: `bst_counter_*` now in `metrics` shm. Directive block `metrics { listen; path; allow; auth_basic; per_location; }`. Series: requests by server, status class, protocol; latency histograms; connections; TLS handshakes and kTLS mode; upstream state and latency; cache hits by tier; limit and WAF actions; XDP drops by reason; `bastion_build_info`; `bastion_config_reload_success`; worker restarts.

- [ ] **Step 1: Write failing tests**
  - `test_format_valid`: output passes `promtool check metrics`.
  - `test_counts_accurate`: 10,000 requests are counted exactly across workers.
  - `test_survives_worker_crash`: totals never decrease after a crash, as dead worker counters are kept.
  - `test_cardinality_bounded`: arbitrary paths or Hosts cannot create new series; unknown Hosts go to `_other`.
  - `test_default_not_public`: metrics are only exposed where configured, and `listen` on a public address warns in `-t`.
  - `test_scrape_low_cost`: scrape during load doesn't affect worker latency.
- [ ] **Step 2: Run** `./dev make test-int K=metrics` → FAIL.
- [ ] **Step 3: Implement** with scrape in the helper, aggregated from cache-line-aligned per-worker slots.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(ops): add Prometheus metrics`

### Task 5: Trace context

**Files:**
- Create: `src/filters/trace.{c,h}`
- Test: `tests/unit/test_traceparent.c`, `tests/integration/test_trace.py`

**Interfaces:**
- Produces: Directives `trace_context on|off`, `trace_trust <cidr>`. Variables `$trace_id`, `$span_id`. Parses, validates and propagates `traceparent` and `tracestate`. No span exporter.

- [ ] **Step 1: Write failing tests**
  - `parse_valid_invalid`: W3C test cases; all-zero IDs, bad version, wrong lengths → regenerated.
  - `test_propagates`: upstream gets the same trace ID and a new parent ID.
  - `test_generates`: none present → new valid IDs.
  - `test_untrusted_regenerates`: outside `trace_trust` → replaced by default.
  - `test_in_logs`: `$trace_id` matches the upstream's.
- [ ] **Step 2: Run** `./dev make test-unit T=traceparent` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** same plus `./dev make test-int K=test_trace` → PASS.
- [ ] **Step 5: Commit** `feat(ops): add W3C trace context propagation`

### Task 6: Admin API and bastionctl

**Files:**
- Create: `src/ops/admin.{c,h}`, `tools/bastionctl.c`, `docs/admin-api.md`
- Test: `tests/integration/test_admin.py`

**Interfaces:**
- Consumes: Parsers from Phase 4, `bst_json`, purge, `bst_block_*`, upstream state.
- Produces: Directive `admin { socket <path> mode= group=; }`. Endpoints over a Unix socket: `GET /status`, `GET /config`, `POST /reload`, `POST /upgrade`, `GET|POST /upstreams[/name/peer/drain|enable]`, `POST /cache/purge`, `GET|POST|DELETE /blocks`, `POST /maintenance`, `POST /challenge`. `bastionctl status|reload|upgrade|upstream|purge|block|unblock|maintenance|challenge`, with `--json`, built into the same binary, chosen by `argv[0]`.

- [ ] **Step 1: Write failing tests**
  - `test_no_network_listener`: no TCP port opens for admin.
  - `test_socket_permissions`: file mode is 0600, and another unprivileged user is denied.
  - `test_peer_cred`: `SO_PEERCRED` logged for each write action.
  - `test_drain_upstream`: no new requests to the peer, and in-flight requests finish.
  - `test_purge_cli`: `bastionctl purge --tag x` works end to end.
  - `test_block_unblock`: updates XDP and user-space state.
  - `test_block_allowlisted_refused`: refused with a clear error.
  - `test_reload_error_reported`: bad config returns 400 with the parse error.
  - `test_runtime_vs_reload`: runtime changes are documented as non-persistent, and reset by reload, tested for `drain`.
  - `test_malformed_requests`: fuzz-style bad JSON → 400 and the helper survives.
  - `test_helper_down`: bastionctl gives a clear error.
- [ ] **Step 2: Run** `./dev make test-int K=admin` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(ops): add local admin API and bastionctl`

### Task 7: ACME

**Files:**
- Create: `src/ops/acme.{c,h}`, `src/ops/acme_http01.c`, `src/ops/acme_alpn.c`, `src/ops/acme_dns.c`, `src/ops/http_client.{c,h}`
- Test: `tests/integration/test_acme.py`, with pinned Pebble and `challtestsrv` containers

**Interfaces:**
- Consumes: `bst_json`, OpenSSL, reload.
- Produces: Directives: `acme { email; ca letsencrypt|zerossl|<url>; staging; storage; challenge http-01|tls-alpn-01|dns-01; dns_hook; key_type ecdsa-p256|rsa-2048; renew_before; ari on|off; eab_kid; eab_hmac; }`, `tls auto` in `server`. HTTP-01 tokens are placed in a shm table, read by workers at `/.well-known/acme-challenge/`. TLS-ALPN-01 serves `acme-tls/1` by SNI with a certificate from shm. DNS-01 hooks run from master with a fixed environment and arguments, not through a shell. Compile step adds `tls auto` implied listeners.

- [ ] **Step 1: Write failing tests** with Pebble
  - `test_http01_issue`: fresh server obtains a certificate and serves it after automatic reload.
  - `test_alpn_issue`, `test_dns_hook_issue`.
  - `test_temp_cert_before_issue`: a temporary self-signed certificate serves immediately, and the port stays functional.
  - `test_renewal`: near-expiry cert renews with no failed requests.
  - `test_ca_down_keeps_cert`: old certificate continues with exponential backoff.
  - `test_order_failure_backoff`: invalid challenge → backoff, no tight retry, rate limits respected via `Retry-After`.
  - `test_multi_domain`: several names per `server`, and separate servers don't block each other.
  - `test_storage_permissions`: account and private keys have mode 0600, owned by the expected user.
  - `test_restart_reuses`: restart doesn't reissue.
  - `test_simple_config`: the 4-line config in `config-language.md` runs a working HTTPS site against Pebble.
  - `test_token_path_traversal`: challenge endpoint serves only known tokens.
  - `test_ca_response_malformed`: bad JSON or oversized responses → handled.
- [ ] **Step 2: Run** `./dev make test-int K=acme` → FAIL.
- [ ] **Step 3: Implement** in the helper. The helper needs outbound network and write access to `storage`, so its seccomp and Landlock profile differs from workers'.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(ops): add ACME certificate automation`

### Task 8: Hardware tuning and doctor

**Files:**
- Create: `src/ops/numa.{c,h}`, `src/ops/doctor.{c,h}`, `src/io/steering.{c,h}`, `docs/tuning.md`
- Test: `tests/integration/test_tuning.py`, `tests/vm/test_tuning_vm.py`

**Interfaces:**
- Produces: Directives: `worker_cpu_affinity auto|<list>`, `numa auto|off`, `huge_pages auto|on|off`, `steering none|incoming_cpu|ebpf`, `uring_napi`, `epoll_busy_poll`. `bastion doctor [-c file]` prints a table of kernel version, features present, sysctls and limits with recommended values, and exits non-zero if a `require` directive would fail. It only reads and never changes system settings.

- [ ] **Step 1: Write failing tests**
  - `test_cpu_pinned`: `Cpus_allowed_list` matches per worker.
  - `test_affinity_respects_cpuset`: in a container with limited CPUs, `workers auto` and pinning use the allowed CPUs.
  - `test_incoming_cpu`: option reads back.
  - `test_ebpf_steering`: a program is attached, and connections reach the expected worker in a simulated test.
  - `test_huge_pages_fallback`: not available → normal pages, logged.
  - `test_numa_single_node`: harmless on a single node.
  - `test_doctor_output`: reports `io_uring`, kTLS, BPF, BBR, `busy_poll`, `tcp_syncookies`, `somaxconn`, and fd limits; reported status matches reality in Docker.
  - `test_doctor_no_changes`: a sysctl snapshot is unchanged afterwards.
  - VM tier `test_busy_poll_mode`: enabling `SO_BUSY_POLL` and `uring_napi` still serves correctly.
- [ ] **Step 2: Run** `./dev make test-int K=tuning` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** same plus `./dev make test-vm K=tuning` → PASS.
- [ ] **Step 5: Commit** `feat(ops): add CPU, NUMA and steering tuning with bastion doctor`

### Task 9: systemd

**Files:**
- Create: `src/proc/systemd.{c,h}`, `packaging/bastion.service`, `packaging/bastion.socket.example`
- Test: `tests/vm/test_systemd.py`, `tests/unit/test_sd_notify.c`

**Interfaces:**
- Produces: `bst_sd_notify(const char *state)`, implemented directly on `$NOTIFY_SOCKET` with no libsystemd. `bst_sd_listen_fds`, used by the listener step. Watchdog support through `WATCHDOG_USEC`. Unit: `Type=notify`, `NotifyAccess=main`, `ExecReload`, restricted capability set covering only what master needs, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `RestrictAddressFamilies`, `LimitNOFILE`, and `RuntimeDirectory`, `StateDirectory`, `CacheDirectory`, `LogsDirectory`.

- [ ] **Step 1: Write failing tests**
  - `test_notify_ready`: `systemctl start` returns once serving.
  - `test_reload_status`: `systemctl reload` reports `RELOADING` then `READY`.
  - `test_socket_activation`: fds from a `.socket` unit are used.
  - `test_upgrade_mainpid`: stays active across upgrade.
  - `test_watchdog`: hung master is restarted by systemd.
  - `test_unit_security_score`: `systemd-analyze security bastion` scores at or under 3.0, or the gap is documented.
  - `test_xdp_with_unit`: BPF and listeners on low ports work under the restricted capability set.
- [ ] **Step 2: Run** `./dev make test-vm K=systemd` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(ops): add systemd integration and hardened unit`

### Task 10: Packaging

**Files:**
- Create: `packaging/nfpm.yaml`, `packaging/postinstall.sh`, `packaging/bastion.conf.default`, `packaging/logrotate`, `scripts/build-release.sh`, `.github/workflows/ci.yml`, `.github/workflows/release.yml`
- Modify: `docker/release.Dockerfile`
- Test: `tests/packaging/test_packages.py`

**Interfaces:**
- Produces: `make test-packaging`. `scripts/build-release.sh <version> <arch>` → `dist/bastion-<v>-linux-<arch>` static binary, `.deb`, `.rpm`, `SHA256SUMS`, SBOM, plus a scratch image. `bastionctl` symlink. CI runs unit, integration, conformance and fuzz-smoke on x86_64 and arm64 runners, and VM tests on runners with KVM.

- [ ] **Step 1: Write failing tests**
  - `test_static`: `ldd` says not dynamic; runs in a `scratch` container.
  - `test_deb_install_debian_ubuntu`, `test_rpm_install_rhel`: install, start, serve the default page, remove cleanly in fresh containers.
  - `test_config_preserved`: upgrade of a package keeps the user's config.
  - `test_docker_scratch`: `docker run -v ... bastion serve /www` works without a shell, and as non-root with `CAP_NET_BIND_SERVICE` only.
  - `test_version_stamp`: `--version` includes git revision and dep versions.
  - `test_arm64_x86_64`: both builds pass a smoke test, using QEMU user mode for the foreign architecture.
- [ ] **Step 2: Run** `./dev make test-packaging` → FAIL.
- [ ] **Step 3: Implement** with hardening flags `-fstack-protector-strong -D_FORTIFY_SOURCE=3 -fPIE -static-pie -Wl,-z,relro,-z,now -fstack-clash-protection -fcf-protection` (x86_64) or `-mbranch-protection=standard` (arm64).
- [ ] **Step 4: Run** same → PASS. Verify PIE and RELRO in the test.
- [ ] **Step 5: Commit** `build: add release packaging and CI`
