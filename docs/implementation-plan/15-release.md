# Phase 15: Release Hardening (Milestone M7)

**Goal:** Prove the whole system against the original request: extremely performant, resilient, secure and HTTP compliant, with documentation that makes simple setups fast.

**Architecture:** No new features. Each task is a gate with a pass condition. Fixes for findings use normal test-first cycles, and each finding gets a regression test.

**Spec:** [README.md](README.md).

## Review Focus

1. Slow memory or fd leak that shows only after days → the soak gate catches it. (Task 3)
2. Combined features failing together, such as an HTTP/3 client on a compressed, cached, proxied location during an upstream failure and a reload → the matrix and chaos tests cover these combinations. (Task 2)
3. Benchmarks that flatter Bastion, through different settings or Docker measurement → published method with identical settings on real hosts. (Task 4)
4. Default config unsafe on a real host, or simple config that does not work as documented → fresh-host walkthrough. (Task 6)
5. Security issues in unsafe C after all the unit coverage → independent review and long fuzz. (Tasks 1, 5)

---

### Task 1: Long fuzz campaign

**Files:**
- Modify: `fuzz/corpus/*`, `docs/conformance.md`

**Interfaces:**
- Consumes: all `fuzz/fuzz_*.c` harnesses.

- [ ] **Step 1: Add missing harnesses.** List every parser in `src/` and confirm each has a harness: h1, chunked, h2 frames, HPACK, range, URI, Cache-Control, cache header, PROXY protocol, JWT, JSON, config, DNS, JA4, ACME responses, QUIC endpoint.
- [ ] **Step 2: Run** each harness for at least 24 CPU-hours on real hardware using `make fuzz T=name SECS=86400`, with sanitizers.
- [ ] **Step 3: Fix** each crash with a regression test and a reproducer in the corpus.
- [ ] **Step 4: Verify** the final 24-hour run has zero new crashes.
- [ ] **Step 5: Commit** `test: add long fuzz findings to regression corpus`

### Task 2: Feature matrix and fault injection

**Files:**
- Create: `tests/matrix/test_matrix.py`, `tests/chaos/test_chaos.py`

**Interfaces:**
- Produces: `make test-matrix`, `make test-chaos`.

- [ ] **Step 1: Write the matrix**, a pairwise combination of: backend (uring, epoll), protocol (h1, h1+TLS, h1+kTLS, h2, h3), handler (static, proxy-h1, proxy-h2), cache (off, miss, hit, stale), compression (off, each), auth (off, basic, JWT), filters (WAF, limit, challenge). Each cell asserts correct body, headers and framing.
- [ ] **Step 2: Write chaos tests:** random worker and helper kills under load, upstream kills, packet loss and reorder through `tc netem`, disk full, cache dir removed, clock jumps, memory pressure via cgroups, fd exhaustion, simultaneous reloads. Assert no crash except those injected, no corrupted response, recovery within a set time, and no leak afterwards.
- [ ] **Step 3: Run** `./dev make test-matrix test-chaos` and fix findings.
- [ ] **Step 4: Run** again → PASS, twice in a row, to catch flakes.
- [ ] **Step 5: Commit** `test: add feature matrix and fault injection suites`

### Task 3: Soak

**Files:**
- Create: `scripts/soak.sh`, `docs/soak-results.md`

**Interfaces:**
- Produces: `scripts/soak.sh --hours 72 --target host`, with mixed traffic across all protocols, periodic reloads, and an hourly record of RSS, fds, connections, CPU and latency percentiles.

- [ ] **Step 1: Write** the soak script and a check that fits a trend line to RSS and fds.
- [ ] **Step 2: Run** 72 hours on a real Linux host, with ASan disabled, and a separate 12-hour run in the ASan build.
- [ ] **Step 3: Verify:** after warm-up, RSS and fds have no upward trend within noise; p99 latency stays stable; zero unexplained errors.
- [ ] **Step 4: Fix** findings and repeat if any fix touches a hot path.
- [ ] **Step 5: Commit** `test: add soak harness and record results`

### Task 4: Benchmarks and optimization

**Files:**
- Modify: `scripts/bench.sh`, `docs/tuning.md`
- Create: `docs/benchmarks.md`, `bench/results/`

**Interfaces:**
- Consumes: `scripts/bench.sh`.

**Pass condition:** on identical real hardware, using two machines joined by at least 25 GbE and with matching settings and worker counts, Bastion at least matches nginx on throughput and p99 for each scenario, or the shortfall is explained in `docs/benchmarks.md` and approved by the user. No absolute requests-per-second promise is made, since it depends on hardware.

- [ ] **Step 1: Run** every scenario: static small and large, TLS handshake rate, kTLS and user-space TLS, HTTP/2, HTTP/3, proxy, cache hit, and XDP drop rate. Include io_uring and epoll for each.
- [ ] **Step 2: Profile** with `perf` and flamegraphs, and list the top hot spots for each scenario.
- [ ] **Step 3: Optimize** only measured hot spots, one change at a time, with before and after numbers. Decide defaults for `SEND_ZC` threshold, SQPOLL, and custom-BIO TLS reads here, using this data.
- [ ] **Step 4: Verify** the whole test suite still passes after each change, then publish the method, commands, hardware and raw results in `docs/benchmarks.md`.
- [ ] **Step 5: Commit** `perf: apply measured optimizations and publish benchmarks`

**Blocker to raise with the user:** this task needs two real Linux servers. If none exist at this point, ask how to proceed rather than substituting Docker results.

### Task 5: Security review

**Files:**
- Create: `docs/security.md`, `docs/threat-model.md`, `SECURITY.md`

**Interfaces:**
- Consumes: entire source tree.

- [ ] **Step 1: Write** the threat model: attackers on the network, compromised workers, malicious upstreams, and local unprivileged users, with mitigations and accepted risks, including fork-without-exec.
- [ ] **Step 2: Run** static analysis: `clang --analyze`, `cppcheck`, and CodeQL. Triage all findings to fixed or justified false positive.
- [ ] **Step 3: Audit** by hand each `memcpy`, arithmetic on sizes taken from the network, and each entry in the seccomp allowlist. Check the final allowlist is minimal by trying to remove each entry.
- [ ] **Step 4: Run** a separate reviewer agent over each protocol parser and over the sandbox. **Recommend to the user** an independent human audit before internet-facing production use, since automated review doesn't replace it. Dependency CVE check is included in CI.
- [ ] **Step 5: Commit** `docs: add threat model and security policy`

### Task 6: Documentation and first-run experience

**Files:**
- Create: `docs/guide/getting-started.md`, `docs/guide/static-sites.md`, `docs/guide/reverse-proxy.md`, `docs/guide/tls.md`, `docs/guide/caching.md`, `docs/guide/ddos.md`, `docs/guide/migrating-from-nginx.md`, `docs/guide/operations.md`, `examples/*.conf`
- Modify: `README.md`, `docs/config-reference.md`
- Test: `tests/integration/test_docs.py`

**Interfaces:**
- Consumes: `bastion -t`, generated reference.

- [ ] **Step 1: Write failing tests**
  - `test_all_examples_parse`: each config block in `docs/` and `examples/` passes `bastion -t`.
  - `test_reference_complete`: all directives documented, with examples for at least the top 50.
  - `test_docs_links`: no broken links.
- [ ] **Step 2: Run** `./dev make test-int K=test_docs` → FAIL.
- [ ] **Step 3: Write the docs.** The top of the README shows the 4-line HTTPS config. Include a table of nginx directives and their Bastion counterparts.
- [ ] **Step 4: Verify** with a timed walkthrough on a fresh VM following only the guide: install package, write the simple config, get an HTTPS site with HTTP/3 running against Pebble or a staging CA. Target under 5 minutes. Run `./dev make test-int K=test_docs` → PASS.
- [ ] **Step 5: Commit** `docs: add user guide and verified examples`

### Task 7: 1.0 gate

**Files:**
- Create: `CHANGELOG.md`
- Modify: `docs/conformance.md`

**Interfaces:**
- Consumes: everything above.

- [ ] **Step 1: Verify all of these pass on `main`,** recording output in the release notes:
  - `./dev make test-unit test-int test-vm conformance fuzz-smoke test-matrix test-chaos test-packaging`
  - h2spec and h3spec: 0 failures. testssl.sh: no HIGH or CRITICAL findings.
  - Every row in the README scope table maps to a passing test, listed in `docs/conformance.md`.
  - Soak, fuzz, benchmark and security tasks complete with no open blockers.
- [ ] **Step 2: Check** that `docs/conformance.md` lists each deviation and untested area honestly, including `xdp mode hw` and anything limited by available hardware.
- [ ] **Step 3: Build** release artifacts for both architectures, verifying checksums and running a smoke test on each.
- [ ] **Step 4: Ask the user** to approve publishing. Tagging and publishing are outward-facing and need explicit confirmation.
- [ ] **Step 5: Commit** `chore: prepare 1.0.0 release notes`
