# Phase 12: L7 Security

**Goal:** ACLs, GCRA rate limits across workers, escalation signals, WAF-lite and a very simple proof-of-work challenge with a replaceable frontend.

**Architecture:** See [architecture.md](architecture.md) section 7. Checks run in the early phase, before routing to a handler. Limits use lock-free GCRA over shared memory. The challenge stores nothing on the server.

**Spec:** [architecture.md](architecture.md), [config-language.md](config-language.md).

## Review Focus

1. Clients behind CDN or NAT: all share one address, or the real client arrives via PROXY protocol → limits key on the correct address, and XDP escalation doesn't fire on a CDN's address. (Tasks 1, 3)
2. Spoofed `X-Forwarded-For` to evade limits → ignored unless the peer is trusted. (Task 1)
3. IPv6 rotation inside a /64 → counted as a single client. (Task 1)
4. Forged or expired challenge cookie, or one from another IP prefix → rejected without server state. (Task 5)
5. Non-browser API clients on `challenge auto` → documented response with an allowlist, not an endless challenge loop. (Task 5)

---

### Task 1: Rate limit zones

**Files:**
- Create: `src/sec/limit.{c,h}`, `src/sec/sec_directives.c`
- Test: `tests/unit/test_gcra.c`, `tests/integration/test_limit.py`

**Interfaces:**
- Produces: `bst_limit_result bst_limit_check(bst_limit_zone *, bst_str key, uint64_t now_us)` returning allowed, delay or reject, with retry-after. Directives: `limit_zone <name> { key; rate; size; mode reject|delay; status; ipv6_prefix; dry_run; }`, `limit <zone>` at server and location. The key hash is keyed SipHash, so attackers cannot aim collisions. Directive `limit_headers on|off` (default off) adds `RateLimit` draft fields to responses.

- [ ] **Step 1: Write failing tests**
  - `gcra_rate`: simulated clock, exact allowed count at each rate and burst.
  - `gcra_cas_threads`: 8 threads with TSan, total admitted within 1% of the theoretical amount.
  - `table_full`: LRU replacement of the oldest slot, without an unbounded probe and without a crash.
  - `clock_backwards`: no permanent lockout.
  - `test_limit_across_workers`: rate applies globally with 4 workers.
  - `test_429_retry_after`: reject carries `Retry-After`.
  - `test_ipv6_prefix`: rotating addresses within a /64 share a bucket.
  - `test_mapped_ipv4`: `::ffff:` form shares the IPv4 bucket.
  - `test_xff_spoof`: XFF from an untrusted peer has no effect on `$remote_addr`.
  - `test_dry_run`: logged and counted, never blocked.
- [ ] **Step 2: Run** `./dev make test-unit T=gcra && ./dev make test-int K=test_limit` → FAIL.
- [ ] **Step 3: Implement.** Each slot's 64-bit theoretical arrival time updates by CAS. There are no locks.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(sec): add shared GCRA rate limits`

### Task 2: Connection limits and ACLs

**Files:**
- Create: `src/sec/connlimit.{c,h}`, `src/sec/acl.{c,h}`
- Test: `tests/integration/test_acl.py`

**Interfaces:**
- Produces: `bst_connlimit_acquire(zone, ip)` and `_release`, and a per-worker crash cleanup path that rebuilds counts. `bst_acl_check(const bst_acl *, const bst_ip *)`. Directives: `limit_conn <per_ip n> <subnet4 /p n> <subnet6 /p n>`, `allow`, `deny`, `allow_file`, `deny_file`, `acl_default`. ACLs apply both at connection accept (for server-wide lists) and per location. File reloads go through normal reload.

- [ ] **Step 1: Write failing tests**
  - `test_per_ip_limit`: excess connections close immediately, before TLS.
  - `test_counters_released`: counts return to 0 after close, across all exit paths.
  - `test_worker_crash_counter`: `kill -9` of a worker doesn't leave a permanent count, using per-worker counter slots.
  - `test_allow_deny_order`: first match or longest prefix per the documented rule, consistent with XDP semantics.
  - `test_location_acl`: 403 at a location with other locations open.
  - `test_acl_uses_real_ip`: `real_ip`-derived address when trusted.
  - `test_deny_file_large`: 1M CIDRs load in less than 2 seconds and match in constant-ish time.
- [ ] **Step 2: Run** `./dev make test-int K=acl` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(sec): add connection limits and IP ACLs`

### Task 3: Escalation

**Files:**
- Create: `src/sec/escalate.{c,h}`, `src/sec/block.{c,h}`
- Test: `tests/unit/test_escalate.c`, `tests/integration/test_escalate.py`

**Interfaces:**
- Consumes: `block_ring`, `bst_h2_guard` hook from Phase 7.
- Produces: `bst_escalate_strike(bst_worker *, const bst_ip *, bst_strike_kind, const bst_conn *)`. A master-side `bst_block_apply(const bst_block_req *)`, with an interface `bst_block_backend { add, remove, list }`. Phase 12 ships a user-space shm backend, used by workers at accept. Phase 13 adds XDP behind the same interface. Directive `escalate after= window= block=` inside `limit_zone`, `waf_rule` and `http2_abuse`, plus `escalation_ceiling`.

- [ ] **Step 1: Write failing tests**
  - `strike_window`: N strikes within a window → one request sent.
  - `never_blocks_allowlisted`: allowlisted and trusted CIDRs are ignored by master validation.
  - `ceiling`: past the ceiling, requests are refused and counted, and existing blocks remain.
  - `ttl_expiry`: blocks expire.
  - `ring_full`: full ring drops the request and counts it, with no blocking in workers.
  - `malformed_ring_entry`: master rejects a bad entry, as a compromised worker cannot escalate into arbitrary master actions.
  - `test_escalate_end_to_end`: a hostile client ends up blocked at accept across all workers within 1 second of crossing the threshold.
  - `test_proxy_protocol_no_network_block`: client address from PROXY protocol → L7 block only, verified as a backend flag.
  - `test_quic_unvalidated_no_strike`: spoofable QUIC peers before address validation aren't escalated.
  - `test_ipv6_prefix_block`: covers the /64.
- [ ] **Step 2: Run** `./dev make test-unit T=escalate && ./dev make test-int K=test_escalate` → FAIL.
- [ ] **Step 3: Implement** following the rules in architecture.md section 7.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(sec): add escalation pipeline and block backends`

### Task 4: WAF-lite

**Files:**
- Create: `src/sec/waf.{c,h}`
- Test: `tests/unit/test_waf.c`, `tests/integration/test_waf.py`

**Interfaces:**
- Consumes: `bst_regex`, `bst_tpl`, `$ja4`.
- Produces: `bst_waf_action bst_waf_eval(const bst_waf_set *, const bst_stream *)`. A rule has one or more `match <subject> <op> <value>` lines that AND together, and `action allow|deny <status>|log|challenge|limit <zone>`. Subjects: `path`, `uri`, `query`, `arg:<name>`, `header:<name>`, `cookie:<name>`, `method`, `host`, `ip`, `ja4`, `content_type`, `content_length`, `user_agent`, `protocol`, `tls_version`. Operators: `=`, `!=`, `~`, `!~`, `prefix`, `suffix`, `contains`, `in_cidr`, `in_file`, `>`, `<`, `missing`, `exists`. `rule_mode enforce|log`, `waf <rules...>`. A deliberately small feature set: no body content inspection and no scoring engine.

- [ ] **Step 1: Write failing tests**
  - `each_subject`, `each_op`: table of expected matches.
  - `normalized_path`: encoding tricks like `/%77p-admin` match `/wp-admin`, since rules run after normalization.
  - `multi_header`: all values of repeated headers are checked.
  - `missing_header`: `missing` true and `~` false.
  - `first_match_wins`: ordering is documented and tested.
  - `redos`: regex limits are enforced.
  - `test_ja4_block`: a rule matching curl's JA4 denies curl over TLS, and HTTP/1.1 cleartext isn't matched.
  - `test_log_mode`: logs only.
  - `test_waf_action_challenge`: routes to Task 5.
  - `test_evaluation_cost`: 1,000 rules add less than 100 µs per request on the benchmark host, or is flagged in `docs/tuning.md`.
- [ ] **Step 2: Run** `./dev make test-unit T=waf && ./dev make test-int K=test_waf` → FAIL.
- [ ] **Step 3: Implement.** Rules compile at load into flat arrays, with cheap subjects evaluated before regex within a rule.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(sec): add lightweight request filter rules`

### Task 5: Simple challenge

The user asked for an extremely simple design with no over-engineering, and for the frontend to be replaceable.

**Design:**

1. A request without a valid pass cookie gets a `403` with `Cache-Control: no-store` and the HTML page, or a plain-text `403` when the client doesn't accept HTML.
2. The page gets a token: `expiry.ipprefix_hash.hmac`, and a difficulty in leading zero bits.
3. The browser finds `nonce` so that `SHA-256(token + "." + nonce)` has that many leading zero bits.
4. It sends `POST /.bastion/challenge` with the token, nonce and original URL. Bastion checks HMAC, expiry, IP prefix and hash, then sets the cookie `bastion_pass=<expiry>.<hmac>` and returns a redirect to the original path.
5. Later requests verify the HMAC. Nothing is stored on the server.

**Custom frontend contract:** the page is any HTML file. Bastion replaces one placeholder, `{{bastion_challenge}}`, with `<script>` code that defines `window.BASTION = { token, difficulty, verifyUrl, redirect, solve() }`. `solve()` runs the proof of work in a Web Worker, submits it, and resolves after redirecting. A page can also ignore `solve()` and do the math itself using the documented steps above.

**Files:**
- Create: `src/sec/challenge.{c,h}`, `src/sec/challenge_page.html`, `src/sec/challenge_client.js`, `docs/challenge.md`, `examples/challenge/custom.html`
- Test: `tests/unit/test_challenge.c`, `tests/integration/test_challenge.py`

**Interfaces:**
- Produces: `bool bst_challenge_cookie_valid(const bst_challenge_cfg *, bst_str cookie, const bst_ip *, uint64_t now)`, `bst_challenge_issue`, `bst_challenge_verify_pow`. Directives: `challenge on|off|auto`, `challenge_page <file>`, `challenge_difficulty`, `challenge_pass_ttl`, `challenge_token_ttl`, `challenge_ip_prefix4`, `challenge_ip_prefix6`, `challenge_allow <cidr>`, `challenge_cookie_name`. Secret lives in shm, rotating with one-generation overlap.

- [ ] **Step 1: Write failing tests**
  - `valid_flow`: issue, solve, verify and validate.
  - `wrong_nonce`, `tampered_token`, `expired_token`: rejected.
  - `wrong_ip_prefix`: token or cookie from another prefix is rejected.
  - `difficulty_bits`: boundary at exactly N zero bits, for N crossing a byte boundary.
  - `cookie_tamper`, `cookie_expired`: rejected, using constant-time comparison.
  - `secret_rotation`: previous-generation cookies valid through overlap, then not.
  - `test_browser_flow`: headless browser completes the default page and reaches the protected page.
  - `test_custom_page`: `examples/challenge/custom.html` with the placeholder works, including a page that calculates proof itself.
  - `test_missing_placeholder`: `-t` reports a custom page without the placeholder as a warning.
  - `test_non_html_client`: `Accept: application/json` → plain 403, no script.
  - `test_challenge_allow`: allowlisted CIDR bypasses.
  - `test_open_redirect`: verification with `redirect=https://evil.example` → local path only.
  - `test_challenge_csp`: page works under `security_headers strict` with a per-response CSP nonce.
  - `test_verify_endpoint_flood`: endpoint hit by junk stays cheap, and invalid requests can count toward `escalate`.
  - `test_cookie_flags`: `HttpOnly`, `SameSite=Lax`, and `Secure` over TLS.
  - `test_not_cached`: challenged responses are never stored by the cache.
- [ ] **Step 2: Run** `./dev make test-unit T=challenge && ./dev make test-int K=test_challenge` → FAIL.
- [ ] **Step 3: Implement** with HMAC-SHA-256. The default page and script are embedded in the binary, and a `challenge_page` file loads at config time.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(sec): add simple proof-of-work challenge with custom frontend`

### Task 6: Automatic challenge

**Files:**
- Modify: `src/sec/challenge.c`
- Test: `tests/integration/test_challenge_auto.py`

**Interfaces:**
- Produces: `challenge auto` is on only while under attack. Directives: `challenge_auto_rps`, `challenge_auto_block_rate`, `challenge_auto_hold`. One shared atomic flag, set by the helper from aggregated counters at 1 Hz. Metric `bastion_under_attack`. Admin can force it in Phase 14. No other auto-mitigation logic.

- [ ] **Step 1: Write failing tests**
  - `test_activates`: traffic above the threshold turns on the challenge within 2 seconds on every worker.
  - `test_deactivates`: traffic falling below stays on through `challenge_auto_hold` and then turns off, with no flapping under oscillating load.
  - `test_passes_retained`: a client holding a valid pass isn't re-challenged when attack mode activates.
  - `test_challenge_on_overrides`: `on` and `off` ignore the flag.
- [ ] **Step 2: Run** `./dev make test-int K=challenge_auto` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(sec): enable challenge automatically under attack`
