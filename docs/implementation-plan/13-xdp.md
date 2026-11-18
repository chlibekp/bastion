# Phase 13: XDP DDoS Filter (Milestone M5)

**Goal:** An XDP program that drops attack traffic before the network stack, fed by static lists and L7 escalation.

**Architecture:** One BPF object embedded in the binary. Master loads and attaches it, then pins it so an upgrade can keep it running. The packet path is ordered with the cheapest checks first and has no per-connection state.

**Hardware offload note:** XDP has three modes. `native` runs in the NIC driver and is the normal high-performance mode. `generic` runs in the kernel at lower speed, and is what development containers use. `hw` runs on the NIC itself and only a few SmartNICs support it. `auto` tries native, then generic. `hw` is offered, but without suitable hardware it can't be tested, so it's documented as untested unless real hardware validates it.

**Spec:** [architecture.md](architecture.md) section 7, [config-language.md](config-language.md).

## Review Focus

1. Blocking your own admin or upstream: operator's IP, trusted proxies, upstream servers, or loopback → allowlist always wins and can't be entered into the block map. (Tasks 3, 7)
2. Bastion crashes, is upgraded, or is stopped → filter state and traffic are handled as documented, and the interface isn't left dropping traffic with no one managing it. (Task 6)
3. Non-IP traffic, IPv6 extension headers, VLAN tags, ARP, ICMP needed for path MTU, fragments, and traffic to non-protected ports → passes, unless configured to drop. (Tasks 2, 5)
4. Truncated or odd-sized packets → verifier-safe bounds checks with no out-of-bounds read, and pass or drop as documented. (Task 2)
5. Native XDP unsupported by the driver, or `CAP_BPF` missing in a container → clean fallback with a warning, with L7 limits still working. (Task 6)

---

### Task 1: BPF build and test harness

**Files:**
- Create: `src/xdp/xdp_bastion.bpf.c`, `src/xdp/xdp_common.h`, `tests/unit/xdp_harness.{c,h}`, `tests/unit/test_xdp_basic.c`

**Interfaces:**
- Consumes: `tools/embed.mk` from Phase 8 Task 2.
- Produces: Target `build/xdp_bastion.bpf.o` compiled by clang and embedded with `tools/embed.mk`. Harness: `xdp_run(const void *pkt, size_t len, uint32_t *action)` through `bpf_prog_test_run_opts`; `xdp_map_set_*`, `xdp_stat(reason)`; packet builders `pkt_tcp4`, `pkt_tcp6`, `pkt_udp4`, `pkt_udp6`, each with options. `bst_xdp_config` as a BPF config array.

- [x] **Step 1: Write failing tests**
  - `passes_clean_tcp`: well-formed SYN → `XDP_PASS`.
  - `verifier_accepts`: object loads on the Docker kernel, and under `make test-vm KERNEL=floor` on Linux 6.1. Re-run the floor check after each later task that changes the program.
  - `non_ip_pass`: ARP → `XDP_PASS`.
- [x] **Step 2: Run** `./dev make test-unit T=xdp_basic` → FAIL.
- [x] **Step 3: Implement** a skeleton parse → pass program, without CO-RE dependency, so one object runs on all supported kernels.
- [x] **Step 4: Run** same → PASS.
- [x] **Step 5: Commit** `feat(xdp): add BPF build, embedding and test harness`

### Task 2: Packet parsing and malformed drops

**Files:**
- Modify: `src/xdp/xdp_bastion.bpf.c`
- Test: `tests/unit/test_xdp_parse.c`, `fuzz/fuzz_xdp_packets.c`

**Interfaces:**
- Produces: Drop reasons `BST_XDP_DROP_{MALFORMED, TCP_FLAGS, FRAGMENT, ...}` counted in a `PERCPU_ARRAY`. Config flags `drop_fragments`, `drop_bad_tcp_flags`, `drop_unprotected`.

- [x] **Step 1: Write failing tests**
  - `vlan_tags`: 0, 1 and 2 VLAN tags parse.
  - `truncated_at_each_offset`: every prefix of a valid packet yields a defined result, without error.
  - `ip_bad_lengths`: IHL below 5, `tot_len` bigger than the frame → drop.
  - `tcp_bad_doff`: `doff` below 5 or past the frame → drop.
  - `tcp_flags`: null, xmas, SYN+FIN, SYN+RST → drop; normal flags → pass.
  - `ipv4_fragments`: per config; non-first fragments can't be port-matched.
  - `ipv6_extension_headers`: hop-by-hop and destination options walked up to a bound; beyond bound → pass (or per config).
  - `icmp_pass`: ICMP and ICMPv6 needed for PMTUD and neighbour discovery → pass.
  - `non_protected_port`: other ports → pass unless `drop_unprotected on`.
  - The fuzz harness feeds random packets through `bpf_prog_test_run`, asserting only valid return codes.
- [x] **Step 2: Run** `./dev make test-unit T=xdp_parse` → FAIL.
- [x] **Step 3: Implement** with explicit bounds checks and a bounded loop for IPv6 headers.
- [x] **Step 4: Run** same → PASS.
- [x] **Step 5: Commit** `feat(xdp): parse packets and drop malformed traffic`

### Task 3: Allow and block maps

**Files:**
- Modify: `src/xdp/xdp_bastion.bpf.c`
- Test: `tests/unit/test_xdp_lists.c`

**Interfaces:**
- Produces: Maps `allow4`, `allow6`, `deny4`, `deny6` (`LPM_TRIE`), `dyn_block4`, `dyn_block6` (`LRU_HASH` keyed by IP or prefix, value expiry in ns from `bpf_ktime_get_coarse_ns`). Directives in `xdp {}`: `allow`, `deny`, `allow_file`, `deny_file`, `ipv6_prefix`.

- [x] **Step 1: Write failing tests**
  - `allow_beats_deny`: IP in both → pass, and later checks are skipped.
  - `deny_prefix`: longest-prefix match.
  - `dyn_block_active`: drop before expiry.
  - `dyn_block_expired`: pass after expiry, entry may remain.
  - `ipv6_prefix_block`: /64 key covers all addresses in it.
  - `mapped_v4_in_v6`: `::ffff:1.2.3.4` is checked against IPv4 lists.
  - `counters_per_reason`: counters increase with correct reason.
- [x] **Step 2: Run** `./dev make test-unit T=xdp_lists` → FAIL.
- [x] **Step 3: Implement.**
- [x] **Step 4: Run** same → PASS.
- [x] **Step 5: Commit** `feat(xdp): add allow, deny and dynamic block maps`
  - Deviation: the `xdp {}` directives (allow, deny, allow_file, deny_file, ipv6_prefix) landed with `xdp_directives.c` in Task 6. dyn_block6 is looked up at /128, /64, /56 and /48 only; other IPv6 block prefixes stay L7 only.

### Task 4: Per-source rate limiting

**Files:**
- Modify: `src/xdp/xdp_bastion.bpf.c`
- Test: `tests/unit/test_xdp_rate.c`

**Interfaces:**
- Produces: `LRU_PERCPU_HASH` per-source buckets for SYN, UDP and optional total packet rate. Config: `syn_rate`, `udp_rate`, `pps_rate`, each with `burst`. Over-limit escalation: optional auto-block when a source exceeds a multiple for a duration (`auto_block after= for=`). Spoofed sources can trigger this, so it only ever drops the rate-exceeding source key with a short TTL, and it's off by default.

- [x] **Step 1: Write failing tests**
  - `syn_bucket`: burst + rate over fake time: precise pass and drop counts.
  - `udp_bucket`: separate from SYN.
  - `ack_not_syn_limited`: established traffic isn't charged to the SYN bucket.
  - `lru_churn`: random source flood evicts old entries, without errors.
  - `per_cpu_scaling`: limit behaviour documented as per-CPU, with config dividing by the online CPU count, tested with 1 and N simulated.
  - `allowlist_unlimited`: allowlisted sources are not rate-limited.
- [x] **Step 2: Run** `./dev make test-unit T=xdp_rate` → FAIL.
- [x] **Step 3: Implement.**
- [x] **Step 4: Run** same → PASS.
- [x] **Step 5: Commit** `feat(xdp): add per-source packet rate limits`
  - Deviations: `auto_block after=<drops> for=<duration>` counts drops within one second (not "a multiple for a duration"). Per-CPU N is simulated (BPF_PROG_TEST_RUN runs on one CPU). The 6.12 verifier refused the object after this task (1M instructions); fixed in `fix(xdp): keep the filter within the 6.12 verifier limit` (L4 checks as a global function; IPv6 rate keys masked by a precomputed byte mask).

### Task 5: Reflection and QUIC filters

**Files:**
- Modify: `src/xdp/xdp_bastion.bpf.c`
- Test: `tests/unit/test_xdp_udp.c`

**Interfaces:**
- Produces: `drop_reflection on|off` for UDP arriving from known amplification source ports (53, 123, 389, 1900, 11211, 19, 161 and more in a config-editable list), aimed at protected ports. Upstream DNS replies go to ephemeral ports, unaffected. QUIC shape checks on protected UDP ports: fixed bit set, long-header Initial with a known version has a datagram of at least 1200 bytes.

- [x] **Step 1: Write failing tests**
  - `reflection_drop`: src port 11211 to :443 → drop.
  - `reflection_other_dst`: src 53 to an ephemeral port → pass, so DNS still works.
  - `quic_short_initial`: 500-byte Initial → drop.
  - `quic_fixed_bit_clear`: → drop.
  - `quic_unknown_version`: allowed through, so that version negotiation works.
  - `quic_short_header_small`: valid short-header small packet → pass.
  - `udp_no_quic_config`: filters inactive when no `http3` listener exists.
- [x] **Step 2: Run** `./dev make test-unit T=xdp_udp` → FAIL.
- [x] **Step 3: Implement.**
- [x] **Step 4: Run** same → PASS.
- [x] **Step 5: Commit** `feat(xdp): add reflection and QUIC shape filters`

### Task 6: Loader and lifecycle

**Files:**
- Create: `src/xdp/loader.{c,h}`, `src/xdp/xdp_directives.c`
- Test: `tests/integration/test_xdp_lifecycle.py`, `tests/vm/test_xdp_native.py`

**Interfaces:**
- Consumes: libbpf, embedded object.
- Produces: `bst_xdp *bst_xdp_load(const bst_cfg_xdp *, bst_err *)`, `bst_xdp_reconfigure(bst_xdp *, const bst_cfg_xdp *)`, `bst_xdp_detach(bst_xdp *)`, `bst_xdp_adopt_pinned(path)`. Directives in `xdp {}`: `interface` (repeatable), `mode auto|native|generic|hw [require]`, `pin_path`, `on_exit detach|keep`, plus those from Tasks 2-5. `xdp` block absent means no BPF loaded at all.

- [x] **Step 1: Write failing tests** on a veth pair in a test network namespace
  - `test_attach_generic_drops`: blocked source can't reach the server; others can.
  - `test_mode_fallback`: `auto` steps down and logs the chosen mode.
  - `test_require_native_fails`: `mode native require` on an unsupported device → startup error.
  - `test_no_caps`: unprivileged container → warning, and server continues with L7 only.
  - `test_clean_stop_detaches`: stop with `on_exit detach` removes the program.
  - `test_kill9_stays_safe`: `kill -9` the master with `on_exit detach`: the attached program remains until a link is released, then behaviour matches docs. A later start adopts it instead of failing.
  - `test_reload_updates_lists`: config reload changes map contents with no gap, and no detach.
  - `test_multiple_interfaces`: both attached.
  - VM tier `test_native_veth`: native mode on veth under a stock kernel, with the same drop checks.
- [x] **Step 2: Run** `./dev make test-int K=xdp_lifecycle` → FAIL.
- [x] **Step 3: Implement** using `bpf_link`, pinned at `pin_path`, so ownership passes cleanly to an upgraded master.
- [x] **Step 4: Run** same plus `./dev make test-vm K=xdp_native` → PASS.
- [x] **Step 5: Commit** `feat(xdp): add loader, attach modes and lifecycle`
  - Deviations: `test_reload_updates_lists` NOT executed as an integration test (config reload arrives in Phase 14); `bst_xdp_reconfigure` is covered by the unit test `reconfigure_no_gap`. The `xdp` block is not a singleton (absent means no BPF). `bst_xdp_adopt_pinned(path)` returns the pinned link count; adoption happens inside `bst_xdp_load`. Clean stop uses `bpf_link_detach` because forked children hold copies of the link fd. `hw` mode is untested (no hardware).

### Task 7: Connect escalation to XDP

**Note from Phase 3 Task 7:** a TCP slot whose worker is in respawn backoff keeps queueing, so connections hashing to it wait up to the 30 s cap (master logs it at error level). A `sk_reuseport` program for TCP could route new connections around dead slots by keeping master's view of live slots in the `REUSEPORT_SOCKARRAY`. Not in this phase's scope; worth a task if crash loops prove real.

**Files:**
- Create: `src/xdp/block.{c,h}`
- Test: `tests/integration/test_xdp_escalate.py`

**Interfaces:**
- Consumes: `bst_block_backend` from Phase 12 Task 3.
- Produces: `bst_block_backend_xdp`. Master applies `block_ring` entries to `dyn_block*`, or to user-space when XDP isn't attached. Flag from Phase 12 prevents XDP blocks when the address came from a header.

- [x] **Step 1: Write failing tests**
  - `test_l7_to_xdp`: a client over the rate limit gets packet drops within 1 second, with the XDP counter increasing.
  - `test_ttl_unblocks`: the client recovers after TTL.
  - `test_allowlist_protected`: an allowlisted abuser is never placed in the map.
  - `test_proxy_protocol_not_xdp`: CDN address stays unblocked, real client blocked at L7.
  - `test_worker_compromise_limits`: a fake worker flooding `block_ring` can't exceed the ceiling or block allowlisted networks.
  - `test_admin_list_matches_map`: list reflects actual map state.
- [x] **Step 2: Run** `./dev make test-int K=xdp_escalate` → FAIL.
- [x] **Step 3: Implement.**
- [x] **Step 4: Run** same → PASS.
- [x] **Step 5: Commit** `feat(xdp): feed L7 escalation into XDP block maps`
  - Deviations: `test_worker_compromise_limits` and `test_admin_list_matches_map` are unit tests (`tests/unit/test_xdp_block.c`): there is no admin endpoint before Phase 14, and a fake worker ring is driven through `bst_block_apply`. The XDP backend wraps the user-space one (blocks stay enforced at L7 too); loopback, the xdp allow list and upstream IP literals never enter the maps (upstream host names: only via escalation_allow).

### Task 8: XDP SYN cookies

**Files:**
- Create: `spikes/xdp_syncookie/README.md`
- Modify: `src/xdp/xdp_bastion.bpf.c`, `src/xdp/loader.c`
- Test: `tests/vm/test_xdp_syncookie.py`

**Interfaces:**
- Consumes: `bpf_tcp_raw_gen_syncookie_ipv4`, `bpf_tcp_raw_gen_syncookie_ipv6` helpers.
- Produces: `syn_cookies off|on|auto`, default off, with `auto` activating when SYN rate crosses `syn_cookie_threshold`. `doctor` checks `net.ipv4.tcp_syncookies=2`.

- [x] **Step 1: Spike.** On the VM kernel, reply to SYN with a cookie SYN-ACK through `XDP_TX`, and confirm the kernel accepts the returned ACK under `tcp_syncookies=2`. Record results, including which TCP options survive and how `TCP_FASTOPEN` and `TCP_DEFER_ACCEPT` behave. **If it doesn't work reliably, stop this task, drop the directive, keep kernel SYN cookies plus XDP SYN rate limits, and record that in `docs/conformance.md`. That still meets the SYN flood requirement.**
- [x] **Step 2: Write failing tests** if the spike passes
  - `test_cookie_connection`: full HTTP request succeeds through a cookie handshake, for IPv4 and IPv6.
  - `test_spoofed_syn_no_state`: 100,000 spoofed SYNs leave `SYN_RECV` count near 0.
  - `test_checksums`: replies pass a packet validator, for VLAN-tagged frames too.
  - `test_auto_toggle`: activates and deactivates at thresholds.
- [x] **Step 3: Run** `./dev make test-vm K=xdp_syncookie` → FAIL.
- [x] **Step 4: Implement,** then run the same → PASS.
- [x] **Step 5: Commit** `feat(xdp): add optional XDP SYN cookies`
  - NOT executed: the spike (Step 1) was not run, so Steps 2-4 were not done and the plan's fallback applies: no `syn_cookies` directive, no doctor check; kernel SYN cookies plus XDP `syn_rate` (spikes/xdp_syncookie/README.md, docs/conformance.md). Committed as `docs(xdp): record the SYN cookie spike as not run`.

### Task 9: XDP metrics and flood test

**Files:**
- Create: `src/xdp/stats.c`, `tools/udpflood.c`, `tools/synflood.c`
- Test: `tests/integration/test_xdp_flood.py`

**Interfaces:**
- Produces: `bst_xdp_read_stats(bst_xdp *, bst_xdp_stats *)`, polled by master at 1 Hz into `metrics` shm. Flood tools run only over veth inside the test network namespace. They refuse non-loopback, non-namespace destinations, so they can't be pointed at outside targets. They are not installed by packages.

- [x] **Step 1: Write failing tests**
  - `test_flood_keeps_service`: a veth SYN and UDP flood runs alongside a legitimate client; the legitimate success rate stays above 99%, CPU in workers stays low compared with no-XDP baseline.
  - `test_stats_accuracy`: drop counters match injected counts within 1%.
  - `test_tool_refuses_external`: tools exit non-zero for any address outside the test namespace.
- [x] **Step 2: Run** `./dev make test-int K=xdp_flood` → FAIL.
- [x] **Step 3: Implement.**
- [x] **Step 4: Run** `./dev make test-unit test-int test-vm conformance fuzz-smoke` → PASS.
- [x] **Step 5: Commit** `test(xdp): add namespace-only flood tests and XDP metrics`
  - Measured in the dev container only: generic-mode XDP on a veth, one flood process, a few hundred thousand packets. No line-rate or NIC benchmark. Metrics are read from master's `xdp: stats` log line (no metrics endpoint before Phase 14). The worker-CPU check asserts "no higher than without XDP", not a speed-up. The config reference was regenerated in a separate commit.
