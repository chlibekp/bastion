# Phase 1: Foundation

**Goal:** A reproducible Linux build and test setup driven from the Mac, plus core libraries used by everything else.

**Architecture:** `./dev` runs every command in a Debian-based Docker image. Dependencies build from pinned source into `build/deps/<arch>/`. See [architecture.md](architecture.md) sections 2 and 9.

**Spec:** [README.md](README.md), [architecture.md](architecture.md). Global Constraints in the README apply to every task.

## Review Focus

1. `./dev` run from a path containing spaces → works, because all paths are quoted. (Task 1)
2. Arena requests larger than chunk size, and size overflow near `SIZE_MAX` → separate allocation or NULL, never a wrapped size. (Task 3)
3. Timer cancelled from inside another timer's callback in the same tick → cancelled timer never fires. (Task 5)
4. JSON with deep nesting, duplicate keys, or lone surrogates → rejected with an error and no crash. (Task 8)
5. Log messages containing control characters or newlines → escaped, so logs cannot be forged. (Task 9)

---

### Task 1: Repository, dev image and dependency build

**Files:**
- Create: `Makefile`, `dev`, `docker/dev.Dockerfile`, `docker/release.Dockerfile`, `deps/versions.env`, `scripts/build-deps.sh`, `.clang-format`, `.gitignore`, `.editorconfig`, `src/main.c`, `tests/unit/tap.h`, `tests/unit/test_smoke.c`, `tests/integration/conftest.py`, `tests/integration/test_version.py`, `LICENSE`, `README.md`

**Interfaces:**
- Produces: `./dev <cmd>`; `make all|test-unit|test-int|test-vm|fuzz-smoke|conformance|clean`; `BUILD=debug|asan|tsan|release`; `make test-unit T=name`; `tests/unit/tap.h` with `TEST(name)`, `ASSERT(cond)`, `ASSERT_EQ(a,b)`, `ASSERT_STR(a,b)`; pytest fixture `bastion(config_text, backend=...)` that starts a server on free ports and yields ports and logs; parametrization over both backends.

- [ ] **Step 1: Write failing tests**
  - `test_smoke` : `1 + 1 == 2`, proving the TAP harness reports pass and fail by exit code.
  - `test_version.py::test_version_output`: `bastion --version` exits 0 and prints `bastion ` followed by a semver and the linked OpenSSL version.
  - `test_version.py::test_dev_path_with_spaces`: `./dev` works from a copied tree in a directory containing a space.
- [ ] **Step 2: Run** `./dev make test-unit T=smoke` → FAIL, because no build exists yet.
- [ ] **Step 3: Implement.** Dev image: Debian trixie with clang, lld, make, cmake, python3 with pytest, qemu-system, nghttp2 client tools, curl with HTTP/3 where available. `./dev` uses `docker run --privileged --security-opt seccomp=unconfined --ulimit memlock=-1`, a bind-mounted tree, and a named volume for `build/`. `versions.env` pins OpenSSL 3.5.x, ngtcp2, nghttp3, liburing, libbpf, PCRE2, zstd, brotli, zlib-ng and mimalloc, each with URL and SHA-256, verified by `build-deps.sh` before extraction. Release image: Alpine with static musl linking, because ASan and TSan need glibc but the shipped binary must be static.
- [ ] **Step 4: Run** `./dev make test-unit T=smoke && ./dev make test-int K=version` → PASS. Also `./dev make BUILD=release` and `file build/release/bastion` shows a statically linked binary (run through `docker/release.Dockerfile`).
- [ ] **Step 5: Commit** `build: add dev environment, pinned deps and test harness`

### Task 2: Stock kernel VM test tier

**Files:**
- Create: `scripts/vm-run.sh`, `docker/vm-kernel.Dockerfile`, `tests/vm/test_kernel_features.py`

**Interfaces:**
- Produces: `make test-vm [K=expr] [KERNEL=floor|current]`. Runs pytest in a QEMU guest booted with a stock Debian kernel with the repo mounted over 9p or virtiofs. `floor` is Debian bookworm's 6.1 series, which proves the Linux 6.1 runtime floor. `current` is Debian trixie's kernel and is the default. KVM is used when `/dev/kvm` exists, otherwise TCG.

- [ ] **Step 1: Write failing tests** `test_kernel_features.py`
  - `test_ktls_module`: after `modprobe tls`, `tcp_available_ulp` contains `tls`.
  - `test_bbr_available`: after `modprobe tcp_bbr`, available congestion controls contain `bbr`.
  - `test_busy_poll_sysctl`: `/proc/sys/net/core/busy_poll` exists.
  - `test_io_uring_works`: kernel reports `io_uring_disabled == 0`.
  - `test_landlock_active`: `/sys/kernel/security/lsm` lists `landlock`. If Debian's kernel doesn't enable it by default, the VM boots with `lsm=` set to include it.
- [ ] **Step 2: Run** `./dev make test-vm K=kernel_features` → FAIL, target missing.
- [ ] **Step 3: Implement** `scripts/vm-run.sh <cmd>`: boot kernel plus a minimal initramfs, run the command, return its exit code through a result file, with a timeout of 600 seconds.
- [ ] **Step 4: Run** same command → PASS. Record the boot time in the script header, since it decides how many tests can sit in this tier.
- [ ] **Step 5: Commit** `test: add stock-kernel VM test tier`

### Task 3: Arena, slab, refcounted buffers

**Files:**
- Create: `src/core/arena.{c,h}`, `src/core/slab.{c,h}`, `src/core/buf.{c,h}`
- Test: `tests/unit/test_mem.c`

**Interfaces:**
- Produces: `bst_arena *bst_arena_new(size_t chunk); void *bst_arena_alloc(bst_arena *, size_t); void bst_arena_reset(bst_arena *); void bst_arena_free(bst_arena *); bst_slab *bst_slab_new(size_t obj, size_t per_chunk); void *bst_slab_get(bst_slab *); void bst_slab_put(bst_slab *, void *); bst_buf *bst_buf_new(size_t cap); bst_buf *bst_buf_ref(bst_buf *); void bst_buf_unref(bst_buf *);`

- [ ] **Step 1: Write failing tests**
  - `arena_alignment`: every result is aligned to 16.
  - `arena_large_request`: allocation of chunk × 4 succeeds and survives reset then free under ASan.
  - `arena_overflow`: `bst_arena_alloc(a, SIZE_MAX - 8)` → NULL.
  - `arena_reset_reuses`: after reset, allocation does not grow total mapped size.
  - `slab_reuse`: put then get returns the same pointer.
  - `buf_refcount`: two refs, unref twice, freed once, verified under ASan.
- [ ] **Step 2: Run** `./dev make test-unit T=mem` → FAIL, undefined symbols.
- [ ] **Step 3: Implement** with bump-pointer arenas and ASan poison annotations on reset, so use-after-reset is caught in `BUILD=asan`.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(core): add arena, slab and refcounted buffers`

### Task 4: Strings and body chains

**Files:**
- Create: `src/core/str.{c,h}`, `src/core/chain.{c,h}`
- Test: `tests/unit/test_chain.c`

**Interfaces:**
- Produces: `bst_str {const char *p; uint32_t len;}`, `BST_S("lit")`, `bst_str_eq`, `bst_str_ieq`, `bst_str_to_u64(bst_str, uint64_t *)` with overflow detection. `bst_chain` with `bst_chain_add_mem(chain, bst_buf *, off, len)`, `bst_chain_add_file(chain, int fd, off_t off, off_t len)`, `bst_chain_len`, `bst_chain_consume(chain, n)`, `bst_chain_to_iov(chain, struct iovec *, int max)` which stops at the first file segment, `bst_chain_clear`.

- [ ] **Step 1: Write failing tests**
  - `u64_overflow`: `"18446744073709551616"` → error; `"18446744073709551615"` → ok.
  - `u64_rejects_sign_and_space`: `"+1"`, `" 1"`, `""` → error.
  - `chain_partial_consume`: 3 segments, consume across a boundary, remaining iov matches.
  - `chain_releases_refs`: consumed memory segments drop their buffer refs.
  - `chain_iov_stops_at_file`: mem, file, mem → 1 iovec.
- [ ] **Step 2: Run** `./dev make test-unit T=chain` → FAIL.
- [ ] **Step 3: Implement.** Segments come from a slab. File segments do not own the fd; an optional release callback handles open-file cache refs.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(core): add strings and body chains`

### Task 5: Clock and timer wheel

**Files:**
- Create: `src/core/time.{c,h}`, `src/core/wheel.{c,h}`
- Test: `tests/unit/test_wheel.c`

**Interfaces:**
- Produces: `uint64_t bst_now_ms(void)` (coarse monotonic), `bst_timer {…}`, `bst_wheel_init(bst_wheel *, uint64_t now)`, `bst_timer_arm(bst_wheel *, bst_timer *, uint64_t ms, void (*cb)(void *), void *ud)`, `bst_timer_cancel(bst_timer *)`, `bst_wheel_advance(bst_wheel *, uint64_t now)`, `int64_t bst_wheel_next_ms(const bst_wheel *)`.

- [ ] **Step 1: Write failing tests**
  - `fires_on_time`: armed at 100 ms → fires on advance to ≥100, not at 99.
  - `long_timer_cascades`: 1 hour timer fires at the right tick.
  - `cancel_in_callback`: timer A cancels timer B in the same tick → B does not fire.
  - `rearm_in_callback`: callback rearms itself → fires once per period.
  - `next_ms`: returns a strictly positive lower bound on the delay to the earliest timer (never later than it, may wake early), or −1 if empty.
  - `large_clock_jump`: advance by 7 days with 10,000 timers → all fire, no quadratic work.
- [ ] **Step 2: Run** `./dev make test-unit T=wheel` → FAIL.
- [ ] **Step 3: Implement** a hierarchical wheel of 4 levels with 256 slots and 1 ms resolution, and intrusive doubly-linked lists.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(core): add coarse clock and timer wheel`

### Task 6: Keyed hash, SPSC ring, shared memory

**Files:**
- Create: `src/core/hash.{c,h}`, `src/core/ring.{c,h}`, `src/core/shm.{c,h}`
- Test: `tests/unit/test_shared.c`

**Interfaces:**
- Produces: `uint64_t bst_siphash13(const uint8_t key[16], const void *, size_t)`; `bst_spsc *bst_spsc_init(void *mem, size_t cap)`, `bool bst_spsc_push(bst_spsc *, const void *, uint32_t)`, `int32_t bst_spsc_pop(bst_spsc *, void *out, uint32_t max)`; `void *bst_shm_create(const char *name, size_t size, int *fd_out)`, `void *bst_shm_attach(int fd, size_t size)`.

- [ ] **Step 1: Write failing tests**
  - `siphash_vectors`: published SipHash-1-3 test vectors match.
  - `ring_wraparound`: variable-size messages across the wrap boundary retain content.
  - `ring_full`: push on a full ring returns false and leaves state valid.
  - `ring_threads`: 1M messages across 2 threads in order, also run under `BUILD=tsan`.
  - `shm_fork_shared`: a child writes through the mapping, the parent observes it.
- [ ] **Step 2: Run** `./dev make test-unit T=shared` → FAIL.
- [ ] **Step 3: Implement.** The ring uses C11 acquire and release atomics with cached head and tail. Shm uses `memfd_create` with `MFD_CLOEXEC` and sealing of the size.
- [ ] **Step 4: Run** same with `BUILD=asan`, then `BUILD=tsan` → PASS.
- [ ] **Step 5: Commit** `feat(core): add keyed hash, SPSC ring and shared memory`

### Task 7: IP parsing and CIDR trie

**Files:**
- Create: `src/core/addr.{c,h}`, `src/core/cidr.{c,h}`
- Test: `tests/unit/test_cidr.c`, `fuzz/fuzz_addr.c`

**Interfaces:**
- Produces: `bst_sockaddr`, `bst_addr_parse(bst_str, bst_ip *)`, `bst_addr_format`, `bst_ip_canon` (maps `::ffff:a.b.c.d` to IPv4), `bst_cidr_parse`, `bst_cidr_set *bst_cidrset_new(void)`, `bst_cidrset_add(set, cidr, void *value)`, `void *bst_cidrset_match(const bst_cidrset *, const bst_ip *)` with longest-prefix wins.

- [ ] **Step 1: Write failing tests**
  - `parse_rejects_bad`: `1.2.3`, `1.2.3.4.5`, `01.2.3.4`, `256.1.1.1`, `::g`, `1::2::3` → error.
  - `mapped_v4`: `::ffff:10.0.0.1` matches `10.0.0.0/8`, so IPv4-mapped addresses cannot bypass an ACL.
  - `longest_prefix`: `10.0.0.0/8=A` and `10.1.0.0/16=B`; `10.1.2.3` → B.
  - `v6_prefix`: `2001:db8::/32` matches and neighbouring prefix does not.
  - `host_bits_set`: `10.0.0.1/8` → error.
- [ ] **Step 2: Run** `./dev make test-unit T=cidr` → FAIL.
- [ ] **Step 3: Implement** a path-compressed binary trie, read-only after load so it is safe to share by COW.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(core): add IP parsing and CIDR matching`

### Task 8: Strict JSON

**Files:**
- Create: `src/core/json.{c,h}`
- Test: `tests/unit/test_json.c`, `fuzz/fuzz_json.c`, `fuzz/corpus/json/`

**Interfaces:**
- Produces: `bst_json *bst_json_parse(bst_arena *, const char *, size_t, bst_err *)` with `bst_json_get(obj, "key")`, `bst_json_str`, `bst_json_int`, `bst_json_arr_len`, `bst_json_arr_at`; writer `bst_jw_*` that escapes correctly. Used by JWT, ACME, the admin API and logs.

- [ ] **Step 1: Write failing tests**
  - `rfc8259_valid_invalid`: table of valid and invalid documents.
  - `depth_limit`: nesting 65 → error (limit 64), no recursion crash.
  - `duplicate_key`: `{"a":1,"a":2}` → error, because JWT claim parsing must not be ambiguous.
  - `bad_unicode`: lone surrogate `"\ud800"` and invalid UTF-8 → error.
  - `int_range`: `1e400` and values above 2^53 are reported as out of range by `bst_json_int`.
  - `writer_escapes`: control chars and quotes round-trip through parser.
- [ ] **Step 2: Run** `./dev make test-unit T=json` → FAIL.
- [ ] **Step 3: Implement** the parser with an explicit depth counter and arena allocation.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(core): add strict JSON parser and writer`

### Task 9: Error log and counters

**Files:**
- Create: `src/core/log.{c,h}`, `src/core/counters.{c,h}`
- Test: `tests/unit/test_log.c`

**Interfaces:**
- Produces: `bst_log(level, fmt, ...)` with compile-time format checks, `bst_log_init(fd, level)`; `bst_counter_id bst_counter_register(const char *name, const char *help, labels)`, `bst_counter_add(id, n)`, `bst_histogram_observe(id, value)`, operating on a per-process table that Phase 14 moves into shm without changing callers.

- [ ] **Step 1: Write failing tests**
  - `log_escapes_control`: message containing `\n` and `\x1b` prints as `\n` and `\x1b` escape text on a single line.
  - `log_level_filter`: below-level messages do not format arguments.
  - `log_fd_gone`: writes to a closed fd do not crash and increment a drop counter.
  - `histogram_buckets`: values land in the correct log-linear buckets.
- [ ] **Step 2: Run** `./dev make test-unit T=log` → FAIL.
- [ ] **Step 3: Implement.** Log lines go through a single `write` so concurrent processes do not interleave. Log calls are fine on error paths only; request-rate logging goes through the Phase 14 ring.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(core): add error log and counters`

### Task 10: Fuzz infrastructure

**Files:**
- Create: `fuzz/README.md`, `fuzz/harness.mk`, `scripts/fuzz-smoke.sh`
- Modify: `Makefile`

**Interfaces:**
- Produces: `make fuzz-smoke` builds every `fuzz/fuzz_*.c` with libFuzzer, ASan and UBSan, and runs each for 60 seconds with its `fuzz/corpus/<name>/`. `make fuzz T=name SECS=n` runs one. Any crash writes a reproducer to `fuzz/crashes/` and fails the run. Fixed crash inputs are copied to the corpus as regressions.

- [ ] **Step 1: Write failing test** `tests/integration/test_fuzz_infra.py::test_detects_crash`: a deliberately crashing harness in `tests/fixtures/` makes the script exit non-zero and writes a reproducer.
- [ ] **Step 2: Run** `./dev make test-int K=fuzz_infra` → FAIL.
- [ ] **Step 3: Implement** the Make fragment and script.
- [ ] **Step 4: Run** same → PASS, and `./dev make fuzz-smoke` → exit 0 for `fuzz_addr` and `fuzz_json`.
- [ ] **Step 5: Commit** `test: add fuzz harness infrastructure`
