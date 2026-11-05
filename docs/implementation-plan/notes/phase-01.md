# Phase 1 Notes

Decisions made during execution, work deferred, and what later phases must pick up. Read this before starting a later phase.

## Carry to later phases

- to Phase 3 loop task: next_ms can return 4294967295, clamp before epoll_wait (exceeds INT_MAX). bst_timer_arm is relative to w->now, so loop must advance wheel before running I/O callbacks or their timeouts fire early by the staleness. Don't call advance from a callback.
- to Phase 3 and 13: worker must unmap sibling workers' rings after fork or a compromised worker can forge records on or brick another's ring. Pop caller duties: max equals protocol record bound, SMALL from hostile peer means discard, drains need per-tick budget. (Superseded: resync runs only after CORRUPT, see ruling below.)
- to Phase 14: upgrade creates fresh rings per generation, per ruling.
- to Phase 14: map only the worker's own log ring, sibling tampering otherwise.
- to Phases 13 and 14: ring consumers drain on a periodic tick, not only wakeups; pass max = protocol record bound; resync on CORRUPT or SMALL once per tick.
- to Phase 12 Task 3 and Phase 13: must add bst_cidrset_overlaps(set, cidr) and test: allowlisted 2001:db8:1:2::5/128, abuser ::6, /64 block must be refused. Match-based check passes wrongly today (architecture.md section 7 rules 2 and 4).
- to Phase 12: operator docs state ::/0 doesn't match mapped IPv4 clients. deny_file adds /32 or /128 for bare hosts instead of loosening the parser.
- to Phase 11 JWT: NumericDate allows fractions and bst_json_int returns NOT_INTEGER, handle explicitly and fail closed. typeof(get(missing)) equals JSON null, required-claim checks must test presence. Cap JSON input length before parsing, for all consumers (JWT, ACME, admin API), about 45x memory.
- to Phase 3 sandbox: seccomp allowlist for logging needs write, rt_sigprocmask, rt_sigpending, rt_sigtimedwait.
- to Phase 3: don't add libc skips to sandbox tests, a skip-all on musl would be a false green (make test-int BUILD=musltest K=sandbox).
- Phase 3 seccomp allowlist, from core code. Workers: `write`, `rt_sigprocmask`, `rt_sigpending`, `rt_sigtimedwait` (log), `getpid`, `clock_gettime` (log prefix), `getrandom` (JSON objects over 8 members, OpenSSL), `mmap`, `munmap`, `mprotect`, `madvise`, `brk`, `mremap`, `futex` (malloc, aio pool), `exit_group`. Master only: `memfd_create`, `ftruncate`, `fcntl`, `fstat`, `newfstatat`, `close`. Keep `memfd_create` off the worker list. No file-open syscalls are needed for logging.
- Phase 3: a sandboxed ASan worker can't report: LSan's exit check and ASan report paths need `clone` and `/proc`. Plan `detect_leaks=0` or `_exit` in children. musl has no `execinfo`, so a crash handler's return-address walk needs `-fno-omit-frame-pointer`. Set aio pool thread stack sizes explicitly, because musl's default is 128 KiB.
- Phase 3: `T=` takes one name; `T='loop,io_tcp,uring_only' BACKEND=uring` in the plan needs the Makefile extended. `bst_timer` needs zero-init, and slab or arena memory isn't zeroed, so a miss is a wild write: add `bst_timer_init`.
- Phase 3 (blocking fd): master opens the log destination and gives pipes their own non-blocking description.
- Phase 13: `find src -name '*.c'` will sweep `src/xdp/*.bpf.c` into `LIB_SRCS`; exclude it.
- Phase 14: `BST_COUNTER_MAX 256` runs out around 17 vhosts at 15 series each, silently. `bst_log_dropped_total` should use the `bastion_*` metric prefix. `bst_jw_str`, `bst_jw_str_lossy`, `bst_siphash13` and `bst_spsc_push` abort under UBSan on a zero-initialised `bst_str`, so fix before the first absent log field. `bst_shm_attach` should verify seals.
- Phase 15: base images and apt packages are unpinned. Dep builds run as root in a privileged container with a writable repo including `.git/hooks`, which is a host code execution path if a dep is compromised. Five dep hashes are first-download pins (liburing, libbpf, brotli, zlib-ng, mimalloc); audit them. `curl` in `vm-run.sh` has no `--max-time`. x86_64 VM pins and the KVM path have never run here. Pool URLs for Debian kernels age out, and the bump steps are at the pin table in `scripts/vm-run.sh`. `current`'s snapshot fallback is unverified (service returned 503 and 504).
- Any phase: `build-deps.sh` doesn't rebuild dependents when a dependency's stamp changes, for example ngtcp2 on OpenSSL.
- Host disk is limited. `docker volume ls | grep bastion` shows superseded volumes: `bastion-build` is unused, and two small `bastion-build-*` volumes are left by the host test.

## Rulings

Each states what was decided, why, and what it costs if wrong.

- Ruling: work in place on phase branches, no git worktree — plan's Global Constraints declare the branch-per-phase workflow and the repo holds nothing else — cost if wrong: none, branches stay isolated from main.
- Ruling: pushing beyond the plan commit is not assumed — "push to main" read as the plan commit (52010c0). Phase merges go to local main; pushing them gets raised with the user — cost if wrong: user pushes later with one command.
- Ruling: commit trailer is `Co-Authored-By: Claude <noreply@anthropic.com>` — user instruction ("dont mention claude opus") and plan Global Constraint override harness default — cost if wrong: trailer amend.
- Ruling A: T1 creates `test-vm`, `fuzz-smoke`, `conformance` as targets that print "not implemented yet" and exit 2; T2 and T10 replace them, conformance replaced in Phase 15 or earlier when suites land — T2/T10 step 2 still fail as intended — cost if wrong: trivial Makefile edit.
- Ruling B: `./dev` selects Alpine image from docker/release.Dockerfile whenever args contain `BUILD=release`; deps live in `build/deps/<arch>-<glibc|musl>/` — keeps plan's exact command and prevents ABI mixing — cost if wrong: path rename.
- Ruling C: `test_dev_path_with_spaces` lives in `tests/host/test_dev_paths.sh`, run on host via `make`-free direct call; the pytest case skips with a reason if docker CLI is absent — only host can launch docker — cost if wrong: test relocation.
- Ruling D: T1 writes fixture to spec with `--version` proving binary discovery only; first real exercise in Phase 3 where server starts — cost if wrong: fixture fixes in Phase 3.
- Ruling E: type name is `bst_cidrset` everywhere — matches function prefix — cost if wrong: rename.
- Ruling F: T8 defines `src/core/err.h`: `typedef struct bst_err { char msg[256]; const char *file; int line; int col; } bst_err;` with `bst_err_set(bst_err *, fmt, ...)` (NULL-safe) — first task needing it — cost if wrong: struct edit before many consumers.
- Ruling G: T7 and T8 write harness and smoke it with direct `clang -fsanitize=fuzzer,address,undefined` for 10 s; T10 folds them in — satisfies "same task" without needing infra — cost if wrong: none.
- Ruling H: JSON depth 64 and wheel geometry are named compile-time constants, not tunables — internal safety/design constants, not operator knobs; parser limits stay fixed so JWT behaviour cannot be weakened by config — cost if wrong: add directive later.
- Ruling I: `bst_counter_register(const char *name, const char *help, const char *labels)`, labels is comma-separated `k=v` text or NULL — simplest form that works with Prometheus output — cost if wrong: signature edit before consumers exist.
- Ruling J: `T=` accepts both `cfg` and `fuzz_cfg` — keeps both spellings in plan valid — cost if wrong: none.
- Ruling: LICENSE stays MIT placeholder pending user answer — user never chose; flagged to user — cost if wrong: replace one file before release.
- Ruling: 5 first-download dep hashes (liburing, libbpf, brotli, zlib-ng, mimalloc) accepted, GitHub tag archives publish no checksum — hash pin still blocks later tampering, not a pre-existing compromise — cost if wrong: dep re-audit; recorded for Phase 15 security task.
- Ruling: docker/vm-kernel.Dockerfile omitted unless the implementer finds a real use — dev image already carries QEMU and tools, an unused Dockerfile is dead code — cost if wrong: add one small file.
- Ruling: user reply "yes" read as keep MIT license — user confirmed nothing more explicit — cost if wrong: replace LICENSE before release.
- Ruling: Task 4 missing RED satisfied by per-test mutation check — tests already exist, so that's the only way left to prove they can fail — cost if wrong: weak tests slip through.
- Ruling: chain total length capped at INT64_MAX — offsets and lengths are off_t — cost if wrong: one comparison changes.
- Ruling: bst_wheel_next_ms is a strictly positive lower bound, never late, -1 if empty, plan text amended — exact min needs a slot walk on every loop iteration, and an early wake is harmless — cost if wrong: up to about 3.9 spurious wakes per second.
- Ruling: bst_spsc_init formats once; new bst_spsc_attach seeds from shared indices and writes nothing; new bst_spsc_resync lets a consumer recover after a producer is replaced — respawn is normal per architecture, and pop already distrusts shared bytes — cost if wrong: hostile rd can misframe only into bytes attacker could publish anyway.
- Ruling: rings are not shared across generations; each generation gets fresh rings, old memfds retained by master until that generation exits — SPSC cannot serve two producers on a slot, keeps rollback intact — cost if wrong: small extra shm during upgrade.
- Ruling: bst_spsc_pop needs a fuzz harness in Task 6 though brief omitted it — it parses attacker framing in a root process, which the Global Constraint describes — cost if wrong: one extra small harness.
- Ruling: replacing a producer never triggers resync; consumer resyncs only after CORRUPT, per ring, at most once per drain tick; each side re-asserts its own index (pop on empty republishes differing rd, push on used>cap republishes wr) — keeps a crashed worker's last logs and heals hostile leftovers without signals, supersedes the earlier "master signals resync" wording — cost if wrong: one load on empty pop, and resync policy in callers changes.
- Ruling: amended R2 — consumer resyncs after CORRUPT or SMALL, at most once per drain tick; max equals protocol record bound — SMALL can only mean peer broke framing — cost if wrong: buggy honest caller's oversize record drops unread records.
- Ruling: amended R3 — every failed push reasserts differing wr; consumers must drain on a periodic tick — closes N1 with no write on a healthy ring — cost if wrong: one store per attacker write on failed push.
- Ruling: mandatory /len in bst_cidr_parse stands — every planned directive is <cidr>, bare address fails closed at load — cost if wrong: deny_file adds /32 or /128 itself.
- Ruling: bst_cidrset_overlaps deferred to Phase 12 Task 3 and Phase 13, not Task 7 — brief doesn't ask, the need is real: match() can't tell that a /64 block covers an allowlisted /128 — cost if wrong: added before escalation exists, so nothing shipped depends on it.
- Ruling: arena tail pointer fixed inside Task 8, promoting Task 3 minor — it makes JSON parsing a CPU denial of service at small chunk sizes — cost if wrong: none.
- Ruling: writer enforces structure but doesn't detect duplicate keys, header narrowed — duplicate detection in the writer costs memory for a caller bug — cost if wrong: an internal caller emits a duplicate key, which bst's own parser rejects in tests.
- Ruling: bst_jw_str_lossy added now, not Phase 14 — brief says logs use this writer, and attacker log suppression otherwise — cost if wrong: unused until Phase 14.
- Ruling: bst_json_int range is exactly +/-(2^53-1) — brief says "above 2^53" but 2^53 can't be told from 2^53+1 in a double consumer — cost if wrong: one comparison.
- Ruling: arena linearity test uses CPU-time deadline (30 s for 8 MiB, measured 0.5 s vs 95 s mutant), replacing earlier "work bound, not wall-clock" ruling; bst_arena_walks removed — a counter can't observe an uninstrumented walk — cost if wrong: flake on extreme CI load, CPU time avoids scheduler noise.
- Ruling: Task 9 missing true RED accepted through reviewer's mutation sweep (26 of 36 killed, survivors explained) — tests were written with the code, mutation is the only remaining proof — cost if wrong: survivors stay untested, listed as minors.
- Ruling: bst_counters_reset becomes bst_counters_reset_for_test under BST_TEST, absent from release — prevents wiping shared table after Phase 14 — cost if wrong: test build flag.
- Ruling: trap deaths get an honest summary with exit status, signal and replayable seed, not a captured reproducer — libFuzzer lacks a SIGTRAP handler and nothing in src uses traps — cost if wrong: a trap crash needs a seed replay to reproduce.
- Ruling: fuzz seed is per run from the clock, printed for every harness, overridable as SEED=n — constant seed would make Phase 15 long runs repeat the same exploration — cost if wrong: none, replay stays available through the printed seed.
- Ruling: all 8 Important plus 6 triaged minors fixed in Phase 1, before Phase 2 — cheap now, Phase 3 and 6 hit them first — cost if wrong: about one fix round.
- Ruling: log format is ISO-8601 UTC ms, pid per line, tag, level, message — plan silent, operators need when and which process — cost if wrong: format change while only test_log asserts it.
- Ruling: musl unit tier and test-tsan added now; x86_64 passthrough now, tier scheduled by plan amendment in Phases 3 and 4 — shipped binary is musl and x86_64 has security-critical paths; x86_64 deps deferred due to host disk — cost if wrong: arch bugs found later than they could be.
- Ruling: mimalloc wiring assigned to Phase 3 worker-start task — architecture required it and no phase owned it — cost if wrong: small task move.
- Ruling: build output per-tree volume by path hash, deps in shared volume — prevents another tree's objects producing false green — cost if wrong: extra volume per tree.
- Ruling: one more reviewed residual task on phase/01-foundation before merge, a deliberate departure from skill's "no second fix wave" — findings are load-bearing and small, a sandboxed glibc worker dies on its first log line, false dep stamps poison every later result; parking them costs more — cost if wrong: one extra review.
- Ruling: log time uses pure UTC date conversion, not gmtime_r, replacing earlier wording — gmtime_r opens files and allocates on glibc — cost if wrong: small date function, tested against gmtime_r.
- Ruling: BUILD=musltest fails on non-musl image; py3-pytest added to Alpine; VM kernel cache moved to shared volume — prevents false musl results and 697 MB per tree — cost if wrong: small build edits.

## Deferred minor findings

Triaged by the whole-phase review as safe to defer. Owners are in the carry list where one is needed.

- Task 1: minor (deferred): TAP failure exit code only checked by hand through TAP_SELFTEST_FAIL, no automated assertion (test_smoke.c)
- Task 1: minor (deferred): tap_register drops tests past 256 silently (tap.h)
- Task 1: minor (deferred): conftest stdout.log handle unclosed; "io {" substring match fragile (conftest.py)
- Task 1: minor (deferred): Makefile pkg-config 2>/dev/null hides failures
- Task 1: minor (deferred): clean leaves build/deps undocumented; TAP order depends on constructor order; dev --mount breaks on comma in path
- Task 2: minor (deferred): guest guard fixture belongs in tests/vm/conftest.py once more VM tests land
- Task 2: minor (deferred): Landlock test reads LSM list only, no landlock_create_ruleset call (Phase 3 sandbox VM tests cover enforcement)
- Task 2: minor (deferred): initrd cache key ignores dev-image binaries; no lock around extraction; staging dir leaks on failure; curl lacks --max-time; misplaced shellcheck comment; zstd maybe unused; vm-run.sh does five jobs
- Task 2: minor (deferred): check_pin_failure.sh leaves .keep if killed mid-test; skips on non-aarch64; x86_64 and KVM paths never run here; current-kernel snapshot fallback unverified (service 504)
- Task 3: minor (deferred): arena chunk append walks list (no tail pointer); bst_buf_ref(NULL) crashes while unref(NULL) tolerated; dead stride branch in slab.c; slab put lacks double-put detection; no redzone between arena allocations; missing tests for slab_new(0,n), slab_new(n,0), buf_new(0), oversized chunk mapped accounting
- Task 3: minor (deferred): test_mem.c duplicates ASan detection from poison.h, #error catches drift
- Task 4: minor (deferred): to_iov max>=0 undocumented; doc that chained buffers are immutable and non-moving; add returns -1 for both bad args and exhaustion; test fake fds uncommented; no test shares one slab between two chains
- Task 5: minor (deferred): periodic timers cost elapsed/period callbacks on catch-up, header claim false, consider coalescing at loop layer; clock_gettime result unchecked in time.c and "1-4 ms" should allow 10 ms on HZ=100; next_ms probes up to 1024 slots per call, bitmap possible; wheel.c:73 comment wrong for clamped timers; MAX_DELTA needs _Static_assert(SPAN_BITS<64); b<<shift wraps near UINT64_MAX (unreachable); document advance and next_ms from a callback as forbidden/approximate; no tests for self-cancel, arming another timer mid-advance, cancelling a cascaded same-tick timer
- Task 5: minor (deferred): ticks_run counts events not slot probes; public struct field exists mainly for tests
- Task 6: minor (deferred): no F_SEAL_SEAL in shm.c (upgrade path can be denied by a process holding the fd); bst_shm_attach does not verify seals; memfd mode 777, try MFD_NOEXEC_SEAL then fall back on EINVAL; prefix read by plain memcpy of racing bytes; wr and rd share a 128-byte block; no _Static_assert(ATOMIC_LLONG_LOCK_FREE==2); test thread hang on failure; dead store test_shared.c:224; init NULL and cap>UINT32_MAX untested; NULL+0 in hash.c and ring.c; citation URL unpinned
- Task 6: minor (deferred): resync trusts shm.wr, an honest producer's next publish makes pop CORRUPT once then second resync recovers; ring_producer_respawn attaches consumer only after children exit and uses _exit not SIGKILL; fuzz_spsc single-threaded, not run by make until Task 10
- Task 6: minor (deferred): ring.h and architecture.md say "every failed push" but a can-never-fit push returns before reload and doesn't republish; wr healing also needs a producer push attempt, idle producer strands unread records until its next push. Both-peers-hostile not scanned.
- Task 7: minor (deferred): duplicate_add second half observes nothing; no test for 0:0:0:0:0:ffff forms, ::FFFF, ::ffff:0:0/96, 45-byte max; many_prefixes_against_reference has no reference; addr.h comment wrong on max length and literal 45 unnamed; duplicate CBAD("::/129") line; consider warn_unused_result on add
- Task 7: minor (deferred): no assertion for parser ::ffff:0:0/96 to 0.0.0.0/0, nor add with host-bits-set mapped rule
- Task 8: minor (deferred): json.h undocumented memory amplification (about 45x, callers must cap len, per-consumer config directive); bst_jw_str with NULL,0 is UB; line counter overflows after 2.2 GiB newlines while col saturates; getrandom failure silently falls back to address-derived key, should fail parse, reachable under seccomp; typeof(NULL) returns BST_JSON_NULL so a missing claim looks like JSON null; duplicate-key error points past closing brace; weak e.col test, no mixed depth test, no err overflow test, no OOM test (-Dbst_arena_alloc=faulty_alloc works)
- Task 8: minor (deferred): lossy path reserves 6x input up front (sticky error on failure); per-byte replacement rather than maximal-subpart
- Task 8: minor (deferred): test_json clock_gettime results unchecked; comment cites -O2 95 s while report measured 277 s under ASan
- Task 9: minor (deferred): log.h should state bst_log isn't async-signal-safe; add tests for surviving mutants: pre-existing pending SIGPIPE preserved, EINTR retry, UTF-8 bounds F0/F4/E0, bucket guard, init-level clamp; dead straddle branch at log.c:~159 and redundant truncated=true
- Task 9: minor (deferred): make test-unit BUILD=release fails to compile without BST_TEST; log.h re-init vs counters.h startup-only registration; drop_id plain static is TSAN-visible if init races logging; stale drop_id after reset_for_test (test-only); log_drops_before_init_move_into_counter test name misleading
- Task 10: minor (deferred): scratch dir leaks on interrupt, add trap; SECS and FUZZ_TIMEOUT unvalidated; tests don't cover UBSan fatal or leak; README omits env knobs; fuzz/corpus/spsc/ops seed low value; no outer wall-clock guard on corpus load
- Task 10: minor (deferred): SEED=0 and SEED above 2^32-1 accepted, printed seed may not replay; build-failed harnesses print no seed line; temp log orphaned on interrupt; Test unit written to grep is unanchored; same SEED passed to all harnesses in multi-harness run
- Task R: minor (deferred): log_first_line_opens_no_files compiles out outside x86_64 and aarch64; filter doesn't cover stat or access; build-deps doesn't rebuild dependents when a dep's stamp changes (e.g. ngtcp2 on openssl)

## Final verification on 87390a4

`test-unit`, `test-unit BUILD=musltest`, `test-tsan`, `test-int` (10 passed, 1 skipped), `test-int BUILD=musltest` (1 passed, 10 skipped: fuzz tests need glibc), `test-vm K=kernel_features` on `current` and `floor` (6 passed each), `test-deps`, `BUILD=release` (static, OpenSSL 3.5.9), `fuzz-smoke SECS=5`, and `tests/host/test_dev_paths.sh` all exit 0. x86_64 has not run: arm64 only so far.
