# Phase 3: I/O Runtime and Processes

**Goal:** The I/O API on both backends, all requested socket options, the master/worker/helper model, and the sandbox from the start.

**Architecture:** See [architecture.md](architecture.md) sections 1, 3, 4 and 8. A shared backend conformance test suite runs identically on io_uring and epoll.

**Spec:** [architecture.md](architecture.md), [README.md](README.md).

## Review Focus

1. Peer resets during a large file send → one completion with an error, fd and buffers released, no SIGPIPE. (Task 2)
2. io_uring provided buffers run out under burst → the recv rearms when buffers return, with no lost data or hang. (Task 3)
3. Running in a container whose seccomp profile blocks io_uring → automatic epoll fallback, with a logged reason. (Task 4)
4. `EMFILE` during an accept storm → accept pauses and resumes, without a busy loop. (Task 9)
5. Kernel lacks an optional socket option → warning, with server still starting, except for options marked `require`. (Task 5)

---

### Task 1: Loop API with epoll, timers and wakeups

**Files:**
- Create: `src/io/loop.h`, `src/io/loop.c`, `src/io/loop_epoll.c`, `src/io/sock.{c,h}`
- Test: `tests/unit/test_loop.c`

**Interfaces:**
- Produces: `bst_loop_*` and `bst_io_poll` from architecture.md section 3; `bst_loop_timer_arm(bst_loop *, bst_timer *, ms, cb, ud)`; `bst_sock *bst_sock_wrap(bst_loop *, int fd)`; `bst_sock_close(bst_sock *)`, which guarantees that no callback runs after it returns. `bst_loop_wake(bst_loop *)` is thread-safe.

- [ ] **Step 1: Write failing tests** (these run per backend through `BST_TEST_BACKEND`)
  - `timer_fires`: a timer fires within 10 ms of the deadline in a running loop.
  - `poll_ready`: socketpair write → `bst_io_poll` callback with `POLLIN`.
  - `close_cancels`: closing with a pending poll → callback never runs.
  - `wake_from_thread`: wake from another thread exits `epoll_wait` promptly.
  - `stop_inside_callback`: `bst_loop_stop` in a callback returns from `bst_loop_run` after the current batch.
- [ ] **Step 2: Run** `./dev make test-unit T=loop BACKEND=epoll` → FAIL.
- [ ] **Step 3: Implement.** Edge-triggered epoll, with deferred frees processed at the end of each iteration so closed sockets are safe.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(io): add loop API with epoll backend`

### Task 2: Stream I/O, file sends and thread pool

**Files:**
- Modify: `src/io/loop_epoll.c`
- Create: `src/io/aio.{c,h}`, `src/io/net_common.c`
- Test: `tests/unit/test_io_tcp.c`

**Interfaces:**
- Produces: `bst_io_accept_start/stop`, `bst_io_recv_start/stop`, `bst_io_send`, `bst_io_connect`, `bst_aio_submit` from architecture.md.

- [ ] **Step 1: Write failing tests**
  - `send_chain_large`: 64 MiB chain of mem and file segments arrives byte-identical at a slow reader.
  - `completion_once`: exactly one completion per send, including on errors.
  - `peer_reset_midsend`: RST during send → completion with `ECONNRESET`, no SIGPIPE, no leak.
  - `recv_eof`: peer shutdown → callback with `(NULL, 0)`.
  - `connect_refused`: → `ECONNREFUSED` by callback.
  - `aio_runs_off_loop`: work executes on another thread, `done` on the loop thread.
  - `sendfile_truncated_file`: file truncated during a send → error completion instead of a spin.
- [ ] **Step 2: Run** `./dev make test-unit T=io_tcp BACKEND=epoll` → FAIL.
- [ ] **Step 3: Implement** with `writev` plus `sendfile`, `MSG_NOSIGNAL`, and `readahead` in the pool when a `preadv2(RWF_NOWAIT)` probe reports non-resident pages. Pool size comes from `aio_threads`.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(io): add TCP I/O, file sends and aio pool on epoll`

### Task 3: io_uring backend

**Files:**
- Create: `src/io/loop_uring.c`, `src/io/uring_bufs.c`
- Uses: `src/core/buf.{c,h}` (already extended in Phase 1 with `bst_buf_wrap` and `bst_buf_init`)
- Test: reuses `tests/unit/test_loop.c`, `tests/unit/test_io_tcp.c`; adds `tests/unit/test_uring_only.c`

**Interfaces:**
- Consumes: liburing. Implements the same API as epoll, with no new public symbols. Provided-buffer ring slots are delivered as `bst_buf` through `bst_buf_wrap` (or `bst_buf_init` over a pooled header) with a release hook that returns the slot to the ring.

- [ ] **Step 1: Write failing tests** (`test_uring_only`)
  - `multishot_accept_burst`: 1,000 connections → exactly 1,000 callbacks.
  - `multishot_recv_rearms`: rearms automatically when the kernel ends multishot.
  - `buffer_exhaustion`: 4 buffers with a 1 MiB stream and a slow consumer → all bytes delivered in order once buffers return.
  - `cq_overflow`: small CQ under burst → nothing lost.
  - `splice_file_send`: file segments reach the peer byte-identical through the pipe pool.
- [ ] **Step 2: Run** `./dev make test-unit T='loop,io_tcp,uring_only' BACKEND=uring` → FAIL.
- [ ] **Step 3: Implement.** Ring setup with `SINGLE_ISSUER`, `DEFER_TASKRUN`, `COOP_TASKRUN`, `R_DISABLED`. Provided buffer rings for recv, `IORING_REGISTER_RING_FDS`, multishot accept and recv, linked ops where they reduce syscalls, pending-send tracking so that closes wait for in-flight completions. `IORING_OP_SEND_ZC` remains an optional path above a size threshold set by `uring_send_zc_min`, measured in Phase 15 before being enabled by default. SQPOLL and NAPI are config options.
- [ ] **Step 4: Run** same → PASS on both backends.
- [ ] **Step 5: Commit** `feat(io): add io_uring backend`

### Task 4: Backend selection and fallback

**Files:**
- Create: `src/io/backend.c`
- Modify: `src/io/loop.c`
- Test: `tests/integration/test_backend.py`

**Interfaces:**
- Produces: `io { backend, uring_entries, uring_bufs, uring_sqpoll, uring_napi, uring_send_zc_min, aio_threads, aio_queue }` directives. Log line `io backend: <name> (<reason>)`. Metric `bastion_io_backend{name}`.

- [ ] **Step 1: Write failing tests**
  - `test_auto_prefers_uring`: privileged environment → log says `uring`.
  - `test_fallback_seccomp_blocked`: a test seccomp filter returning `EPERM` for `io_uring_setup` makes `auto` choose `epoll`, with the reason logged.
  - `test_sysctl_disabled`: `kernel.io_uring_disabled=2` → epoll with reason.
  - `test_forced_uring_fails`: `backend uring` with the filter → startup error, exit 1.
  - `test_flag_ladder`: simulated `EINVAL` on `DEFER_TASKRUN` → steps down and still uses io_uring.
- [ ] **Step 2: Run** `./dev make test-int K=backend` → FAIL.
- [ ] **Step 3: Implement** as designed in architecture.md section 3. `BST_TEST_URING_FAIL=` env var, compiled only in non-release builds, injects setup errors.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(io): select backend at runtime with fallback`

### Task 5: Listeners and socket options

**Files:**
- Create: `src/io/listener.{c,h}`, `src/io/sockopts.c`, `src/io/io_directives.c`
- Test: `tests/integration/test_sockopts.py`, `tests/vm/test_sockopts_vm.py`

**Interfaces:**
- Produces: `bst_listener_create(const bst_cfg_listen *, int slots, int *fds, bst_err *)`; `bst_sock_apply_accepted(int fd, const bst_tcp_profile *)`. `tcp_profile` directives: `fastopen`, `fastopen_key`, `defer_accept`, `busy_poll`, `prefer_busy_poll`, `busy_poll_budget`, `nodelay`, `quickack`, `congestion`, `notsent_lowat`, `user_timeout`, `keepalive`, `rcvbuf`, `sndbuf`, `pacing_rate`, `mark`, `freebind`, `backlog`, `steering`. Each accepts a trailing `require`.

- [ ] **Step 1: Write failing tests**
  - `test_reuseport_slots`: 4 workers → 4 sockets; connections from many source ports reach more than one worker.
  - `test_fastopen`: client with `TCP_FASTOPEN_CONNECT`, second connection delivers data in SYN (counted by `TCPFastOpenPassive` in `/proc/net/netstat`).
  - `test_defer_accept`: a connection that sends nothing is not accepted before the timeout.
  - `test_getsockopt_roundtrip`: each configured option reads back from the socket via a debug dump.
  - `test_missing_opt_warns`: unavailable `congestion bbr` under LinuxKit → warning and successful start.
  - `test_missing_opt_require`: `congestion bbr require` → exit 1.
  - VM tier `test_bbr_applied`, `test_busy_poll_applied`: read back on a stock kernel.
- [ ] **Step 2: Run** `./dev make test-int K=sockopts` → FAIL.
- [ ] **Step 3: Implement.** Also set `IP_BIND_ADDRESS_NO_PORT` on outbound sockets later in Phase 9. Doc text must describe interactions: `TCP_DEFER_ACCEPT` delays empty connections, and TFO data can be replayed, so it obeys the same safe-method policy as 0-RTT.
- [ ] **Step 4: Run** `./dev make test-int K=sockopts && ./dev make test-vm K=sockopts` → PASS.
- [ ] **Step 5: Commit** `feat(io): add listeners with configurable TCP socket options`

### Task 6: UDP batch I/O

**Files:**
- Create: `src/io/udp.{c,h}`
- Test: `tests/unit/test_udp.c`

**Interfaces:**
- Produces: `bst_udp_start(bst_sock *, bst_udp_recv_cb, void *ud)`, delivering a batch of `{bst_buf *, src, dst, ecn, gro_segment_size}`; `bst_udp_send(bst_sock *, bst_udp_pkt *pkts, int n, bst_done_cb, void *ud)` with GSO segment size, `dst` source-address selection through `IP_PKTINFO`/`IPV6_RECVPKTINFO`, and ECN marking. Options `udp_gso`, `udp_gro`, `rcvbuf`.

- [ ] **Step 1: Write failing tests** (both backends)
  - `batch_recv`: 64 sent datagrams received with correct sources.
  - `gro_split`: GRO-coalesced buffers split at segment boundaries.
  - `gso_send`: GSO send of 10 × 1200 bytes yields 10 packets at the peer.
  - `gso_unsupported_fallback`: simulated `EIO` from GSO → plain send, GSO then disabled for the socket.
  - `pktinfo_reply`: reply leaves from the address the query arrived on, on a multi-address host.
  - `ecn_roundtrip`: TOS ECT(0) reaches receiver metadata.
- [ ] **Step 2: Run** `./dev make test-unit T=udp` → FAIL.
- [ ] **Step 3: Implement** with `recvmmsg`/`sendmmsg` on epoll and multishot `RECVMSG`/`SENDMSG` on io_uring.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(io): add batched UDP I/O with GSO and GRO`

### Task 7: Master, workers and helper

**Files:**
- Create: `src/proc/master.{c,h}`, `src/proc/worker.{c,h}`, `src/proc/helper.{c,h}`, `src/proc/signals.c`, `src/proc/channel.c`
- Test: `tests/integration/test_process.py`

**Interfaces:**
- Produces: `int bst_master_run(bst_config *)`, `void bst_worker_main(int slot, bst_runtime *)`, `void bst_helper_main(bst_runtime *)`. `bst_runtime` holds compiled config, listener fds, shm mappings and a master channel (`socketpair` with typed messages). Signals on master: `TERM`/`INT` fast stop; `QUIT` graceful stop. Worker hook `bst_worker_on_conn` is set by HTTP phases. Directives: `shutdown_timeout`, `group`, `worker_rlimit_nofile` are new. `workers`, `user` and `pid` were registered by Phase 2 (`src/config/core_directives.c`): consume them and extend that table entry and its apply, do not register them again (a second registration is a startup error). This is the task that starts workers, so it also links mimalloc statically (per architecture.md section 2, in glibc and musl builds) and registers it with `CRYPTO_set_mem_functions` before any OpenSSL call, as in architecture.md section 2.

- [ ] **Step 1: Write failing tests**
  - `test_worker_count`: `workers 4` → 1 master, 4 workers, 1 helper.
  - `test_worker_crash_respawn`: `kill -9` of a worker → replacement within 1 second, others keep serving.
  - `test_crash_loop_backoff`: a worker that crashes on start → respawn delay grows, capped at 30 s, and master logs at error level.
  - `test_helper_crash_respawn`: same for the helper.
  - `test_graceful_stop`: `QUIT` during a slow transfer completes it and then exits 0.
  - `test_shutdown_timeout`: `QUIT` with a stuck client → exit after `shutdown_timeout`.
  - `test_master_death`: `kill -9` master → workers exit, through `PR_SET_PDEATHSIG` and the channel EOF, no orphans.
  - `test_no_zombies`: after 10 worker kills, no `Z` state children remain.
  - `test_privilege_drop`: as root with `user nobody`, workers run as nobody and master stays root.
  - `test_mimalloc_registered`: in a worker, `CRYPTO_get_mem_functions` returns mimalloc's `mi_malloc`, `mi_realloc` and `mi_free`, and the registration happened before the first OpenSSL call.
- [ ] **Step 2: Run** `./dev make test-int K=process` → FAIL.
- [ ] **Step 3: Implement** using `signalfd` in master's small loop. Workers set `PR_SET_PDEATHSIG` after dropping privileges, then recheck `getppid`. A crash handler writes signal number and return addresses to the error log using only async-signal-safe calls.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(proc): add master, worker and helper lifecycle`

### Task 8: Sandbox

**Files:**
- Create: `src/proc/sandbox.{c,h}`, `src/proc/seccomp_tables.c`, `src/proc/landlock.c`
- Test: `tests/integration/test_sandbox.py`, `tests/vm/test_sandbox_vm.py`, `tests/fixtures/sandbox_probe.c`

**Interfaces:**
- Produces: `int bst_sandbox_apply(const bst_cfg_sandbox *, bst_sandbox_role, const bst_sandbox_paths *, bst_err *)`, plus `bst_uring_restrict(ring)`. Directives in `sandbox {}`: `seccomp`, `landlock`, `namespaces`, `drop_capabilities`, `extra_read`, `extra_write`. `BST_TEST_SANDBOX_PROBE` hook in non-release builds attempts a named forbidden action from the worker.

- [ ] **Step 1: Write failing tests**
  - `test_execve_killed`: worker attempting `execve` is killed with `SIGSYS`, and master logs and respawns it.
  - `test_ptrace_blocked`, `test_socket_raw_blocked`, `test_bpf_blocked`, `test_mount_blocked`.
  - `test_uring_restricted`: a worker submitting a non-allowlisted opcode such as `IORING_OP_SOCKET` receives `-EACCES`, and `IORING_REGISTER` of new restrictions fails.
  - VM tier `test_landlock_read`: worker reading `/etc/passwd` is denied, while the serving root is readable.
  - VM tier `test_landlock_write`: worker writing outside cache and temp directories is denied.
  - `test_no_caps`: `/proc/<worker>/status` shows `CapEff`, `CapPrm` and `CapBnd` all zero, `NoNewPrivs: 1`, and `Seccomp: 2`.
  - `test_not_dumpable`: `Dumpable` is 0 and `RLIMIT_CORE` is 0.
  - `test_log_mode`: `seccomp log` lets the probe proceed and records it.
  - `test_missing_landlock_warns`: kernel without Landlock → warning and start, unless `require`.
  - `test_all_tests_sandboxed`: pytest fixture fails any test whose worker has `Seccomp != 2`, unless the test opts out.
  - `test_no_new_threads`: a worker attempting `clone` or `fork` is killed, `clone3` returns `ENOSYS`, and the aio pool still works.
  - `test_uring_async_under_sandbox`: an io_uring file read that has to punt to a kernel worker completes inside the sandbox.
  - Acceptance: the seccomp tests run against the musl binary as well as the glibc one, with `./dev make test-int BUILD=musltest K=sandbox` (the `BST_TEST_SANDBOX_PROBE` hook exists in that build, which is not `BUILD=release`), once per phase from this task on, and the x86_64 seccomp table is exercised under `./dev --platform linux/amd64`.
- [ ] **Step 2: Run** `./dev make test-int K=sandbox && ./dev make test-vm K=sandbox` → FAIL.
- [ ] **Step 3: Implement** in the order set out in architecture.md section 8, using hand-built BPF filters, with `x86_64` and `aarch64` tables and an `AUDIT_ARCH` check. No libseccomp. The worker allowlist is the shortest list that lets all current tests pass. It grows only with a justified comment.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(proc): sandbox workers with seccomp, Landlock and capability drop`

### Task 9: Overload protection

**Files:**
- Create: `src/io/admission.{c,h}`
- Test: `tests/integration/test_overload.py`

**Interfaces:**
- Produces: `bool bst_admit_conn(bst_worker *)`, `bst_worker_mem_charge/release(size_t)`, `bst_overloaded(const bst_worker *)`. Directives in `limits {}`: `max_connections`, `worker_memory`, `overload_status`, `overload_retry_after`, `reserve_fds`.

- [ ] **Step 1: Write failing tests**
  - `test_emfile`: fd limit reached → accept pauses for a backoff period, CPU stays below 10%, service resumes after fds free.
  - `test_max_connections`: above the limit, new connections are closed immediately and counted.
  - `test_memory_budget`: over budget, new requests get `overload_status` with `Retry-After`, and memory stays below the cap.
  - `test_recovery`: after load ends, the server returns to normal without restart.
- [ ] **Step 2: Run** `./dev make test-int K=overload` → FAIL. The tests need the Phase 4 `return` handler, so this task's integration tests use a raw accept-and-respond test mode compiled into non-release builds until Phase 4 replaces it.
- [ ] **Step 3: Implement** using per-worker atomic counters. Keep one reserved fd, used to accept and immediately close when at `EMFILE`, so clients are not left waiting in the queue.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(io): add admission control and memory budgets`
