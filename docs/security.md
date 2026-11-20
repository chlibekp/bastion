# Security review (Phase 15, Task 5)

Done on 2026-11-20 at commit 7308908 plus the fixes listed here. The threat model is in
[threat-model.md](threat-model.md); the reporting policy in [SECURITY.md](../SECURITY.md).

**Bastion has had automated review only. An independent human security audit is recommended
before any internet-facing production use.** The tools and reviewer passes below find classes of
bugs; they do not replace a person reading the protocol code against the RFCs with an attacker's
eye.

## 1. Static analysis

All tools run inside the dev image (`docker/dev.Dockerfile`, Debian trixie), which pins
`clang-tools-19=1:19.1.7-3+b1` (scan-build) and `cppcheck=2.17.1-2`. CI runs both in the
`static-analysis` job.

### clang static analyzer (scan-build 19.1.7)

```
./dev bash -c 'make deps && CCC_CC=clang scan-build-19 --use-cc=clang -o build/scan make -k -j8 BUILD=debug'
```

66 distinct reports over the whole tree (`src/`, the test hooks and fixtures, `BST_TEST` on),
from three runs: the final clean plist run gave 62, and an earlier run also reported
`http/h1/stream_ops.c:188`, `http/h2/sched.c:486` and `http/h2/bridge.c:209,251` (the analyzer's
path budget makes the set vary a little between runs). All 66 are triaged.

| Finding | Count | Verdict |
|---|---|---|
| `src/proxy/forward_headers.c:144` NULL to `memcpy` | 1 | **Fixed** (ce34743): an out-of-memory `cat()` for the `Forwarded` host element was not checked. The same review found that an out-of-memory read of the trusted `X-Forwarded-For` / `Forwarded` chain was taken as "no earlier hops"; both now fail the request. No regression test: the arena has no failure injection, and the path is out-of-memory only. |
| `src/io/test_listeners.c:248` leak of `pf` / `held` | 2 | **Fixed** (49e87c9): test-only code (`BST_TEST`), leak when one of two `calloc`s fails. |
| Use after free in list teardown loops: `handlers/ofcache.c:160`, `cache/ram.c:217,219`, `http/h3/h3_bridge.c:1006`, `http/h3/quic.c:1189` | 5 | False positive. Each loop calls a function that unlinks the element from the list it walks and then frees it, and re-reads the list head (or a `next` saved before the call) on the next turn. The analyzer does not see that the free also removes the element from the list. |
| Use after free with a busy/depth counter: `http/h2/conn.c` (10), `http/h1/conn.c:1057`, `http/h1/stream_ops.c:188`, `http/h2/sched.c:486`, `http/h2/bridge.c:209,251`, `tls/conn.c:185,439,584`, `proxy/client_h2.c` (9) | 27 | False positive. These objects are freed only when a re-entrancy counter (`depth`, `busy`) reaches zero; callers hold the counter across every callback that might close the object. The analyzer assumes the counter is already zero inside the guarded region. These paths run under ASan in every unit and integration test and in the HTTP/2 and QUIC fuzzers. |
| Garbage value read from a kernel-filled `sockaddr_storage`: `proc/systemd.c:152,156`, `io/net_common.c:99`, `http/h1/conn.c:919`, `ops/metrics.c:896`, `http/h3/quic.c:124` | 6 | False positive: `accept4`, `getsockname` and ngtcp2 fill the structure; the analyzer does not model them. |
| Garbage value from a caller-provided buffer: `filters/trace.c:70`, `proxy/dns.c:132`, `proc/reload.c:90` | 3 | False positive: the callers pass fully initialised strings and arrays (a parsed traceparent; a NUL-terminated name decoded from a reply; `snprintf` output). |
| Uninitialised value on an error path: `ops/tuning_directives.c:64`, `config/parser.c:380,595` | 3 | False positive: the value is assigned only when the called function failed, and that failure is checked before the value is used (`!ok` returns; `fail_oom` returns -1). |
| NULL dereference against an invariant: `core/slab.c:67` (grow succeeded so `free` is set), `core/chain.c:178,187` (`n <= src->len` and the split segment allocated in the first pass), `core/json.c:585` (`dig[i]` is read only below `dlen[i]`), `config/validate.c:154`, `proc/master_setup.c:168` (every listener has a config), `ops/acme_http01.c:157` (a `bst_str` with length has a pointer) | 7 | False positive. |
| NULL to a `nonnull` parameter: `ops/ctl.c:470,528,547,558` (`argv[i]` below `argc`; `pos[0]` when `npos == want >= 1`), `config/template.c:93,101,123` (`name_ok` rejects a NULL name first) | 7 | False positive. |
| `core/log.c:288` buffer size versus `send` length | 1 | False positive: `write_line` is given `pos`, which `bst_log_write_` keeps below the line buffer's size. |
| `sec/challenge.c:682` stream state after `fread` | 2 | False positive: the loop ends at the first short read, and the stream is closed after it. |
| `proc/test_hooks.c:198` leak | 1 | Intended: the `BST_TEST_MASTER_LEAK` hook leaks on purpose so LeakSanitizer tests can see it. |
| `proc/master.c:1012` dead store | 1 | Intended: `real` is overwritten only in `BST_TEST` builds. |

### cppcheck 2.17.1

```
./dev cppcheck -j8 --std=c11 --enable=warning,portability -q -D_GNU_SOURCE -DBST_TEST -Isrc \
  --suppress=missingIncludeSystem --suppress=normalCheckLevelMaxBranches src
```

Also run with `-D__aarch64__` and `-D__x86_64__` over `src/proc/{sandbox,signals,seccomp,seccomp_tables}.c`
(no findings), and over `src/xdp` with the libbpf headers and `SEC()` defined (findings below).

| Finding | Count | Verdict |
|---|---|---|
| `auth/jwks.c:194` `%u` given an `int` | 1 | **Fixed** (49e87c9). |
| `subtractPointers`: `config/compile.c:359`, `config/schema.c:20`, `config/template.c:41`, `sec/challenge.c:467,472`, `xdp/loader.c:300`, `xdp/reuseport.c:102` | 7 | False positive: `__stop_x - __start_x` linker section bounds and `_end - _start` of embedded blobs, the standard idiom. |
| `nullPointerOutOfMemory`: `tls/conn.c:881-889` | 9 | False positive: `c` is checked (`ssl == NULL` covers `c == NULL`, since `s` and `ssl` are only made when `c` is). |
| `nullPointerOutOfMemory`: `proxy/upstream.c:228,230`, `proc/test_hooks.c:98,196` | 4 | Test-only (`BST_TEST`) hooks; an allocation failure there aborts the test, which is acceptable. |
| `uninitvar`: `http/h2/frame.c:242`, `io/tcp_profile.c:48`, `route/vars.c:88`, `tls/ja4.c:275,285`, `ops/admin.c:490`, `ops/tuning_directives.c:60` | 8 | False positive: each array is read only below the count of elements written (`nentries`, `nib`, `o`, `nc`, `nsorted`), and `s` in admin.c is read only when `bst_json_str` succeeded (`why == NULL`). The JA4 bounds were checked by hand: `ciphers_len / 2 <= MAX_CIPHERS` and `next <= BST_JA4_MAX_EXT` are enforced before the copies (ja4.c:265). |
| `http/headers.c:167` NULL `name` | 1 | False positive: `name` is read only when `id == BST_H_UNKNOWN`, and those callers pass a name. |
| `xdp/block.c:167` leak of `b.exempt` | 1 | False positive: `b` (with `exempt`) is stored in the returned backend's `ctx` and freed by its `free` operation. |
| `config/cli.c:85`, `io/test_listeners.c:252` index used before limit check | 2 | Style: both strings/arrays are valid at that index (NUL-terminated argument; `i < n`). |
| `io/backend.c:79` identical condition | 1 | Style: redundant `cap == 0` re-check, harmless. |
| `preprocessorErrorDirective`, `unknownMacro` | 6 | Configuration only: re-run with the architecture and BPF macros defined, as above. |

### CodeQL

**Not executed locally.** CodeQL is not packaged in Debian, and no pinned release with a
verified sha256 was installed into the dev image for this review. A `codeql` job
(`github/codeql-action`, `c-cpp`, `build-mode: none`, `security-extended` queries) was added to
`.github/workflows/ci.yml`; its first results need the same triage as the tables above.

## 2. Hand audit

### `memcpy` / `memmove`

391 call sites in `src/`. Every site in code that handles bytes from the network was read with
its length's origin traced to a check: the HTTP/1.1 request and response parsers, HPACK, HTTP/2
frames (server and upstream client), the HTTP/3 bridge, PROXY protocol v1/v2, DNS replies, UDP
control messages, the JA4 ClientHello reader, Basic auth, the ACME and OCSP HTTP client, ACME
http-01. No unchecked copy was found. Notable bounds:

- HTTP/2 header blocks: server side `max_header_list_size * 4 + 1024`
  (`http/h2/frames.c:23`); upstream side `MAX_HEADER_BLOCK` = 256 KiB
  (`proxy/client_h2.c:691`), both checked before growing.
- HTTP/2 upstream read buffer: a frame longer than `OUR_MAX_FRAME` is a connection error before
  its payload is buffered (`http/h2/frame.c:32`).
- PROXY v2: total length `16 + body` capped at `BST_PP_MAX` and the address block checked
  against `body` before copying (`proxy/proxyproto.c`).
- UDP control messages: the copy is capped at `BST_UDP_CTL`, every `cmsg_len` checked against
  the end, every payload against its type's size (`io/udp.c:60-124`).
- DNS: `rdoff + rdlen <= len` checked when the record is read; address copies require
  `rdlen == 4 / 16` (`proxy/dns.c:153,225`).
- Chunked bodies in the ACME/OCSP client: at most 8 hex digits, total capped at
  `BST_HC_MAX_BODY` before copying (`ops/http_client.c`).

The remaining sites (config compile, logging, metrics, cache index, admin, XDP map setup) copy
fixed-size values or lengths from trusted configuration; they were reviewed by reading the
grep listing, not traced one by one.

### Size arithmetic on network-derived values

Checked in the same files: lengths are compared as `a + b > limit` only where both terms are
already bounded far below `SIZE_MAX` (frame lengths are 24-bit, header blocks capped, chunk sizes
32-bit), so the additions cannot wrap. `bst_chain_take` checks `n > INT64_MAX - dst->len`.

### Phase 12 io_uring mid-header reset

Phase 12 noted that under io_uring a client sending RST in the middle of its request headers
could keep its `limit_conn` slot until `client_header_timeout`. It does **not reproduce** now on
either backend: `tests/integration/test_acl.py::test_reset_mid_headers_gives_slot_back`
(7b9f01e) resets three times with `client_header_timeout 30s` and `limit_conn per_ip=1`, and
the slot is back within 3 s each time, under ASan and under the plain debug build with real
seccomp. The test stays as a regression guard.

## 3. Seccomp allowlist

The allowlist is `src/proc/seccomp_tables.c`: 69 rows (5 of them `BST_SAN_ROW`, compiled into
sanitizer builds only), each with its numbers on x86_64 and aarch64, a role mask (worker, helper,
ACME) and a reason. Each row was read against its `why`. Argument filters were checked for the
dangerous forms: `socket` (inet only), `mmap`/`mprotect` (no `PROT_EXEC`), `fcntl`, `setsockopt`,
`futex` (no priority inheritance), `tgkill` (own process), `tkill` (SIGABRT only). `clone3`
returns `ENOSYS`; `execve`, `fork`, `clone`, `ptrace`, `bpf`, `mount`, `prctl` and `ioctl` are
absent.

### Minimality: removing each row in turn

`scripts/seccomp-minimality.sh` removes one row, rebuilds, and runs integration tests against the
plain debug build with real seccomp until one fails. For this review it gained `TESTS=` and `K=`
(so a row used only by one feature can be tried against that feature's tests) and a per-row
timeout (`ROW_TIMEOUT`, default 900 s): without `sendmsg` a worker blocks instead of dying and the
test run hung forever, which stalled the first sweep.

Run (aarch64, `BUILD=debug`), with the test files for process, sandbox, static files, cache,
spool, proxy, QUIC/UDP, TLS, admin, metrics, ACME and access logs:

| Row | Result |
|---|---|
| `io_uring_enter` | needed: `test_process.py::test_worker_count[uring]` |
| `epoll_pwait` | needed: `test_process.py::test_worker_count[epoll]` |
| `epoll_wait` | not runnable on aarch64 (x86_64 glibc's name for the same call) |
| `epoll_ctl` | needed: `test_process.py::test_worker_count[epoll]` |
| `clock_gettime` | needed: `test_metrics.py::test_xdp_metrics[uring]` |
| `recvfrom` | needed: `test_process.py::test_raw_echo[epoll]` |
| `sendto` | needed: `test_process.py::test_worker_count[uring]` |
| `sendmsg` | needed: `test_process.py::test_raw_echo[epoll]` hangs without it |

**Not completed:** the remaining 61 rows. The sweep runs about 5 to 40 minutes per row on this
host, and it was stopped to leave time for the release verification. No row has been found
unneeded so far, so **no row was removed**. The rest must be run before release:

```
./dev scripts/seccomp-minimality.sh BUILD=debug OUT=minimality.txt \
  TESTS='tests/integration'   # or a feature subset per row, with ONLY=name,name
```

Rows the earlier Phase 4 to 14 tasks added came each with a test that fails without it (the
table's own rule), which the sweep re-checks.

The role masks were not narrowed. `accept4` is allowed for every role (see the threat model's
accepted risks): the ACME role has no listening socket, so a per-role split would tighten
nothing that can be reached today.

## 4. Pending independent reviewer pass

The task asks for a separate reviewer agent over each protocol parser and over the sandbox. That
pass had not run when this file was written. **Pending independent reviewer pass:**

- HTTP/1.1 request parser and chunked body (`src/http/h1/parser.c`, `body.c`, `framing.c`, `scan.c`)
- HTTP/1.1 response parser (`src/http/h1/resp_parser.c`)
- HPACK and HTTP/2 frames (`src/http/h2/hpack.c`, `huffman.c`, `frame.c`, `frames.c`, `guard.c`)
- HTTP/2 upstream client (`src/proxy/client_h2.c`)
- HTTP/3 / QUIC glue (`src/http/h3/quic.c`, `h3_bridge.c`, `token.c`)
- PROXY protocol (`src/proxy/proxyproto.c`)
- DNS (`src/proxy/dns.c`)
- JSON, JWT, JWKS (`src/core/json.c`, `src/auth/jwt.c`, `jwks.c`)
- TLS ClientHello / JA4 and SNI (`src/tls/ja4.c`, `sni.c`)
- Range, Cache-Control, conditional headers (`src/handlers/range.c`, `src/http/cache_control.c`, `conditional.c`)
- ACME / OCSP HTTP client (`src/ops/http_client.c`, `acme*.c`)
- Config lexer and parser (`src/config/lexer.c`, `parser.c`)
- The sandbox (`src/proc/sandbox.c`, `seccomp.c`, `seccomp_tables.c`, `landlock.c`, `namespaces.c`, `child.c`) and the shared regions (`src/core/ring.c`, `shm.c`)

Results will be recorded here.

## 5. Dependency CVEs

`scripts/check-deps-cve.py` asks the NVD API for CVEs that match the exact versions pinned in
`deps/versions.env` by CPE. CI runs it in the `deps-cve` job on every push, pull request and
weekly. Result on 2026-11-20: no CVEs, except one allowed false match:

- **CVE-2019-0190** (allowed): an Apache httpd 2.4.37 mod_ssl bug. NVD's configuration pairs
  httpd with OpenSSL, so a match on the OpenSSL CPE alone returns it. Bastion is not httpd.

liburing has no NVD CPE, so the check returns nothing for it; its pin is reviewed by hand on
bumps. The Debian packages in the build images are outside this check.
