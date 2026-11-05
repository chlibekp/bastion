# Bastion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build Bastion, a Linux HTTP/1.1, HTTP/2 and HTTP/3 server in C with static file serving, caching, reverse proxying and layered DDoS protection, configured through an nginx-like file that stays short for simple sites.

**Architecture:** One privileged master, one pinned shared-nothing worker per core, and one unprivileged helper for background work. Workers run a completion-style I/O API backed by io_uring or epoll. An XDP program drops attack traffic before the kernel network stack sees it, and L7 limits feed it new blocks.

**Tech Stack:** C17 (`gnu17`), GNU Make, OpenSSL 3.5+, ngtcp2, nghttp3, liburing, libbpf, PCRE2, zstd, brotli, zlib-ng, mimalloc. Tests use a small TAP harness, pytest, libFuzzer, h2spec, h3spec and testssl.sh.

**Spec:** this file, [architecture.md](architecture.md) and [config-language.md](config-language.md). Executors read all three before starting a phase.

## How to read this plan

| File | Contents |
|---|---|
| [architecture.md](architecture.md) | Process model, memory, I/O, request flow, security model, core C interfaces |
| [config-language.md](config-language.md) | Config grammar, simple and full examples, directive rules |
| [01-foundation.md](01-foundation.md) | Build, dev environment, core libraries, fuzz setup |
| [02-config.md](02-config.md) | Config parser, schema, CLI |
| [03-io-process.md](03-io-process.md) | io_uring and epoll, socket options, master/worker, sandbox |
| [04-http1.md](04-http1.md) | HTTP core and HTTP/1.1 |
| [05-routing-static.md](05-routing-static.md) | Virtual hosts, locations, rewrites, static files |
| [06-tls.md](06-tls.md) | TLS, kTLS, tickets, OCSP, mTLS, JA4, 0-RTT |
| [07-http2.md](07-http2.md) | HTTP/2 and HPACK |
| [08-http3.md](08-http3.md) | QUIC and HTTP/3 |
| [09-proxy.md](09-proxy.md) | Reverse proxy, upstream pools, WebSocket, gRPC |
| [10-cache.md](10-cache.md) | RAM and disk HTTP cache |
| [11-filters-auth.md](11-filters-auth.md) | Compression, HTTP extras, authentication |
| [12-security.md](12-security.md) | Rate limits, ACLs, WAF-lite, bot challenge |
| [13-xdp.md](13-xdp.md) | XDP DDoS filter |
| [14-operations.md](14-operations.md) | Reload, upgrade, logs, metrics, admin API, ACME, tuning, packaging |
| [15-release.md](15-release.md) | Conformance, soak, benchmarks, docs, 1.0 gate |

## Decided scope

Every row below was either requested directly or answered yes during feature selection.

| Area | Included |
|---|---|
| I/O | epoll, io_uring (default, automatic epoll fallback), `SO_REUSEPORT`, `SO_BUSY_POLL`, `TCP_FASTOPEN`, `TCP_DEFER_ACCEPT` |
| Protocols | HTTP/1.1, HTTP/2, HTTP/3, TLS 1.2 and 1.3, kTLS |
| Crypto and QUIC | OpenSSL, ngtcp2 and nghttp3 as libraries. HTTP/1.1, HTTP/2 and HPACK are hand-written |
| Serving | Range, conditional requests, open-file cache, directory listing, `try_files`, SPA fallback, custom error pages, zero-copy paths |
| Routing | Virtual hosts, nginx-style locations, regex rewrites, redirects, header edits, variables |
| Proxy | Round robin, least connections, consistent hash, peak-EWMA, active and passive health checks, retries, circuit breaking, WebSocket, gRPC, SSE, PROXY protocol v1/v2, upstream TLS and mTLS |
| Cache | RFC 9111, RAM and disk tiers, stampede lock, stale-while-revalidate, stale-if-error, Vary, purge API with tags |
| Compression | zstd, brotli, gzip on the fly, precompressed files, cached variants |
| Security | XDP filter, rate limits with escalation into XDP, JA4, simple proof-of-work challenge with user-replaceable frontend, WAF-lite, Basic, JWT, mTLS and forward auth |
| TLS extras | ACME, X25519MLKEM768, OCSP stapling, ticket key rotation, SNI, hardened defaults, optional 0-RTT |
| Operations | Hot reload, live binary upgrade, seccomp, Landlock, namespaces, capability drop, Prometheus, JSON logs, W3C trace context, admin API, `bastionctl` |
| Tuning | CPU pinning, NUMA, socket steering, huge pages, UDP GSO/GRO |
| HTTP extras | 103 Early Hints, request IDs, security header presets, maintenance mode, body size controls |
| Packaging | Static x86_64 and arm64 binaries, scratch Docker image, deb and rpm, hardened systemd unit |

## Non-goals

These were explicitly declined or are ruled out by a decision above.

- Raw TCP/TLS `stream` proxying.
- FastCGI and uwsgi upstreams.
- Lua, WebAssembly or any embedded scripting.
- GeoIP.
- HTTP/2 server push (browsers removed it).
- HTTP/1.1 to HTTP/2 `Upgrade: h2c` (removed by RFC 9113). Prior-knowledge h2c is supported.
- A forward proxy. `CONNECT` is refused apart from extended CONNECT used for WebSocket.
- macOS and BSD. Bastion is Linux-only.
- Reuse of `absurd-http-server` code. Its ideas may be borrowed, not its source.

## Global Constraints

- Language: C17 with GNU extensions (`-std=gnu17`), compiled warning-free with `-Wall -Wextra -Wshadow -Wconversion -Wformat=2 -Werror`.
- Runtime floor: Linux 6.1. Newer kernel features are detected at runtime and must degrade cleanly.
- Library floor: OpenSSL 3.5, ngtcp2 1.24. Task 1 of Phase 1 pins exact versions and SHA-256 hashes in `deps/versions.env`.
- All public C symbols use the `bst_` prefix. Files use one responsibility each and should stay below about 800 lines.
- Hand-written protocol parsers treat every input byte as hostile, and each one has a libFuzzer harness in the same task that adds it.
- No blocking syscall on a worker event loop. Disk or CPU-heavy work goes through `bst_aio_submit`.
- No hard-coded tunable. A limit, timeout or size is a config directive with a safe default and non-empty documentation.
- Secure and simple by default: omitted directives must produce a safe, working server.
- Unit and integration tests run under ASan and UBSan. All integration tests run on both I/O backends unless a task says otherwise.
- All workers run sandboxed during tests from Phase 3 onward. Adding a syscall to the allowlist needs a one-line justification comment.
- Commit trailer, on every commit: `Co-Authored-By: Claude <noreply@anthropic.com>`. Never name a model in it.
- Work on a branch per phase (`phase/NN-name`), merged after phase acceptance passes.

## Test environment facts

Probed on the development machine on 2026-11-04. They shape the test tiers.

| Fact | Consequence |
|---|---|
| Dev host is an arm64 Mac | All build and test commands run in Linux through `./dev`, a Docker wrapper |
| Docker Desktop kernel is 6.10.14-linuxkit aarch64 | Good for io_uring, BPF test runs, veth and generic XDP |
| Kernel config has `# CONFIG_TLS is not set` | kTLS can't run in Docker Desktop, so kernel-feature tests run in a QEMU VM with a stock distro kernel (Phase 1, Task 2) |
| `CONFIG_SECURITY_LANDLOCK` did not appear in the kernel config | Landlock enforcement tests belong to the VM tier. Docker covers only the "unavailable" warning path |
| Only `reno` and `cubic` available, no `net.core.busy_poll` sysctl | BBR and busy-poll tests also belong to the VM tier |
| `CONFIG_BPF_SYSCALL`, `CONFIG_XDP_SOCKETS`, `CONFIG_NET_SCH_NETEM` are set | BPF test runs, generic XDP and `tc netem` tests can run in Docker |
| Containers have no physical NIC | Native driver mode on real hardware and all performance numbers require a real Linux host |
| `io_uring_setup` succeeded under this Docker install's default seccomp profile | Other environments do block it, so fallback tests inject the failure with a test seccomp filter and don't rely on Docker's profile. `./dev` stays privileged for BPF |
| Debian trixie ships ngtcp2 1.11, older than the floor | Dependencies are built from pinned source |

### Test tiers

| Tier | Command | Where | Covers |
|---|---|---|---|
| Unit | `./dev make test-unit [T=name]` | Docker | Pure logic, under ASan and UBSan |
| Unit, musl | `./dev make test-unit BUILD=musltest` | Docker (Alpine) | The same suite on musl, with test hooks and no sanitizers |
| Unit, TSan | `./dev make test-tsan` | Docker | The unit suite under ThreadSanitizer |
| x86_64 | `./dev --platform linux/amd64 <cmd>` | Docker, emulated | Passes the platform to Docker; x86_64 deps and the seccomp table are scheduled in Phases 3 and 4, not built yet |
| Integration | `./dev make test-int [K=expr]` | Docker | Real server, both backends, pytest |
| Kernel | `./dev make test-vm [K=expr] [KERNEL=floor\|current]` | QEMU with stock kernel | kTLS, Landlock, BBR, busy poll, native veth XDP, Linux 6.1 floor |
| Fuzz smoke | `./dev make fuzz-smoke` | Docker | Each harness for 60 seconds |
| Conformance | `./dev make conformance` | Docker | h2spec, h3spec, testssl.sh, HTTP corpus |
| Performance | `scripts/bench.sh` | Real Linux hosts | Throughput and latency, compared with nginx |

## Task conventions

Each task follows a test-first cycle in five steps, written compactly. "Run" steps state the exact command and the expected result. Test bullets give the test name followed by its assertion, with `→` separating input from expected result. The implementer writes the test bodies from those assertions.

Task interfaces name what other tasks depend on. Anything not named is the implementer's choice, within the constraints above.

## Milestones

| Milestone | Finished after | Proves |
|---|---|---|
| M1: Static server | Phase 5 | HTTP/1.1 static site on both backends, sandboxed, first benchmark |
| M2: Secure web server | Phase 7 | TLS, kTLS, HTTP/2, h2spec clean |
| M3: All protocols | Phase 8 | HTTP/3, h3spec clean, connection migration |
| M4: Edge server | Phase 11 | Proxy, cache, compression and auth working together |
| M5: Protected | Phase 13 | L7 limits escalate into XDP drops |
| M6: Operable | Phase 14 | Reload and upgrade with no failed requests, ACME, packages |
| M7: 1.0 | Phase 15 | All release gates green |

Run phases in numeric order, since later phases consume interfaces from earlier ones. Phases 7 and 8 are the only neighbours that can be swapped.

## Key risks

| Risk | Handling |
|---|---|
| Project size. This is a multi-month effort even with automation | Each milestone yields a usable server, and scope can stop cleanly at any of them |
| ngtcp2 maintainers once declined OpenSSL QUIC API support and cited 0-RTT limits, though later packages ship an OpenSSL backend | Phase 8, Task 1 is a spike. If 0-RTT fails on HTTP/3, 0-RTT stays TCP-only and the limit gets documented |
| kTLS through a custom BIO depends on internal OpenSSL constants | Decided against. kTLS connections use the public socket BIO path (see architecture.md) |
| kTLS RX and TLS 1.3 KeyUpdate interaction | RX defaults off. Phase 6, Task 1 measures the actual behaviour on the VM kernel |
| XDP SYN cookies rely on kernel behaviour with `tcp_syncookies=2` | Phase 13, Task 8 starts with a spike. Normal kernel syncookies remain the fallback |
| "Fully HTTP compliant" cannot be proved absolutely | Compliance means passing the listed suites and an RFC requirement corpus. Any deviation is recorded in `docs/conformance.md` |
| Performance targets without suitable hardware | Docker results are never reported as performance results. The target is relative: match or beat nginx on identical hardware |
