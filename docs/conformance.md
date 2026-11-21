# HTTP/1.1 conformance

`tests/conformance/h1_rfc_requirements.yaml` lists requirements a server has to meet under RFC 9110
and RFC 9112, one entry each, with the section it comes from, the wording level (MUST, SHOULD,
MAY), the raw request bytes, and what must come back. `make conformance K=h1` sends every entry
to the real binary, on both the epoll and io_uring backends, with the worker sandboxed, and fails
on any entry that is not met. Later phases add their own corpora to the same target.

```
./dev make conformance K=h1
```

The corpus is a list of flat mappings written in the YAML subset described at the top of the file,
so any YAML tool can read it and the suite needs no YAML library. An entry whose `status` or
`close` shows Bastion differing from the requirement carries a `deviation:` line and is listed
below; there are none today.

## What is covered

| Area | Entries | RFC sections |
|---|---|---|
| Message parsing: line endings, NUL, bare CR, version | 9 | 9112 2.2, 2.3 |
| Request line and request-target: methods, 414, forms, Host | 18 | 9112 3, 3.2; 9110 9.1 |
| Fields: whitespace before the colon, obs-fold, counts and sizes | 7 | 9112 5; 6585 5 |
| Body framing: Transfer-Encoding and Content-Length | 12 | 9112 6.1 to 6.3 |
| Chunked bodies: extensions, trailers, overflow | 6 | 9112 7.1 |
| Connections: persistence, close, pipelining, error closes | 6 | 9112 9.3, 9.6 |
| Semantics: Date, 405 and Allow, HEAD, 204, 304, Expect | 10 | 9110 6.6.1, 8.6, 9.3, 10.1.1, 15 |

68 entries in all. The count comes from the file: `test_corpus_is_well_formed` fails when an id repeats, a required
field is missing, or there are fewer than 50 entries.

## Choices the RFCs leave open

These are not deviations (the requirement is MAY or SHOULD, or a MUST that allows either of two
behaviours) but a reader comparing with another server will see them:

- **Bare LF.** RFC 9112 section 2.2 allows a recipient to take a lone LF as a line ending.
  Bastion answers 400 unless `http1_allow_bare_lf on`, because proxies that disagree about line
  endings enable request smuggling.
- **Both Content-Length and Transfer-Encoding.** Section 6.1 allows rejecting or processing with
  the Transfer-Encoding winning, then closing. Bastion rejects with 400 and closes.
- **Repeated or listed Content-Length.** Section 6.3 lets a recipient accept a list of equal
  values. Bastion refuses every duplicate and every list, equal or not.
- **Obsolete line folding.** Section 5.2 allows rejecting or replacing each fold with SP.
  Bastion rejects with 400.
- **Transfer codings.** Only `chunked` is understood. A list ending in `chunked` after another
  coding is answered 501, a list that does not end in `chunked` 400 (both close).
- **HTTP/1.x minors.** A request with a minor above 1 is treated as HTTP/1.1 (section 2.3);
  `http/1.1` in lower case is not a version and is answered 400.
- **Absolute-form and Host.** An absolute-form target wins over a disagreeing Host (section
  3.2.2); userinfo in either is refused.
- **Close after a refusal.** A refused request whose framing is sound (405, 417) keeps the
  connection when it had no body; every other error closes it, because the bytes after it cannot
  be trusted to start a request.
- **Cache visibility (RFC 9111).** The cache is never required to store a response, and the
  RFC sets no time for a stored response to become usable. Bastion writes objects on its I/O
  pool, so a new object is served from the cache only once its write has finished. A request on
  the same worker waits for that write. A request on another worker may go to the origin
  meanwhile, as in nginx. A fast or graceful stop lets queued writes finish, so stored objects
  survive a restart (`test_cache_eviction.py::test_restart_survives`).

## Not covered yet

Range and conditional requests, caching, `Upgrade`, `Content-Encoding`, and the request-target
forms that need routing arrive with the phases that implement them (5 onwards) and their corpora.
`TRACE` and `CONNECT` are answered 405 with `Allow` until a phase serves them.

## Differential check

`tests/conformance/h1_vs_nginx.py` sends the same requests to Bastion and to an nginx on `PATH`
and prints the entries where the two statuses differ. It is for a person to read and never fails:
nginx is not the standard, and some differences are Bastion being stricter on purpose. It needs
nginx, which the development image does not carry, so it prints a note and stops there.

## TLS scan gate (testssl.sh): NOT executed so far

`tests/conformance/test_testssl.py` starts the default TLS configuration and scans it with
testssl.sh. It fails on any HIGH or CRITICAL finding, on any protocol other than TLS 1.2 and 1.3
being offered, and on any cipher outside the allowed list (the ECDHE AEAD suites and the three
TLS 1.3 suites).

testssl.sh is not in the development image and nothing fetches it. The test looks for it in the
`TESTSSL` environment variable, then `testssl.sh` or `testssl` on `PATH`, then
`build/tools/testssl.sh*/testssl.sh`; when none exists it skips and says so.

```
TESTSSL=/path/to/testssl.sh ./dev make conformance K=testssl
```

**Status: the scan has not been run against Bastion.** In every run to date the test skipped, so no
claim is made that the default configuration is free of HIGH or CRITICAL findings, and the result
parser has only been written from testssl.sh's documented JSON, never exercised on real output.
Run it once with the tool present, fix what it finds, and replace this paragraph with the result.

## HTTP/2 conformance gate (h2spec): NOT executed so far

`tests/conformance/test_h2spec.py` starts one TLS listener (`tls http2`) and one cleartext listener
(`h2c`) and runs h2spec in strict mode (`-S`) against each, on both backends. It requires zero
failures in the JUnit report of every run.

h2spec is not in the development image and nothing fetches it. The test looks for it in the
`H2SPEC` environment variable, then `h2spec` on `PATH`, then `build/tools/h2spec*/h2spec`; when
none exists it skips and says so.

```
H2SPEC=/path/to/h2spec ./dev make conformance K=h2spec
```

**Status: h2spec has not been run against Bastion.** In every run to date the four test cases
skipped, so the plan's "0 failures under h2spec strict" is NOT shown. The command line and the
JUnit parsing follow h2spec's documented options and have never been exercised against the real
tool. What does stand in for it, and is not the same thing: `tests/unit/test_h2_conn.c`,
`test_h2_flow.c`, `test_h2_validate.c`, `test_h2_abuse.c` and `test_h2_frame.c`/`test_hpack.c`
(frame, HPACK, state-machine, flow-control and abuse rules written from RFC 9113 and RFC 7541), and
the integration clients curl, nghttp, h2load and the hand-written `tests/tools/h2_attack.py`.
Run h2spec once with the tool present, fix what it finds, and replace this paragraph with the result.

### Known deviations from the letter of RFC 9113

- A header list larger than `http2_max_header_list_size` closes the connection with
  `ENHANCE_YOUR_CALM` instead of answering that stream with 431: the HPACK decoder has to stop
  decoding, and without decoding the whole block the connection's compression state would be lost.
- `:protocol` (RFC 8441) is accepted only when `http2_connect_protocol on` advertises it, and until
  the Phase 9 tunnel exists a request using it is answered 501.

## QUIC (RFC 9000, RFC 9001, RFC 9369)

The endpoint is `src/http/h3/quic.c` on ngtcp2 1.26 with its OpenSSL backend
(`spikes/quic/README.md` records why). Tested by `tests/unit/test_quic_token.c`,
`tests/integration/test_quic_endpoint.py`, `test_quic_routing.py` and `test_quic_udp.py`. The h3spec
and interop gates exist but have NOT been executed (see "HTTP/3 and QUIC conformance gates" below).

### Choices and known deviations

- **`quic_retry never` still sends a Retry in one case.** When the first Initial of a connection
  does not carry the start of the ClientHello (a ClientHello split over two Initials, as large
  post-quantum key shares make it, arriving out of order), ngtcp2 buffers that crypto data only for
  a validated address and asks for a Retry (`NGTCP2_ERR_RETRY`). Bastion sends it whatever
  `quic_retry` says, so `never` means "never on the server's own initiative". The cost is one round
  trip for those handshakes; refusing would fail them.
- Version Negotiation is sent only in answer to a datagram of at least 1200 bytes (RFC 9000 section
  6.1 allows ignoring smaller ones), and is always smaller than its trigger.
- A stateless reset is sent only for a short-header packet of at least 22 bytes, and is always one
  byte smaller than the packet that caused it, capped at 64 bytes (RFC 9000 section 10.3.3: this
  is what stops two endpoints from resetting each other forever). **Resets are not rate limited**
  (RFC 9000 section 10.3 suggests it): a flood of short-header packets for unknown connection IDs
  gets one smaller reset each.
- An invalid Retry token gets `CONNECTION_CLOSE(INVALID_TOKEN)` without state (RFC 9000 section
  8.1.2); an invalid NEW_TOKEN token is ignored and the client is treated as unvalidated.
- A connection is kept for three PTOs after it sent or received CONNECTION_CLOSE and repeats its
  close to every packet meanwhile, without the backoff RFC 9000 section 10.2.1 suggests.
- SNI on QUIC moves a handshake to the named server's QUIC context (`tls/sni.c`, `bst_tls_sni.quic`),
  never to a TCP one, so several servers with different certificates share one `http3` address. A
  name no server has gets the default server's QUIC context: `tls_default_cert` has no QUIC context
  of its own, so it applies to TCP only.
- Sending (`src/http/h3/txq.c`, tested by `tests/integration/test_quic_udp.py`): a connection's
  back-to-back packets of one size go out as one UDP_SEGMENT send of up to 16 datagrams
  (`quic_gso`); an EIO turns GSO off for the socket and the packets go again one by one. Pacing
  (`quic_pacing`) caps a burst at ngtcp2's send quantum and waits for its next transmission time.
  ECN (`quic_ecn`, RFC 9000 section 13.4) reads and sets the marks ngtcp2 reports and asks for.
- Path MTU discovery (`quic_mtu_discovery`, RFC 9000 section 14.3) sets
  `IP_PMTUDISC_PROBE`: don't-fragment on, the kernel's own path MTU (learnt from ICMP, which can be
  forged) ignored, so only acknowledged probes raise the packet size, up to
  `quic_max_udp_payload`. A probe larger than the local interface fails with EMSGSIZE; it is sent
  by itself, so nothing else is lost with it. Other send errors drop the unsent packets of that
  send, and loss recovery sends their data again.

## HTTP/3 (RFC 9114, RFC 9204)

`src/http/h3/h3_bridge.c` on nghttp3 1.19 maps request streams onto the shared HTTP semantics layer
(the same validation, router and handlers as HTTP/1.1 and HTTP/2). Tested by
`tests/integration/test_h3_semantics.py` (parity with HTTP/2 for ranges, conditionals, HEAD and
error pages, 1 GiB in both directions, cancellation, trailers, GOAWAY, 100 concurrent streams,
per-name certificates) and `test_quic_routing.py` (migration mid-transfer).

### Choices and known deviations

- A malformed request (pseudo-header rules, connection-specific fields, `te` other than
  `trailers`, a Content-Length the body contradicts) is a stream error `H3_MESSAGE_ERROR`; the
  connection goes on. nghttp3 finds most of these itself, the shared `validate_pseudo.c` the rest.
- A regular field whose value contains CR, LF or NUL is removed by nghttp3 before the server sees
  it, rather than making the request malformed. RFC 9110 section 5.5 allows rejecting or replacing;
  removing the field means it can never reach a handler or a log.
- A header (or trailer) section larger than `http3_max_field_section_size`, counted as RFC 9114
  section 4.2.2 says, is answered 431.
- After a complete response to a request whose body is still arriving, the server sends
  `STOP_SENDING(H3_NO_ERROR)` (RFC 9114 section 4.1).
- File bodies are read on the aio pool with `pread`, 64 KiB at a time, one read per stream at a
  time, and at most 512 KiB ahead of what the client acknowledged per stream, so a slow disk
  delays only the streams waiting for it, never the worker's loop.
- A graceful stop sends GOAWAY (a shutdown notice, then the final one) and closes each connection
  with `H3_NO_ERROR` once its requests finished; the UDP socket keeps receiving meanwhile, and new
  connections are dropped.
- Alt-Svc (RFC 7838, `src/http/h3/altsvc.c`, `alt_svc auto|off|<value>`): HTTP/1.1 and HTTP/2
  responses of a server with a `listen ... http3` carry `Alt-Svc: h3=":<port>"; ma=86400` for its
  first `http3` listener, on TLS and cleartext listeners alike; a handler's own Alt-Svc wins, and
  HTTP/3 responses carry none. Tested by `tests/integration/test_h3_extras.py` (curl follows the
  advertisement from its Alt-Svc cache to HTTP/3).
- 0-RTT follows the Phase 6 policy unchanged: `early_data` of the server's `tls_profile`, the
  shared `bst_early_allow` anti-replay table (one ticket, one 0-RTT attempt, across TCP and QUIC
  and all workers), `early_data_methods` (425 Too Early for the rest). The QUIC context sets
  `max_early_data` to 0xffffffff, the only value RFC 9001 section 4.6.1 allows, so
  `early_data_max_size` does not limit HTTP/3 0-RTT; QUIC's own flow control does.
- Abuse guards share the HTTP/2 buckets of `http2_abuse` (counted in `bastion_h2_abuse_total`):
  client RESET_STREAM or STOP_SENDING of request streams is charged to `rst_rate` (once per
  stream; kind `stream_reset`) and requests nghttp3 rejects as malformed to `server_reset_rate`;
  either budget running out closes the connection with `H3_EXCESSIVE_LOAD`. QPACK and
  control-stream connection errors are counted as `qpack` and `control_stream`. Resetting a
  critical stream (control, QPACK encoder or decoder) closes the connection with
  `H3_CLOSED_CRITICAL_STREAM` (RFC 9114 section 6.2.1).

## HTTP/3 and QUIC conformance gates (h3spec, quic-interop-runner): NOT executed so far

`tests/conformance/test_h3spec.py` runs h3spec against an `http3` listener on both backends and
requires zero failures. h3spec is not in the development image and nothing fetches it: the test
looks in `H3SPEC`, then `h3spec` on `PATH`, then `build/tools/h3spec*/h3spec`, and skips saying so.

```
H3SPEC=/path/to/h3spec ./dev make conformance K=h3
```

`tests/conformance/test_quic_interop.py` runs quic-interop-runner (handshake, transfer, retry,
resumption, multiplexing) with Bastion as the server against at least two client implementations
(default ngtcp2 and quic-go). It is a manual gate: it needs nested Docker, a runner checkout
(`QUIC_INTEROP_RUNNER`) and a Bastion server image for the runner (`BASTION_INTEROP_IMAGE`), none
of which the development image has; otherwise it skips.

**Status: neither tool has been run against Bastion.** In every run to date both gates skipped, so
the plan's "0 failures under h3spec" and the interop matrix are NOT shown; their command lines and
result parsing follow the tools' documentation and have never been exercised on real output (only
the parsers' own unit cases run). What stands in for them, and is not the same thing: the
integration tests named above, driven by curl (OpenSSL's QUIC client and nghttp3), the ngtcp2-based
`tests/fixtures/h3client.c`, `openssl s_client -quic` and hand-made datagrams. Run both once with the
tools present, fix what they find, and replace this paragraph with the result.

## Long fuzz campaign (Phase 15 Task 1): 24 CPU-hour gate NOT executed

**The plan's gate (each harness at least 24 CPU-hours on real hardware, then a final 24-hour run with
zero new crashes) was NOT executed:** no real hardware was available. Only a short campaign ran: every
harness once for 600 s (ASan + UBSan, libFuzzer, fresh seed, scratch copy of the checked-in corpus),
three at a time in the `./dev` container on an arm64 Mac (Docker Desktop, 6 vCPUs), on 2026-11-20.
That is about 0.17 CPU-hours per harness, under 1% of the gate. Before it, a 20 s smoke of every
harness found the two crashes below.

Harnesses added in this task: `acme_resp` (the ACME client's HTTP response parser and the JSON walk
over directory, order, authorization and problem documents), `traceparent`, `basic` (Basic
Authorization values and Argon2id PHC strings), `waf` (rule match lines, then their evaluation
against a fuzzed request: arguments, cookies, repeated headers), `http_fields` (Accept-Encoding,
HTTP-date) and `logfmt` (the access-log JSON and text escapers).

| Harness | Execs in 600 s | Harness | Execs in 600 s |
|---|---|---|---|
| acme_resp (new) | 24,330,483 | ja4 | 63,922,226 |
| addr | 86,049,778 | json | 26,406,204 |
| basic (new) | 73,715,483 | jwt | 60,101,383 |
| cache_control | 9,961,679 | logfmt (new) | 16,164,996 |
| cache_header | 27,093,665 | proxyproto | 51,005,595 |
| cfg | 11,780,587 | quic_endpoint | 9,550,493 |
| cfg_roundtrip | 9,786,137 | range | 80,951,780 |
| channel | 115,894,567 | sni | 87,754,046 |
| dns | 94,156,458 | spsc | 13,872,655 |
| h1_chunked | 4,786,128 | tcpkey | 114,137,848 |
| h1_parser | 13,007,401 | tpl | 41,170,311 |
| h1_resp | 13,069,385 | traceparent (new) | 84,281,662 |
| h2_frame | 36,736,957 | udp_cmsg | 70,327,107 |
| hpack | 3,243,766 | uri | 28,854,530 |
| http_fields (new) | 46,489,358 | values | 9,051,605 |
| waf (new) | 48,542,583 | xdp_packets | 105,095,279 |

Result: 32 harnesses, zero crashes in the 600 s runs. Findings, both from the smoke run, each with
its reproducer kept in the corpus:

- `basic`: `bst_basic_decode` documented a NUL-terminated user but left it ending at the colon, so
  `user.p` read as a C string carried `:<password>`. No caller did that; fixed anyway
  (`fuzz/corpus/basic/regress-user-not-nul-terminated`, unit test `decode_rules`).
- `logfmt`: a harness property, not a product bug. The JSON escaper writes NUL as `\u0000` (valid
  JSON), which Bastion's own strict parser refuses by policy; the harness no longer checks such
  values with that parser (`fuzz/corpus/logfmt/regress-nul-in-json-value`).

Parsers covered through a neighbouring harness rather than their own: HTTP/3 frames and QPACK
(nghttp3, reached through `quic_endpoint`), the admin API bodies (`json`), X-Forwarded-For
(`addr`). To close the gate, run `./dev make fuzz T=<name> SECS=86400` per harness on real hardware.

## SYN floods: kernel SYN cookies, not XDP SYN cookies

Phase 13 Task 8 planned optional SYN cookies answered from XDP (`syn_cookies off|on|auto`). The
spike that had to prove them on the supported kernels was **NOT executed**
(`spikes/xdp_syncookie/README.md`), so the plan's fallback applies and the directive does not exist.
SYN floods are met by the kernel's own SYN cookies (`net.ipv4.tcp_syncookies`, 1 by default on
Debian), by the XDP per-source `syn_rate` limit, and by `deny` lists and escalation blocks in XDP,
which drop a flood before the TCP stack. A spoofed-source flood is left to the kernel's cookies.

## Scope table to tests (Phase 15 Task 7)

Each row of the "Decided scope" table in `docs/implementation-plan/README.md` maps to suites that
passed in the 1.0.0 gate run on commits `897e4d6` and `a4a4cd9`. The second commit changed only a
chaos test (see `CHANGELOG.md` for counts). Integration
tests are in `tests/integration/`, VM tests in `tests/vm/`, unit tests in `tests/unit/`. A row
passing here means its tests passed in Docker on an arm64 host. It does not mean every listed
feature was exercised on real hardware: see the next section.

| Area | Passing tests |
|---|---|
| I/O | `test_backend.py`, `test_sockopts.py`; VM `test_io_backend_vm.py`, `test_uring_vm.py`, `test_sockopts_vm.py`; unit `test_backend.c`, `test_sockopts.c`, `test_uring_net.c` |
| Protocols | `test_h1_conn.py`, `test_h2_basic.py`, `test_h2_flow.py`, `test_h2_semantics.py`, `test_h2_abuse.py`, `test_h2_extras.py`, `test_h3_semantics.py`, `test_h3_extras.py`, `test_tls_conn.py`, `test_ktls_fallback.py`; VM `test_ktls.py`; conformance `h1` corpus |
| Crypto and QUIC | `test_quic_endpoint.py`, `test_quic_routing.py`; unit `test_quic_token.c`, `test_hpack.c`, `test_deps.c` |
| Serving | `test_static.py`, `test_static_extras.py`, `test_file_safety.py`; unit `test_range.c`, `test_conditional.c`, `test_ofcache.c` |
| Routing | `test_vhost.py`, `test_route.py`, `test_rewrite.py`; unit `test_location.c`, `test_vhost.c` |
| Proxy | `test_proxy.py`, `test_proxy_translation.py`, `test_pool.py`, `test_upstream_dns.py`, `test_upstream_resilience.py`, `test_upstream_tls.py`, `test_websocket.py`, `test_grpc.py`, `test_sse.py`, `test_proxyproto.py`; unit `test_balance.c`, `test_breaker.c` |
| Cache | `test_cache.py`, `test_cache_eviction.py`, `test_cache_purge.py`, `test_cache_stale.py`; unit `test_cache_*.c` |
| Compression | `test_compress.py`, `test_compress_variants.py`; unit `test_compress.c`, `test_accept_encoding.c` |
| Security | `test_xdp_lifecycle.py`, `test_xdp_flood.py`, `test_xdp_escalate.py`, `test_limit.py`, `test_escalate.py`, `test_ja4.py`, `test_challenge.py`, `test_challenge_auto.py`, `test_waf.py`, `test_auth_basic.py`, `test_auth_jwt.py`, `test_auth_forward.py`, `test_mtls.py`; VM `test_xdp_vm.py`, `test_xdp_native.py` (generic and native driver modes only) |
| TLS extras | `test_acme.py`, `test_ocsp.py`, `test_tickets.py`, `test_sni.py`, `test_early_data.py`; unit `test_tls_ctx.c`, `test_tickets.c`, `test_sni.c` |
| Operations | `test_reload.py`, `test_upgrade.py`, `test_sandbox.py`, `test_process_security.py`, `test_metrics.py`, `test_access_log.py`, `test_trace.py`, `test_admin.py`; VM `test_sandbox_vm.py`, `test_process_vm.py`; unit `test_seccomp.c` |
| Tuning | `test_tuning.py`, `test_quic_udp.py`; VM `test_tuning_vm.py`, `test_quic_udp_vm.py` |
| HTTP extras | `test_http_extras.py` |
| Packaging | `tests/packaging/test_packages.py`, `test_systemd_unit.py`, `tests/host/test_packages_host.sh` (arm64 only) |

Combined features are covered by `tests/matrix` (24 pairwise cells) and `tests/chaos` (18 fault
injections).

## Deviations and untested areas at 1.0.0

These are the gaps at the 1.0.0 gate. None of them is hidden by a skip or an xfail. Each one is
something that was not run.

- **`xdp mode hw` (offload)**: never tested. No NIC with XDP offload was available. Generic and
  native modes are tested in the VM.
- **kTLS**: the Docker Desktop kernel has no `tls` module, so integration runs exercise only the
  user-space fallback (`test_ktls_fallback.py`). kTLS itself is tested only in the VM tier.
- **h2spec, h3spec, quic-interop-runner, testssl.sh**: NOT executed (see their sections above).
  None of these tools is in the development image or pinned, so their tests skip. This explains
  most of the 9 skips in the conformance run.
- **Benchmarks (Task 4)**: NOT executed. No two real hosts on 25 GbE were available. No
  performance claim relative to nginx is made, and the `SEND_ZC`, SQPOLL and custom-BIO defaults
  were not set from measurements.
- **72-hour soak and 12-hour ASan soak (Task 3)**: NOT executed.
- **24 CPU-hour fuzz per harness (Task 1)**: NOT executed. Only 600 s per harness ran, plus the
  60 s `fuzz-smoke` in this gate.
- **Seccomp allowlist minimality**: only 8 of the 69 rows were proven necessary by a removal
  sweep. The other 61 were reviewed by hand but not swept.
- **CodeQL**: runs only in CI. It was not run locally.
- **CI workflows**: written but never executed on a CI runner.
- **amd64 artifacts**: not built and not smoke-tested. Only arm64 was built
  (`scripts/build-release.sh 0.1.0 arm64`, SHA256SUMS verified, host package tests passed on
  debian:trixie, ubuntu:24.04, almalinux:9 and the scratch image). The QEMU check of the amd64
  binary reported NOT RUN.
- **Fresh-VM walkthrough (Task 6 Step 4)**: the timed walkthrough of under 5 minutes, from package
  install to HTTPS and HTTP/3 against Pebble on a fresh VM, was not performed. `test_docs.py` and
  `test_quickstart.py` stand in for it inside the container.
- **`tls auto`**: does not yet open the HTTP/3 listener or the IPv6 listeners that
  `docs/config-language.md` promises. Either the code or that document must change before this is
  closed.
- **Packages do not ship `docs/guide/`**: the deb and rpm install the binary, the unit and the
  config, but not the user guide.
- **systemd hardening**: `systemd-analyze security` scores the unit 3.8 ("OK"), not lower.
- **`SECURITY.md`**: the vulnerability-report contact is still a placeholder. It must be filled
  in before publishing.
- **Independent review**: all security review so far was automated (static analysis plus reviewer
  agents). An independent human audit is recommended before internet-facing production use.
