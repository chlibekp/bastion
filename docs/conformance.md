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
`tests/integration/test_quic_endpoint.py`, `test_quic_routing.py` and `test_quic_udp.py`; the h3spec and interop gates
arrive with Phase 8 Task 6.

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
  is what stops two endpoints from resetting each other forever). Resets are not rate limited.
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
- File bodies are read on the loop thread with `pread`, 64 KiB at a time and at most 512 KiB ahead
  of what the client acknowledged per stream; the TLS-over-TCP path stages through the aio pool
  instead. A slow disk therefore stalls a worker's HTTP/3 connections while it reads.
- A graceful stop sends GOAWAY (a shutdown notice, then the final one) and closes each connection
  with `H3_NO_ERROR` once its requests finished; the UDP socket keeps receiving meanwhile, and new
  connections are dropped.
