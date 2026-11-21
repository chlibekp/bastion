# Testing

Bastion's tests are layered: C unit tests, Python integration tests against the real binary, a
feature matrix, fault injection, VM tests on stock kernels, protocol conformance, fuzzing and
release checks. Every tier runs through `./dev` (see [building](building.md)). This page lists
each tier, its target, its knobs and what it needs.

## Summary

| Tier | Command | Where the tests are | Build used |
|---|---|---|---|
| Unit | `./dev make test-unit [T=a,b] [BACKEND=epoll\|uring]` | `tests/unit/test_*.c` | `asan` unless `BUILD` is given |
| Unit, ThreadSanitizer | `./dev make test-tsan` | same | `tsan` |
| Unit, musl | `./dev make test-unit BUILD=musltest` | same | `musltest` |
| Dependencies | `./dev make test-deps` | `tests/deps/` | none |
| Integration | `./dev make test-int [K=expr]` | `tests/integration/` | `asan` unless `BUILD` is given |
| Integration, real seccomp | `./dev make test-int-nosan` | a subset of `tests/integration/` | `debug` (or `NOSAN_BUILD`) |
| Feature matrix | `./dev make test-matrix` | `tests/matrix/` | `asan` |
| Fault injection | `./dev make test-chaos` | `tests/chaos/` | `asan` |
| VM | `./dev make test-vm [KERNEL=floor\|current] [K=expr]` | `tests/vm/` | `debug` |
| Conformance | `./dev make conformance [K=expr]` | `tests/conformance/` | `asan` |
| Fuzzing | `./dev make fuzz T=<name> [SECS=n]`, `./dev make fuzz-smoke [SECS=n]` | `fuzz/fuzz_*.c` | its own |
| Release | `./dev make check-release BUILD=release` | `Makefile`, `scripts/` | `release` |
| Packaging | `./dev make test-packaging BUILD=release` | `tests/packaging/` | `release` |
| Host | `tests/host/test_dev_paths.sh`, `tests/host/test_packages_host.sh <v>` | `tests/host/` | runs on the host |

The test targets use `BUILD=asan` (AddressSanitizer and UndefinedBehaviorSanitizer) unless
`BUILD` is given on the command line. `BUILD=release` is refused by `test-unit` because the
release binary has no test hooks: use `BUILD=musltest` for the suites on musl.

## Unit tests

```
./dev make test-unit                 # every tests/unit/test_*.c
./dev make test-unit T=loop,io_tcp   # tests/unit/test_loop.c and test_io_tcp.c
./dev make test-unit BACKEND=uring   # backend-parametrised tests on io_uring
```

- Each `tests/unit/test_<name>.c` is its own binary and prints TAP. `tests/unit/tap.h` is the
  harness; `make tap-selftest` (run by `test-unit`) checks that it exits 1 on a failure or on no
  tests, aborts on overflow and prints no duplicated lines from a forked child.
- `BACKEND` (`epoll` or `uring`, default `epoll`) is passed to the tests as `BST_TEST_BACKEND`.
  `test_uring_only` always runs on io_uring.
- Request corpora for the HTTP/1.1 parser and framing tests are in `tests/corpus/` (format in
  [tests/corpus/README.md](../tests/corpus/README.md)).

At the 1.0.0 gate the suite reported 990 `ok` lines and no failures.

## Integration tests

```
./dev make test-int
./dev make test-int K='cache or compress'
./dev make test-int BUILD=musltest
```

pytest starts the real `bastion` binary with generated configurations and talks to it over real
sockets: HTTP/1.1, HTTP/2, HTTP/3 (through the `h3client` fixture built from the pinned ngtcp2 and
nghttp3), TLS, ACME (against a test CA in `tests/integration/acme_util.py`), DNS, the admin API,
reload and upgrade. Most tests run on both backends. `K` is passed to `pytest -k`.

The target also builds the fixtures the tests need: `seccomp_no_uring` (runs a command under a
seccomp filter that refuses `io_uring_setup`, to test the epoll fallback), `h3client`, and the
`synflood` and `udpflood` generators for the XDP tests (they refuse any target outside loopback
or the test network namespace and are never installed).

`tests/integration/conftest.py` fails a test at teardown when any process left a sanitizer
report.

### `test-int-nosan`

```
./dev make test-int-nosan
./dev make test-int-nosan NOSAN_BUILD=musltest
```

A sanitizer build allows extra system calls, so only a build without sanitizers proves that the
seccomp filter lets a real worker serve files, terminate TLS and speak HTTP/2. This target runs
the file serving, rewrite, TLS and HTTP/2 tests against the `debug` build with seccomp on.
Afterwards, `dmesg | grep type=1326` should show no new seccomp kill.

### Documentation checks

`tests/integration/test_docs.py` checks this documentation:

- every fenced block tagged `conf` in `README.md`, `SECURITY.md`, `docs/*.md` and `docs/guide/*.md`,
  and every `examples/*.conf`, passes `bastion -t`. Paths under `/srv/www`, `/etc/bastion`,
  `/var/lib/bastion`, `/var/cache/bastion`, `/var/log/bastion`, `/run/bastion` and
  `/usr/share/bastion/html` are mapped to a scratch tree with a site, certificates, a password
  file and a JWT key, so examples should use those prefixes;
- every relative link and anchor in those files resolves;
- the configuration reference matches the binary's schema and has an example for each of the
  most used directives;
- the README starts with the HTTPS configuration;
- every Bastion directive named in the nginx migration table exists.

Run it alone with `./dev make test-int K=test_docs`. Fragments that are not complete
configurations use an `nginx` tag or none, and are not checked.

## Feature matrix

```
./dev make test-matrix
```

`tests/matrix/test_matrix.py` tests pairwise combinations of the features a request can meet:
backend (io_uring, epoll), protocol (HTTP/1.1, HTTP/1.1 over TLS, over kTLS, HTTP/2, HTTP/3),
handler (static, proxy to HTTP/1.1, proxy to HTTP/2), cache state (off, miss, hit, stale),
compression (off, gzip, br, zstd), auth (off, Basic, JWT) and a filter (WAF, limit, challenge).
The cells come from a deterministic all-pairs cover, and `test_cover_is_pairwise` proves the cover.
Each cell checks the exact body, the headers the features promise and the framing, and also the
feature's refusal on the same protocol.

## Fault injection

```
./dev make test-chaos
```

`tests/chaos/test_chaos.py` runs the server under load while something breaks: worker and
helper kills, origin kills, packet loss and reordering (`tc netem`), a full disk under the cache,
the cache directory removed, wall-clock jumps, memory pressure through a cgroup v2 limit,
descriptor exhaustion and simultaneous reloads. Each test asserts that master stays up, no
completed response is corrupt, and every path recovers once the fault is gone. It needs the
privileged `./dev` container; what it cannot do elsewhere it skips, with the reason (`-rs`).

## VM tests

```
./dev make test-vm                   # KERNEL=current: Debian trixie's kernel
./dev make test-vm KERNEL=floor      # Debian bookworm's 6.1 kernel, the supported floor
```

`scripts/vm-run.sh` boots a stock Debian kernel in QEMU and runs pytest on `tests/vm/` inside
the guest. This is where the features that Docker Desktop's kernel lacks are tested: kTLS
(`test_ktls.py`), Landlock and namespaces (`test_sandbox_vm.py`), socket options and tuning, the
QUIC routing program and UDP offloads, the io_uring backend, XDP. The io_uring and XDP unit
suites are built first in `BUILD=debug` and run in the guest.

## Conformance

```
./dev make conformance
./dev make conformance K=h1
H2SPEC=/path/to/h2spec ./dev make conformance K=h2spec
H3SPEC=/path/to/h3spec ./dev make conformance K=h3
TESTSSL=/path/to/testssl.sh ./dev make conformance K=testssl
```

`tests/conformance/` runs an HTTP/1.1 RFC requirement corpus (`h1_rfc_requirements.yaml`)
against the real binary on both backends, plus gates for h2spec, h3spec, quic-interop-runner and
testssl.sh. Those tools are not in the development image and nothing downloads them: each test
looks for its tool in an environment variable, then on `PATH`, then under `build/tools/`, and
skips with a message when it is absent. **They have not been run against Bastion yet**; see
[conformance.md](conformance.md) for each gate and its status.

## Fuzzing

```
./dev make fuzz T=json SECS=30       # one harness
./dev make fuzz-smoke                # every harness, SECS each (default 60)
./dev make fuzz-smoke SEED=1234      # replay a run
```

Every parser has a libFuzzer harness `fuzz/fuzz_<name>.c` (ASan and UBSan) with a seed corpus in
`fuzz/corpus/<name>/`: the configuration language, HTTP/1.1 requests, responses and chunked
bodies, HTTP/2 frames and HPACK, the QUIC endpoint, URIs, ranges, JSON, JWT, Basic credentials,
DNS answers, ACME responses, PROXY headers, JA4, `traceparent`, WAF rules, log formats, XDP
packets and more (32 harnesses at 1.0.0). A crash writes a reproducer to `fuzz/crashes/`. The
workflow is in [fuzz/README.md](../fuzz/README.md).

## Release and packaging

`check-release` and `test-packaging` are described in [building](building.md#check-release).
`scripts/seccomp-minimality.sh` removes each seccomp allowlist row in turn to show every row is
needed; [security.md](security.md#3-seccomp-allowlist) records how far that sweep got.

## What has not been run

The 1.0.0 gate results are in [CHANGELOG.md](../CHANGELOG.md). Not executed so far: h2spec,
h3spec, quic-interop-runner, testssl.sh, benchmarks against nginx on real hosts, a 72-hour soak,
24 CPU-hours of fuzzing per harness, the full seccomp minimality sweep, CodeQL outside CI, the CI
workflows on a runner, amd64 artifacts, and `xdp mode hw`. [conformance.md](conformance.md#deviations-and-untested-areas-at-100)
has the details.
