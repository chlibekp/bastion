# Changelog

## 1.0.0 (unreleased)

This is the first release candidate. It covers every row of the "Decided scope" table in
`docs/implementation-plan/README.md`. The deviations and untested areas are listed in
`docs/conformance.md` under "Deviations and untested areas at 1.0.0". Read that section before
deploying.

**Publishing status:** the user approved merging into `main` and pushing it, and nothing else.
No tag was made and no GitHub release was published. Both still need explicit approval.

### Gate results

All suites below ran in the `./dev` container on an arm64 Mac (Docker Desktop) on 2026-11-20.
Each exit code is make's own.

| Suite | Commit | Result |
|---|---|---|
| `make test-unit` (run twice) | 897e4d6 | 990 ok, 0 not ok, rc=0 both runs |
| `make test-int` (asan) | 897e4d6 | 1740 passed, 9 skipped, rc=0 |
| `TEST_BUILD=debug make test-int` (real seccomp) | 897e4d6 | 1733 passed, 16 skipped, rc=0 |
| `make test-vm` | 897e4d6 | 72 passed, rc=0 |
| `make conformance` | 897e4d6 | 139 passed, 9 skipped (h2spec, h3spec, interop, testssl.sh absent), rc=0 |
| `make fuzz-smoke` | 897e4d6 | 32 harnesses clean, rc=0 |
| `make check-release BUILD=release` | 897e4d6 | rc=0 (allowlist 61 names, mimalloc linked, no test seams) |
| `make test-matrix` | 897e4d6 | 24 passed, rc=0 |
| `make test-chaos` | 897e4d6 | 1 failed, 17 passed (a test-harness race, fixed in a4a4cd9) |
| `make test-chaos` (twice in a row) | a4a4cd9 | 18 passed, rc=0 both runs |
| `make test-packaging BUILD=release` | a4a4cd9 | 15 passed, 1 skipped (docker CLI is host-only), rc=0 |
| `tests/host/test_packages_host.sh 0.1.0` | a4a4cd9 | ALL PASS: debian:trixie, ubuntu:24.04, almalinux:9, scratch image. The amd64 QEMU check reported NOT RUN |

The chaos fix changed only `tests/chaos/test_chaos.py`. `shutil.rmtree` could fail with ENOTEMPTY
when the server stored a new cache entry while the tree was being removed. The test now retries
the removal until it succeeds. No source code changed after the unit and integration runs on
897e4d6.

### Release artifacts

`scripts/build-release.sh 0.1.0 arm64` built these files: a static-pie aarch64 binary, a deb, an
rpm, an SPDX SBOM and the scratch image `bastion:0.1.0-arm64`. `shasum -a 256 -c SHA256SUMS`
reported OK for all four files. The version string is still `0.1.0`, the build's `VERSION`. A
1.0.0 build has to set it.

amd64 artifacts were **NOT built**. That needs a QEMU build, which was not run because of time and
disk limits.

### NOT executed

h2spec, h3spec, quic-interop-runner, testssl.sh; benchmarks against nginx on real hosts; 72-hour
soak; 24 CPU-hour fuzz per harness; seccomp minimality sweep of 61 of 69 rows; CodeQL outside CI;
CI workflows on a runner; amd64 artifacts; fresh-VM timed walkthrough; `xdp mode hw`; kTLS under
Docker (VM only). The details are in `docs/conformance.md`.

### Known gaps

- `tls auto` does not open the HTTP/3 or IPv6 listeners that `docs/config-language.md` describes.
- The packages do not include `docs/guide/`.
- The systemd unit's `systemd-analyze security` score is 3.8.
- The vulnerability contact in `SECURITY.md` is a placeholder.
- An independent human security audit is recommended before internet-facing production use.
