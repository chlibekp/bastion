# Building

Bastion builds and is tested in Linux containers driven by `./dev`, so the host needs only Docker
and Bash. This page covers the build environment, the dependencies, the build types and the
`make` targets. [Testing](testing.md) covers the test targets in detail.

## Requirements

- Docker (Docker Desktop on macOS works; the 1.0.0 gate ran on an arm64 Mac).
- Bash, `git` and `shasum` on the host (`./dev` hashes the tree path with `shasum -a 256`).
- Disk space for two images and the dependency volume.

To run the result you need Linux 6.1 or later. That is the oldest kernel the VM tests boot
(`KERNEL=floor`, Debian bookworm's 6.1 series); some features need newer kernels (for example
`uring_napi` and `epoll_busy_poll` need 6.9). `bastion doctor` reports what a host offers.

## `./dev`

```
./dev [--platform <p>] <cmd> [args...]
```

`./dev` builds the image (quietly, cached by Docker) and runs `<cmd>` in it with the tree mounted
at `/work`. With no command it opens a shell.

| Image | Dockerfile | Base | Used when |
|---|---|---|---|
| `bastion-dev` | `docker/dev.Dockerfile` | `debian:trixie-slim` (glibc) | by default: ASan and TSan need glibc |
| `bastion-release` | `docker/release.Dockerfile` | `alpine:3.22` (musl) | when an argument is `BUILD=release` or `BUILD=musltest` |

Volumes:

- `build/` inside the container is a per-tree Docker volume, `bastion-build-<hash of the tree's
  absolute path>`, so two clones never share objects. Files under `build/` are **not** visible on
  the host; run tools that need them through `./dev`.
- Dependencies live in one shared volume, `bastion-deps`, because they do not depend on the tree.
- `--platform linux/amd64` (or another Docker platform) is passed to `docker build` and
  `docker run` and gets its own build volume. The x86_64 dependencies have not been built and
  verified in this way yet (see [the status in the README](../README.md#status-and-limits)).

## Dependencies

Every third-party library is built from a pinned, hash-verified source listed in
`deps/versions.env`, into `build/deps/<arch>-<glibc|musl>/`, by `scripts/build-deps.sh`:

| Library | Used for |
|---|---|
| OpenSSL | TLS 1.2 and 1.3, QUIC crypto, ACME and JWT crypto |
| ngtcp2, nghttp3 | QUIC and HTTP/3 |
| liburing | the io_uring backend |
| libbpf | the XDP and `sk_reuseport` programs |
| PCRE2 | regular expressions in locations, names and rewrites |
| zstd, brotli, zlib-ng | response compression |
| mimalloc | the allocator |

`bastion --version` prints the versions linked into a binary. `make deps` runs on every build and
rebuilds only a dependency whose version, hash or recipe changed (it keeps a stamp per
dependency). [third-party.md](third-party.md) lists the licences.

## Build types

```
./dev make                     # BUILD=debug
./dev make BUILD=asan
./dev make BUILD=release       # static PIE on musl, in the Alpine image
```

The binary is `build/<BUILD>/bastion` inside the container.

| `BUILD` | Flags | Purpose |
|---|---|---|
| `debug` (default) | `-O0 -g3` | development |
| `asan` | `-O1`, AddressSanitizer and UndefinedBehaviorSanitizer, no recovery | the default for test targets |
| `tsan` | `-O1`, ThreadSanitizer | `make test-tsan` |
| `musltest` | `-O1 -g`, musl | the test suites against musl (Alpine image) |
| `release` | `-O2`, static PIE, full RELRO, `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=3`, stack clash protection, CET (x86_64) or PAC/BTI (arm64) | packages |

Every build compiles with `-Wall -Wextra -Wshadow -Wconversion -Wformat=2 -Werror`, so a warning
fails the build. Every build except `release` contains test-only hooks (`-DBST_TEST`);
`make check-release` proves none reached the release binary. mimalloc replaces `malloc` only in
`release` and `musltest`, because the sanitizers need the libc allocator.

Objects depend on the exact compiler, flags and version: changing any of them rebuilds
everything that depends on it. `EXTRA_CFLAGS` adds compiler flags; `CC` selects the compiler
(default `clang`).

## Make targets

All of them run through `./dev`, for example `./dev make test-unit T=loop`.

| Target | Does |
|---|---|
| `all` (default) | builds `build/$(BUILD)/bastion` |
| `deps` | builds the pinned dependencies (also run by every other target) |
| `test-unit` | unit tests; see [testing](testing.md#unit-tests) |
| `test-tsan` | the unit suite under ThreadSanitizer |
| `test-deps` | checks that every pinned library resolves through `pkg-config` and links |
| `test-int`, `test-int-nosan` | integration tests (pytest against the real binary) |
| `test-matrix`, `test-chaos` | the feature matrix and fault injection suites |
| `test-vm` | tests in a QEMU VM on a stock Debian kernel |
| `conformance` | protocol conformance corpora and external tools |
| `fuzz`, `fuzz-smoke` | libFuzzer harnesses |
| `check-release` | release binary checks (needs `BUILD=release`) |
| `test-packaging` | builds the packages and tests them (needs `BUILD=release`) |
| `gen-reference` | regenerates `docs/config-reference.md` from the binary |
| `gen-known-headers` | regenerates the known-header perfect hash from `src/http/known_headers.def` |
| `gen-huffman` | regenerates the HPACK Huffman tables |
| `help` | prints the test knobs |
| `clean` | removes the build output (not the dependencies) |

### `check-release`

```
./dev make check-release BUILD=release
```

Builds the static binary and checks that:

- every directive table and post-compile hook registered in `src/` survived the link;
- no test seam (`BST_TEST_*`, `--test-listeners`, `bst_test_*`, the sandbox probe) is in it;
- the release seccomp allowlist matches `scripts/check-release-allowlist.sh`;
- the listener code is present and `malloc` resolves to mimalloc.

### Packages

```
./dev make test-packaging BUILD=release
scripts/build-release.sh <version> <amd64|arm64> [outdir]
```

`scripts/build-release.sh` runs on the host. It builds in the release container (under QEMU user
mode when the architecture is not the host's) and writes to `dist/` by default:

- `bastion-<v>-linux-<arch>`, the static PIE binary;
- `bastion_<v>-1_<arch>.deb` and `bastion-<v>-1.<x86_64|aarch64>.rpm`;
- `bastion-<v>-linux-<arch>.spdx.json`, an SPDX SBOM;
- `SHA256SUMS`;
- a scratch container image `bastion:<v>-<arch>` holding only the binary.

The packages are described by `packaging/nfpm.yaml`. They install `/usr/bin/bastion`, the
`/usr/bin/bastionctl` symlink, `bastion.service`, `/etc/bastion/bastion.conf` (kept on upgrade),
`/etc/logrotate.d/bastion`, a default page under `/usr/share/bastion/html`, `man 8 bastion` and a
few documents under `/usr/share/doc/bastion/`. The version string comes from `VERSION` in the
`Makefile` (currently `0.1.0`).

## Regenerated files

Some files are generated and committed. Edit their source, run the target, commit both.

| File | Source | Target |
|---|---|---|
| `docs/config-reference.md` | the directive tables in `src/` and `scripts/config-reference-examples.txt` | `./dev make gen-reference` |
| known-header hash table | `src/http/known_headers.def` | `./dev make gen-known-headers` |
| `src/http/h2/huffman_table.inc` | RFC 7541 code lengths in `scripts/gen-huffman.py` | `./dev make gen-huffman` |

`tests/integration/test_docs.py` fails when the configuration reference is stale or a directive
has no documentation.

## Host-side checks

`tests/host/test_dev_paths.sh` runs on the host and checks `./dev` itself: a tree path with
spaces, that a changed `-D` flag recompiles, and that a second tree builds its own code.
`tests/host/test_packages_host.sh <version>` installs the built packages in Debian, Ubuntu and
AlmaLinux containers and runs the scratch image.
