# Bastion

A Linux HTTP/1.1, HTTP/2 and HTTP/3 server written in C. Early development: see
`docs/implementation-plan/` for the plan and architecture.

## Building and testing

All builds and tests run in Linux containers through `./dev` (needs Docker). Dependencies
(OpenSSL, ngtcp2, nghttp3, liburing, libbpf, PCRE2, zstd, brotli, zlib-ng, mimalloc) are built
from the pinned, hash-verified sources in `deps/versions.env` into
`build/deps/<arch>-<glibc|musl>/`, cached in the shared `bastion-deps` Docker volume. Build output
lives in a per-tree volume (`bastion-build-<hash of the tree path>`), so clones do not share objects.

```
./dev make                       # build (BUILD=debug|asan|tsan|release, default debug)
./dev make test-unit [T=name]    # tests/unit/test_<name>.c, under ASan and UBSan
./dev make test-unit BUILD=musltest  # the same suite on musl (Alpine image)
./dev make test-tsan             # the unit suite under ThreadSanitizer
./dev make test-deps             # every pinned dep resolves through pkg-config and links
./dev --platform linux/amd64 <cmd>   # pass a Docker platform (x86_64 deps not built yet)
./dev make test-int [K=expr]     # pytest integration tests
./dev make BUILD=release         # static musl binary (Alpine image)
./dev make clean
```

`test-vm` (`KERNEL=floor|current`) and `fuzz-smoke` work; `conformance` is a placeholder until
later phases (exit 2). `tests/host/test_dev_paths.sh` runs on the host and checks `./dev` from a
path with spaces, that a changed `-D` flag recompiles, and that a second tree builds its own code.

## License

MIT, see `LICENSE`.
