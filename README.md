# Bastion

A Linux HTTP/1.1, HTTP/2 and HTTP/3 server written in C. Early development: see
`docs/implementation-plan/` for the plan and architecture.

## Building and testing

All builds and tests run in Linux containers through `./dev` (needs Docker). Dependencies
(OpenSSL, ngtcp2, nghttp3, liburing, libbpf, PCRE2, zstd, brotli, zlib-ng, mimalloc) are built
from the pinned, hash-verified sources in `deps/versions.env` into
`build/deps/<arch>-<glibc|musl>/`, cached in the `bastion-build` Docker volume.

```
./dev make                       # build (BUILD=debug|asan|tsan|release, default debug)
./dev make test-unit [T=name]    # tests/unit/test_<name>.c, under ASan and UBSan
./dev make test-int [K=expr]     # pytest integration tests
./dev make BUILD=release         # static musl binary (Alpine image)
./dev make clean
```

`test-vm`, `fuzz-smoke` and `conformance` are placeholders until later phases (exit 2).
`tests/host/test_dev_paths.sh` checks `./dev` from a path with spaces and runs on the host.

## License

MIT, see `LICENSE`.
