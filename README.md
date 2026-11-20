# Bastion

An HTTPS site with a certificate from Let's Encrypt:

```conf
acme { email admin@example.com; }
server {
    name example.com www.example.com;
    tls auto;
    root /srv/www;
}
```

Bastion is a Linux web server and reverse proxy written in C: HTTP/1.1, HTTP/2 and HTTP/3,
automatic certificates, a shared HTTP cache, rate limits and XDP DDoS filtering, with every worker
sandboxed by seccomp and Landlock. Every directive has a safe default, so the four directives above
are a complete configuration: the server listens on 443 and redirects port 80 to it.

Pre-1.0: see [SECURITY.md](SECURITY.md) and the [threat model](docs/threat-model.md) before exposing it
to the internet.

## Documentation

- [Getting started](docs/guide/getting-started.md): install, configure, HTTPS and HTTP/3
- [Static sites](docs/guide/static-sites.md), [reverse proxy](docs/guide/reverse-proxy.md),
  [TLS](docs/guide/tls.md), [caching](docs/guide/caching.md),
  [DDoS protection](docs/guide/ddos.md)
- [Migrating from nginx](docs/guide/migrating-from-nginx.md)
- [Operations](docs/guide/operations.md): reload, upgrade, logs, metrics, admin API, systemd
- [Configuration reference](docs/config-reference.md), generated from the binary
- [Examples](examples/): complete configurations, each checked by `bastion -t` in the tests
- [Quickstart recipes](docs/quickstart.md), [tuning](docs/tuning.md),
  [systemd](docs/systemd.md), [admin API](docs/admin-api.md), [challenge](docs/challenge.md),
  [conformance](docs/conformance.md)

The design and the plan it was built from are in `docs/implementation-plan/`.

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
./dev make test-int BUILD=musltest   # integration tests against the musl binary
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
