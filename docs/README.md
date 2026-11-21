# Bastion documentation

Start with [getting started](guide/getting-started.md) for an HTTPS site in a few minutes, or
[quickstart](quickstart.md) for short recipes. Every configuration shown in these pages is checked
by `bastion -t` in the test suite (`tests/integration/test_docs.py`).

## Guides

Task-oriented pages, each with complete configurations.

| Guide | Covers |
|---|---|
| [Getting started](guide/getting-started.md) | install, check the host, an HTTPS site, HTTP/3, start |
| [Static sites](guide/static-sites.md) | roots, virtual hosts, single-page apps, locations, caching and security headers |
| [Reverse proxy](guide/reverse-proxy.md) | proxying, forwarded headers, WebSockets, gRPC, behind a load balancer, TLS upstreams |
| [Load balancing and upstreams](guide/load-balancing.md) | balancing methods, health checks, ejection, retries, circuit breaking, DNS |
| [TLS](guide/tls.md) | certificates, profiles, mTLS, HSTS |
| [Automatic certificates (ACME)](guide/acme.md) | how issuance works, challenges, CAs, renewal, storage |
| [HTTP/3 and QUIC](guide/http3.md) | listeners, Alt-Svc, packet routing, Retry, settings |
| [Caching](guide/caching.md) | the HTTP cache, freshness, stale content, purging |
| [Compression](guide/compression.md) | zstd, Brotli and gzip on the fly, pre-compressed files, BREACH |
| [Access control](guide/access-control.md) | ACLs, connection and rate limits, WAF rules, escalation, authentication |
| [DDoS protection](guide/ddos.md) | how the layers fit together, the challenge page |
| [XDP packet filtering](guide/xdp.md) | the XDP filter, rates, lists, modes, pinning |
| [Logging and metrics](guide/logging-and-metrics.md) | error and access logs, formats, redaction, every Prometheus metric |
| [Reload and live upgrade](guide/reload-and-upgrade.md) | changing configuration and binary without downtime |
| [Operations](guide/operations.md) | day-to-day running: processes, signals, logs, admin API, systemd |
| [Migrating from nginx](guide/migrating-from-nginx.md) | directive table and differences |

## Reference

| Page | Covers |
|---|---|
| [Configuration](configuration.md) | syntax, value types, contexts, inheritance, includes, variables, `-t` and `-T` |
| [Configuration reference](config-reference.md) | every directive, generated from the binary |
| [Command line](cli.md) | `bastion`, `bastionctl`, signals, exit codes |
| [Admin API](admin-api.md) | endpoints of the Unix socket API |
| [systemd](systemd.md) | the unit, live upgrade, sandboxing, socket activation |
| [Tuning](tuning.md) | `bastion doctor`, CPUs, NUMA, kTLS, HTTP/2, WAF costs |
| [The challenge](challenge.md) | the proof-of-work page and `challenge auto` |
| [Troubleshooting](troubleshooting.md) | start failures, warnings, status codes, crashes |
| [FAQ](faq.md) | common questions |

## Internals and project

| Page | Covers |
|---|---|
| [Architecture](architecture.md) | processes, event loop, I/O backends, shared memory, reload, upgrade, sandbox |
| [Building](building.md) | `./dev`, dependencies, build types, make targets, packages |
| [Testing](testing.md) | every test tier and its target |
| [Conformance](conformance.md) | protocol coverage, deviations, and what has not been tested |
| [Threat model](threat-model.md) | assets, trust boundaries, attackers, accepted risks |
| [Security review](security.md) | static analysis, audits, the seccomp allowlist, dependency CVEs |
| [Third-party software](third-party.md) | bundled libraries and licences |
| [Implementation plan](implementation-plan/README.md) | the design and the phased plan Bastion was built from |
