# FAQ

### Is Bastion ready for production?

Not yet without care. It is a 1.0.0 release candidate. The test gates in
[CHANGELOG.md](../CHANGELOG.md) passed on arm64, but h2spec, h3spec, quic-interop-runner and
testssl.sh have not been run, amd64 artifacts have not been built, the CI workflows have never run
on a runner, and there has been no long soak or fuzz campaign. Read
[conformance.md](conformance.md#deviations-and-untested-areas-at-100), the
[threat model](threat-model.md) and [SECURITY.md](../SECURITY.md) first.

### Which platforms does it run on?

Linux only, 6.1 or later, on x86_64 and arm64. Only arm64 builds have been made and tested so far.
Optional features need more: io_uring (falls back to epoll), kTLS (the `tls` module), Landlock,
XDP and BPF, `uring_napi` (6.9). `bastion doctor` reports what a host has.

### How is it different from nginx?

The configuration looks similar, and [migrating from nginx](guide/migrating-from-nginx.md) has a
directive table. Differences in short: HTTP/3, ACME, rate limiting, the challenge page, Prometheus
metrics and XDP filtering are built in; every directive has a safe default; workers are sandboxed
with seccomp and Landlock; reload re-executes master with the same PID; there are no modules,
no scripting and no FastCGI or uwsgi.

### Does it support FastCGI, PHP, Lua or modules?

No. It serves files and proxies HTTP (HTTP/1.1 or HTTP/2 to upstreams, including gRPC and
WebSockets). Applications must speak HTTP themselves, or sit behind something that does.

### Can I run it without a configuration file?

Yes, for simple cases: `bastion serve /srv/www --port 8080` or
`bastion proxy http://127.0.0.1:3000 --port 8080` ([CLI](cli.md#serve-and-proxy-no-configuration-file)).

### Does it daemonise?

No. It runs in the foreground under systemd or any supervisor. The package's unit is
`Type=notify` ([systemd](systemd.md)).

### Why does it need root?

Master binds privileged ports, reads private keys that stay `root:root 0600`, loads BPF programs
and sets up the sandbox. Workers and the helper drop to `user` and give up every capability. A
server started as non-root works for ports above 1024, without dropping users and without
emptying the capability bounding set (it warns).

### Can it run in a container?

Yes. The release build makes a scratch image holding only the static binary. In a container,
Docker's default seccomp profile refuses io_uring (Bastion uses epoll), and XDP and `quic_routing
ebpf` need `CAP_BPF` and `CAP_NET_ADMIN`; without them those features are off with a warning.
Landlock depends on the host kernel.

### How do I see the effective configuration?

`bastion -T -c <file>` prints it with every default. It expands environment variables, so it can
show secrets.

### Where are the logs?

Errors go to standard error (the journal under systemd) unless `error_log` is set. Access logs
are off unless `access_log` is set; the packaged configuration writes
`/var/log/bastion/access.log` ([logging and metrics](guide/logging-and-metrics.md)).

### Does the cache purge by URL?

No. Purge by tag (from the `Cache-Tag` response header), by host, or everything, through
`bastionctl purge` or the `PURGE` method from addresses in `purge_method_allow`
([caching](guide/caching.md#purging)).

### Does it support wildcard certificates?

From ACME only with `challenge dns-01` and a `dns_hook` ([ACME](guide/acme.md#dns-01-hook)), or
from files with `tls_cert`.

### Can several sites share one IP and port?

Yes. Servers sharing an address are chosen by `Host`, and with TLS the certificate is chosen by
SNI, on TCP and QUIC alike.

### Is the admin API reachable over the network?

No. It is HTTP over a Unix socket only, protected by the socket's file mode
([admin API](admin-api.md)).

### How do I report a vulnerability?

See [SECURITY.md](../SECURITY.md). The contact there is still a placeholder: the project owner has
to set it up before the first public release.
