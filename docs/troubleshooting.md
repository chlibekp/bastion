# Troubleshooting

Start with three commands:

```
bastion -t -c /etc/bastion/bastion.conf     # does the configuration load?
bastion doctor -c /etc/bastion/bastion.conf # what does this host offer?
journalctl -u bastion -e                    # what did the server log?
```

`bastion -T` prints the configuration with every default, which answers most "why does it do
that" questions. Set `error_log <path> info` (or `debug`, briefly) for more detail.

## The server does not start

| Symptom | Cause and fix |
|---|---|
| `cannot read the default configuration (use -c file)` | no `/etc/bastion/bastion.conf`, or not readable by the user running `bastion` |
| `server has no "listen"` | add `listen`, or use `tls auto` (which implies 443 and 80) |
| `tls auto needs an acme {} block` | add `acme { email ...; }` |
| a bind error on a port | another program holds the port (`ss -ltnup`), or the user cannot bind ports below 1024: start as root (master keeps root, workers drop to `user`) or grant `CAP_NET_BIND_SERVICE` |
| a missing `root` directory | `root` is opened at start; a missing directory is a startup error |
| exits with status 1 right after the workers start | a child failed at startup; the log line before says why (often a `require` the kernel cannot meet: check `bastion doctor -c`) |
| another server already running | the `pid` file is locked by a running master; a second server with the same file refuses to start |

## Warnings at start

| Warning | Meaning |
|---|---|
| `workers run as root: set "user"` | add `user bastion;` (the package creates that user) |
| `sandbox: landlock unavailable: file access is limited by permissions and seccomp only` | the kernel (or container) has no Landlock; add `landlock on require` to refuse to start instead |
| io backend `epoll` with a reason | io_uring is disabled (`kernel.io_uring_disabled`), refused by a seccomp profile (Docker's default refuses it) or too old; epoll works fine |
| an XDP warning | missing `CAP_BPF`/`CAP_NET_ADMIN` or kernel support; the filter is off, other limits apply |
| `quic_routing ebpf` falling back to `hash` | same capabilities missing; HTTP/3 works, but clients that change address lose their connection |
| `metrics listen ... is not a loopback address` | protect the endpoint with `allow` or `auth_basic` |

## A worker was killed

A worker that makes a system call outside its seccomp allowlist is killed by the kernel. Master
logs the death and respawns it (with backoff), and `bastion_child_crashes_total` grows.

1. Look for the audit record: `dmesg | grep type=1326` (or `journalctl -k`). It names the system
   call number (`syscall=`).
2. Reproduce with `sandbox { seccomp log; }`: the call is recorded instead of fatal.
3. Report it with the record, `bastion --version` and the configuration that triggers it. Do not
   leave `seccomp log` or `seccomp off` in production.

## Requests fail

| Status | Usual causes |
|---|---|
| 400 | malformed request; the HTTP/1.1 parser is strict ([conformance](conformance.md)) |
| 403 | `allow`/`deny`, `auth_mtls` without a certificate, a WAF `deny`, a directory with no index and `autoindex off` |
| 404 | file not found under `root`; a `location` marked `internal`; `symlinks off` (the default) and the path is a symlink; `dotfiles deny` (the default) and a path component starts with `.` (`/.well-known/` included: allow it in its own location) |
| 413 | body over `client_max_body_size` (1m by default) |
| 421 | the `Host` names another server than the TLS SNI did (`host_sni_mismatch`) |
| 429 | a `limit_zone` refused (or `overload_status 429`) |
| 431 | header section too large |
| 500 | a regex hit `regex_match_limit` or `regex_depth_limit` |
| 502 | upstream refused the connection, sent an invalid or oversized response head, or a `resolve` name is not resolved yet |
| 503 | no healthy upstream server, a circuit breaker, worker over `worker_memory`, maintenance mode, `auth_forward` service down, too many concurrent password hashes |
| 504 | upstream did not connect within `connect_timeout` or did not answer within `read_timeout` |
| 507 | disk full while spooling a buffered body |

The access log (`$status`, `$upstream_status`, `$upstream_addr`) and the error log tell the
statuses apart. `bastionctl upstreams` shows which upstream servers are up and drained.

## TLS and certificates

- **Self-signed certificate in the browser with `tls auto`:** issuance has not finished. See
  [ACME troubleshooting](guide/acme.md#troubleshooting-issuance).
- **Wrong certificate:** SNI picks the server by name; a client that sends no SNI, or an unknown
  name, gets the default server's certificate (`tls_default_cert` to choose another, TCP only).
- **`tls_cert` changes not picked up:** certificates are read at load; reload after replacing
  the files.
- **kTLS not used:** `bastion doctor` shows whether the `tls` kernel module is loaded;
  `bastion_tls_ktls_connections{mode="user"}` counts connections that stayed in user space.

## HTTP/3 does not work

- UDP port 443 must be open, not just TCP.
- `tls auto` alone opens no HTTP/3 listener: add `listen 443 http3;` ([HTTP/3](guide/http3.md)).
- Browsers try HTTP/3 only after seeing `Alt-Svc` on a TCP response, and fall back silently.
  Test with `curl --http3-only`.

## Reload did not apply

- `bastion_config_reload_success` is 0 after a failed reload; the error is in the log, and
  `bastionctl reload` returns it directly.
- Admin API changes (drains, maintenance, challenge override) are reset by a reload by design.

## Performance

[Tuning](tuning.md) covers CPUs, NUMA, steering, kTLS, HTTP/2 and the I/O backend. Check
`bastion doctor` for `somaxconn`, `tcp_max_syn_backlog` and descriptor limits first.

## Logs missing lines

`bastion_log_dropped_total` counts access log lines dropped because a worker's ring was full
while the helper was behind (raise `log_buffer`) or a write failed (disk full). A worker never
waits for the log.

## Reporting a bug

Include `bastion --version`, the smallest configuration that reproduces it (review `-T` output
before sharing: it can contain secrets), the log lines and the kernel version. Security issues go
through [SECURITY.md](../SECURITY.md), not a public issue.
