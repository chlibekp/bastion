# Threat model

This document names who Bastion defends against, what each attacker can reach, what stops them,
and the risks we accept. The process model and sandbox it relies on are specified in
[implementation-plan/architecture.md](implementation-plan/architecture.md) (sections 1 and 8).
What the static analysis and hand audit found is in [security.md](security.md). How to report a
vulnerability is in [SECURITY.md](../SECURITY.md).

## Assets

- **Private keys**: TLS certificate keys, session ticket keys, the ACME account key. Master loads
  them; workers inherit them in memory through `fork`.
- **Integrity of responses**: cached objects, upstream responses passed on, files served.
- **Availability**: the listeners, the connection and request limits, the shared regions.
- **The host**: master starts as root to bind ports, attach XDP and create io_uring rings.
- **Operator controls**: the admin socket, the config, the block list, the metrics endpoint.

## Trust boundaries

```
 network ──► XDP program ──► kernel TCP/UDP ──► worker (sandboxed, unprivileged)
                                                 │  shared regions (memfd, atomics only)
 upstreams ◄────────────────────────────────────┘
 local user ──► admin socket (helper) ──► master (root, small poll loop)
```

Text version: network traffic first meets the XDP program, then the kernel, then a worker.
Workers talk to upstreams. Local users can reach only the admin socket, which the helper serves.
Master talks to children over one `SOCK_SEQPACKET` channel each and through shared regions.

## Attacker 1: on the network

Can send any bytes over TCP, UDP (QUIC) and TLS to any listener, at any rate, from many
addresses, and can reset connections at any point.

| Threat | Mitigation |
|---|---|
| Memory corruption in a parser (HTTP/1.1, HPACK, HTTP/2 frames, QPACK through nghttp3, QUIC through ngtcp2, PROXY protocol, JSON, JWT, TLS ClientHello for JA4, DNS replies, config) | Bounded parsers with explicit length checks; ASan/UBSan on every unit and integration run; libFuzzer targets per parser with a regression corpus (`fuzz/`); hand audit of every `memcpy` and every size taken from the wire ([security.md](security.md)). |
| Code execution after a corruption | The worker is unprivileged, has no capabilities, `no_new_privs`, Landlock on its paths, and a seccomp allowlist that kills on anything else: no `execve`, `fork`, `clone`, `ptrace`, `bpf`, `mount`, `prctl`, `ioctl`, executable mappings or new files outside its roots. |
| Resource exhaustion (slowloris, header floods, HTTP/2 rapid reset, CONTINUATION floods, QUIC floods, compression bombs) | Per-connection timeouts (`client_header_timeout`, body, idle), header and frame limits, HTTP/2 abuse detection, `limit_conn`, `limit_req`, admission control, escalation into XDP drops. |
| Volumetric floods | XDP drops blocked addresses before the stack; SYN cookies; per-IP limits. |
| Request smuggling / desync with upstreams | Strict HTTP/1.1 framing (one `Content-Length`, no `Transfer-Encoding` with it, no obs-fold), requests normalised before forwarding. |
| Spoofed client address | The client address is taken from a header or PROXY protocol only from `real_ip_from` peers; `X-Forwarded-*` and `Forwarded` values sent upstream are replaced unless the connection comes from `trusted_proxies`. |
| Path traversal | Files open with `openat2(RESOLVE_BENEATH)` from the root's descriptor; Landlock as a second layer. |

## Attacker 2: a compromised worker

Assumes code execution inside one worker (the outcome Attacker 1 aims for). It holds what the
worker holds: the TLS private keys and ticket keys in memory, its listening sockets, its slot in
the shared regions, and its channel to master.

| Threat | Mitigation |
|---|---|
| Steal the keys | Not prevented: they are in its memory. Accepted (see below); certificates should be revoked if a worker is known to be compromised. |
| Escalate to root | No capabilities, `no_new_privs`, seccomp allowlist, Landlock, optional namespaces. Process creation is impossible. |
| Corrupt master through shared regions | Regions use atomics and CAS only, no process-shared locks. Master and helper take every index and length from their own trusted state (`bst_spsc_attach` takes `cap` from master), and treat every record read from a region as hostile: bounds-checked, never followed as a pointer. |
| Corrupt master through the channel | Messages are fixed-format, length-checked `SOCK_SEQPACKET` records; master ignores malformed ones. |
| Block arbitrary addresses through the block ring | A worker can ask master to block addresses, the same power the L7 limits already give it. Blocks are bounded in number and expire. Accepted. |
| Crash-respawn to defeat ASLR | See fork-without-exec below: exponential backoff and a crash metric. |
| Attack sibling workers | Separate processes; the Landlock signal scope (ABI 6) and seccomp (`tgkill` only to itself) stop signals. Siblings share only the regions above. |

## Attacker 3: a malicious or compromised upstream

Can send any response bytes, hold connections open, and send endless or malformed bodies, on
HTTP/1.1, HTTP/2 or gRPC, with or without TLS.

| Threat | Mitigation |
|---|---|
| Memory corruption in the response parsers | Same parsers and fuzzing as for clients (`resp_parser.c`, the HTTP/2 client). |
| Response splitting / header injection to clients | Upstream responses go through the strict response parser and are re-serialised; hop-by-hop headers dropped. |
| Cache poisoning | Cache keys are configured per location; `Vary` honoured; responses with `Set-Cookie` are not stored unless `cache_ignore_headers` says so (`src/cache/policy.c`). |
| Resource exhaustion | Upstream timeouts, spool limits, circuit breakers, retries bounded. |
| Downgrade or MITM of upstream TLS | The upstream `tls verify` directive with a CA bundle (docs/config-reference.md). |

## Attacker 4: a local unprivileged user

Has a shell on the same host but not root and not the Bastion user.

| Threat | Mitigation |
|---|---|
| Use the admin API | Authentication is the socket's file mode (default `0600`, or `0660` with a named group; any mode that lets other users in is a config error), checked again with `SO_PEERCRED`: only root and the server's owner uid are let through unless the group is configured. Write actions are logged with the caller's pid, uid and gid. |
| Read keys or cache files | Key files belong to root; cache and temp directories belong to the Bastion user with private modes. |
| `ptrace` or read worker memory | `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`. |
| Take a listening port first | Master binds before dropping; `SO_REUSEPORT` sockets are owned by one uid, and the pid file is `flock`ed so a second instance refuses to start. |
| Inject into the log pipe or tty | Children `setsid` and point fds 0-2 at `/dev/null` before the drop, so `TIOCSTI` on root's tty is impossible. |
| Metrics | The metrics listener is opt-in and should bind to loopback or a private address; it exposes counters only. |

## Accepted risks

1. **Fork without exec.** Workers, the helper and the ACME job are forked from master without
   `exec`, so they share one ASLR layout, and every child holds a copy of master's memory at fork
   time, including private keys. A crash-respawn loop could help a blind ROP attack find gadgets.
   Mitigation: exponential respawn backoff, the crash counter metric, and the seccomp kill (no
   useful syscalls for a chain). Re-exec per child can be added later without changing the design.
2. **Admin socket authentication is the file mode plus `SO_PEERCRED`.** There is no token or TLS:
   anyone the filesystem lets connect, and whose uid passes the peer check, is an administrator.
   Operators who widen the group take responsibility for its members.
3. **The helper writes shared regions on admin requests.** Purge, drain/enable and maintenance
   requests from the admin socket are carried out by the helper, which writes the shared regions
   workers read (upstream state, cache purge table). A compromised helper can therefore change
   what workers serve. The helper is sandboxed in its own role (`BST_SANDBOX_HELPER`), takes no network input
   but the admin socket, the metrics listener (if configured) and health checks, and validates
   every request (lengths, JSON shape) before acting.
4. **The ACME job role.** ACME runs in its own forked role (`BST_SANDBOX_ACME`) with network
   access to the CA and write access to the certificate directory; it is the only role allowed
   `fsync`. A compromise of it could replace certificates and keys on disk, which take effect on
   the next reload. It parses JSON and PEM from the CA only.
5. **`accept4` is allowed for every role.** The seccomp table has one row for all roles: workers
   accept client connections, and the helper accepts on the metrics and admin listeners that
   master made and bound for it. The ACME role has no listening socket, so the allowance there is
   inert; splitting the row per role is a possible later tightening.
6. **XDP pins outlive the process with `on_exit keep`.** With `xdp { on_exit keep; }` the XDP
   program and its block maps stay attached after a clean stop, so blocks keep applying while
   Bastion is down or restarting. This is on purpose (no unprotected gap), but a block list then
   persists until the next start or a manual `ip link set dev <if> xdp off`. The default is
   `detach`.
7. **Keys in worker memory.** See Attacker 2. Keyless TLS or an external signer is out of scope
   for 0.1.
8. **Connection counts are approximate.** `limit_conn` uses a count-min sketch; a collision can
   only make a limit stricter, never looser.
9. **An io_uring multishot accept in a dying worker** can take one queued connection that is then
   lost with the worker (architecture.md section 3).
10. **Kernel trust.** io_uring, BPF/XDP, seccomp and Landlock are kernel features; a kernel bug
    in them is outside what Bastion can mitigate. `kernel.io_uring_disabled` and the `backend
    epoll` setting let operators avoid io_uring entirely.

## Open issues

The Phase 12 note that, on io_uring, a client resetting in the middle of its request headers
could hold its `limit_conn` slot until `client_header_timeout` is tracked in
[security.md](security.md#phase-12-io_uring-mid-header-reset), with its current status.
