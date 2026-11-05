# Bastion Architecture

This is the design that all phase plans implement. Interfaces given here are binding. If a task needs to change one, update this file in the same commit.

## 1. Processes

```
                 ┌──────────────────────────────────────┐
                 │ master (root)                        │
                 │ config, listeners, BPF load/attach,  │
                 │ TLS key loading, reload, upgrade     │
                 │ never parses network input           │
                 └───┬───────────────┬──────────────┬───┘
         fork, sandbox│              │              │ applies block ring
          ┌──────────▼───┐   ┌───────▼───────┐  ┌───▼─────────────┐
          │ worker 0..N  │   │ helper        │  │ XDP program and │
          │ one per core │   │ ACME, OCSP,   │  │ BPF maps        │
          │ shared-      │   │ health checks,│  └─────────────────┘
          │ nothing      │   │ DNS, cache    │
          └──────┬───────┘   │ eviction, log │
                 │           │ writer, admin │
                 │           └───────┬───────┘
                 └──── shared memory ┘
```

- **Master** stays small and holds root. It owns every listening socket so that accept queues survive worker replacement. It never reads from client sockets.
- **Workers** handle all client traffic. They inherit compiled config and TLS keys through `fork`, then drop privileges and apply the sandbox before touching the network.
- **Helper** is one unprivileged process with its own event loop. It runs anything that must exist only once.
- **Accepted risk:** workers are forked without `exec`, so siblings share an ASLR layout and a crash-respawn loop could assist a blind ROP attack. Mitigation: exponential respawn backoff and a crash metric. Re-exec per worker can be added later without changing the design.

### Shared memory

Each region is an anonymous `memfd` mapped by master before forking, so upgrades can pass them on. Regions use only atomics and CAS. No process-shared mutex is used because a crashed worker would hold it forever.

| Region | Contents |
|---|---|
| `metrics` | Per-worker counters and histograms, cache-line aligned |
| `limits` | GCRA rate limit tables, per-IP connection counters |
| `tickets` | TLS ticket keys, `mlock`ed and `MADV_DONTDUMP` |
| `cache_index` | Disk cache index, stampede locks, tag purge table |
| `upstream_state` | Health, ejection and resolved addresses, published by helper |
| `log_rings`, `block_ring` | SPSC rings per worker: logs to helper, block requests to master |

Ring lifecycle rules:

- `bst_spsc_init` only formats a new region. Master calls it once, before anything uses the ring, and never on a live ring.
- `bst_spsc_attach` writes nothing to shared memory and seeds the local indices from the shared ones. Its `cap` always comes from trusted master state, never from the region. Each process attaches for its role after fork or respawn, so a respawned producer or consumer resumes on the same ring: unread records stay readable and bytes a crashed producer never published are ignored.
- Replacing a producer never triggers a resync. Unread records stay readable, and the successor attaches and carries on. No signal from master is needed.
- `bst_spsc_resync` is for the consumer: it clears the corrupt state and jumps to the current shared write index, dropping unread records. A consumer calls it only after pop returns CORRUPT or SMALL, per ring, at most once per drain tick, and never in a loop. Its `max` must equal the protocol's record bound, so SMALL means the peer broke framing; unread records are dropped only then.
- Each side owns its index and re-asserts it. Pop on a ring that looks empty republishes a differing `rd`. Every failed push, after reloading `rd`, republishes a differing `wr`. A write happens only on a difference, so a healthy ring sees no shared write. A dead peer's wild index therefore heals without a new API, but only if consumers drain on a periodic tick and not only on wakeups, since this healing depends on polling.
- Rings are not shared across generations (a live upgrade or a reload each creates one), because SPSC cannot serve old and new workers on one slot. Each generation gets freshly initialised rings, and master keeps the old generation's memfds mapped until that generation has exited, so rollback stays intact.

## 2. Memory

- Per-connection and per-request **arenas** reset at end of life. The request hot path should not call `malloc`.
- **Slabs** hold fixed-size objects such as connections, streams and timers.
- **Refcounted buffers** carry bytes through parsers, filters and sends, avoiding copies.
- mimalloc is statically linked as the general allocator and registered with OpenSSL through `CRYPTO_set_mem_functions`, since musl's malloc is slow under load. The registration is wired in the worker-start task (Phase 3, Task 7), before any OpenSSL call.
- **Budgets** exist per connection and per worker. Overruns shed load rather than risk the OOM killer.

## 3. I/O API

The core exposes a completion-style interface. The io_uring backend maps to it directly and the epoll backend emulates it with non-blocking syscalls on readiness. Nothing above `src/io/` may use `epoll_*` or `io_uring_*`, except for registering the restricted ring in `sandbox.c`.

```c
typedef struct bst_loop bst_loop;
typedef struct bst_sock bst_sock;
typedef enum { BST_BACKEND_AUTO, BST_BACKEND_URING, BST_BACKEND_EPOLL } bst_backend;

bst_loop   *bst_loop_new(const bst_loop_cfg *cfg, bst_err *err);
int         bst_loop_run(bst_loop *l);
void        bst_loop_stop(bst_loop *l);
bst_backend bst_loop_backend(const bst_loop *l);
uint64_t    bst_loop_now_ms(const bst_loop *l);

typedef void (*bst_accept_cb)(void *ud, int fd, const bst_sockaddr *peer, int err);
typedef void (*bst_recv_cb)(void *ud, bst_buf *data, int err);          /* NULL data, 0 err = EOF */
typedef void (*bst_done_cb)(void *ud, size_t bytes, int err);
typedef void (*bst_poll_cb)(void *ud, uint32_t events, int err);

int  bst_io_accept_start(bst_loop *, int listen_fd, bst_accept_cb, void *ud);
int  bst_io_accept_stop(bst_loop *, int listen_fd);
int  bst_io_recv_start(bst_sock *, bst_recv_cb, void *ud);
int  bst_io_recv_stop(bst_sock *);
int  bst_io_send(bst_sock *, bst_chain *, bst_done_cb, void *ud);       /* completes once fully written */
int  bst_io_connect(bst_sock *, const bst_sockaddr *, bst_done_cb, void *ud);
int  bst_io_poll(bst_sock *, uint32_t events, bst_poll_cb, void *ud);   /* one-shot readiness */

int  bst_aio_submit(bst_loop *, void (*work)(void *), void (*done)(void *), void *arg);
```

### Disk I/O

| Backend | Reads | Zero-copy send |
|---|---|---|
| io_uring | `IORING_OP_READ`, `OPENAT2`, `STATX` | `IORING_OP_SPLICE` through a per-worker pipe pool |
| epoll | `preadv2(RWF_NOWAIT)`, thread pool on `EAGAIN` | `sendfile`, with `readahead` in the pool first when pages are not resident |

### Backend selection

`auto` tries io_uring with `SINGLE_ISSUER`, `DEFER_TASKRUN` and `COOP_TASKRUN`, and steps down through fewer flags if they are rejected. It falls back to epoll on `ENOSYS`, `EPERM`, a required opcode being absent, or `kernel.io_uring_disabled`. The choice gets logged at startup. `io_backend uring` makes unavailability a startup error rather than a fallback.

**io_uring and seccomp:** ring operations are not syscalls, so seccomp cannot filter them. Rings are created with `IORING_SETUP_R_DISABLED` and locked using `IORING_REGISTER_RESTRICTIONS` to the exact opcodes the worker needs before they are enabled.

## 4. Connections and listeners

Master creates one socket per worker slot for each listener, with `SO_REUSEPORT`, and applies the socket options in config. Workers inherit them. Because master holds a copy of each fd, replacing a worker never loses queued connections.

### Generations and QUIC routing

Each reload or upgrade creates a new worker **generation**, placed in new slots. For TCP, new workers begin accepting from the same fds and old ones stop accepting and drain.

QUIC needs more, because packets for existing connections must reach whichever worker owns them, even after address changes or generation changes:

```
Server-issued CID: | 1 byte version/flags | 2 bytes slot | 13+ random bytes |
```

An `sk_reuseport` BPF program reads the slot from the destination CID and looks it up in a `REUSEPORT_SOCKARRAY`. Initial packets and unknown slots hash onto the slots of the active generation. Old slots stay in the array until drained.

## 5. Request flow

```
bytes → TLS → protocol (h1 | h2 | h3) → bst_stream
  → early filters (ACL, limits, WAF, challenge, auth)
  → router (vhost, location, rewrite)
  → handler (static | proxy | return | redirect | internal)
  → response filters (headers, compress, cache store)
  → protocol → TLS or kTLS → socket
```

Protocols and handlers only meet through `bst_stream`, so each handler works on every protocol without per-protocol code.

```c
typedef struct bst_stream bst_stream;

typedef struct bst_stream_ops {             /* implemented by h1, h2, h3 */
    int  (*send_head)(bst_stream *, const bst_resp_head *, bool end_stream);
    int  (*send_interim)(bst_stream *, int status, const bst_headers *);
    int  (*send_body)(bst_stream *, bst_chain *, bool end_stream, bst_done_cb, void *ud);
    int  (*send_trailers)(bst_stream *, const bst_headers *);
    void (*read_body)(bst_stream *, size_t credit);   /* grants request-body flow credit */
    void (*reset)(bst_stream *, bst_stream_err);
} bst_stream_ops;

typedef struct bst_handler_ops {            /* implemented by handlers */
    void (*on_request)(bst_stream *);
    void (*on_body)(bst_stream *, bst_chain *, bool end_stream);
    void (*on_trailers)(bst_stream *, const bst_headers *);
    void (*on_reset)(bst_stream *, bst_stream_err);
} bst_handler_ops;

typedef struct bst_filter_ops {             /* response filter chain */
    int (*on_head)(bst_filter *, bst_resp_head *, bool end_stream);
    int (*on_body)(bst_filter *, bst_chain *, bool end_stream);
} bst_filter_ops;
```

HTTP/1.1 and HTTP/2 run over either cleartext or TLS, so they talk to a transport rather than to a socket or an `SSL` object. Phase 4 provides the plain transport and Phase 6 the TLS one. HTTP/3 does not use it because QUIC owns its own encryption.

```c
typedef struct bst_transport_ops {
    int  (*recv_start)(bst_transport *, bst_recv_cb, void *ud);
    int  (*recv_stop)(bst_transport *);
    int  (*send)(bst_transport *, bst_chain *, bst_done_cb, void *ud);
    bool (*zero_copy_files)(const bst_transport *);   /* cleartext or kTLS TX */
    void (*shutdown)(bst_transport *, bst_done_cb, void *ud);
    void (*close)(bst_transport *);
} bst_transport_ops;
```

**Backpressure:** a `send_body` completion callback is the only signal to produce more data. Request bodies arrive only after credit is granted through `read_body`. No layer may buffer without limit.

**Body chains:** `bst_chain` holds memory or file segments. HTTP/1.1 sends file segments with zero copy when the socket is cleartext or has kTLS TX. HTTP/2, HTTP/3 and user-space TLS read them into buffers through the loop.

## 6. TLS

OpenSSL is used through its public API only.

- **Connection path:** each TLS socket gets an OpenSSL socket BIO in non-blocking mode with `SSL_OP_ENABLE_KTLS`. `SSL_do_handshake`, `SSL_read` and `SSL_write` run when `bst_io_poll` reports readiness.
- **With kTLS TX active:** `BIO_get_ktls_send` is true, so response bytes bypass OpenSSL and travel through plain `bst_io_send`, gaining zero-copy file sends and full io_uring batching.
- **Why not a custom BIO:** that would let io_uring own all reads, but OpenSSL's kTLS hooks (`BIO_CTRL_SET_KTLS`) are in an internal header. Pinned or not, the plan avoids depending on them. The Phase 6 benchmark revisits this only if the gap proves large.
- **Defaults:** TLS 1.2 and 1.3, ECDHE with AEAD ciphers only, groups `X25519MLKEM768:X25519:P-256`, kTLS TX on, kTLS RX off.
- **Keys:** master loads private keys and workers inherit them in memory. Sandboxed workers cannot read key files.
- **Certificate change** (including ACME renewal) triggers a graceful reload.

## 7. DDoS layers

| Layer | Stops | Where |
|---|---|---|
| XDP | Blocked IPs, malformed packets, reflection sources, per-source SYN and UDP floods, invalid QUIC shapes | Driver or generic hook |
| Kernel | SYN cookies, `TCP_DEFER_ACCEPT` empty-connection filtering | TCP stack |
| Worker, connection | Per-IP connection limits, handshake and header deadlines, JA4 rules | Before routing |
| Worker, request | Rate limits, WAF-lite, challenge, protocol abuse guards | Before handler |
| Upstream | Circuit breakers, retry budget, cache stale-if-error | Handler |

### Escalation rules

A worker that sees an IP exceed `escalate` thresholds writes a request to its `block_ring`. Master validates it and writes the BPF block map with a TTL. Workers have no `bpf()` access.

These rules prevent the mechanism from becoming a self-inflicted outage:

1. Only peers that completed a TCP handshake or a validated QUIC path can be escalated, so spoofed packets cannot get a victim's IP blocked.
2. Allowlisted and trusted-proxy CIDRs can never enter the block map.
3. If the client address came from PROXY protocol or `real_ip`, it is not the packet source, so escalation stays at L7 and does not touch XDP.
4. IPv6 is keyed by a configurable prefix, `/64` by default.
5. Every block has a TTL, and master enforces a global ceiling on active blocks.

## 8. Sandbox

Applied in each worker and the helper, in this order, each step configurable:

1. Open needed files, set up rings and shared memory, and start the aio thread pool.
2. Optional mount, PID, IPC and UTS namespaces.
3. `setgroups`, `setgid`, `setuid`, then clear all capabilities and the bounding set. Set `PR_SET_PDEATHSIG` after this, because changing user clears it.
4. `PR_SET_NO_NEW_PRIVS`, `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`.
5. Landlock: read-only on serving roots, read-write on cache and temp directories, nothing else.
6. seccomp-bpf allowlist with per-architecture syscall tables, installed with `SECCOMP_FILTER_FLAG_TSYNC` so pool threads are covered. Default action is `SECCOMP_RET_KILL_PROCESS`; `seccomp log` eases debugging.

Process and thread creation is blocked by seccomp, which is why the pool starts first. `clone3` returns `ENOSYS`, since its flags sit behind a pointer that seccomp cannot inspect. `RLIMIT_NPROC=0` is deliberately not used, because io_uring's kernel workers are subject to that limit and async file operations could stall.

## 9. Source layout

```
src/core/      arena, slab, buf, chain, str, hash, time, wheel, ring, shm, cidr, json, log, counters
src/config/    lexer, parser, schema, compile, template, cli
src/io/        loop, loop_uring, loop_epoll, sock, listener, udp, aio
src/proc/      master, worker, helper, signals, sandbox, seccomp_tables, upgrade, systemd
src/http/      headers, stream, semantics, errors, date
src/http/h1/   parser, body, conn, serialize
src/http/h2/   frame, huffman, hpack, conn, stream, flow, sched, guard
src/http/h3/   quic, cid, token, h3_bridge, guard
src/route/     vhost, location, regex, rewrite, uri
src/handlers/  static, ofcache, range, autoindex, return, internal
src/tls/       ctx, conn, ktls, sni, tickets, ocsp, ja4, early
src/proxy/     upstream, dns, pool, client_h1, client_h2, handler, balance, health, breaker, tunnel, proxyproto, spool
src/cache/     policy, store, index, ram, filter, lock, purge
src/filters/   compress, headers, early_hints, request_id, trace, maintenance
src/auth/      basic, jwt, forward
src/sec/       limit, connlimit, acl, escalate, waf, challenge
src/xdp/       xdp_bastion.bpf.c, reuseport_quic.bpf.c, reuseport, loader, block, stats
src/ops/       logger, metrics, admin, acme, doctor, numa
tools/         bastionctl, embed.mk, namespace-only flood tools
tests/         unit, integration, vm, corpus, conformance
fuzz/          one harness per parser
```

Log lines (`src/core/log.c`) are `2026-11-05T12:34:56.789Z <pid> <tag> LEVEL message`: UTC, the pid read on every line so it is right after fork, and a short tag set with `bst_log_set_tag` (default `-`).
