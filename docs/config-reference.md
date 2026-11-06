# Configuration reference

Generated file: do not edit. It is produced from the directive tables in the binary
(`bastion --dump-schema`). Regenerate it with `./dev make gen-reference` (it runs
`scripts/gen-config-reference.sh`) and commit the result; `test_reference_up_to_date`
fails when it is stale.

`bastion -T` prints the effective configuration with environment variables expanded, so it
can show secrets. Review its output before sharing it. Error messages echo up to 40 bytes
of an offending value after expansion too, so an error about a secret-bearing argument can
show part of the secret: review error output before pasting it into a bug report.

Contexts are the places a directive may appear. `global` is the top level of the file.

## Directives

### `aio_queue`

```nginx
aio_queue <int 1..65536>;
```

Most disk jobs queued, running or awaiting completion per worker; past it a read fails with EAGAIN instead of growing memory. Each queued job costs a small record.

- Contexts: io
- Default: `256`
- Repeatable: no

### `aio_threads`

```nginx
aio_threads <auto|int 1..64>;
```

Disk thread pool size per worker (blocking reads and readahead), or auto for the CPU count, at most 8. Each thread costs a 256 KiB stack; too few makes cold-file reads queue.

- Contexts: io
- Default: `auto`
- Repeatable: no

### `backend`

```nginx
backend <auto|uring|epoll>;
```

Event loop: auto picks io_uring and falls back to epoll when it is unavailable (ENOSYS, EPERM from seccomp or kernel.io_uring_disabled, a missing opcode), uring makes that a startup error, epoll never tries io_uring. The choice and its reason are logged at start and shown by `bastion -t`.

- Contexts: io
- Default: `auto`
- Repeatable: no

### `backlog`

```nginx
backlog <int 1..65535> [require];
```

The listen(2) backlog: connections the kernel queues before the server accepts. The default is 4096. The kernel caps it at net.core.somaxconn without an error; bastion warns when that happens.

- Contexts: tcp_profile
- Default: `4096`
- Repeatable: no

### `busy_poll`

```nginx
busy_poll <duration 1..1000000 us> [require];
```

SO_BUSY_POLL: poll the network device for this long before sleeping on a socket. Lower latency, paid for with CPU. Raising it above the net.core.busy_poll sysctl needs CAP_NET_ADMIN, which master has before it drops privileges.

- Contexts: tcp_profile
- Default: none
- Repeatable: no

### `busy_poll_budget`

```nginx
busy_poll_budget <int 1..65535> [require];
```

SO_BUSY_POLL_BUDGET (Linux 5.11): packets processed per busy poll. Values above the kernel's default need CAP_NET_ADMIN.

- Contexts: tcp_profile
- Default: none
- Repeatable: no

### `client_max_body_size`

```nginx
client_max_body_size <size>;
```

Largest accepted request body; 0 means unlimited.

- Contexts: server, location
- Default: `1m`
- Repeatable: no

### `congestion`

```nginx
congestion <string> [require];
```

TCP congestion control algorithm by kernel name (bbr, cubic, reno, ...). It must be listed in net.ipv4.tcp_available_congestion_control; the kernel refuses a missing one (bbr needs the tcp_bbr module), and bastion warns, or fails with `require`.

- Contexts: tcp_profile
- Default: none
- Repeatable: no

### `defer_accept`

```nginx
defer_accept <duration 1000000..3600000000 us> [require];
```

TCP_DEFER_ACCEPT: the kernel completes the handshake but hands the connection to the server only when data arrives, or when this time (rounded up to the kernel's retransmit schedule) has passed. This delays connections that send nothing, such as a client waiting for a server greeting, a health check that only connects, or a port scan, and it hides them from the accept queue; it also saves a wakeup per request.

- Contexts: tcp_profile
- Default: none
- Repeatable: no

### `error_log`

```nginx
error_log <path> [<debug|info|notice|warn|error>];
```

Error log path and optional minimum level (default warn).

- Contexts: global
- Default: none
- Repeatable: no

### `fastopen`

```nginx
fastopen <int 1..1048576> [require];
```

TCP Fast Open on the listener: the queue length of connections that arrive with data in the SYN. The data can be replayed by the network (a duplicated SYN delivers it twice), so it is as dangerous as TLS 0-RTT early data and obeys the same policy: only safe methods run from it. Needs the server bit of net.ipv4.tcp_fastopen (value 2 or 3); without it the kernel ignores Fast Open and bastion warns.

- Contexts: tcp_profile
- Default: none
- Repeatable: no

### `fastopen_key`

```nginx
fastopen_key <string> [require];
```

The TCP Fast Open cookie key: 32 hex digits, or four groups of 8 separated by '-'. Share one key across machines behind one address so a client's cookie works on all. This is a secret: `bastion -T` prints it like any other directive, so keep the config's permissions tight and review `-T` output before sharing it. Without it the kernel picks a random key.

- Contexts: tcp_profile
- Default: none
- Repeatable: no

### `freebind`

```nginx
freebind <bool> [require];
```

IP_FREEBIND: bind to an address the machine does not have yet (a floating IP that moves to this host later).

- Contexts: tcp_profile
- Default: none
- Repeatable: no

### `group`

```nginx
group <string>;
```

Group for workers and the helper. Default: the primary group of user.

- Contexts: global
- Default: none
- Repeatable: no

### `include`

```nginx
include <path>;
```

Include another file or glob here (expanded by the parser).

- Contexts: global, io, sandbox, limits, xdp, tcp_profile, tls_profile, log_format, upstream, cache_store, limit_zone, waf_rule, server, location, metrics, admin, acme
- Default: none
- Repeatable: yes

### `io`

```nginx
io { ... }
```

I/O backend and its tuning; every default applies when the block is absent.

- Contexts: global
- Block context: io
- Default: none
- Repeatable: no
- Singleton block: at most once; when it is absent its children's defaults still apply

### `keepalive`

```nginx
keepalive idle=<duration 1000000..32767000000 us> interval=<duration 1000000..32767000000 us> count=<int 1..127> [require];
```

TCP keepalive probes on accepted connections: first probe after idle, then one every interval, and the connection is dropped after count unanswered probes. All three are needed. Detects peers that vanished without closing.

- Contexts: tcp_profile
- Default: none
- Repeatable: no
- Option `idle=`: duration 1000000..32767000000 us, required
- Option `interval=`: duration 1000000..32767000000 us, required
- Option `count=`: int 1..127, required

### `listen`

```nginx
listen <string> [tcp_profile=<string>];
```

Listen on port, addr:port or [v6]:port. tcp_profile=name picks the socket tuning from a tcp_profile block (default: nodelay on, backlog 4096, the kernel's defaults otherwise). A socket has one set of options, so two listens on one address may name at most one profile between them.

- Contexts: server
- Default: none
- Repeatable: yes
- Option `tcp_profile=`: string

### `location`

```nginx
location <string> ... { ... }
```

A location block: [= | ^~ | ~ | ~*] pattern. Locations nest and inherit from the enclosing location.

- Contexts: server, location
- Block context: location
- Default: none
- Repeatable: yes

### `mark`

```nginx
mark <int 1..4294967295> [require];
```

SO_MARK: the firewall mark on the connection's packets, for policy routing and netfilter. Needs CAP_NET_ADMIN, which master has before it drops privileges.

- Contexts: tcp_profile
- Default: none
- Repeatable: no

### `name`

```nginx
name <string> ...;
```

Host names this server answers to (lower-cased, except ~regex names, kept as written); none makes it the default.

- Contexts: server
- Default: none
- Repeatable: yes

### `nodelay`

```nginx
nodelay <bool> [require];
```

TCP_NODELAY on accepted connections: send small writes at once instead of waiting to coalesce them. On by default; HTTP responses are written whole, so Nagle only adds latency.

- Contexts: tcp_profile
- Default: `on`
- Repeatable: no

### `notsent_lowat`

```nginx
notsent_lowat <size 1..2147483647 bytes> [require];
```

TCP_NOTSENT_LOWAT: do not report the socket writable while this many bytes are queued unsent. Bounds the memory a slow client pins and keeps responses fresh for HTTP/2 prioritisation.

- Contexts: tcp_profile
- Default: none
- Repeatable: no

### `pacing_rate`

```nginx
pacing_rate <size 1..4294967294 bytes> [require];
```

SO_MAX_PACING_RATE: the most bytes per second one connection may send (the size suffixes mean bytes: 10m is 10 MiB per second). Enforced by the fq qdisc, or by TCP's own pacing on Linux 4.13 and later.

- Contexts: tcp_profile
- Default: none
- Repeatable: no

### `pid`

```nginx
pid <path>;
```

Path of the pid file. Master writes and locks it at start and removes it at exit; a second server with the same file refuses to start.

- Contexts: global
- Default: none
- Repeatable: no

### `prefer_busy_poll`

```nginx
prefer_busy_poll <bool> [require];
```

SO_PREFER_BUSY_POLL (Linux 5.11): let busy polling defer the device's own interrupt handling while the application polls. Only useful with busy_poll.

- Contexts: tcp_profile
- Default: none
- Repeatable: no

### `quickack`

```nginx
quickack <bool> [require];
```

TCP_QUICKACK on each accepted connection (set per connection: the kernel does not keep it). `off` delays acknowledgements so they ride on data, saving packets; `on` is how a new connection starts anyway.

- Contexts: tcp_profile
- Default: none
- Repeatable: no

### `rcvbuf`

```nginx
rcvbuf <size 4096..1073741824 bytes> [require];
```

SO_RCVBUF: receive buffer size, set before the handshake so it shapes the window the connection starts with. Disables receive autotuning for the connection. The kernel caps it at net.core.rmem_max; bastion warns when that happens.

- Contexts: tcp_profile
- Default: none
- Repeatable: no

### `server`

```nginx
server { ... }
```

A virtual server: listeners, names and locations.

- Contexts: global
- Block context: server
- Default: none
- Repeatable: yes

### `shutdown_timeout`

```nginx
shutdown_timeout <duration 1000..86400000000 us>;
```

How long a graceful stop (SIGQUIT) waits for connections in progress. Workers still busy after it are killed.

- Contexts: global
- Default: `30s`
- Repeatable: no

### `sndbuf`

```nginx
sndbuf <size 4096..1073741824 bytes> [require];
```

SO_SNDBUF: send buffer size. Disables send autotuning for the connection. The kernel caps it at net.core.wmem_max; bastion warns when that happens.

- Contexts: tcp_profile
- Default: none
- Repeatable: no

### `steering`

```nginx
steering <none|incoming_cpu|ebpf> [require];
```

How connections reach a worker: none leaves it to the kernel's hash over the worker sockets, incoming_cpu prefers the socket of the worker pinned to the CPU that received the packet (SO_INCOMING_CPU: the slot-th socket prefers CPU slot modulo the CPU count). ebpf is not supported yet and is a config error.

- Contexts: tcp_profile
- Default: none
- Repeatable: no

### `tcp_profile`

```nginx
tcp_profile <string> { ... }
```

A named set of TCP socket options for listeners (`listen ... tcp_profile=name`). Names are unique. A listener without one gets the default profile: nodelay on and backlog 4096. An option the running kernel refuses logs a warning and the server starts; add `require` to an option to make that a startup error.

- Contexts: global
- Block context: tcp_profile
- Default: none
- Repeatable: yes

### `uring_bufs`

```nginx
uring_bufs <int 2..32768>;
```

Receive buffers in each worker's io_uring provided-buffer ring, 16 KiB each. Rounded up to a power of two, with a warning. Memory is the count times 16 KiB per worker; a ring that runs dry only delays receiving until buffers come back.

- Contexts: io
- Default: `256`
- Repeatable: no

### `uring_entries`

```nginx
uring_entries <int 2..32768>;
```

io_uring submission queue size per worker (the completion queue is twice that). Rounded up to a power of two, with a warning. Costs about 64 bytes per submission entry and 16 per completion entry, per worker; too small makes submissions wait.

- Contexts: io
- Default: `256`
- Repeatable: no

### `uring_napi`

```nginx
uring_napi <bool> [require];
```

NAPI busy polling for io_uring (Linux 6.9 or later): lower latency, paid for with CPU spent polling the network device. On an older kernel it logs a warning and runs without it; add `require` to make that a startup error (so is backend epoll, which has no NAPI). `bastion -t` shows whether NAPI is on.

- Contexts: io
- Default: `off`
- Repeatable: no

### `uring_send_zc_min`

```nginx
uring_send_zc_min <size>;
```

Memory sends of at least this size use io_uring zero-copy send; 0 turns it off. Saves a copy on large sends but holds the pages until the kernel is done, and closing a socket with such pages queued resets the connection. It costs more than it saves for small sends, so it is off until measured.

- Contexts: io
- Default: `0`
- Repeatable: no

### `uring_sqpoll`

```nginx
uring_sqpoll <off|duration 1000..60000000 us>;
```

off, or how long the io_uring submission-polling kernel thread spins idle before sleeping (1ms to 1m; rounded up to whole milliseconds). Saves a syscall per batch at the cost of a kernel thread per worker that burns a CPU while busy and for this long after.

- Contexts: io
- Default: `off`
- Repeatable: no

### `user`

```nginx
user <string>;
```

Workers and the helper drop to this user after binding sockets and creating their event loops; master stays root. Without it, a server started as root runs its workers as root, with a warning. Ignored, with a warning, when not started as root.

- Contexts: global
- Default: none
- Repeatable: no

### `user_timeout`

```nginx
user_timeout <duration 1000..86400000000 us> [require];
```

TCP_USER_TIMEOUT: drop a connection when sent data stays unacknowledged this long (rounded down to milliseconds). Without it the kernel waits out its retransmit schedule, about 15 minutes.

- Contexts: tcp_profile
- Default: none
- Repeatable: no

### `worker_rlimit_nofile`

```nginx
worker_rlimit_nofile <int 1..1073741816>;
```

Open file limit (soft and hard) each worker sets for itself, before dropping privileges. Default: the limit the server was started with.

- Contexts: global
- Default: none
- Repeatable: no

### `workers`

```nginx
workers <auto|int 1..4096>;
```

Worker process count, or auto for one per CPU this process may run on.

- Contexts: global
- Default: `auto`
- Repeatable: no
