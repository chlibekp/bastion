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

### `accept_backoff`

```nginx
accept_backoff <duration 1000..60000000 us>;
```

How long a listener stops accepting after accept fails with EMFILE, ENFILE, ENOBUFS or ENOMEM, from 1 millisecond to 60 seconds. A short time recovers quickly once descriptors free up; a long one costs less CPU while they do not.

- Contexts: limits
- Default: `100ms`
- Repeatable: no

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

### `alias`

```nginx
alias <path>;
```

Like root, but the part of the request path that the location matched is replaced by this path instead of the path being appended: location /img/ { alias /srv/pics/; } serves /img/a.png from /srv/pics/a.png. Use it with a prefix location.

- Contexts: location
- Default: none
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

### `chunk_ext_limit`

```nginx
chunk_ext_limit <size 16..65536 bytes>;
```

Most bytes of chunk extensions (the text after a ';' on a chunk-size line) one chunk of a request body may carry. Extensions are ignored; more than this is answered 400 and the connection closed.

- Contexts: server
- Default: `1k`
- Repeatable: no

### `client_body_min_rate`

```nginx
client_body_min_rate <size>;
```

Slowest accepted request body, in bytes per second, averaged over client_body_timeout. 0 turns the rate check off (only a body that stops completely times out).

- Contexts: server
- Default: `1k`
- Repeatable: no

### `client_body_timeout`

```nginx
client_body_timeout <duration 1000..3600000000 us>;
```

Window in which a request body must make progress: every window, at least client_body_min_rate bytes per second must have arrived, or the request is answered 408 and the connection closed.

- Contexts: server
- Default: `30s`
- Repeatable: no

### `client_header_buffer_size`

```nginx
client_header_buffer_size <size 256..1048576 bytes>;
```

Initial read buffer for a request head. It grows up to large_client_header_buffers when a head needs more; most requests never do.

- Contexts: server
- Default: `1k`
- Repeatable: no

### `client_header_timeout`

```nginx
client_header_timeout <duration 1000..3600000000 us>;
```

Time a client has to send a complete request head, counted from its first byte (or from the connection, for the first request). A slow head is answered 408 and the connection closed. The limit is on the whole head, so trickling bytes does not extend it.

- Contexts: server
- Default: `10s`
- Repeatable: no

### `client_max_body_size`

```nginx
client_max_body_size <size>;
```

Largest accepted request body; 0 means unlimited.

- Contexts: server, location
- Default: `1m`
- Repeatable: no

### `client_max_header_count`

```nginx
client_max_header_count <int 1..4096>;
```

Most header lines in one request. One more is refused with 431.

- Contexts: server
- Default: `100`
- Repeatable: no

### `client_max_trailer_size`

```nginx
client_max_trailer_size <size ..1048576 bytes>;
```

Largest trailer section (the header lines after the last chunk) of a chunked request body, in bytes. A larger one is refused with 431. Trailer fields that could change how a message is framed, routed or authenticated are dropped.

- Contexts: server
- Default: `8k`
- Repeatable: no

### `client_max_uri_size`

```nginx
client_max_uri_size <size 256..1048576 bytes>;
```

Largest request-target (path and query), in bytes. A longer one is refused with 414 as soon as the byte over the limit arrives, so the server never buffers it. It must fit inside large_client_header_buffers.

- Contexts: server
- Default: `8k`
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

### `dotfiles`

```nginx
dotfiles <deny|allow>;
```

Whether a path with a component that starts with '.' (/.env, /.git/config) is served. deny: it is a 404 whatever exists there. allow: it is treated like any other file. /.well-known/ is not special: allow it in its own location.

- Contexts: global, server, location
- Default: `deny`
- Repeatable: no

### `drop_capabilities`

```nginx
drop_capabilities <bool> [require];
```

Clears every capability set of every thread, bounding, ambient and inheritable included, whether or not `user` changes the uid. Emptying the bounding set needs master to start as root; otherwise it warns, and `require` makes that a startup error.

- Contexts: sandbox
- Default: `on`
- Repeatable: no

### `error_log`

```nginx
error_log <path> [<debug|info|notice|warn|error>];
```

Error log path and optional minimum level (default warn).

- Contexts: global
- Default: none
- Repeatable: no

### `etag`

```nginx
etag <bool>;
```

Whether static files carry an ETag ("<mtime in hex>-<size in hex>", strong) and If-Match, If-None-Match and If-Range are evaluated against it. With off only Last-Modified validates.

- Contexts: global, server, location
- Default: `on`
- Repeatable: no

### `expires`

```nginx
expires <off|duration> [<immutable>];
```

Adds Expires and Cache-Control: max-age=<duration> to 200, 201, 204, 206, 301, 302, 303, 304, 307 and 308 responses. immutable adds the immutable directive (for files whose name changes with their content). 0s sends no-cache. off: nothing is added.

- Contexts: global, server, location
- Default: none
- Repeatable: no

### `extra_read`

```nginx
extra_read <path>;
```

An absolute path workers and the helper may read, on top of the serving roots. A path that does not exist at start gets no access, with a warning.

- Contexts: sandbox
- Default: none
- Repeatable: yes

### `extra_write`

```nginx
extra_write <path>;
```

An absolute path workers and the helper may read and write, on top of the cache and temp directories. A path that does not exist at start gets no access, with a warning.

- Contexts: sandbox
- Default: none
- Repeatable: yes

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

### `header_add`

```nginx
header_add <string> <template> [<always>];
```

Adds a response header (another line when the name is already there). The value is a template. By default only on 2xx and 3xx responses; with always also on errors. A value that expands to a CR or LF is dropped whole, with a warning in the log. Operations of the global, server and location blocks all apply, in that order.

- Contexts: global, server, location
- Default: none
- Repeatable: yes

### `header_remove`

```nginx
header_remove <string>;
```

Removes a response header, whatever its value, on every status.

- Contexts: global, server, location
- Default: none
- Repeatable: yes

### `header_set`

```nginx
header_set <string> <template> [<always>];
```

Sets a response header, replacing any of that name the handler or an earlier operation gave. Same value, always and ordering rules as header_add.

- Contexts: global, server, location
- Default: none
- Repeatable: yes

### `http1_allow_bare_lf`

```nginx
http1_allow_bare_lf <bool>;
```

Accept a lone LF as a line ending in HTTP/1.1 requests (RFC 9112 section 2.2 allows it, but proxies that disagree about line endings enable request smuggling). Off by default: a bare LF is answered 400. A bare CR is always refused.

- Contexts: server
- Default: `off`
- Repeatable: no

### `http1_max_pipeline`

```nginx
http1_max_pipeline <int 1..1024>;
```

Most requests of one HTTP/1.1 connection that may be accepted ahead of their responses. Beyond it the server stops reading the connection until responses go out, so a client that pipelines and never reads cannot grow server memory.

- Contexts: server
- Default: `8`
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

### `keepalive_requests`

```nginx
keepalive_requests <int 1..1073741824>;
```

Most requests one connection serves; the last response carries Connection: close.

- Contexts: server
- Default: `1000`
- Repeatable: no

### `keepalive_timeout`

```nginx
keepalive_timeout <duration ..86400000000 us>;
```

How long an idle connection waits for its next request. 0s turns keep-alive off: every response closes the connection.

- Contexts: server
- Default: `75s`
- Repeatable: no

### `landlock`

```nginx
landlock <bool> [require];
```

Limits file access to the serving roots and extra_read, read only, and the cache, temp and extra_write directories, read and write. Log files need no rule: each process holds its own open description. On a kernel without Landlock it warns and starts; add `require` to make that a startup error.

- Contexts: sandbox
- Default: `on`
- Repeatable: no

### `large_client_header_buffers`

```nginx
large_client_header_buffers <size 1024..1048576 bytes>;
```

Largest request head (request line and all header lines), in bytes. A larger one is refused with 431. Must be at least client_max_uri_size.

- Contexts: server
- Default: `16k`
- Repeatable: no

### `limits`

```nginx
limits { ... }
```

Overload protection, per worker. Every default applies when the block is absent.

- Contexts: global
- Block context: limits
- Default: none
- Repeatable: no
- Singleton block: at most once; when it is absent its children's defaults still apply

### `lingering_close`

```nginx
lingering_close <bool>;
```

When the server closes a connection after an error response, send FIN, then keep reading (and discarding) for up to lingering_timeout so the client sees the response rather than a reset caused by unread request bytes.

- Contexts: server
- Default: `on`
- Repeatable: no

### `lingering_timeout`

```nginx
lingering_timeout <duration 1000..60000000 us>;
```

Longest a lingering close keeps draining the client.

- Contexts: server
- Default: `5s`
- Repeatable: no

### `listen`

```nginx
listen <string> [<default_server>] [tcp_profile=<string>];
```

Listen on port, addr:port or [v6]:port. tcp_profile=name picks the socket tuning from a tcp_profile block (default: nodelay on, backlog 4096, the kernel's defaults otherwise). A socket has one set of options, so two listens on one address may name at most one profile between them. The flag default_server makes this server answer a request whose Host matches no name on the address (otherwise the server with no name, else the first one).

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

### `max_connections`

```nginx
max_connections <int 1..1048576>;
```

Most connections one worker holds open. A connection arriving past it is accepted and closed at once, without a response, and counted in the worker's overload log line. Keep it below worker_rlimit_nofile minus reserve_fds and the descriptors files and upstream connections need, or the worker meets the descriptor limit first.

- Contexts: limits
- Default: `10240`
- Repeatable: no

### `max_ranges`

```nginx
max_ranges <int 1..1000>;
```

Most byte ranges one Range header may ask for. A request with more is answered with the whole file and status 200, which the protocol allows and which keeps a client from making the server assemble thousands of pieces. Overlapping and adjacent ranges are merged first; 1 serves single ranges only.

- Contexts: global, server, location
- Default: `10`
- Repeatable: no

### `merge_slashes`

```nginx
merge_slashes <bool>;
```

Collapse runs of '/' in the request path before routing and file lookup, so //a///b is served as /a/b. With off they are kept as written, and an empty path segment names nothing in a directory (a 404).

- Contexts: server
- Default: `on`
- Repeatable: no

### `name`

```nginx
name <string> ...;
```

Host names this server answers to: an exact name, *.example.com (any host below it), example.* (any suffix) or ~regex (kept as written; the others are lower-cased). The match order is exact, then the longest leading wildcard, then the longest trailing wildcard, then regexes in file order. A server with no name is the default for its address.

- Contexts: server
- Default: none
- Repeatable: yes

### `namespaces`

```nginx
namespaces <bool> [require];
```

Runs each worker and the helper in mount, PID, IPC and UTS namespaces of its own, with a private root holding only the serving roots, the cache and temp directories and the extra_ paths. Needs root in master. Log lines from a child then say pid 1. Where a namespace is not permitted it warns and starts; add `require` to make that a startup error.

- Contexts: sandbox
- Default: `off`
- Repeatable: no

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

### `open_file_cache`

```nginx
open_file_cache [<off>] [max=<int 1..1000000>] [ttl=<duration 1000000..86400000000 us>] [errors=<bool>];
```

Keeps the descriptor and size of recently served files, per worker, so a hot file is not opened and stat'ed for every request. max=<n> entries (each holds one open descriptor, so n counts against the open-file limit), ttl=<duration> how long an entry is trusted before the file is looked at again (a file replaced inside the ttl is served as it was), errors=on also remembers files that were not found. off disables the cache.

- Contexts: global
- Default: `off`
- Repeatable: no
- Option `max=`: int 1..1000000
- Option `ttl=`: duration 1000000..86400000000 us
- Option `errors=`: bool

### `overload_retry_after`

```nginx
overload_retry_after <duration 1000000..3600000000 us>;
```

The Retry-After of an overload response, from 1 second to 1 hour, rounded up to whole seconds. Set it to about how long a burst lasts: a short value brings retries back into a worker that is still full.

- Contexts: limits
- Default: `1s`
- Repeatable: no

### `overload_status`

```nginx
overload_status <int 400..599>;
```

The HTTP status of a request refused because the worker is over worker_memory. 503 tells clients and load balancers to try elsewhere; 429 tells well-behaved clients to slow down.

- Contexts: limits
- Default: `503`
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

### `redirect`

```nginx
redirect <301|302|303|307|308> <template>;
```

Answers with a redirect: status 301, 302, 303, 307 or 308 and the target as Location. The target may use variables ($1 of the location's regex, $request_uri); when it has no '?' the request's own query string is appended. Prefer $request_uri to $uri in a target: $uri is decoded. A target that begins with a value from the request ($arg_x, $http_x) is warned about by -t as an open redirect.

- Contexts: server, location
- Default: none
- Repeatable: no

### `redirect_https`

```nginx
redirect_https [<301|302|303|307|308>];
```

Answers every request with a redirect to the same host and path on https (https://$host$request_uri): 301 by default, or the status given.

- Contexts: server, location
- Default: none
- Repeatable: no

### `regex_depth_limit`

```nginx
regex_depth_limit <int 10..10000000>;
```

Deepest nesting of backtracking one regular-expression match may reach (PCRE2's depth limit). Reaching it fails the match like regex_match_limit.

- Contexts: global
- Default: `1000`
- Repeatable: no

### `regex_match_limit`

```nginx
regex_match_limit <int 100..100000000>;
```

Most backtracking steps one regular-expression match may take (PCRE2's match limit), for location, name and rewrite patterns. A match that reaches it is a failure, not a non-match: the request is answered 500, so a pattern such as (a+)+$ cannot hold a worker with a long URI. Raise it only for a pattern you trust.

- Contexts: global
- Default: `100000`
- Repeatable: no

### `request_header_remove`

```nginx
request_header_remove <string>;
```

Removes a request header the client sent before the handler sees it.

- Contexts: global, server, location
- Default: none
- Repeatable: yes

### `request_header_set`

```nginx
request_header_set <string> <template>;
```

Sets a request header before the handler sees it (and before a proxy forwards it), replacing any of that name the client sent. The value is a template.

- Contexts: global, server, location
- Default: none
- Repeatable: yes

### `reserve_fds`

```nginx
reserve_fds <int 1..64>;
```

Descriptors each worker holds open and unused. When the process is out of descriptors (EMFILE) it gives them up to accept waiting connections and close them at once, so clients see a reset instead of waiting in the listen queue, then takes them back. They count against worker_rlimit_nofile.

- Contexts: limits
- Default: `1`
- Repeatable: no

### `return`

```nginx
return <int 200..599> [<template>];
```

Answers every request with a fixed status. The text is the body; for 301, 302, 303, 307 and 308 it is the Location instead. Both may use variables ($uri, $arg_x, $1 of the location's regex). With no text the body is the standard error page for the status.

- Contexts: server, location
- Default: none
- Repeatable: no

### `rewrite`

```nginx
rewrite <string> <template> [<last|break>];
```

Rewrites the request path when the regular expression matches it, to the replacement ($1 to $9 are the groups; the query string is kept unless the replacement has a '?'). The match runs on the normalized path. Rules of a server run before the location is chosen, rules of a location after. Without a flag the next rule runs on the new path. last: stop, and search for the location again with the new path (at most rewrite_max_cycles times a request). break: stop here and keep the location. A rule set in a block replaces the rules it would inherit.

- Contexts: server, location
- Default: none
- Repeatable: yes

### `rewrite_max_cycles`

```nginx
rewrite_max_cycles <int 1..1000>;
```

Most times one request may restart the location search through a rewrite with the last flag. A request that would go on is answered 500: a rewrite loop.

- Contexts: global, server, location
- Default: `10`
- Repeatable: no

### `root`

```nginx
root <path>;
```

The directory the files of this scope are served from: the request path is appended to it. An absolute path. The directory is opened once at startup (a missing one is a startup error) and the workers may read nothing outside the served roots, extra_read and what the sandbox allows. A path can never leave the root: '..' is removed by normalization and the kernel refuses anything that resolves above it (openat2 with RESOLVE_BENEATH).

- Contexts: global, server, location
- Default: none
- Repeatable: no

### `sandbox`

```nginx
sandbox { ... }
```

What contains a compromised worker or helper; master stays outside it. Every default applies when the block is absent.

- Contexts: global
- Block context: sandbox
- Default: none
- Repeatable: no
- Singleton block: at most once; when it is absent its children's defaults still apply

### `seccomp`

```nginx
seccomp <off|on|log> [require];
```

Syscall allowlist, per role, on every thread. on kills the process on anything else; log lets it run and records it in the kernel audit log, for debugging a missing entry; off has no filter. On a kernel without seccomp filters it warns and starts; add `require` to make that a startup error.

- Contexts: sandbox
- Default: `on`
- Repeatable: no

### `send_min_rate`

```nginx
send_min_rate <size>;
```

Slowest accepted reader of a response, in bytes per second, averaged over send_timeout. 0 turns the rate check off.

- Contexts: server
- Default: `1k`
- Repeatable: no

### `send_timeout`

```nginx
send_timeout <duration 1000..3600000000 us>;
```

Window in which a response must make progress: every window, at least send_min_rate bytes per second must have been accepted by the client, or the connection is closed. Frees workers held by clients that never read.

- Contexts: server
- Default: `30s`
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

### `server_tokens`

```nginx
server_tokens <bool>;
```

Whether the Server header names the version (bastion/x.y) or only bastion.

- Contexts: server
- Default: `on`
- Repeatable: no

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

### `symlinks`

```nginx
symlinks <on|off|owner_match>;
```

Whether a symbolic link inside a root may be followed. off: never, a link is a 404. on: followed, but only while the result stays inside the root. owner_match: followed when the target belongs to the same owner as the root directory, and still never out of the root. Magic links (/proc/self/...) are always refused.

- Contexts: global, server, location
- Default: `off`
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

### `unknown_host`

```nginx
unknown_host <default|421|close>;
```

What happens to a request whose Host matches no server name on the address it arrived on. It is read on the default server of that address. default: the default server answers. 421: answer 421 Misdirected Request and keep the connection. close: close the connection without a response.

- Contexts: server
- Default: `default`
- Repeatable: no

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

off, or how long the io_uring submission-polling kernel thread spins idle before sleeping (1ms to 1m; rounded up to whole milliseconds). Saves a syscall per batch at the cost of a kernel thread per worker that burns a CPU while busy and for this long after. The thread keeps the credentials of whoever creates the ring, so with `user` set the ring is created after dropping privileges. That needs kernel.io_uring_disabled=0, or the user's group in kernel.io_uring_group; otherwise `backend auto` ignores this directive with a warning and `backend uring` refuses to start.

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

### `worker_memory`

```nginx
worker_memory <size 1048576..1099511627776 bytes>;
```

Memory one worker may spend on request state (buffered bodies, headers, response buffers). Past it, new requests get overload_status with Retry-After instead of growing the process, and requests already running finish. It is a budget the worker keeps, not an operating system limit: allocator overhead, TLS state and the page cache come on top.

- Contexts: limits
- Default: `1g`
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
