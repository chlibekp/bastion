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

### `acl_default`

```nginx
acl_default <allow|deny>;
```

What an address no allow or deny rule matches gets.

- Contexts: global, server, location
- Default: `allow`
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

### `allow`

```nginx
allow <string> ...;
```

Lets these addresses or CIDRs (or all) in. Rules are checked in order and the first that matches decides; a scope that writes rules replaces the inherited ones. Server-scope rules apply at accept (the connection is closed before TLS), location rules per request (403). The address is the one real_ip trusts.

- Contexts: global, server, location
- Default: none
- Repeatable: yes

### `allow_file`

```nginx
allow_file <path>;
```

An allow rule matching any address or CIDR the file lists, one per line, # comments. Read at load into a prefix tree (a million entries load in about a second).

- Contexts: global, server, location
- Default: none
- Repeatable: yes

### `alt_svc`

```nginx
alt_svc <string>;
```

The Alt-Svc field (RFC 7838) of the server's HTTP/1.1 and HTTP/2 responses, which tells clients where the same server speaks HTTP/3. auto: `h3=":<port>"; ma=86400` for the server's first `listen ... http3`, nothing when it has none. off: no field. Any other value is sent as written. A handler that sets Alt-Svc keeps its own; HTTP/3 responses carry none.

- Contexts: server
- Default: `auto`
- Repeatable: no

### `auth_basic`

```nginx
auth_basic <string>;
```

HTTP Basic authentication with this realm, against auth_basic_file; off turns it off here. A missing or wrong password gets 401 with WWW-Authenticate. $auth_user is the user let in.

- Contexts: global, server, location
- Default: `off`
- Repeatable: no

### `auth_basic_file`

```nginx
auth_basic_file <path>;
```

The users of auth_basic: `user:$argon2id$v=19$m=..,t=..,p=..$salt$hash` lines, as `bastion passwd user` prints them. Read by the master at load (a file that can not be read or parsed fails the load) and kept out of core dumps. Entries weaker than m=19456 KiB, t=2 draw a warning.

- Contexts: global, server, location
- Default: none
- Repeatable: no

### `auth_cache_ttl`

```nginx
auth_cache_ttl <duration ..86400000000 us>;
```

How long a verified credential is remembered per worker, keyed by an HMAC with a random per-worker key (never the plaintext); 0s hashes every request.

- Contexts: global, server, location
- Default: `60s`
- Repeatable: no

### `auth_forward`

```nginx
auth_forward <string> [path=<string>] [timeout=<duration 1000..60000000 us>] [pass_headers=<string>] [response_headers=<string>] [fail=<string>];
```

auth_forward <upstream> [path=/auth] [timeout=5s] [pass_headers=Authorization,Cookie] [response_headers=X-User,..] [fail=closed], or off. Before the handler a GET goes to the auth service with the listed request headers and X-Original-Method, -URI, -Host and -Proto (client copies of those are removed). 2xx lets the request in with the response_headers copied onto it (client copies removed); 401, 403 and redirects go back to the client with their body; a timeout, refused connection or any other answer is 503. There is no fail-open. The request body is not sent.

- Contexts: global, server, location
- Default: none
- Repeatable: no
- Option `path=`: string
- Option `timeout=`: duration 1000..60000000 us
- Option `pass_headers=`: string
- Option `response_headers=`: string
- Option `fail=`: string

### `auth_jwt`

```nginx
auth_jwt [<string>] [keys=<path>] [secret=<path>] [alg=<string>] [iss=<string>] [aud=<string>] [leeway=<duration ..3600000000 us>] [header=<string>] [cookie=<string>];
```

JWT bearer authentication: auth_jwt keys=<JWKS or PEM file> [alg=ES256,RS256,..] [iss=..] [aud=a,b] [leeway=30s] [header=Authorization | cookie=name], or secret=<file> for HS256 (the only way HS256 is ever accepted), or off. Allowed algorithms: ES256, ES384, RS256, PS256, EdDSA; `none` never. Keys are picked by kid; an unknown kid is refused. exp, nbf and iat are checked with leeway. $auth_user is the sub claim, $jwt_claim_NAME any claim.

- Contexts: global, server, location
- Default: none
- Repeatable: no
- Option `keys=`: path
- Option `secret=`: path
- Option `alg=`: string
- Option `iss=`: string
- Option `aud=`: string
- Option `leeway=`: duration ..3600000000 us
- Option `header=`: string
- Option `cookie=`: string

### `auth_jwt_claim_header`

```nginx
auth_jwt_claim_header <string> <string>;
```

auth_jwt_claim_header <claim> <header>: the claim (a string or a number) goes to the upstream in that request header. The client's own copies of the header are always removed, and a value with a control byte (CR, LF) is never sent.

- Contexts: global, server, location
- Default: none
- Repeatable: yes

### `auth_jwt_required_claim`

```nginx
auth_jwt_required_claim <string> ...;
```

Claims a token must carry to pass.

- Contexts: global, server, location
- Default: none
- Repeatable: yes

### `auth_max_concurrent`

```nginx
auth_max_concurrent <int 1..100000>;
```

Password hashes one worker runs at once (they run on the aio pool, never on the event loop). Past it a request needing one gets 503 with Retry-After: 1, so a password flood can not take the worker down.

- Contexts: global, server, location
- Default: `16`
- Repeatable: no

### `auth_mtls`

```nginx
auth_mtls <string> ...;
```

Requests here need a verified client certificate: 403 without one. on (or required) takes any verified certificate; a list of subject DNs (in the $ssl_client_s_dn form) or DNS SAN names takes only those; off. It is one of the auth_require mechanisms. Use it with tls_client_auth optional to protect some locations only.

- Contexts: server, location
- Default: `off`
- Repeatable: no

### `auth_require`

```nginx
auth_require <any|all>;
```

How the mechanisms configured here combine (auth_mtls, auth_jwt, auth_basic, auth_forward, checked in that order): any lets in the first that passes, all needs every one.

- Contexts: global, server, location
- Default: `any`
- Repeatable: no

### `autoindex`

```nginx
autoindex <bool>;
```

List a directory that has no index file. The listing streams in directory order (it is never sorted, so a directory of a million files costs bounded memory); names starting with '.' are left out unless dotfiles allow, and links unless symlinks is on.

- Contexts: global, server, location
- Default: `off`
- Repeatable: no

### `autoindex_format`

```nginx
autoindex_format <html|json>;
```

The listing as an html page, or as a json array of {name, type, mtime, size}.

- Contexts: global, server, location
- Default: `html`
- Repeatable: no

### `backend`

```nginx
backend <auto|uring|epoll>;
```

Event loop: auto picks io_uring and falls back to epoll when it is unavailable (ENOSYS, EPERM from seccomp or kernel.io_uring_disabled, a missing opcode), uring makes that a startup error, epoll never tries io_uring. The choice and its reason are logged at start and shown by `bastion -t`.

- Contexts: io
- Default: `auto`
- Repeatable: no

### `background_revalidate`

```nginx
background_revalidate <bool>;
```

Within stale-while-revalidate, a stale response is served at once and one request in the background (across all workers) refreshes it. off: stale responses are revalidated in line.

- Contexts: cache_store
- Default: `on`
- Repeatable: no

### `backlog`

```nginx
backlog <int 1..65535> [require];
```

The listen(2) backlog: connections the kernel queues before the server accepts. The default is 4096. The kernel caps it at net.core.somaxconn without an error; bastion warns when that happens.

- Contexts: tcp_profile
- Default: `4096`
- Repeatable: no

### `balance hash`

```nginx
balance hash <template> [<consistent>];
```

The same key (`balance hash $remote_addr;`, any template) goes to the same server. With `consistent`, servers sit on a hash ring, so removing one of n moves only about 1/n of the keys, and a server already carrying 25% more than its share passes its keys on to the next (bounded load).

- Contexts: upstream
- Default: none
- Repeatable: no

### `balance least_conn`

```nginx
balance least_conn;
```

The server with the fewest open requests from this worker relative to its weight; ties go round robin.

- Contexts: upstream
- Default: none
- Repeatable: no

### `balance peak_ewma`

```nginx
balance peak_ewma;
```

Two servers drawn at random, the one with the lower moving average of response latency (peaks count at once, recovery decays over 10 s) times its open requests wins: slow servers get less traffic.

- Contexts: upstream
- Default: none
- Repeatable: no

### `balance round_robin`

```nginx
balance round_robin;
```

Smooth weighted round robin, the default: over any window each server gets its weight's share, interleaved rather than in bursts.

- Contexts: upstream
- Default: none
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

### `cache`

```nginx
cache <string>;
```

Caches the responses of `proxy` in the named `cache_store` (RFC 9111, as a shared cache), or `off`. A hit is answered without the upstream, with Age and Cache-Status (RFC 9211), conditional requests (304) and a single Range (206); a stale response is revalidated with its validators. Only complete responses are stored: one cut short, or failed, never is.

- Contexts: global, server, location
- Default: `off`
- Repeatable: no

### `cache_background_fill`

```nginx
cache_background_fill <bool>;
```

on: when a client leaves while its response is being stored, the response is fetched again in the background and stored. off: the fill is dropped. Either way a partial object is never stored.

- Contexts: global, server, location
- Default: `off`
- Repeatable: no

### `cache_bypass`

```nginx
cache_bypass <template> ...;
```

Templates: when one is non-empty and not "0", the request skips the lookup and goes to the upstream (its response may still be stored): `cache_bypass $cookie_session`.

- Contexts: global, server, location
- Default: none
- Repeatable: yes

### `cache_compressed_variants`

```nginx
cache_compressed_variants <bool>;
```

on: a response compressed on the fly is stored compressed (the filter order is upstream, compress, cache store), one variant per set of codings the client accepts, so a hit is not compressed again. Accept-Encoding is never part of the key as received. off: compressed responses are not stored; only identity ones are.

- Contexts: global, server, location
- Default: `on`
- Repeatable: no

### `cache_cookies_policy`

```nginx
cache_cookies_policy <no_store|strip>;
```

A response with Set-Cookie: `no_store` (the default) passes it uncached; `strip` stores it without its Set-Cookie fields (the client that caused the fill still gets them).

- Contexts: global, server, location
- Default: `no_store`
- Repeatable: no

### `cache_honor_request_cc`

```nginx
cache_honor_request_cc <bool>;
```

on: a client's Cache-Control: no-cache (or max-age=0, or Pragma: no-cache) makes the cache revalidate. off (the default): clients can not force load onto the upstream.

- Contexts: global, server, location
- Default: `off`
- Repeatable: no

### `cache_ignore_headers`

```nginx
cache_ignore_headers <cache-control|expires|set-cookie|vary|cdn-cache-control|none> ...;
```

Response fields the cache acts as if absent: cache-control, expires, set-cookie (stores responses that set cookies: dangerous), vary, cdn-cache-control; or none.

- Contexts: global, server, location
- Default: `none`
- Repeatable: no

### `cache_key`

```nginx
cache_key <template>;
```

What identifies a stored response. Request fields not in the key (and not in the response's Vary) must not change the response, or one client could be served another's: X-Forwarded-Host and friends are rewritten by the proxy for that reason.

- Contexts: global, server, location
- Default: `$scheme$host$request_uri`
- Repeatable: no

### `cache_max_tags`

```nginx
cache_max_tags <int 1..64>;
```

Tags kept per stored response (cache_tag_header); more are ignored.

- Contexts: cache_store
- Default: `32`
- Repeatable: no

### `cache_methods`

```nginx
cache_methods <GET|HEAD> ...;
```

Methods answered from the cache. Only GET responses are stored; HEAD is answered from a stored GET.

- Contexts: global, server, location
- Default: `GET HEAD`
- Repeatable: no

### `cache_no_store_if`

```nginx
cache_no_store_if <template> ...;
```

Templates: when one is non-empty and not "0", the response is not stored.

- Contexts: global, server, location
- Default: none
- Repeatable: yes

### `cache_status_header`

```nginx
cache_status_header <string>;
```

The RFC 9211 field that tells the client what the cache did (hit, fwd=miss, stored, ...), or off.

- Contexts: global, server, location
- Default: `Cache-Status`
- Repeatable: no

### `cache_store`

```nginx
cache_store <string> { ... }
```

A named HTTP cache store (`cache name` uses it): one file per object below `disk`, a shared index of them, and an optional per-worker RAM tier. Names are unique.

- Contexts: global
- Block context: cache_store
- Default: none
- Repeatable: yes

### `cache_tag_header`

```nginx
cache_tag_header <string>;
```

The response field whose comma- or space-separated tags a stored response can be purged by (`PURGE` with `Purge-Tag: a, b`), or off. Removed from what clients get unless cache_tag_header_pass is on. At most cache_max_tags tags count per response.

- Contexts: global, server, location
- Default: `Cache-Tag`
- Repeatable: no

### `cache_tag_header_pass`

```nginx
cache_tag_header_pass <bool>;
```

on: the tag header reaches clients too.

- Contexts: global, server, location
- Default: `off`
- Repeatable: no

### `cache_valid`

```nginx
cache_valid <string> ...;
```

Freshness for responses with none of their own (no CDN-Cache-Control, s-maxage, max-age or Expires): `cache_valid 200 301 10m`, `cache_valid any 1m`, or `cache_valid 5m` for 200. Without one, such a response is stored only with heuristic freshness (a 200-type response with Last-Modified), never an error.

- Contexts: global, server, location
- Default: none
- Repeatable: yes

### `cache_vary_limit`

```nginx
cache_vary_limit <int 1..64>;
```

A response whose Vary names more fields than this is not stored (Vary: * never is).

- Contexts: global, server, location
- Default: `8`
- Repeatable: no

### `chunk_ext_limit`

```nginx
chunk_ext_limit <size 16..65536 bytes>;
```

Most bytes of chunk extensions (the text after a ';' on a chunk-size line) one chunk of a request body may carry. Extensions are ignored; more than this is answered 400 and the connection closed.

- Contexts: server
- Default: `1k`
- Repeatable: no

### `ciphers_tls12`

```nginx
ciphers_tls12 <string> ...;
```

TLS 1.2 cipher suites in order of preference (OpenSSL names). The default is ECDHE key exchange with AEAD ciphers only.

- Contexts: tls_profile
- Default: `ECDHE+AESGCM ECDHE+CHACHA20`
- Repeatable: no

### `ciphersuites_tls13`

```nginx
ciphersuites_tls13 <string> ...;
```

TLS 1.3 cipher suites in order of preference.

- Contexts: tls_profile
- Default: `TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256`
- Repeatable: no

### `circuit_breaker`

```nginx
circuit_breaker [max_pending=<int 1..1048576>] [max_active=<int 1..1048576>] [max_retries=<int 1..1048576>] [fails=<int 1..1000000>] [for=<duration 1000..3600000000 us>];
```

Per-worker limits: `max_pending=` requests waiting for a response head, `max_active=` requests in flight, `max_retries=` retries in flight; a request over a limit gets 503 with Retry-After at once, nothing queues. With `fails=`, that many consecutive failures open the breaker for `for=` (default 10s): requests get 503, then one probe request decides whether it closes or opens again.

- Contexts: upstream
- Default: none
- Repeatable: no
- Option `max_pending=`: int 1..1048576
- Option `max_active=`: int 1..1048576
- Option `max_retries=`: int 1..1048576
- Option `fails=`: int 1..1000000
- Option `for=`: duration 1000..3600000000 us

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

### `compress`

```nginx
compress <zstd|br|gzip|off> ...;
```

Compresses responses on the fly with the codings listed (zstd, br, gzip), choosing by the client's Accept-Encoding (q-values first, then this server's order zstd, br, gzip), or off. Applies to every handler and protocol. A response that is already encoded, marked no-transform, answers a Range request, a HEAD, a 204 or a 304, is smaller than compress_min_size or not of a compress_types type is sent as it is. A compressed response loses Content-Length, gets Vary: Accept-Encoding and a weak ETag.

- Contexts: global, server, location
- Default: `off`
- Repeatable: no

### `compress_level_br`

```nginx
compress_level_br <int 0..11>;
```

Brotli quality, 0 to 11. Levels above 6 cost much CPU for little gain on the fly.

- Contexts: global, server, location
- Default: `4`
- Repeatable: no

### `compress_level_gzip`

```nginx
compress_level_gzip <int 1..9>;
```

gzip level, 1 to 9.

- Contexts: global, server, location
- Default: `5`
- Repeatable: no

### `compress_level_zstd`

```nginx
compress_level_zstd <int 1..19>;
```

zstd level, 1 (fastest) to 19. The default favours speed.

- Contexts: global, server, location
- Default: `3`
- Repeatable: no

### `compress_max_concurrent`

```nginx
compress_max_concurrent <int 1..1000000>;
```

Compressed streams one worker runs at once; past it responses go uncompressed. The compressors' memory is charged to worker_memory as well, and a stream whose compressor does not fit goes uncompressed too.

- Contexts: global, server, location
- Default: `1024`
- Repeatable: no

### `compress_min_size`

```nginx
compress_min_size <size>;
```

A response whose length is known and smaller than this is sent as it is: the framing would cost more than it saves. A response of unknown length is compressed.

- Contexts: global, server, location
- Default: `256`
- Repeatable: no

### `compress_sensitive`

```nginx
compress_sensitive <bool>;
```

off: responses to requests with Cookie or Authorization, and responses that set a cookie, are not compressed, because a secret reflected next to attacker-chosen text in a compressed body leaks through its length (BREACH). on: compress them too.

- Contexts: global, server, location
- Default: `off`
- Repeatable: no

### `compress_types`

```nginx
compress_types <string> ...;
```

Media types that are compressed, by the Content-Type without parameters; `text/*` matches every text type. A response without Content-Type is not compressed.

- Contexts: global, server, location
- Default: `text/html text/css text/plain text/javascript application/javascript application/json application/xml image/svg+xml`
- Repeatable: no

### `compress_window`

```nginx
compress_window <int 10..24>;
```

log2 of the compression window in bytes (10 to 24): memory per stream against ratio. gzip uses at most 15.

- Contexts: global, server, location
- Default: `15`
- Repeatable: no

### `congestion`

```nginx
congestion <string> [require];
```

TCP congestion control algorithm by kernel name (bbr, cubic, reno, ...). It must be listed in net.ipv4.tcp_available_congestion_control; the kernel refuses a missing one (bbr needs the tcp_bbr module), and bastion warns, or fails with `require`.

- Contexts: tcp_profile
- Default: none
- Repeatable: no

### `connect_timeout`

```nginx
connect_timeout <duration 1000..600000000 us>;
```

How long a connection to an upstream server may take; past it the request gets 504 Gateway Timeout (a refused connection gets 502).

- Contexts: upstream
- Default: `5s`
- Repeatable: no

### `content_type_options`

```nginx
content_type_options <string> [<force>];
```

Overrides the X-Content-Type-Options of security_headers: a value, or off for none. With force it replaces a value the handler or upstream set; without, theirs is kept.

- Contexts: global, server, location
- Default: none
- Repeatable: no

### `continuation_max`

```nginx
continuation_max <int 1..65536>;
```

Most CONTINUATION frames in one header block. More ends the connection (ENHANCE_YOUR_CALM); the block's total size is separately bounded by http2_max_header_list_size.

- Contexts: http2_abuse
- Default: `32`
- Repeatable: no

### `control_queue_max`

```nginx
control_queue_max <size 4096..1073741824 bytes>;
```

Bytes of control frames (acknowledgements, resets, header blocks) that may wait for a client that does not read its socket. Past it the connection is closed.

- Contexts: http2_abuse
- Default: `1m`
- Repeatable: no

### `csp`

```nginx
csp <string> [<force>];
```

Overrides the Content-Security-Policy of security_headers: a value, or off for none. With force it replaces a value the handler or upstream set; without, theirs is kept.

- Contexts: global, server, location
- Default: none
- Repeatable: no

### `default_type`

```nginx
default_type <string>;
```

The Content-Type of a file whose extension is in no `types` entry or the built-in table.

- Contexts: global, server, location
- Default: `application/octet-stream`
- Repeatable: no

### `defer_accept`

```nginx
defer_accept <duration 1000000..3600000000 us> [require];
```

TCP_DEFER_ACCEPT: the kernel completes the handshake but hands the connection to the server only when data arrives, or when this time (rounded up to the kernel's retransmit schedule) has passed. This delays connections that send nothing, such as a client waiting for a server greeting, a health check that only connects, or a port scan, and it hides them from the accept queue; it also saves a wakeup per request.

- Contexts: tcp_profile
- Default: none
- Repeatable: no

### `deny`

```nginx
deny <string> ...;
```

Refuses these addresses or CIDRs (or all); see allow for the order.

- Contexts: global, server, location
- Default: none
- Repeatable: yes

### `deny_file`

```nginx
deny_file <path>;
```

A deny rule matching any address or CIDR the file lists; as allow_file.

- Contexts: global, server, location
- Default: none
- Repeatable: yes

### `dh_none`

```nginx
dh_none <bool>;
```

Never offer finite-field Diffie-Hellman (DHE) in TLS 1.2, even when ciphers_tls12 names a DHE suite.

- Contexts: tls_profile
- Default: `on`
- Repeatable: no

### `disk`

```nginx
disk <path> size=<size 1048576.. bytes>;
```

Directory of the store's objects and its size limit: `disk /var/cache/bastion size=50g`. Required. Made at start if missing (owned by `user`) and granted write access by the sandbox. Objects are written to tmp/ and renamed into place, so a crash never leaves a partial object; least recently used objects are removed by the helper to stay under size.

- Contexts: cache_store
- Default: none
- Repeatable: no
- Option `size=`: size 1048576.. bytes, required

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

### `dry_run`

```nginx
dry_run <bool>;
```

on: requests over the limit are logged and counted (bastion_limit_dry_run_total) but never refused or delayed.

- Contexts: limit_zone
- Default: `off`
- Repeatable: no

### `early_data`

```nginx
early_data <bool>;
```

Accept TLS 1.3 0-RTT early data. Off by default: early data can be replayed, so only the methods of early_data_methods are served from it, once per ticket across all workers; anything else is answered 425 Too Early. Never accepted on a server that requests client certificates.

- Contexts: tls_profile
- Default: `off`
- Repeatable: no

### `early_data_max_size`

```nginx
early_data_max_size <size 1..1048576 bytes>;
```

Most early data bytes a connection may send before the handshake completes.

- Contexts: tls_profile
- Default: `16k`
- Repeatable: no

### `early_data_methods`

```nginx
early_data_methods <GET|HEAD|POST|PUT|DELETE|OPTIONS|PATCH> ...;
```

Request methods that may be served from early data (they must be safe to replay).

- Contexts: tls_profile
- Default: `GET HEAD`
- Repeatable: no

### `early_data_window`

```nginx
early_data_window <duration 15000000..3600000000 us>;
```

How long Bastion remembers that a ticket was used for early data; the same ticket presented again within it is refused early data (it is a full handshake instead). OpenSSL itself refuses a ticket whose reported age is more than 10 seconds off, so the minimum keeps the table at least as long as that.

- Contexts: tls_profile
- Default: `20s`
- Repeatable: no

### `early_hint`

```nginx
early_hint <string>;
```

A Link value for the 103 Early Hints response, e.g. "</app.css>; rel=preload; as=style". Repeat it for several.

- Contexts: global, server, location
- Default: none
- Repeatable: yes

### `early_hints`

```nginx
early_hints <bool>;
```

on: a 103 Early Hints response with the early_hint Link values is sent before the handler starts, over HTTP/1.1, HTTP/2 and HTTP/3 (never to an HTTP/1.0 client). A 103 from a proxied upstream is forwarded either way.

- Contexts: global, server, location
- Default: `off`
- Repeatable: no

### `empty_frame_rate`

```nginx
empty_frame_rate <int 1..10000000>;
```

DATA, HEADERS and CONTINUATION frames without payload and without an end flag, per second. The budget is a leaky bucket that holds this many events and drains this many per second: a client inside it is never affected, one that keeps going past it has the connection closed with GOAWAY(ENHANCE_YOUR_CALM) and counted in bastion_h2_abuse_total.

- Contexts: http2_abuse
- Default: `100`
- Repeatable: no

### `error_log`

```nginx
error_log <path> [<debug|info|notice|warn|error>];
```

Error log path and optional minimum level (default warn).

- Contexts: global
- Default: none
- Repeatable: no

### `error_page`

```nginx
error_page <string> <string> ...;
```

Answers the listed statuses (400 to 599) with the page at a URI of this server, keeping the status: error_page 404 /404.html; The page is served through the router once; if it fails too, the built-in page for that failure is sent, so a missing error page never loops. Put the page in a location marked internal to hide it from direct requests. The statuses of a block add to those of its parent.

- Contexts: global, server, location
- Default: none
- Repeatable: yes

### `etag`

```nginx
etag <bool>;
```

Whether static files carry an ETag ("<mtime in hex>-<size in hex>", strong) and If-Match, If-None-Match and If-Range are evaluated against it. With off only Last-Modified validates.

- Contexts: global, server, location
- Default: `on`
- Repeatable: no

### `evict_batch`

```nginx
evict_batch <int 1..1000000>;
```

Objects the helper removes per eviction round (one round a second).

- Contexts: cache_store
- Default: `64`
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

TCP Fast Open on the listener: the queue length of connections that arrive with data in the SYN. The data can be replayed by the network (a duplicated SYN delivers it twice), so it is as dangerous as TLS 0-RTT early data and obeys the same policy: only a safe method (GET, HEAD, OPTIONS) runs from it, anything else is answered 425 Too Early and `$ssl_early_data` is 1 for the request. Needs the server bit of net.ipv4.tcp_fastopen (value 2 or 3); without it the kernel ignores Fast Open and bastion warns.

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

### `forwarded_headers`

```nginx
forwarded_headers <xff|forwarded|off>;
```

How the client is described to the upstream: `xff` sets X-Forwarded-For, X-Forwarded-Proto and X-Forwarded-Host; `forwarded` sets RFC 7239 Forwarded; `off` sends neither. Whatever a client sends in these fields is replaced, unless the connection comes from `trusted_proxies`: then its values are kept and this hop is appended. Connection cannot remove them.

- Contexts: global, server, location
- Default: `xff`
- Repeatable: no

### `frame_options`

```nginx
frame_options <string> [<force>];
```

Overrides the X-Frame-Options of security_headers: a value, or off for none. With force it replaces a value the handler or upstream set; without, theirs is kept.

- Contexts: global, server, location
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

### `groups`

```nginx
groups <string> ...;
```

Key exchange groups in order of preference (OpenSSL names). The default leads with the post-quantum hybrid X25519MLKEM768, then X25519 and P-256.

- Contexts: tls_profile
- Default: `X25519MLKEM768 X25519 P-256`
- Repeatable: no

### `handshake_timeout`

```nginx
handshake_timeout <duration 1000000..3600000000 us>;
```

Time a client has to finish the TLS handshake, from the first byte of the connection. A client that stalls or never starts is closed at the deadline.

- Contexts: tls_profile
- Default: `10s`
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

### `health_check`

```nginx
health_check [path=<string>] [expect=<string>] [interval=<duration 10000..3600000000 us>] [timeout=<duration 1000..600000000 us>] [fails=<int 1..1000>] [passes=<int 1..1000>];
```

Active health checks, sent by the helper process (one probe per server per interval, however many workers): `path=` (default /), `interval=` (5s), `timeout=` (2s), `fails=` (3 consecutive failures mark the server down), `passes=` (2 consecutive passes bring it back) and `expect=` (a status or range, default 200-399). For a TLS upstream the TCP connect alone is checked.

- Contexts: upstream
- Default: none
- Repeatable: no
- Option `path=`: string
- Option `expect=`: string
- Option `interval=`: duration 10000..3600000000 us
- Option `timeout=`: duration 1000..600000000 us
- Option `fails=`: int 1..1000
- Option `passes=`: int 1..1000

### `host_sni_mismatch`

```nginx
host_sni_mismatch <421|allow>;
```

A request whose Host (or :authority) belongs to another server than the one the TLS handshake chose by SNI: `421` answers 421 Misdirected Request, so no site's content reaches a client through another site's certificate; `allow` serves it. A request for a server that asks for client certificates is always 421. A connection that sent no SNI is not compared.

- Contexts: server
- Default: `421`
- Repeatable: no

### `hsts`

```nginx
hsts <string> [<force>];
```

Overrides the Strict-Transport-Security (TLS only) of security_headers: a value, or off for none. With force it replaces a value the handler or upstream set; without, theirs is kept.

- Contexts: global, server, location
- Default: none
- Repeatable: no

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

### `http2_abuse`

```nginx
http2_abuse { ... }
```

Budgets against HTTP/2 attacks that cost the server work or memory for next to nothing from the client: Rapid Reset (CVE-2023-44487), MadeYouReset (CVE-2025-8671), CONTINUATION floods (CVE-2024-27983), and the 2019 settings, ping, reset, empty-frame and dependency floods (CVE-2019-9511 to -9518). Every default applies when the block is absent.

- Contexts: server
- Block context: http2_abuse
- Default: none
- Repeatable: no
- Singleton block: at most once; when it is absent its children's defaults still apply

### `http2_connect_protocol`

```nginx
http2_connect_protocol <bool>;
```

Advertise SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 8441), which lets clients open WebSocket and other tunnels as an extended CONNECT request (`:protocol`). Off refuses such requests as malformed. Turn it on only where a handler that serves tunnels exists; until then an extended CONNECT is answered 501.

- Contexts: server
- Default: `off`
- Repeatable: no

### `http2_connection_window`

```nginx
http2_connection_window <size 65535..2147483647 bytes>;
```

Bytes of request bodies a client may have in flight over the whole connection (the connection-level flow-control window; raised from the protocol's 65535 with a WINDOW_UPDATE when the connection starts).

- Contexts: server
- Default: `1m`
- Repeatable: no

### `http2_header_table_size`

```nginx
http2_header_table_size <size ..1048576 bytes>;
```

SETTINGS_HEADER_TABLE_SIZE: the HPACK dynamic table the client may use for request headers, and the most Bastion uses for response headers. Each decoder holds this much per connection; 0 turns HPACK indexing off.

- Contexts: server
- Default: `4k`
- Repeatable: no

### `http2_idle_timeout`

```nginx
http2_idle_timeout <duration 1000000..86400000000 us>;
```

How long an HTTP/2 connection with no request in progress may stay silent before it is closed (after a GOAWAY).

- Contexts: server
- Default: `120s`
- Repeatable: no

### `http2_initial_window`

```nginx
http2_initial_window <size 1..2147483647 bytes>;
```

SETTINGS_INITIAL_WINDOW_SIZE: bytes of request body a client may send on one stream before the handler has taken some. Credit comes back as the handler reads, so a stream holds at most this much unread data.

- Contexts: server
- Default: `64k`
- Repeatable: no

### `http2_max_concurrent_streams`

```nginx
http2_max_concurrent_streams <int 1..1048576>;
```

SETTINGS_MAX_CONCURRENT_STREAMS: most requests one HTTP/2 connection may have in progress. A request opened beyond it is refused with RST_STREAM(REFUSED_STREAM), which clients retry safely. Each open stream costs a few kilobytes, so this bounds what one connection can hold.

- Contexts: server
- Default: `128`
- Repeatable: no

### `http2_max_frame_size`

```nginx
http2_max_frame_size <size 16384..16777215 bytes>;
```

SETTINGS_MAX_FRAME_SIZE: the largest frame payload accepted. A larger frame ends the connection (FRAME_SIZE_ERROR) before its payload is read. At least 16384, the protocol's own minimum.

- Contexts: server
- Default: `16k`
- Repeatable: no

### `http2_max_header_list_size`

```nginx
http2_max_header_list_size <size 1024..16777216 bytes>;
```

SETTINGS_MAX_HEADER_LIST_SIZE: the most a request's header fields may add up to, each counted as name + value + 32 bytes (RFC 9113 section 6.5.2), after HPACK decoding. It also bounds the compressed header block that is buffered, so a block that never ends (a CONTINUATION flood) is cut at this size and a small block that expands into huge headers (an HPACK bomb) is cut as it expands. Either ends the connection.

- Contexts: server
- Default: `16k`
- Repeatable: no

### `http2_priorities`

```nginx
http2_priorities <bool>;
```

Honour RFC 9218 priorities (the Priority header and PRIORITY_UPDATE frames): responses are written in urgency order, and equally urgent incremental ones share the connection round-robin. Off sends in the order the responses became ready.

- Contexts: server
- Default: `on`
- Repeatable: no

### `http2_recv_window_policy`

```nginx
http2_recv_window_policy <fixed|eager>;
```

When request-body credit goes back to the client: `fixed` sends a WINDOW_UPDATE once half of a window has been consumed by the handler (fewer frames), `eager` sends one as soon as the handler took the data (tighter memory, more frames).

- Contexts: server
- Default: `fixed`
- Repeatable: no

### `http2_write_chunk`

```nginx
http2_write_chunk <size 1024..16777216 bytes>;
```

Most DATA payload handed to the socket in one write. Smaller writes let a later, more urgent response overtake one in progress sooner (priorities take effect between writes) at the cost of more system calls; with the listener's tcp_profile TCP_NOTSENT_LOWAT this keeps little data queued in the kernel.

- Contexts: server
- Default: `64k`
- Repeatable: no

### `http3_max_field_section_size`

```nginx
http3_max_field_section_size <size 1024..1048576 bytes>;
```

SETTINGS_MAX_FIELD_SECTION_SIZE of HTTP/3 (RFC 9114 section 4.2.2): the largest request header or trailer section, counted as name plus value plus 32 per field. A larger one is answered 431.

- Contexts: server
- Default: `16k`
- Repeatable: no

### `http3_qpack_blocked_streams`

```nginx
http3_qpack_blocked_streams <int 0..1000>;
```

SETTINGS_QPACK_BLOCKED_STREAMS (RFC 9204): request streams the client may leave waiting on dynamic table updates at once.

- Contexts: server
- Default: `16`
- Repeatable: no

### `http3_qpack_table_size`

```nginx
http3_qpack_table_size <size ..1048576 bytes>;
```

SETTINGS_QPACK_MAX_TABLE_CAPACITY (RFC 9204): the dynamic table the client's QPACK encoder may use on one connection. 0 turns the dynamic table off.

- Contexts: server
- Default: `4k`
- Repeatable: no

### `http_on_tls_port`

```nginx
http_on_tls_port <close|respond>;
```

A client that speaks plain HTTP to a TLS port: `close` drops the connection, `respond` answers a small 400 page in plain text. Read on the default server of the listener.

- Contexts: server
- Default: `close`
- Repeatable: no

### `inactive`

```nginx
inactive <duration 1000000..31536000000000 us>;
```

An object not requested for this long is removed, fresh or not.

- Contexts: cache_store
- Default: `10m`
- Repeatable: no

### `include`

```nginx
include <path>;
```

Include another file or glob here (expanded by the parser).

- Contexts: global, io, sandbox, limits, xdp, tcp_profile, tls_profile, log_format, upstream, cache_store, limit_zone, waf_rule, server, location, metrics, admin, acme, http2_abuse
- Default: none
- Repeatable: yes

### `index`

```nginx
index <string> ...;
```

The files a request for a directory (a path ending in '/') tries, in order; the first that exists is served. When none does, the directory is listed if autoindex is on, else the answer is 403. A name is a file name only.

- Contexts: global, server, location
- Default: `index.html`
- Repeatable: no

### `intercept_errors`

```nginx
intercept_errors <bool>;
```

on: an upstream response of 400 or above is replaced by bastion's own error page (or the `error_page` for it), and its body is not read.

- Contexts: global, server, location
- Default: `off`
- Repeatable: no

### `internal`

```nginx
internal;
```

Marks the location as reachable only by internal redirects (try_files and error_page): a client asking for it directly gets 404.

- Contexts: location
- Default: none
- Repeatable: no

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

### `ipv6_prefix`

```nginx
ipv6_prefix <int 1..128>;
```

IPv6 clients are keyed by this prefix: addresses rotated inside one /64 are one client.

- Contexts: limit_zone
- Default: `64`
- Repeatable: no

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

### `keepalive`

```nginx
keepalive <int 0..65536>;
```

Idle connections to this upstream each worker keeps open for reuse; 0 closes every connection after its response.

- Contexts: upstream
- Default: `32`
- Repeatable: no

### `keepalive_requests`

```nginx
keepalive_requests <int 1..1073741824>;
```

Most requests one connection serves; the last response carries Connection: close.

- Contexts: server
- Default: `1000`
- Repeatable: no

### `keepalive_requests`

```nginx
keepalive_requests <int 1..1000000000>;
```

Requests one upstream connection carries before it is closed.

- Contexts: upstream
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

### `keepalive_timeout`

```nginx
keepalive_timeout <duration 1000..3600000000 us>;
```

How long an idle upstream connection is kept. Keep it below the upstream's own idle timeout, so the upstream does not close a connection just as a request goes out on it.

- Contexts: upstream
- Default: `60s`
- Repeatable: no

### `key`

```nginx
key <template>;
```

What a bucket counts: $remote_addr (the client address after real_ip, IPv6 cut to ipv6_prefix, ::ffff: addresses as IPv4) or any template. Hashed with a random SipHash key, so clients can not aim at one slot.

- Contexts: limit_zone
- Default: `$remote_addr`
- Repeatable: no

### `ktls`

```nginx
ktls <off|tx|tx+rx> [require];
```

Kernel TLS: tx lets the kernel encrypt responses, so files go out by sendfile; tx+rx also decrypts in the kernel; off keeps TLS in user space. Where the kernel, the module or the cipher cannot do it, the connection runs in user space with one warning per start; `require` makes that a startup error. A client KeyUpdate that asks the server to rekey its sending direction closes a kTLS connection.

- Contexts: tls_profile
- Default: `tx`
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

### `limit`

```nginx
limit <string> ...;
```

Applies these limit_zone names to the requests of the scope, in order; the first that refuses answers. A scope that names its own replaces the inherited list; `limit off` clears it.

- Contexts: global, server, location
- Default: none
- Repeatable: no

### `limit_conn`

```nginx
limit_conn [per_ip=<int 1..10000000>] [subnet4=<string>] [subnet6=<string>];
```

Open connections per client across all workers: `limit_conn per_ip=20 subnet4=24:200 subnet6=48:200`. Read on a listener's default server. Past a limit the connection is closed at accept, before TLS. Peers in real_ip_from are not limited (their connections carry many clients).

- Contexts: global, server
- Default: none
- Repeatable: no
- Option `per_ip=`: int 1..10000000
- Option `subnet4=`: string
- Option `subnet6=`: string

### `limit_headers`

```nginx
limit_headers <bool>;
```

on: responses carry the RateLimit and RateLimit-Policy fields (draft-ietf-httpapi-ratelimit-headers) of the first zone of `limit`.

- Contexts: global, server, location
- Default: `off`
- Repeatable: no

### `limit_zone`

```nginx
limit_zone <string> { ... }
```

A named request rate limit (`limit name` applies it), shared by every worker: a lock-free GCRA table in shared memory. Names are unique.

- Contexts: global
- Block context: limit_zone
- Default: none
- Repeatable: yes

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
listen <string> [<default_server|tls|http2|h2c|http3|proxy_protocol>] ... [tcp_profile=<string>];
```

Listen on port, addr:port or [v6]:port. tcp_profile=name picks the socket tuning from a tcp_profile block (default: nodelay on, backlog 4096, the kernel's defaults otherwise). A socket has one set of options, so two listens on one address may name at most one profile between them. The flag default_server makes this server answer a request whose Host matches no name on the address (otherwise the server with no name, else the first one). The flag tls makes every connection on the address start with a TLS handshake (see tls_cert and tls_profile); all servers on one address must agree on it. The flag http2 (with tls) offers HTTP/2 through ALPN, next to HTTP/1.1; the flag h2c (cleartext only) lets a client start HTTP/2 with its connection preface (prior knowledge, RFC 9113 section 3.3), while any other request on the address is HTTP/1.1. `Upgrade: h2c` is not supported (RFC 9113 removed it). All servers on one address must agree on http2 and h2c. The flag http3 makes the listen a UDP socket serving HTTP/3 over QUIC v1 and v2 (the server needs tls_cert; see the quic_ directives); it is a socket apart from any TCP listen on the same port and takes no other transport flag. The flag proxy_protocol makes every connection start with a PROXY protocol v1 or v2 header (before TLS), accepted only from proxy_protocol_from; its source becomes the client address.

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

### `lock`

```nginx
lock <bool>;
```

Stampede protection: when many requests miss on one key at once, one of them (in any worker) fetches it and the others wait for the stored object. A response that is not storable releases the waiters at once, and each fetches its own.

- Contexts: cache_store
- Default: `on`
- Repeatable: no

### `lock_max_waiters`

```nginx
lock_max_waiters <int 1..10000000>;
```

Requests each worker lets wait on fills at once; more go to the upstream.

- Contexts: cache_store
- Default: `4096`
- Repeatable: no

### `lock_timeout`

```nginx
lock_timeout <duration 10000..600000000 us>;
```

How long requests wait for another request's fill before going to the upstream themselves; also how long a fill whose worker died holds the lock.

- Contexts: cache_store
- Default: `5s`
- Repeatable: no

### `maintenance`

```nginx
maintenance <string>;
```

on: every request is answered 503 with Retry-After, except from maintenance_allow peers. A file path instead of on: that file (read at load, up to 1 MiB) is the HTML page sent. A runtime toggle comes with the admin API.

- Contexts: global, server, location
- Default: `off`
- Repeatable: no

### `maintenance_allow`

```nginx
maintenance_allow <cidr> ...;
```

Peers (CIDR) served as usual during maintenance.

- Contexts: global, server, location
- Default: none
- Repeatable: no

### `maintenance_retry_after`

```nginx
maintenance_retry_after <duration 1000000..86400000000 us>;
```

The Retry-After of the maintenance 503, in whole seconds.

- Contexts: global, server, location
- Default: `300s`
- Repeatable: no

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

### `max_entries`

```nginx
max_entries <int 0..67108864>;
```

Slots of the shared index (about 128 bytes each). 0: one per 8 KiB of `size`, at least 1024 and at most 16M. A full index stores nothing new, counted and logged.

- Contexts: cache_store
- Default: `0`
- Repeatable: no

### `max_object`

```nginx
max_object <size 1.. bytes>;
```

Largest response body stored; a larger one is passed through uncached.

- Contexts: cache_store
- Default: `1g`
- Repeatable: no

### `max_ranges`

```nginx
max_ranges <int 1..1000>;
```

Most byte ranges one Range header may ask for. A request with more is answered with the whole file and status 200, which the protocol allows and which keeps a client from making the server assemble thousands of pieces. Overlapping and adjacent ranges are merged first; 1 serves single ranges only.

- Contexts: global, server, location
- Default: `10`
- Repeatable: no

### `max_tunnels`

```nginx
max_tunnels <int 0..16777216>;
```

Tunnels each worker holds open at once; past it an upgrade gets 503. 0: no limit.

- Contexts: global, server, location
- Default: `0`
- Repeatable: no

### `max_upstream_h2_streams`

```nginx
max_upstream_h2_streams <int 1..65536>;
```

Streams one HTTP/2 upstream connection carries at once (the server's own SETTINGS_MAX_CONCURRENT_STREAMS also applies, the smaller wins); a new connection is opened only when every one is full.

- Contexts: upstream
- Default: `100`
- Repeatable: no

### `max_upstream_header_size`

```nginx
max_upstream_header_size <size 1024..1048576 bytes>;
```

Largest response head an upstream may send; a longer one is a 502.

- Contexts: global, server, location
- Default: `16k`
- Repeatable: no

### `merge_slashes`

```nginx
merge_slashes <bool>;
```

Collapse runs of '/' in the request path before routing and file lookup, so //a///b is served as /a/b. With off they are kept as written, and an empty path segment names nothing in a directory (a 404).

- Contexts: server
- Default: `on`
- Repeatable: no

### `min_uses`

```nginx
min_uses <int 1..1000>;
```

Requests for a key before its response is stored: 2 or more keeps one-off URLs out of the store.

- Contexts: cache_store
- Default: `1`
- Repeatable: no

### `mode`

```nginx
mode <reject|delay>;
```

reject: past the burst, refuse with `status` and Retry-After. delay: hold up to another burst of requests until each conforms, refuse past that.

- Contexts: limit_zone
- Default: `reject`
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

### `ocsp_file`

```nginx
ocsp_file <path>;
```

A DER OCSP response to staple, read at start and when it changes; matched to the certificate it answers for. Used instead of a fetch.

- Contexts: server
- Default: none
- Repeatable: yes

### `ocsp_responder_override`

```nginx
ocsp_responder_override <string>;
```

URL of the OCSP responder to use instead of the one named in the certificate (http only: the helper speaks plain HTTP).

- Contexts: server
- Default: none
- Repeatable: no

### `ocsp_stapling`

```nginx
ocsp_stapling <bool>;
```

Staple an OCSP response to the handshake. The helper process fetches and verifies responses; a certificate with no OCSP URL is skipped silently.

- Contexts: tls_profile
- Default: `off`
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

### `panic_threshold`

```nginx
panic_threshold <percent>;
```

When fewer than this share of the primary servers are healthy, health is ignored and requests go to every server with an address (better some errors than a stampede on the survivors). 0% (the default): an upstream with no healthy server answers 503 with Retry-After at once.

- Contexts: upstream
- Default: `0%`
- Repeatable: no

### `passive_eject`

```nginx
passive_eject [fails=<int 1..1000000>] [window=<duration 1000..3600000000 us>] [for=<duration 1000..3600000000 us>];
```

Ejects a server after `fails=` (default 5) failures of real requests (connect errors, timeouts, resets and 5xx responses) within `window=` (10s), for `for=` (30s). Every worker counts into the same shared state, so an ejection applies to all of them at once.

- Contexts: upstream
- Default: none
- Repeatable: no
- Option `fails=`: int 1..1000000
- Option `window=`: duration 1000..3600000000 us
- Option `for=`: duration 1000..3600000000 us

### `permissions_policy`

```nginx
permissions_policy <string> [<force>];
```

Overrides the Permissions-Policy of security_headers: a value, or off for none. With force it replaces a value the handler or upstream set; without, theirs is kept.

- Contexts: global, server, location
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

### `ping_rate`

```nginx
ping_rate <int 1..10000000>;
```

PING frames from the client per second. The budget is a leaky bucket that holds this many events and drains this many per second: a client inside it is never affected, one that keeps going past it has the connection closed with GOAWAY(ENHANCE_YOUR_CALM) and counted in bastion_h2_abuse_total.

- Contexts: http2_abuse
- Default: `50`
- Repeatable: no

### `precompressed`

```nginx
precompressed <bool>;
```

on: for a file the client may get encoded, a sibling name.zst, name.br or name.gz (in the client's order of preference, then zstd, br, gzip) is sent instead, with Content-Encoding, Vary: Accept-Encoding and the original's Content-Type, zero-copy like any file. A sibling older than the original is ignored. Ranges apply to the encoded bytes. Asking for name.br by URL serves it as a plain file.

- Contexts: global, server, location
- Default: `off`
- Repeatable: no

### `prefer_busy_poll`

```nginx
prefer_busy_poll <bool> [require];
```

SO_PREFER_BUSY_POLL (Linux 5.11): let busy polling defer the device's own interrupt handling while the application polls. Only useful with busy_poll.

- Contexts: tcp_profile
- Default: none
- Repeatable: no

### `prefer_server_ciphers`

```nginx
prefer_server_ciphers <bool>;
```

The server's cipher order wins over the client's.

- Contexts: tls_profile
- Default: `on`
- Repeatable: no

### `priority_rate`

```nginx
priority_rate <int 1..10000000>;
```

PRIORITY and PRIORITY_UPDATE frames per second (the dependency flood). Browsers send one per request at page load, so the default is generous. The budget is a leaky bucket that holds this many events and drains this many per second: a client inside it is never affected, one that keeps going past it has the connection closed with GOAWAY(ENHANCE_YOUR_CALM) and counted in bastion_h2_abuse_total.

- Contexts: http2_abuse
- Default: `500`
- Repeatable: no

### `protocol`

```nginx
protocol <http1|http2>;
```

The protocol requests reach the servers in. `http1` (the default): one HTTP/1.1 exchange per connection at a time. `http2`: requests are streams multiplexed over few HTTP/2 connections per worker (cleartext with prior knowledge, or `h2` by ALPN with `tls`), as gRPC needs; response trailers are passed on. A request whose Content-Type is application/grpc gets upstream failures as a gRPC status (`grpc-status` 14 UNAVAILABLE, 4 DEADLINE_EXCEEDED for a timeout) rather than an error page. WebSocket upgrades are not passed to an `http2` upstream.

- Contexts: upstream
- Default: `http1`
- Repeatable: no

### `proxy`

```nginx
proxy <string>;
```

Answers requests by forwarding them: `proxy http://host:port[/path]` to one server, or `proxy name` to an `upstream` block. Every protocol a client speaks (HTTP/1.1, HTTP/2, HTTP/3) reaches the upstream as HTTP/1.1 (HTTP/2 for an upstream with `protocol http2`), with the request head written anew from the parsed request: nothing of the client's bytes passes unparsed. Bodies stream both ways; a response cut off after it started aborts the client's stream, never ending it cleanly.

- Contexts: server, location
- Default: none
- Repeatable: no

### `proxy_buffer_size`

```nginx
proxy_buffer_size <size 4096..16777216 bytes>;
```

Request body bytes read from the client ahead of the upstream: the client is given this much credit each time the previous round reached the upstream.

- Contexts: global, server, location
- Default: `64k`
- Repeatable: no

### `proxy_hide_header`

```nginx
proxy_hide_header <string> ...;
```

Response fields from the upstream that are not passed to the client. Adds to the parent's list.

- Contexts: global, server, location
- Default: none
- Repeatable: yes

### `proxy_host`

```nginx
proxy_host <template>;
```

The Host the upstream sees: `$host` (the client's), `upstream` (the URL's host:port or the upstream's name) or a fixed value.

- Contexts: global, server, location
- Default: `$host`
- Repeatable: no

### `proxy_pass_header`

```nginx
proxy_pass_header <string> ...;
```

Passes response fields that are hidden by default (X-Accel-*). Adds to the parent's list. Date and Server always come from bastion itself.

- Contexts: global, server, location
- Default: none
- Repeatable: yes

### `proxy_protocol_from`

```nginx
proxy_protocol_from <cidr> ...;
```

Address ranges of the balancers allowed to send a PROXY protocol header to a `listen ... proxy_protocol` address (required there; read on the address's default server). A connection from anywhere else is closed without a byte read.

- Contexts: global, server
- Default: none
- Repeatable: no

### `proxy_protocol_timeout`

```nginx
proxy_protocol_timeout <duration 1000..3600000000 us>;
```

How long a `proxy_protocol` connection may take to send its whole header; a missing, malformed or late header closes the connection.

- Contexts: global, server
- Default: `5s`
- Repeatable: no

### `proxy_uri`

```nginx
proxy_uri <pass|strip_prefix>;
```

`pass` sends the request's path and query exactly as the client sent them (after the URL's own path, when `proxy` has one; a `rewrite` sends the rewritten path). `strip_prefix` removes the location's prefix first: `location /api/` sends /api/x as /x.

- Contexts: global, server, location
- Default: `pass`
- Repeatable: no

### `purge_method_allow`

```nginx
purge_method_allow <cidr> ...;
```

Address ranges allowed to send PURGE where `cache` is on: the URL by default, `Purge-Scope: host` for every response of the request's host, `Purge-Scope: all`, or `Purge-Tag: a, b` for the responses tagged so. Each is one O(1) write, effective in every worker at once and kept across restarts. Anyone else gets 403; where no cache is, PURGE is 501.

- Contexts: global, server, location
- Default: none
- Repeatable: no

### `purge_save_interval`

```nginx
purge_save_interval <duration 100000..3600000000 us>;
```

How often the helper saves the purge table (when it changed) to purge.table in the store's directory, so purges survive a restart.

- Contexts: cache_store
- Default: `1s`
- Repeatable: no

### `purge_table_size`

```nginx
purge_table_size <int 1..16777216>;
```

Slots of the purge table (8 bytes each, shared by the workers). Purged tags, hosts and URLs that share a slot only cause extra misses; a larger table, fewer.

- Contexts: cache_store
- Default: `65536`
- Repeatable: no

### `quic_cc`

```nginx
quic_cc <cubic|bbr|reno>;
```

Congestion controller of every connection: cubic (RFC 9438), bbr (BBRv2) or reno.

- Contexts: server
- Default: `cubic`
- Repeatable: no

### `quic_ecn`

```nginx
quic_ecn <bool>;
```

Explicit Congestion Notification (RFC 9000 section 13.4): the ECN marks of received packets are reported to the peer, and sent packets carry ECT(0) unless the path proves it loses or clears the marks (ECN validation). off: no marks are read or set.

- Contexts: server
- Default: `on`
- Repeatable: no

### `quic_gro`

```nginx
quic_gro <bool>;
```

Receive coalesced datagrams (UDP_GRO) when the kernel has it: fewer system calls per packet. Each socket then reserves 64 KiB receive buffers (see io/udp.h).

- Contexts: server
- Default: `on`
- Repeatable: no

### `quic_gso`

```nginx
quic_gso <bool>;
```

Send a connection's back-to-back packets as one UDP_SEGMENT (GSO) send of up to 16 datagrams, when the kernel has it. The peer sees the same datagrams either way. An EIO from a GSO send (a device that cannot segment) turns GSO off for the socket and sends those packets again one by one; the connection is not affected.

- Contexts: server
- Default: `on`
- Repeatable: no

### `quic_handshake_timeout`

```nginx
quic_handshake_timeout <duration 1000000..300000000 us>;
```

A handshake not complete after this long is abandoned and its state freed.

- Contexts: server
- Default: `10s`
- Repeatable: no

### `quic_idle_timeout`

```nginx
quic_idle_timeout <duration 1000000..3600000000 us>;
```

max_idle_timeout transport parameter: a connection with no packet in either direction for this long is freed, silently (RFC 9000 section 10.1).

- Contexts: server
- Default: `30s`
- Repeatable: no

### `quic_initial_max_data`

```nginx
quic_initial_max_data <size 16384..1073741824 bytes>;
```

initial_max_data: bytes a client may send over the whole connection before the server gives more credit.

- Contexts: server
- Default: `1m`
- Repeatable: no

### `quic_initial_max_stream_data`

```nginx
quic_initial_max_stream_data <size 4096..1073741824 bytes>;
```

initial_max_stream_data_bidi_remote and _uni: bytes a client may send on one stream before the server gives more credit.

- Contexts: server
- Default: `256k`
- Repeatable: no

### `quic_max_connections`

```nginx
quic_max_connections <int 1..16777216>;
```

QUIC connections one worker holds at most. A new connection past it is refused with CONNECTION_REFUSED in one small Initial, and no state is kept for it.

- Contexts: server
- Default: `10000`
- Repeatable: no

### `quic_max_streams_bidi`

```nginx
quic_max_streams_bidi <int 1..1048576>;
```

initial_max_streams_bidi: requests a client may have open at once on one connection.

- Contexts: server
- Default: `100`
- Repeatable: no

### `quic_max_streams_uni`

```nginx
quic_max_streams_uni <int 3..100>;
```

initial_max_streams_uni: unidirectional streams a client may open (HTTP/3 needs 3: control, QPACK encoder and decoder).

- Contexts: server
- Default: `3`
- Repeatable: no

### `quic_max_udp_payload`

```nginx
quic_max_udp_payload <size 1200..1472 bytes>;
```

Largest UDP payload a connection sends, the ceiling of path MTU discovery. The default fits a 1500-byte Ethernet MTU under IPv6 headers.

- Contexts: server
- Default: `1452`
- Repeatable: no

### `quic_mtu_discovery`

```nginx
quic_mtu_discovery <bool>;
```

Path MTU discovery (RFC 9000 section 14.3, RFC 8899): packets start at 1200 bytes and grow toward quic_max_udp_payload as probes, sent with the don't-fragment bit, are acknowledged. off: every packet is at most 1200 bytes.

- Contexts: server
- Default: `on`
- Repeatable: no

### `quic_pacing`

```nginx
quic_pacing <bool>;
```

Spread a connection's packets over time at the congestion controller's rate (RFC 9002 section 7.7) instead of sending a whole window at once: at most the send quantum per burst, the next when the pacing timer allows.

- Contexts: server
- Default: `on`
- Repeatable: no

### `quic_retry`

```nginx
quic_retry <auto|always|never>;
```

When a new connection must prove its address with a Retry round trip before the server keeps any state for it (RFC 9000 section 8.1). auto: while more than quic_retry_threshold handshakes are half open in the worker (a flood of Initials from spoofed sources). always: every new connection. never: never on the server's own initiative; a ClientHello that does not start in the first Initial (a large one, post-quantum key shares) still gets a Retry, since the QUIC library buffers it only for a validated address (docs/conformance.md).

- Contexts: server
- Default: `auto`
- Repeatable: no

### `quic_retry_threshold`

```nginx
quic_retry_threshold <int 0..16777216>;
```

Half-open handshakes one worker accepts without Retry under `quic_retry auto`.

- Contexts: server
- Default: `100`
- Repeatable: no

### `quic_routing`

```nginx
quic_routing <ebpf|hash>;
```

How datagrams of an `http3` listener reach the worker that holds their connection. ebpf: master attaches an sk_reuseport program that reads the worker out of the connection ID, so a client whose address changes (NAT rebinding, Wi-Fi to cellular) keeps reaching the same worker. It needs CAP_BPF and CAP_NET_ADMIN at start; without them the server logs a warning and uses hash. hash: the kernel spreads datagrams by address and port, and a client that changes address lands on another worker, which answers with a stateless reset (connection migration across workers is unsupported).

- Contexts: global
- Default: `ebpf`
- Repeatable: no

### `quic_stateless_reset`

```nginx
quic_stateless_reset <bool>;
```

Answer a short-header packet for a connection no worker holds (after a restart, or a client that moved to another worker under `quic_routing hash`) with a stateless reset (RFC 9000 section 10.3), always smaller than the packet that caused it.

- Contexts: server
- Default: `on`
- Repeatable: no

### `quic_versions`

```nginx
quic_versions <v1|v2> ...;
```

QUIC versions served, most preferred first: v1 (RFC 9000), v2 (RFC 9369). A client starting in one may be moved to a preferred one by compatible version negotiation (RFC 9368). Any other version gets a Version Negotiation packet.

- Contexts: server
- Default: `v1 v2`
- Repeatable: no

### `quickack`

```nginx
quickack <bool> [require];
```

TCP_QUICKACK on each accepted connection (set per connection: the kernel does not keep it). `off` delays acknowledgements so they ride on data, saving packets; `on` is how a new connection starts anyway.

- Contexts: tcp_profile
- Default: none
- Repeatable: no

### `ram`

```nginx
ram <size>;
```

Bytes of the RAM tier in front of the disk, split evenly between the workers: each worker keeps its own copies, with no locks (a popular object may be held once per worker). Scan resistant (S3-FIFO): a one-time crawl does not push out the objects in steady use. 0: off.

- Contexts: cache_store
- Default: `0`
- Repeatable: no

### `ram_max_object`

```nginx
ram_max_object <size 1.. bytes>;
```

Largest body kept in the RAM tier; larger objects are served from disk only.

- Contexts: cache_store
- Default: `1m`
- Repeatable: no

### `rate`

```nginx
rate <rate> [burst=<int 1..1000000000>];
```

The rate and burst: `rate 100/s burst=200`. A new key gets `burst` requests at once (1 when unset), then one per 1/rate. Required.

- Contexts: limit_zone
- Default: none
- Repeatable: no
- Option `burst=`: int 1..1000000000

### `rcvbuf`

```nginx
rcvbuf <size ..1073741824 bytes>;
```

SO_RCVBUF of the server's `http3` UDP sockets, in bytes: room for a burst of datagrams while the worker is busy. 0 keeps the kernel's default. The kernel caps it at net.core.rmem_max. (In a tcp_profile block, rcvbuf is the TCP option.)

- Contexts: server
- Default: `0`
- Repeatable: no

### `rcvbuf`

```nginx
rcvbuf <size 4096..1073741824 bytes> [require];
```

SO_RCVBUF: receive buffer size, set before the handshake so it shapes the window the connection starts with. Disables receive autotuning for the connection. The kernel caps it at net.core.rmem_max; bastion warns when that happens.

- Contexts: tcp_profile
- Default: none
- Repeatable: no

### `read_chunk_size`

```nginx
read_chunk_size <size 4096..16777216 bytes>;
```

With sendfile off: the size of each read from the file. One buffer of this size is held per downloading connection, so memory is connections times this.

- Contexts: global, server, location
- Default: `64k`
- Repeatable: no

### `read_timeout`

```nginx
read_timeout <duration 1000..3600000000 us>;
```

How long the upstream may stay silent: before the first byte of the response it is a 504, later the client's response is aborted.

- Contexts: upstream
- Default: `60s`
- Repeatable: no

### `real_ip_from`

```nginx
real_ip_from <cidr> ...;
```

Address ranges allowed to set the client address through `real_ip_header`.

- Contexts: global, server, location
- Default: none
- Repeatable: no

### `real_ip_header`

```nginx
real_ip_header <string>;
```

A header (X-Forwarded-For, X-Real-IP, ...) that names the client, believed only from connections in `real_ip_from`: $remote_addr becomes the rightmost address in it that is not itself in real_ip_from.

- Contexts: global, server, location
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

### `referrer_policy`

```nginx
referrer_policy <string> [<force>];
```

Overrides the Referrer-Policy of security_headers: a value, or off for none. With force it replaces a value the handler or upstream set; without, theirs is kept.

- Contexts: global, server, location
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

### `renegotiation`

```nginx
renegotiation <off>;
```

TLS 1.2 renegotiation is always refused; the only accepted value is off.

- Contexts: tls_profile
- Default: `off`
- Repeatable: no

### `request_buffering`

```nginx
request_buffering <bool>;
```

on: the whole request body is read (in memory up to spool_memory_limit, then in an unnamed file in temp_path) before the upstream sees a byte, and is sent with a Content-Length. off (the default): the body streams through as it arrives. Applies to `http1` upstreams. A full disk answers 507.

- Contexts: global, server, location
- Default: `off`
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

### `request_id`

```nginx
request_id <bool>;
```

on: every request gets a random 128-bit ID ($request_id, 32 hex digits), sent upstream and back to the client in request_id_header. An ID the client sent is replaced unless the peer is in request_id_trust.

- Contexts: global, server, location
- Default: `off`
- Repeatable: no

### `request_id_header`

```nginx
request_id_header <string>;
```

The header field that carries the request ID.

- Contexts: global, server, location
- Default: `X-Request-ID`
- Repeatable: no

### `request_id_trust`

```nginx
request_id_trust <cidr> ...;
```

Peers (CIDR) whose incoming request ID is kept (a balancer that already made one). A kept ID is 1 to 128 letters, digits, '-', '_' or '.', else it is replaced.

- Contexts: global, server, location
- Default: none
- Repeatable: no

### `reserve_fds`

```nginx
reserve_fds <int 1..64>;
```

Descriptors each worker holds open and unused. When the process is out of descriptors (EMFILE) it gives them up to accept waiting connections and close them at once, so clients see a reset instead of waiting in the listen queue, then takes them back. They count against worker_rlimit_nofile.

- Contexts: limits
- Default: `1`
- Repeatable: no

### `resolver`

```nginx
resolver <string> ...;
```

DNS servers (IP addresses, port 53 when omitted; at most 4) the helper asks for `server ... resolve` upstreams, in turn. Only the helper process sends queries: workers never resolve. Query IDs come from the system's CSPRNG and each query uses a fresh socket, so a new random source port.

- Contexts: global
- Default: none
- Repeatable: no

### `resolver_timeout`

```nginx
resolver_timeout <duration 10000..60000000 us>;
```

How long the helper waits for one DNS answer. When the resolver does not answer, the addresses in use stay in use (past their TTL) and a warning is logged.

- Contexts: global
- Default: `5s`
- Repeatable: no

### `resolver_ttl_max`

```nginx
resolver_ttl_max <duration 1000000..86400000000 us>;
```

Longest time a resolved address is kept before asking again.

- Contexts: global
- Default: `1h`
- Repeatable: no

### `resolver_ttl_min`

```nginx
resolver_ttl_min <duration 1000000..3600000000 us>;
```

Shortest time a resolved address is kept before asking again, whatever the record's TTL; also the retry interval after a failed lookup.

- Contexts: global
- Default: `5s`
- Repeatable: no

### `response_buffering`

```nginx
response_buffering <bool>;
```

on: the upstream's response body is read as fast as the upstream sends it, kept in memory up to spool_memory_limit and then in an unnamed file in temp_path, and given to the client at the client's pace, so a slow client does not hold the upstream connection. off (the default): the upstream is read only as fast as the client takes it.

- Contexts: global, server, location
- Default: `off`
- Repeatable: no

### `retry`

```nginx
retry [attempts=<int 0..16>] [budget=<percent>] [on=<string>] [timeout=<duration 1000..3600000000 us>];
```

Retries a failed request on another server: `attempts=` extra tries (default 1, 0 turns retries off), `on=` a comma list of error, timeout and 5xx (default error), `budget=` the share of requests retries may add (default 20%, so an outage is never amplified) and `timeout=` (no new try once the request is that old). A request is never retried once any response byte reached the client, and a request that is not idempotent or has a body only when the connection itself failed (nothing reached the upstream).

- Contexts: upstream
- Default: none
- Repeatable: no
- Option `attempts=`: int 0..16
- Option `budget=`: percent
- Option `on=`: string
- Option `timeout=`: duration 1000..3600000000 us

### `retry_buffered_body`

```nginx
retry_buffered_body <bool>;
```

on: a request whose body was buffered (request_buffering on) may be sent again to another server by `retry` after a failure, even when it is not idempotent. off (the default): once request bytes reached an upstream, a request with a body is never replayed.

- Contexts: global, server, location
- Default: `off`
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

### `rst_rate`

```nginx
rst_rate <int 1..10000000>;
```

RST_STREAM frames from the client per second (Rapid Reset). A browser leaving a page cancels its open streams in one burst, so the default leaves room for http2_max_concurrent_streams of them. The budget is a leaky bucket that holds this many events and drains this many per second: a client inside it is never affected, one that keeps going past it has the connection closed with GOAWAY(ENHANCE_YOUR_CALM) and counted in bastion_h2_abuse_total.

- Contexts: http2_abuse
- Default: `200`
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

### `scan_rate`

```nginx
scan_rate <int 1..10000000>;
```

Files per second the helper reads at start to rebuild the index. Traffic is served meanwhile; an object not yet indexed is a miss.

- Contexts: cache_store
- Default: `10000`
- Repeatable: no

### `seccomp`

```nginx
seccomp <off|on|log> [require];
```

Syscall allowlist, per role, on every thread. on kills the process on anything else; log lets it run and records it in the kernel audit log, for debugging a missing entry; off has no filter. On a kernel without seccomp filters it warns and starts; add `require` to make that a startup error.

- Contexts: sandbox
- Default: `on`
- Repeatable: no

### `security_headers`

```nginx
security_headers <off|basic|strict>;
```

Adds a set of security headers to every response. basic: X-Content-Type-Options: nosniff, X-Frame-Options: SAMEORIGIN, Referrer-Policy: strict-origin-when-cross-origin, and over TLS Strict-Transport-Security: max-age=31536000. strict: X-Content-Type-Options: nosniff, X-Frame-Options: DENY, Referrer-Policy: no-referrer, Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; base-uri 'self', Permissions-Policy: camera=(), microphone=(), geolocation=(), and over TLS Strict-Transport-Security: max-age=63072000; includeSubDomains. HSTS is never sent over cleartext. A header the handler or upstream already set is kept, unless its override says force.

- Contexts: global, server, location
- Default: `off`
- Repeatable: no

### `send_min_rate`

```nginx
send_min_rate <size>;
```

Slowest accepted reader of a response, in bytes per second, averaged over send_timeout. 0 turns the rate check off.

- Contexts: server
- Default: `1k`
- Repeatable: no

### `send_proxy_protocol`

```nginx
send_proxy_protocol <v1|v2>;
```

Every connection to the servers starts with a PROXY protocol header of this version (`v1` text, `v2` binary) naming the client ($remote_addr) and the address it connected to, before TLS. Each request then gets a connection of its own (never pooled: the header names one client). Not with `protocol http2`.

- Contexts: upstream
- Default: none
- Repeatable: no

### `send_timeout`

```nginx
send_timeout <duration 1000..3600000000 us>;
```

Window in which a response must make progress: every window, at least send_min_rate bytes per second must have been accepted by the client, or the connection is closed. Frees workers held by clients that never read.

- Contexts: server
- Default: `30s`
- Repeatable: no

### `send_timeout`

```nginx
send_timeout <duration 1000..3600000000 us>;
```

How long a write of the request to the upstream may make no progress.

- Contexts: upstream
- Default: `60s`
- Repeatable: no

### `sendfile`

```nginx
sendfile <bool>;
```

Send file bodies from the page cache to the socket inside the kernel (sendfile, or splice on io_uring), so the bytes never enter the worker. With off the worker reads each file in read_chunk_size pieces on its thread pool and sends them: slower, and the way to serve a file system that does not support sendfile.

- Contexts: global, server, location
- Default: `on`
- Repeatable: no

### `sendfile_max_chunk`

```nginx
sendfile_max_chunk <size 4096..1073741824 bytes>;
```

The most bytes one sendfile or splice step moves for one connection before the worker serves others: it keeps one fast client downloading a huge file from starving the rest.

- Contexts: global, server, location
- Default: `1m`
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

### `server`

```nginx
server <string> [<backup|resolve>] ... [weight=<int 1..1000>] [max_conns=<int 1..1048576>] [slow_start=<duration 1000000..3600000000 us>];
```

An upstream server: `host:port` (port 80 when omitted; `[v6]:port` for IPv6), with `weight=` (1 to 1000, default 1), `max_conns=` (per worker), `slow_start=` (after it recovers from being down, its share of traffic ramps up over this time), `backup` (used only when no other server can take the request) and `resolve`. A host name without `resolve` is looked up once when the configuration loads and must resolve; with `resolve` the helper looks it up through `resolver` and keeps the addresses fresh within their TTL, with no reload, and the server starts even while DNS fails (its requests are answered 502 until it resolves).

- Contexts: upstream
- Default: none
- Repeatable: yes
- Option `weight=`: int 1..1000
- Option `max_conns=`: int 1..1048576
- Option `slow_start=`: duration 1000000..3600000000 us

### `server_reset_rate`

```nginx
server_reset_rate <int 1..10000000>;
```

Resets the server has to send because of what the client did (malformed requests, frames for closed streams, refused streams: MadeYouReset). The budget is a leaky bucket that holds this many events and drains this many per second: a client inside it is never affected, one that keeps going past it has the connection closed with GOAWAY(ENHANCE_YOUR_CALM) and counted in bastion_h2_abuse_total.

- Contexts: http2_abuse
- Default: `100`
- Repeatable: no

### `server_tokens`

```nginx
server_tokens <bool>;
```

Whether the Server header names the version (bastion/x.y) or only bastion.

- Contexts: server
- Default: `on`
- Repeatable: no

### `settings_rate`

```nginx
settings_rate <int 1..10000000>;
```

SETTINGS frames from the client per second. The budget is a leaky bucket that holds this many events and drains this many per second: a client inside it is never affected, one that keeps going past it has the connection closed with GOAWAY(ENHANCE_YOUR_CALM) and counted in bastion_h2_abuse_total.

- Contexts: http2_abuse
- Default: `20`
- Repeatable: no

### `shutdown_timeout`

```nginx
shutdown_timeout <duration 1000..86400000000 us>;
```

How long a graceful stop (SIGQUIT) waits for connections in progress. Workers still busy after it are killed.

- Contexts: global
- Default: `30s`
- Repeatable: no

### `sigalgs`

```nginx
sigalgs <string> ...;
```

Signature algorithms the server accepts and uses, in order of preference. SHA-1 signatures are not in the default.

- Contexts: tls_profile
- Default: `ecdsa_secp256r1_sha256 ecdsa_secp384r1_sha384 ed25519 rsa_pss_rsae_sha256 rsa_pss_rsae_sha384 rsa_pkcs1_sha256`
- Repeatable: no

### `size`

```nginx
size <size 1024..1073741824 bytes>;
```

Shared memory of the zone, 16 bytes per key (rounded down to a power of two of slots, at least 64). A full table replaces its least recently due key.

- Contexts: limit_zone
- Default: `1m`
- Repeatable: no

### `sndbuf`

```nginx
sndbuf <size 4096..1073741824 bytes> [require];
```

SO_SNDBUF: send buffer size. Disables send autotuning for the connection. The kernel caps it at net.core.wmem_max; bastion warns when that happens.

- Contexts: tcp_profile
- Default: none
- Repeatable: no

### `sni_mismatch`

```nginx
sni_mismatch <default|reject>;
```

A server name no server answers to: `default` serves the default certificate, `reject` fails the handshake with an unrecognized_name alert. Read on the default server.

- Contexts: server
- Default: `default`
- Repeatable: no

### `sni_required`

```nginx
sni_required <bool>;
```

Fail the handshake of a client that sends no server name. Read on the default server of the listener.

- Contexts: server
- Default: `off`
- Repeatable: no

### `spool_memory_limit`

```nginx
spool_memory_limit <size ..1073741824 bytes>;
```

Bytes of a buffered request or response body kept in memory; the rest goes to an unnamed (O_TMPFILE) file in temp_path, which disappears with its last descriptor.

- Contexts: global, server, location
- Default: `1m`
- Repeatable: no

### `stale_if_error`

```nginx
stale_if_error <duration ..31536000000000 us>;
```

How long past its freshness a stored response may be served when the upstream fails (5xx, refused, timed out) (RFC 5861); the response's own stale-if-error counts when longer. Cache-Status then says fwd=stale and detail=stale-if-error. Never for must-revalidate responses.

- Contexts: global, server, location
- Default: `0s`
- Repeatable: no

### `stale_while_revalidate`

```nginx
stale_while_revalidate <duration ..31536000000000 us>;
```

How long past its freshness a stored response may be served while one background request revalidates it (RFC 5861); the response's own stale-while-revalidate counts when longer. Never for must-revalidate, proxy-revalidate, s-maxage or no-cache responses.

- Contexts: global, server, location
- Default: `0s`
- Repeatable: no

### `status`

```nginx
status <int 400..599>;
```

The status of a refused request.

- Contexts: limit_zone
- Default: `429`
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

### `temp_path`

```nginx
temp_path <path>;
```

Directory for spooled bodies (request_buffering, response_buffering). Opened at start and granted write access by the sandbox only when some scope turns buffering on. Files are unnamed (O_TMPFILE): nothing is left behind, even after a crash.

- Contexts: global
- Default: `/tmp`
- Repeatable: no

### `tickets`

```nginx
tickets [<off>] [rotate=<duration 60000000..2592000000000 us>] [keep=<int 1..16>] [file=<path>];
```

Session tickets for resumption. `off` disables them. Otherwise keys rotate every `rotate`, and the newest `keep` keys decrypt old tickets; `file=` reads the keys from a file so several instances resume each other's tickets. Key material lives in one shared, non-dumpable memory region. Every profile that enables tickets must agree on rotate, keep and file.

- Contexts: tls_profile
- Default: `rotate=12h keep=3`
- Repeatable: no
- Option `rotate=`: duration 60000000..2592000000000 us
- Option `keep=`: int 1..16
- Option `file=`: path

### `tls ca`

```nginx
tls ca <path>;
```

PEM file of the CAs the upstream's certificate must lead to, read when the configuration loads (before the sandbox), instead of the system bundle.

- Contexts: upstream
- Default: none
- Repeatable: no

### `tls cert`

```nginx
tls cert <path>;
```

Client certificate (PEM chain) presented to the upstream (mTLS); needs `tls key`.

- Contexts: upstream
- Default: none
- Repeatable: no

### `tls key`

```nginx
tls key <path>;
```

Private key of `tls cert`.

- Contexts: upstream
- Default: none
- Repeatable: no

### `tls sni`

```nginx
tls sni <string>;
```

The name sent as SNI and checked against the upstream's certificate. Default: the server's host as written (an IP address is checked against the certificate's IP entries and not sent as SNI).

- Contexts: upstream
- Default: none
- Repeatable: no

### `tls verify`

```nginx
tls verify <bool>;
```

TLS to the servers of this upstream (any `tls` line turns it on; `proxy https://` does too). `on` (the default) checks the certificate chain against `tls ca` (else the system's CA bundle) and that it names the server (`tls sni`, else the server's host). `off` checks nothing: `bastion -t` warns.

- Contexts: upstream
- Default: none
- Repeatable: no

### `tls versions`

```nginx
tls versions <1.2|1.3> ...;
```

TLS versions offered to the upstream: 1.2, 1.3 or both (the default).

- Contexts: upstream
- Default: none
- Repeatable: no

### `tls_cert`

```nginx
tls_cert <path> <path>;
```

Certificate chain (PEM, leaf first) and its private key. Give two, one RSA and one ECDSA, to serve each client the one it prefers. Master reads both files before the sandbox; workers never can.

- Contexts: server
- Default: none
- Repeatable: yes

### `tls_client_auth`

```nginx
tls_client_auth <off|optional|required>;
```

Client certificates: off, optional (verified if sent, else the connection goes on and a location with auth_mtls answers 403) or required (no certificate fails the handshake). Needs tls_client_ca.

- Contexts: server
- Default: `off`
- Repeatable: no

### `tls_client_ca`

```nginx
tls_client_ca <path>;
```

PEM file of the certificate authorities that sign accepted client certificates.

- Contexts: server
- Default: none
- Repeatable: no

### `tls_client_crl`

```nginx
tls_client_crl <path>;
```

PEM file of certificate revocation lists. When set, a client certificate whose issuer has no CRL here, or that is listed, is refused.

- Contexts: server
- Default: none
- Repeatable: no

### `tls_client_verify_depth`

```nginx
tls_client_verify_depth <int 1..16>;
```

Longest accepted client certificate chain.

- Contexts: server
- Default: `4`
- Repeatable: no

### `tls_default_cert`

```nginx
tls_default_cert <path> <path>;
```

Certificate and key for a handshake that carries no SNI, or one that names no server (unless sni_mismatch is reject). Default: the certificates of the listener's default server.

- Contexts: server
- Default: none
- Repeatable: no

### `tls_ja4`

```nginx
tls_ja4 <bool>;
```

Compute the JA4 fingerprint of each client's TLS ClientHello, for $ja4 (logs, rules). Off costs nothing. Read on the default server of the listener, because the hello arrives before a server is chosen.

- Contexts: server
- Default: `off`
- Repeatable: no

### `tls_profile`

```nginx
tls_profile <string> { ... }
```

A named set of TLS choices that servers share: protocol versions, key exchange groups, ciphers, kTLS, session tickets, OCSP stapling and 0-RTT. A server picks one with `tls_profile name;` and falls back to the documented defaults when it names none.

- Contexts: global
- Block context: tls_profile
- Default: none
- Repeatable: yes

### `tls_profile`

```nginx
tls_profile <string>;
```

The tls_profile block this server uses; default: the documented defaults.

- Contexts: server
- Default: none
- Repeatable: no

### `trusted_proxies`

```nginx
trusted_proxies <cidr> ...;
```

Address ranges of front proxies whose X-Forwarded-* or Forwarded values are kept and appended to. Everyone else's are replaced.

- Contexts: global, server, location
- Default: none
- Repeatable: no

### `try_files`

```nginx
try_files <template> <template> ...;
```

Looks for each argument but the last as a file (a name ending in '/' is a directory) below the root, and serves the first that exists. If none does, the last argument decides: a URI the request is re-routed to, or =code to answer with that status. Arguments may use variables: try_files $uri $uri/ /index.html; gives a single-page application its fallback. A re-route counts against rewrite_max_cycles.

- Contexts: server, location
- Default: none
- Repeatable: no

### `tunnel_drain_timeout`

```nginx
tunnel_drain_timeout <duration 1000..3600000000 us>;
```

After one side of a tunnel ended its direction (half-close), the other side has this long to finish before the tunnel is closed.

- Contexts: global, server, location
- Default: `30s`
- Repeatable: no

### `tunnel_idle_timeout`

```nginx
tunnel_idle_timeout <duration 1000..86400000000 us>;
```

A tunnel with no byte in either direction for this long is closed.

- Contexts: global, server, location
- Default: `1h`
- Repeatable: no

### `tunnel_max_duration`

```nginx
tunnel_max_duration <duration 1000..2592000000000 us>;
```

A tunnel is closed after this long, however busy.

- Contexts: global, server, location
- Default: `24h`
- Repeatable: no

### `types`

```nginx
types <string> <string> ...;
```

Maps file extensions to a media type for Content-Type: types text/x-markdown md markdown; The extension is the last one in the file name, compared without case. These add to the built-in table (about eighty common types) and win over it, and the ones of an outer block apply in an inner one. A text type should carry its charset: types "text/plain; charset=utf-8" txt;

- Contexts: global, server, location
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

### `upstream`

```nginx
upstream <string> { ... }
```

A named group of servers a `proxy` sends requests to (`proxy name`). Names are unique. `proxy http://host:port` makes an unnamed one with that single server and the defaults of this block.

- Contexts: global
- Block context: upstream
- Default: none
- Repeatable: yes

### `upstream_max_response_size`

```nginx
upstream_max_response_size <size>;
```

The largest response body accepted from an upstream; 0 means unlimited. A larger declared Content-Length is a 502; a body that grows past it once the response began aborts the client's stream (never a clean end of a cut response).

- Contexts: global, server, location
- Default: `0`
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

### `versions`

```nginx
versions <1.2|1.3> ...;
```

TLS protocol versions offered: 1.2, 1.3, or both. TLS 1.0 and 1.1 cannot be enabled.

- Contexts: tls_profile
- Default: `1.2 1.3`
- Repeatable: no

### `websocket`

```nginx
websocket <bool>;
```

Where `proxy` is set: an HTTP/1.1 WebSocket upgrade (GET with Upgrade: websocket, a valid Sec-WebSocket-Key and version 13) is passed on, and when the upstream answers 101 the connection becomes a tunnel of opaque bytes both ways. An upstream that answers anything else gets its response relayed as a normal one, never a tunnel. An HTTP/2 client's extended CONNECT (RFC 8441, with `http2_connect_protocol on`) reaches the upstream as that same HTTP/1.1 upgrade, with a key the proxy makes and whose Sec-WebSocket-Accept it checks; the client gets 200 and the stream carries the tunnel. Not for an `http2` upstream. `off` sends upgrades as plain requests and refuses extended CONNECT with 501.

- Contexts: global, server, location
- Default: `on`
- Repeatable: no

### `window_update_rate`

```nginx
window_update_rate <int 1..10000000>;
```

WINDOW_UPDATE frames from the client per second (the window drip). Fast downloads legitimately cause thousands. The budget is a leaky bucket that holds this many events and drains this many per second: a client inside it is never affected, one that keeps going past it has the connection closed with GOAWAY(ENHANCE_YOUR_CALM) and counted in bastion_h2_abuse_total.

- Contexts: http2_abuse
- Default: `5000`
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
