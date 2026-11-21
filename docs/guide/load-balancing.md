# Load balancing and upstreams

An `upstream` block names a group of application servers that `proxy` sends requests to. This
guide goes through the servers of a group, the balancing methods, health checks, passive
ejection, retries, circuit breaking, connection reuse, DNS and runtime control.
[Reverse proxy](reverse-proxy.md) covers the request side: headers, bodies, WebSockets, gRPC and
TLS to the upstream.

## An upstream

```conf
upstream app {
    server 10.0.0.11:3000;
    server 10.0.0.12:3000 weight=2;
    server 10.0.0.13:3000 backup;
}
server {
    listen 80;
    proxy app;
}
```

`proxy app` refers to the block by name. `proxy http://host:port` (no block) makes an unnamed
upstream with one server and every default.

### Servers

```nginx
server <host:port> [backup] [resolve] [weight=n] [max_conns=n] [slow_start=duration];
```

| Part | Meaning |
|---|---|
| `host:port` | an address; port 80 when omitted, `[v6]:port` for IPv6 |
| `weight=` | 1 to 1000, default 1: the server's share relative to the others |
| `max_conns=` | the most requests in flight to this server, per worker |
| `slow_start=` | after the server recovers from being down, its share ramps up over this time (at least 1s) |
| `backup` | used only when no other server can take the request |
| `resolve` | look the name up at run time through `resolver` (see [DNS](#dns)) |

A host name without `resolve` is looked up once, when the configuration loads, and must resolve.

## Balancing methods

| Method | Behaviour |
|---|---|
| `balance round_robin` (default) | smooth weighted round robin: over any window each server gets its weight's share, interleaved rather than in bursts |
| `balance least_conn` | the server with the fewest open requests from this worker, relative to its weight; ties go round robin |
| `balance peak_ewma` | two servers drawn at random; the one with the lower moving average of latency (peaks count at once, recovery decays over 10 s) times its open requests wins, so slow servers get less traffic |
| `balance hash <template> [consistent]` | the same key always goes to the same server |

```conf
upstream sessions {
    server 10.0.0.21:8080;
    server 10.0.0.22:8080;
    server 10.0.0.23:8080;
    balance hash $cookie_session consistent;
}
server {
    listen 80;
    proxy sessions;
}
```

The `hash` key is any template: `$remote_addr`, `$cookie_NAME`, `$http_NAME`, `$request_uri`.
With `consistent`, servers sit on a hash ring, so removing one of n servers moves only about 1/n of
the keys, and a server already carrying 25% more than its share passes keys on to the next one
(bounded load).

`least_conn` and `peak_ewma` count each worker's own requests: workers do not share in-flight
counts.

## Health checks

```conf
upstream app {
    server 10.0.0.11:3000;
    server 10.0.0.12:3000;
    health_check path=/healthz expect=200-299 interval=5s timeout=2s fails=3 passes=2;
}
server {
    listen 80;
    proxy app;
}
```

Active checks are sent by the helper process, one probe per server per interval however many
workers there are. The results are published in shared memory for every worker.

| Option | Default | Meaning |
|---|---|---|
| `path=` | `/` | the path requested |
| `expect=` | `200-399` | a status or range that counts as a pass |
| `interval=` | `5s` | time between probes |
| `timeout=` | `2s` | a probe slower than this fails |
| `fails=` | `3` | consecutive failures that mark the server down |
| `passes=` | `2` | consecutive passes that bring it back |

For a TLS upstream only the TCP connect is checked. Without `health_check`, every server is
assumed up until passive ejection says otherwise.

## Passive ejection

```nginx
passive_eject fails=5 window=10s for=30s;
```

Takes a server out after `fails=` failures of real requests (connect errors, timeouts, resets and
5xx responses) within `window=`, for `for=`. Every worker counts into the same shared state, so an
ejection applies to all workers at once. The defaults are the values shown.

## When no server is healthy

`panic_threshold` (default `0%`) decides. At 0%, an upstream with no healthy server answers 503
with `Retry-After` at once. Above 0%, when fewer than that share of the primary servers are
healthy, health is ignored and requests go to every server with an address, which is better than
a stampede on the few survivors.

```conf
upstream app {
    server 10.0.0.11:3000;
    server 10.0.0.12:3000;
    server 10.0.0.13:3000;
    health_check path=/healthz;
    panic_threshold 50%;
}
server {
    listen 80;
    proxy app;
}
```

`backup` servers take requests only when no primary server can.

## Retries

```nginx
retry attempts=1 on=error,timeout budget=20% timeout=10s;
```

| Option | Default | Meaning |
|---|---|---|
| `attempts=` | `1` | extra tries on another server; 0 turns retries off |
| `on=` | `error` | a comma list of `error`, `timeout` and `5xx` |
| `budget=` | `20%` | the share of requests that retries may add, so an outage is never amplified |
| `timeout=` | none | no new try once the request is this old |

A request is never retried once any byte of the response reached the client. A request that is
not idempotent, or has a body, is retried only when the connection itself failed and nothing
reached the upstream. `retry_buffered_body on` (with `request_buffering on`) allows replaying a
buffered body to another server.

## Circuit breaking

```nginx
circuit_breaker max_pending=1000 max_active=5000 max_retries=100 fails=20 for=10s;
```

Per-worker limits: `max_pending=` requests waiting for a response head, `max_active=` requests in
flight, `max_retries=` retries in flight. A request over a limit gets 503 with `Retry-After` at
once: nothing queues. With `fails=`, that many consecutive failures open the breaker for `for=`
(default 10s); requests get 503, then one probe request decides whether it closes or opens again.

## Connection reuse and timeouts

| Directive | Default | Meaning |
|---|---|---|
| `keepalive` | `32` | idle connections per upstream each worker keeps for reuse; 0 closes after every response |
| `keepalive_requests` | `1000` | requests one connection carries before it is closed |
| `keepalive_timeout` | `60s` | how long an idle connection is kept; keep it below the upstream's own idle timeout |
| `connect_timeout` | `5s` | past it, 504 (a refused connection is 502) |
| `read_timeout` | `60s` | upstream silence: 504 before the response starts, an aborted response after |
| `send_timeout` | `60s` | a write of the request that makes no progress |
| `protocol` | `http1` | `http2` multiplexes requests over few connections per worker (gRPC needs it) |
| `max_upstream_h2_streams` | `100` | streams per HTTP/2 upstream connection |
| `send_proxy_protocol` | none | `v1` or `v2`: send a PROXY header first (each request then gets its own connection) |

These go in the `upstream` block. An unnamed `proxy http://...` upstream uses the defaults.

## DNS

```conf
resolver 10.0.0.2 10.0.0.3;
upstream app {
    server app.internal.example:3000 resolve;
}
server {
    listen 80;
    proxy app;
}
```

With `resolve`, the helper process looks the name up through the `resolver` servers (up to 4, in
turn) and keeps the addresses fresh within their TTL, bounded by `resolver_ttl_min` (5s) and
`resolver_ttl_max` (1h). No reload is needed when DNS changes. The server starts even while DNS
fails; requests to that server get 502 until it resolves. When the resolver stops answering, the
addresses in use stay in use and a warning is logged. Workers never send DNS queries. Each query
uses a fresh socket (a new random source port) and a random query ID.

## Runtime control

With the [admin API](../admin-api.md) enabled:

```
bastionctl upstreams                 # every upstream: index, server, weight, backup, up, drained
bastionctl upstreams app             # one upstream
bastionctl upstream drain app 0      # no new requests to server 0; requests in flight finish
bastionctl upstream enable app 0
```

A drain applies even in panic mode and lasts until the next reload or restart: it is not written
to the configuration. `<peer>` is the server's index or its `host:port` as `upstreams` lists it.

## Metrics

| Metric | Labels | Meaning |
|---|---|---|
| `bastion_upstream_peers` | `upstream`, `server` | peers configured or resolved |
| `bastion_upstream_peers_up` | `upstream`, `server` | peers taking traffic (not down by health checks or passive ejection) |

Access logs can record `$upstream_addr`, `$upstream_status` and `$upstream_response_time`
([logging and metrics](logging-and-metrics.md)).

## A complete example

```conf
resolver 10.0.0.2;
upstream app {
    server 10.0.0.11:3000 weight=2 slow_start=30s;
    server 10.0.0.12:3000 max_conns=200;
    server app-dr.internal.example:3000 backup resolve;
    balance peak_ewma;
    keepalive 64;
    keepalive_timeout 30s;
    health_check path=/healthz interval=2s fails=2 passes=3;
    passive_eject fails=10 window=10s for=20s;
    retry attempts=2 on=error,timeout,5xx budget=10%;
    circuit_breaker max_pending=2000;
    panic_threshold 30%;
}
server {
    listen 80;
    location /api/ {
        proxy app;
        proxy_uri strip_prefix;
    }
}
```
