# Logging and metrics

Bastion writes an error log, optional access logs, and serves Prometheus metrics on a listener
of its own. None of these ever makes a worker wait: workers hand log lines to the helper through
shared memory rings, and counters are plain atomics in shared memory.

## The error log

Errors, warnings and notices go to standard error unless `error_log` names a file. Under systemd
standard error is the journal (`journalctl -u bastion`).

```conf
error_log /var/log/bastion/error.log info;
server { listen 80; root /srv/www; }
```

| Level | Includes |
|---|---|
| `error` | failures that need attention |
| `warn` (default) | the above, and degraded but working states: a missing kernel feature, an insecure setting, an upstream connect failure |
| `notice` | the above, and normal but significant events |
| `info` | the above, and informational lines such as certificate issuance |
| `debug` | everything, including per-datagram QUIC drops; for debugging only |

Each line carries a UTC timestamp, the PID, the process role and the level:

```
2026-11-21T09:08:31.588Z 14 master WARN workers run as root: set "user"
2026-11-21T09:08:34.626Z 23 worker/5 WARN proxy: connecting to 127.0.0.1:9 failed: Connection refused
```

Values from requests are escaped, so a client cannot forge a log line. Log to a file or a pipe in
production, not a terminal ([architecture](../architecture.md#the-sandbox) explains why a tty is a
poor log target for sandboxed workers).

## Access logs

Access logs are off unless `access_log` is set. `access_log` is valid at the top level, in a
server and in a location; a scope's own statements replace those it inherits, and
`access_log off` logs nothing there.

```nginx
access_log <path|stdout|off> [format] [sample=fraction] [errors_only=on] [if=template];
```

| Part | Meaning |
|---|---|
| path | a file, opened by master and written by the helper; `stdout` writes to standard output |
| format | a `log_format` name; `main` (the default) or `combined` are built in |
| `sample=` | log that fraction of requests: `0.1` or `10%`; errors (status 400 and up) are never sampled out |
| `errors_only=on` | only responses with status 400 and up |
| `if=` | only when the template is neither empty nor `0` |

```conf
access_log /var/log/bastion/access.log;
access_log /var/log/bastion/errors.log combined errors_only=on;
server {
    listen 80;
    root /srv/www;
    location /health { access_log off; return 200 "ok\n"; }
    location /static/ { access_log /var/log/bastion/static.log main sample=1%; }
}
```

### Built-in formats

`main` is JSON, one object per line, with these keys:

| Key | Value |
|---|---|
| `time` | `$time_iso8601` |
| `remote_addr` | `$remote_addr` |
| `request_id` | `$request_id` |
| `method` | `$request_method` |
| `uri` | `$request_uri` |
| `protocol` | `$server_protocol` |
| `status` | `$status` |
| `body_bytes_sent` | `$body_bytes_sent` |
| `request_time` | `$request_time` |
| `host` | `$host` |
| `referer` | `$http_referer` |
| `user_agent` | `$http_user_agent` |

`combined` is the nginx-style text format:

```
$remote_addr - $auth_user [$time_local] "$request_method $request_uri $server_protocol" $status $body_bytes_sent "$http_referer" "$http_user_agent"
```

### Your own formats

```conf
log_format timing json {
    time $time_iso8601;
    client $remote_addr;
    method $request_method;
    uri $request_uri;
    status $status;
    duration $request_time;
    upstream $upstream_addr;
    upstream_status $upstream_status;
    upstream_time $upstream_response_time;
    id $request_id;
}
log_format short text "$remote_addr $request_method $request_uri $status $request_time";
access_log /var/log/bastion/timing.log timing;
access_log /var/log/bastion/short.log short;
server { listen 80; proxy http://127.0.0.1:3000; }
```

- `log_format <name> json { <key> <template>; ... }` writes one JSON object per line; each value is
  a string, escaped on its own.
- `log_format <name> text "<template>"` writes the template with every variable escaped (quotes,
  backslashes, control bytes and invalid UTF-8 as `\xHH`), so no value can split a line.

Any variable from [configuration](../configuration.md#variables-in-templates) may appear.

### Redaction

`Authorization`, `Cookie`, `Proxy-Authorization` and `Set-Cookie` always read `[REDACTED]` in
access logs. Add more:

```conf
log_redact_headers x-api-key x-session;
log_redact_query_params token password;
access_log /var/log/bastion/access.log;
server { listen 80; root /srv/www; }
```

- `log_redact_headers` makes `$http_NAME` read `[REDACTED]` for those headers. Listing `cookie`
  also hides every `$cookie_NAME`.
- `log_redact_query_params` redacts those parameters' values in `$arg_NAME`, `$args` and
  `$request_uri`. Names compare case-insensitively after percent-decoding.

### Buffering and rotation

Each worker writes lines into its own ring in shared memory (`log_buffer`, default `1m`, rounded
up to a power of two). The helper drains the rings every `log_flush_interval` (default `1s`, from
10ms to 60s) or as soon as a batch fills, and writes each file's batch. A line that does not fit
while the helper is behind is dropped and counted in `bastion_log_dropped_total`: the worker never
waits.

`USR1` to master reopens every access log file. The package's `/etc/logrotate.d/bastion` rotates
`/var/log/bastion/*.log` daily, keeps 14 compressed copies, and sends `USR1` to the service's main
process after rotating.

## Request IDs and trace context

```conf
request_id on;
trace_context on;
access_log /var/log/bastion/access.log;
server { listen 80; proxy http://127.0.0.1:3000; }
```

- `request_id on` gives every request a random 128-bit ID (`$request_id`, 32 hex digits), sent
  upstream and back to the client in `request_id_header` (default `X-Request-ID`). A client's own
  ID is replaced unless the peer is in `request_id_trust`.
- `trace_context on` sends every upstream request a W3C `traceparent` with `$trace_id` and a new
  `$span_id`. An incoming `traceparent` is kept only when it is valid and the peer is in
  `trace_trust`. No spans are exported.

## Metrics

```conf
metrics {
    listen 127.0.0.1:9145;
    path /metrics;
    allow 127.0.0.1 10.0.0.0/8;
}
server { listen 80; root /srv/www; }
```

The `metrics` block turns on a Prometheus endpoint (text exposition format). The helper serves it
on its own listener, never on a site's port. The counters live in shared memory and survive
reloads, live upgrades and worker crashes.

| Directive | Default | Meaning |
|---|---|---|
| `listen` | `127.0.0.1:9145` | address and port of the endpoint; a non-loopback address draws a warning |
| `path` | `/metrics` | the scrape path; any other path gets 404 |
| `allow` | everyone who reaches the listener | addresses or CIDRs that may scrape (up to 64); others get 403 |
| `auth_basic` | none | a file of `user:$argon2id$...` lines; a scrape without valid credentials gets 401 |
| `per_location` | `off` | also count requests per location |

Label values come from the configuration only, never from requests: a request whose `Host`
matches no server name is counted under `server="_other"`.

### Metric list

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `bastion_build_info` | gauge | `version` | the running build, always 1 |
| `bastion_config_reload_success` | gauge | | 1 when the last configuration load or reload succeeded |
| `bastion_connections` | gauge | | client connections open in the workers |
| `bastion_http_requests_total` | counter | `server`, `code` (`1xx` to `5xx`), `protocol` (`http1`, `http2`, `http3`) | client requests answered |
| `bastion_http_location_requests_total` | counter | `server`, `location` | requests per location (with `per_location on`), the location labelled by its pattern |
| `bastion_http_request_duration_seconds` | histogram | `protocol` | time from the request head to the end of the response; buckets from 1ms to 10s |
| `bastion_io_backend` | counter | `name` (`uring`, `epoll`) | event loops started on each backend |
| `bastion_worker_restarts_total` | counter | | workers and helpers respawned after an unasked exit |
| `bastion_child_crashes_total` | counter | | children that died unasked |
| `bastion_tls_handshakes_total` | counter | `result` (`ok`, `failed`, `timeout`) | TLS handshakes |
| `bastion_tls_ktls_connections` | counter | `mode` (`tx`, `tx+rx`, `user`) | TLS connections by where the record layer runs |
| `bastion_tls_ktls_keyupdate_closed_total` | counter | | connections closed by a client KeyUpdate under kTLS |
| `bastion_quic_events_total` | counter | `kind` | QUIC connections and stateless answers ([HTTP/3](http3.md#watching-it)) |
| `bastion_h2_abuse_total` | counter | `kind` | HTTP/2 and HTTP/3 connections closed for using up an abuse budget |
| `bastion_upstream_peers` | gauge | `upstream`, `server` | upstream peers configured or resolved |
| `bastion_upstream_peers_up` | gauge | `upstream`, `server` | upstream peers taking traffic |
| `bastion_cache_hits_total` | counter | `tier` (`ram`, `disk`) | fresh cache hits by the tier that served them |
| `bastion_limit_rejected_total` | counter | | requests refused by a `limit_zone` |
| `bastion_limit_delayed_total` | counter | | requests held by a `limit_zone` in mode `delay` |
| `bastion_limit_dry_run_total` | counter | | requests a `dry_run` zone would have refused |
| `bastion_conn_limit_refused_total` | counter | | connections closed at accept by `limit_conn` |
| `bastion_acl_denied_total` | counter | | connections and requests an ACL refused |
| `bastion_waf_matches_total` | counter | | WAF rules that matched |
| `bastion_waf_denied_total` | counter | | requests a WAF rule denied |
| `bastion_blocked_total` | counter | | connections and requests refused because of an escalation block |
| `bastion_escalate_requests_total` | counter | | block requests workers sent to master |
| `bastion_escalate_blocks_total` | counter | | blocks master added |
| `bastion_escalate_refused_total` | counter | `reason` (`malformed`, `exempt`, `ceiling`, `backend`) | block requests master refused |
| `bastion_escalate_ignored_total` | counter | | strikes of unvalidated peers, never escalated |
| `bastion_escalate_ring_dropped_total` | counter | | block requests dropped on a full ring |
| `bastion_challenge_issued_total` | counter | | challenge pages sent |
| `bastion_challenge_passed_total` | counter | | challenges solved |
| `bastion_challenge_failed_total` | counter | | challenge answers refused |
| `bastion_under_attack` | gauge | | 1 while `challenge auto` considers the server under attack (only with `challenge auto` configured) |
| `bastion_under_attack_total` | counter | | times `challenge auto` turned on |
| `bastion_xdp_packets_total` | counter | `reason` | packets the XDP filter passed or dropped (only with `xdp {}`; reasons in [XDP](xdp.md#watching-it)) |
| `bastion_log_dropped_total` | counter | | access log lines dropped: a full ring or a failed write |
| `bst_log_dropped_total` | counter | | error log lines dropped (a non-blocking write that would have blocked) |

The `bastion_escalate_*` and `bastion_waf_*` counters appear only when the configuration uses
escalation or WAF rules.
`bastion_h2_abuse_total{kind}` kinds seen in the code are `continuation`, `control_queue`,
`empty`, `ping`, `priority`, `rst`, `server_reset`, `settings` and `window_update` for HTTP/2,
plus `stream_reset`, `qpack` and `control_stream` for HTTP/3.

### Useful queries

```
# requests per second by status class
sum by (code) (rate(bastion_http_requests_total[5m]))

# 99th percentile latency per protocol
histogram_quantile(0.99, sum by (le, protocol) (rate(bastion_http_request_duration_seconds_bucket[5m])))

# upstream servers down
bastion_upstream_peers - on (upstream, server) bastion_upstream_peers_up > 0

# a reload failed
bastion_config_reload_success == 0

# workers crashing
increase(bastion_worker_restarts_total[15m]) > 0
```

## Watching from the command line

```
curl -s http://127.0.0.1:9145/metrics | grep -v '^#'
bastionctl status
journalctl -u bastion -f
```
