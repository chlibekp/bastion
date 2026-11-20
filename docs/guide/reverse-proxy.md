# Reverse proxy

`proxy` forwards requests to an application server. Clients may speak HTTP/1.1, HTTP/2 or
HTTP/3; the upstream gets HTTP/1.1 (or HTTP/2 with `protocol http2`), with the request head
written anew from the parsed request, so no bytes of the client's request pass through unparsed.
[examples/reverse-proxy.conf](../../examples/reverse-proxy.conf) puts this guide together.

## One application

```conf
acme { email admin@example.com; }
server {
    name app.example.com;
    tls auto;
    proxy http://127.0.0.1:3000;
}
```

`proxy http://host:port` makes an unnamed upstream with one server. For a quick test without a
configuration file: `bastion proxy http://127.0.0.1:3000 --port 8080`.

What the application receives by default:

- `Host` is the client's (`proxy_host` changes it).
- `X-Forwarded-For`, `X-Forwarded-Proto` and `X-Forwarded-Host` are set by Bastion, and any the
  client sent are replaced, unless the client is in `trusted_proxies`
  (`forwarded_headers forwarded` sends RFC 7239 `Forwarded` instead, `off` sends neither).
- The request body streams to the upstream as it arrives (`request_buffering on` reads it whole
  first), up to `client_max_body_size` (1m by default: raise it for uploads).
- `connect_timeout` 5s, `read_timeout` and `send_timeout` 60s; a timeout before the response
  starts is a 504, a refused connection a 502.

## Several servers

```conf
upstream app {
    server 10.0.0.11:3000;
    server 10.0.0.12:3000 weight=2;
    server 10.0.0.13:3000 backup;
    balance least_conn;
    keepalive 32;
}
server {
    listen 80;
    proxy app;
}
```

Balancing is smooth weighted round robin by default; `balance least_conn`, `balance peak_ewma`
(latency-aware) and `balance hash $remote_addr consistent` are the alternatives. A `backup`
server takes requests only when no other can. Each worker keeps `keepalive` idle connections per
upstream for reuse.

A host name in `server` is resolved once when the configuration loads and must resolve. With
`server name:port resolve;` and a `resolver`, the helper process looks it up at run time and
follows DNS changes within their TTL; the server starts even while DNS fails.

## Health and failure handling

```conf
upstream app {
    server 10.0.0.11:3000;
    server 10.0.0.12:3000;
    health_check path=/healthz interval=5s fails=3 passes=2;
    passive_eject fails=5 window=10s for=30s;
    retry attempts=1 on=error,timeout budget=20%;
    circuit_breaker max_pending=1000;
}
server {
    listen 80;
    proxy app;
}
```

- `health_check` probes each server from the helper process (once per interval, however many
  workers there are). Without it every server is assumed up.
- `passive_eject` takes a server out after failures of real requests, for every worker at once.
- `retry` tries another server after a failure. It never retries once any byte of the response
  reached the client, and the `budget` caps the extra load retries add during an outage.
- `circuit_breaker` refuses at once (503 with `Retry-After`) rather than queueing past a limit.

When no server is healthy, requests get 503 with `Retry-After` at once (`panic_threshold`
changes that). `bastionctl upstreams` shows each server's state, and `bastionctl upstream drain
app 0` stops new requests to a server before maintenance ([operations](operations.md#the-admin-api)).

## Mixing files and the application

```conf
server {
    listen 80;
    root /srv/www;
    location /api/ { proxy http://127.0.0.1:3000; }
    location /static/ { expires 7d; }
    location / { try_files $uri /index.html; }
}
```

## WebSockets, gRPC and server-sent events

```conf
upstream grpc_backend {
    server 127.0.0.1:50051;
    protocol http2;
}
server {
    listen 443 tls http2;
    tls_cert /etc/bastion/tls/example.com.crt /etc/bastion/tls/example.com.key;
    location /ws/ { proxy http://127.0.0.1:3000; }
    location /events { proxy http://127.0.0.1:3000; response_buffering off; }
    location /helloworld.Greeter/ { proxy grpc_backend; }
}
```

- WebSockets over HTTP/1.1 Upgrade are passed on by default (`websocket on`). For WebSockets
  over HTTP/2 (extended CONNECT, RFC 8441), add `http2_connect_protocol on;` to the server; it is
  off by default. Tunnels have their own idle and maximum durations (`tunnel_idle_timeout`,
  `tunnel_max_duration`).
- gRPC needs an upstream with `protocol http2`; trailers are passed on, and upstream failures
  become a gRPC status for clients that sent `application/grpc`.
- Responses stream to the client as they arrive (`response_buffering` is off by default), so
  server-sent events need nothing special.

## Behind a load balancer or CDN

```conf
real_ip_from 10.0.0.0/8;
real_ip_header X-Forwarded-For;
trusted_proxies 10.0.0.0/8;
server {
    listen 80;
    proxy http://127.0.0.1:3000;
}
```

`real_ip_from` and `real_ip_header` make `$remote_addr` the real client, which access logs, rate
limits and ACLs then use. `trusted_proxies` keeps the balancer's `X-Forwarded-*` values and
appends to them. For a balancer that speaks the PROXY protocol, use `listen 80 proxy_protocol;`
with `proxy_protocol_from`.

## TLS to the upstream

```conf
upstream secure_app {
    server 10.0.0.21:443;
    tls verify on;
    tls sni app.internal.example.com;
    tls ca /etc/bastion/tls/ca.crt;
}
server {
    listen 80;
    proxy secure_app;
}
```

`proxy https://...` or any `tls` line in an upstream turns TLS on. Certificates are verified
against `tls ca` (else the system bundle) and must name `tls sni` (else the server's host as
written); `tls verify off` checks nothing and makes `bastion -t` warn.

Next: cache the application's responses with [caching](caching.md).
