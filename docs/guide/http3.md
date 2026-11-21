# HTTP/3 and QUIC

Bastion serves HTTP/3 over QUIC v1 (RFC 9000) and v2 (RFC 9369), using ngtcp2 and nghttp3. HTTP/3
requests go through the same router, handlers, limits and filters as HTTP/1.1 and HTTP/2. This
guide shows how to turn it on, how clients find it, how QUIC packets reach the right worker, and
the settings worth knowing. [conformance.md](../conformance.md#quic-rfc-9000-rfc-9001-rfc-9369)
lists the protocol choices and known deviations.

## Turning it on

An HTTP/3 listener is a `listen` with the `http3` flag. It is a UDP socket, separate from any TCP
listener on the same port, and takes no other transport flag. The server needs a certificate:
`tls_cert` or `tls auto`.

```conf
server {
    name example.com;
    listen 443 tls http2;
    listen 443 http3;
    listen [::]:443 tls http2;
    listen [::]:443 http3;
    tls_cert /etc/bastion/tls/example.com.crt /etc/bastion/tls/example.com.key;
    root /srv/www;
}
```

Open UDP port 443 in the firewall as well as TCP port 443.

With ACME, write the listeners out: `tls auto` on its own opens only TCP 443 and 80 (IPv4), never
an HTTP/3 listener ([TLS](tls.md#http3-ipv6-and-a-redirect-with-acme)).

```conf
acme {
    email admin@example.com;
    challenge tls-alpn-01;
}
server {
    name example.com;
    listen 443 tls http2;
    listen 443 http3;
    tls auto;
    root /srv/www;
}
server {
    name example.com;
    listen 80;
    redirect_https 308;
}
```

## How clients find HTTP/3

Browsers first connect over TCP. Bastion tells them where HTTP/3 is with an `Alt-Svc` field on
HTTP/1.1 and HTTP/2 responses:

```
Alt-Svc: h3=":443"; ma=86400
```

| `alt_svc` | Effect |
|---|---|
| `auto` (default) | advertises the server's first `listen ... http3`, nothing when it has none |
| `off` | no field |
| any other value | sent as written, for example when a load balancer in front listens on another port |

A response whose handler (for example an upstream) sets `Alt-Svc` keeps its own. HTTP/3 responses
carry none. A browser that cannot reach UDP 443 keeps using TCP.

To test from the command line, a curl built with HTTP/3 support can force it:

```
curl --http3-only -sI https://example.com/
```

## Several sites on one address

SNI selects the server, and its certificate, on QUIC as on TCP, so several servers with different
certificates can share one `http3` address. A handshake that names no configured server gets the
default server's certificate. `tls_default_cert` applies to TCP only.

## Routing packets to workers

QUIC is connection-oriented on top of UDP, and a client's address can change in the middle of a
connection (NAT rebinding, Wi-Fi to cellular). Every packet of a connection must still reach the
worker that holds it. Bastion's connection IDs carry the worker's slot, and `quic_routing` decides
how the kernel uses that:

| `quic_routing` | How | Needs |
|---|---|---|
| `ebpf` (default) | master attaches an `sk_reuseport` BPF program that reads the slot out of the destination connection ID, so a client that changes address still reaches its worker | `CAP_BPF` and `CAP_NET_ADMIN` at start |
| `hash` | the kernel spreads datagrams by address and port; a client that changes address lands on another worker, which answers with a stateless reset (migration across workers is not supported) | nothing |

Without the capabilities, `ebpf` logs a warning and Bastion uses `hash`. The packaged systemd unit
grants both. A live upgrade hands the routing maps to the new master, and a rollback takes them
back.

## Address validation and floods

A QUIC server must not keep state for, or send much to, an address it has not validated. A Retry
round trip proves the client owns its address before the server keeps anything:

| `quic_retry` | When a new connection gets a Retry |
|---|---|
| `auto` (default) | while more than `quic_retry_threshold` (default 100) handshakes are half open in the worker, as in a flood of Initials from spoofed sources |
| `always` | every new connection (one extra round trip for everyone) |
| `never` | never on the server's own initiative; a ClientHello split over two Initials that arrive out of order still gets one ([conformance](../conformance.md#choices-and-known-deviations)) |

Other protections:

- `quic_max_connections` (default 10000) caps connections per worker. Past it a new connection is
  refused with `CONNECTION_REFUSED` in one small packet, and no state is kept.
- `quic_handshake_timeout` (10s) abandons a handshake that does not finish.
- `quic_stateless_reset on` answers packets for connections no worker holds (after a restart, or a
  client that moved under `quic_routing hash`) with a stateless reset, always smaller than the
  packet that caused it.
- With `xdp {}`, `quic_check` (on by default) drops datagrams to `http3` ports that cannot be QUIC,
  and `udp_rate` limits datagrams per source ([XDP](xdp.md)).
- The HTTP/2 abuse budgets of `http2_abuse` apply to HTTP/3 too (stream resets, malformed requests),
  counted in `bastion_h2_abuse_total`.

## Settings

All of these go in the `server` block. Defaults suit most sites.

| Directive | Default | Meaning |
|---|---|---|
| `quic_versions` | `v1 v2` | versions served, most preferred first |
| `quic_cc` | `cubic` | congestion controller: `cubic`, `bbr` (BBRv2) or `reno` |
| `quic_idle_timeout` | `30s` | a connection silent this long is freed |
| `quic_handshake_timeout` | `10s` | an unfinished handshake is abandoned |
| `quic_max_connections` | `10000` | connections per worker |
| `quic_max_streams_bidi` | `100` | requests open at once per connection |
| `quic_max_streams_uni` | `3` | unidirectional streams (HTTP/3 needs 3) |
| `quic_initial_max_data` | `1m` | connection-level flow control credit |
| `quic_initial_max_stream_data` | `256k` | stream-level flow control credit |
| `quic_max_udp_payload` | `1452` | the largest UDP payload sent, the ceiling of path MTU discovery |
| `quic_mtu_discovery` | `on` | grow packets from 1200 bytes as probes are acknowledged |
| `quic_pacing` | `on` | spread packets over time at the congestion controller's rate |
| `quic_gso` | `on` | send back-to-back packets as one UDP GSO send of up to 16 datagrams |
| `quic_gro` | `on` | receive coalesced datagrams (UDP GRO) |
| `quic_ecn` | `on` | Explicit Congestion Notification, with path validation |
| `quic_retry` | `auto` | see above |
| `quic_retry_threshold` | `100` | half-open handshakes per worker before `auto` asks for Retry |
| `quic_stateless_reset` | `on` | see above |
| `http3_max_field_section_size` | `16k` | the largest request header section; larger is 431 |
| `http3_qpack_table_size` | `4k` | QPACK dynamic table the client may use; 0 turns it off |
| `http3_qpack_blocked_streams` | `16` | streams that may wait on QPACK updates |

`quic_routing` is a global directive. The [reference](../config-reference.md#quic_cc) has the full
text of each.

## 0-RTT

0-RTT on HTTP/3 follows the server's `tls_profile`, as on TCP: off by default; with
`early_data on`, only `early_data_methods` (GET and HEAD by default) are served from early data,
once per ticket across all workers and across TCP and QUIC. Other requests in early data get
`425 Too Early`. `early_data_max_size` does not limit HTTP/3 0-RTT; QUIC flow control does.

```conf
tls_profile zero_rtt {
    early_data on;
}
server {
    listen 443 tls http2;
    listen 443 http3;
    tls_cert /etc/bastion/tls/example.com.crt /etc/bastion/tls/example.com.key;
    tls_profile zero_rtt;
    root /srv/www;
}
```

## Watching it

`bastion_quic_events_total{kind}` counts QUIC events:

| `kind` | Counts |
|---|---|
| `opened`, `closed` | connections |
| `retry` | Retry packets sent |
| `vn` | Version Negotiation packets sent |
| `reset` | stateless resets sent |
| `refused` | connections refused at `quic_max_connections` |
| `dropped` | datagrams that got no answer (logged at debug level only) |

`bastion_http_requests_total{protocol="http3"}` and
`bastion_http_request_duration_seconds{protocol="http3"}` cover requests
([logging and metrics](logging-and-metrics.md#metrics)).

## Limits

- `tls auto` does not open HTTP/3 or IPv6 listeners by itself: write them out (see above).
- Connection migration across workers needs `quic_routing ebpf`.
- h3spec and quic-interop-runner have not been run against Bastion
  ([conformance](../conformance.md#http3-and-quic-conformance-gates-h3spec-quic-interop-runner-not-executed-so-far)).
