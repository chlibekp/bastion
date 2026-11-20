# DDoS protection

Bastion defends in layers, each cheaper than the one above it. The defaults already cover the
protocol layers; the rest is opt-in, because what counts as abuse depends on the site.
[examples/ddos.conf](../../examples/ddos.conf) combines the pieces below, and the
[threat model](../threat-model.md) says what each layer is and is not meant to stop.

| Layer | Where it acts | On by default |
|---|---|---|
| `xdp {}` | in the network driver, before the kernel's stack | no (needs CAP_BPF and CAP_NET_ADMIN) |
| `limit_conn` | at accept, before TLS | no |
| Protocol budgets (`http2_abuse`, header and body timeouts, `limits`) | per connection | yes |
| `limit_zone` / `limit` | per request, shared by all workers | no |
| `waf_rule` / `waf` | per request, after routing | no |
| `challenge` | per request, a proof-of-work page | no |
| `escalate` | turns repeated refusals into a block at accept | no |

SYN floods are left to the kernel's SYN cookies (`net.ipv4.tcp_syncookies`, which
`bastion doctor` checks): Bastion does not implement its own.

## Already on

Without any configuration, every connection is bounded:

- Slow clients: `client_header_timeout`, `client_body_timeout` and `client_body_min_rate` close
  connections that trickle; `handshake_timeout` (10s) bounds the TLS handshake.
- HTTP/2: budgets against Rapid Reset, MadeYouReset, CONTINUATION, settings, ping and other
  floods (`http2_abuse`) apply even when the block is absent.
- Overload: `limits` caps connections and worker memory, answering 503 with `Retry-After` rather
  than falling over.

## Rate limits

```conf
limit_zone per_ip {
    rate 20/s burst=40;
}
limit_zone login {
    rate 1/s burst=5;
    status 429;
}
server {
    listen 80;
    proxy http://127.0.0.1:3000;
    limit per_ip;
    location /login { limit login per_ip; }
}
```

A zone is a GCRA table in shared memory, so the rate holds across all workers. It counts per
`$remote_addr` by default (IPv6 clients per /64), with keys hashed under a random key so they
cannot be aimed at one slot. Past the burst a request gets 429 with `Retry-After`; `mode delay`
holds requests instead, and `dry_run on` only counts, which is the safe way to choose a rate.

Behind a balancer, set `real_ip_from` and `real_ip_header`
([reverse proxy](reverse-proxy.md#behind-a-load-balancer-or-cdn)), or every client is the
balancer.

## Connection limits

```conf
limit_conn per_ip=100 subnet4=24:500 subnet6=48:500;
server { listen 80; root /srv/www; }
```

Open connections per client and per subnet, across all workers, closed at accept before any TLS
work.

## Escalation to blocks

```conf
limit_zone per_ip {
    rate 20/s burst=40;
    escalate after=50 window=10s block=10m;
}
escalation_allow 192.0.2.10;
server { listen 80; root /srv/www; limit per_ip; }
```

A client refused `after` times within `window` is blocked for `block`: closed at accept, and, with
`xdp {}`, dropped in the driver. Addresses in `escalation_allow` and `real_ip_from` are never
blocked, and `escalation_ceiling` bounds how many blocks exist at once. `bastionctl blocks`,
`bastionctl block` and `bastionctl unblock` manage them by hand
([operations](operations.md#the-admin-api)).

## WAF rules

```conf
waf_rule no_dotfiles {
    match path prefix /.git;
    action deny 404;
}
waf_rule scanners {
    match user_agent contains sqlmap;
    action deny;
}
server {
    listen 80;
    root /srv/www;
    waf no_dotfiles scanners;
}
```

A rule is one or more `match` lines that must all hold and one `action` (`allow`, `deny`, `log`,
`challenge` or `limit <zone>`). The subjects include the path, query, arguments, headers,
cookies, method, client address and the TLS fingerprint (`ja4`). It is a small rule engine for
known-bad requests, not a replacement for a full WAF. [Tuning](../tuning.md#waf-lite-waf_rule-waf)
covers its cost.

## The challenge page

```conf
challenge_auto_rps 2000;
challenge_auto_block_rate 200;
server {
    listen 80;
    root /srv/www;
    challenge auto;
    challenge_allow 203.0.113.0/24;
    location /api/ { challenge off; }
}
```

`challenge on` makes clients without a valid pass solve a small proof-of-work in the browser
before they are served; `auto` does so only while the request or refusal rate is above the
thresholds. Clients that cannot run JavaScript (API clients, monitoring) get a plain 403: list them
in `challenge_allow` or turn the challenge off for their paths. [The challenge](../challenge.md)
describes the protocol, custom pages and keys.

## XDP

```conf
xdp {
    interface eth0;
    syn_rate 200/s burst=400;
    udp_rate 1000/s burst=2000;
    deny_file /etc/bastion/blocklist.txt;
    allow 198.51.100.0/24;
}
server { listen 80; root /srv/www; }
```

The XDP program drops packets in the driver (or the generic hook) before they cost the kernel's
network stack anything: per-source SYN, UDP and packet rates, deny and allow lists, malformed TCP
flags, UDP reflection from amplification ports, and invalid QUIC packets on HTTP/3 ports. Master
loads it; workers never touch it. Without the privileges or kernel support, Bastion logs a
warning and starts without it: every other layer still applies. `mode` chooses native, generic or
offloaded attachment, and `on_exit keep` leaves the filter in place across a restart.

## Watching an attack

- `bastion_under_attack` (gauge) and `bastion_under_attack_total` (activations) in
  [metrics](operations.md#metrics), and each `challenge auto` change in the log.
- `dry_run on` in a zone shows what a limit would refuse before it refuses anything.
- `bastionctl challenge on` forces the challenge on for every `challenge auto` scope, and
  `bastionctl block <addr>` blocks one address for an hour.
