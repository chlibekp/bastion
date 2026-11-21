# Access control: rate limits, ACLs, WAF rules and authentication

The request-level controls a worker applies before a handler runs: address ACLs, per-client
connection limits, rate limits, WAF rules, authentication, and escalation from repeated refusals
to blocks. [DDoS protection](ddos.md) shows how these layer with XDP and the challenge page;
[the challenge](../challenge.md) documents the proof-of-work page itself.

The client address used by all of these is `$remote_addr`: the peer address, or the address
`real_ip_header` names when the peer is in `real_ip_from`, or the source of a PROXY protocol
header. Behind a load balancer, set those first ([reverse proxy](reverse-proxy.md#behind-a-load-balancer-or-cdn)).

## Order of checks

For each connection, then each request, roughly in this order:

1. Server-level `allow`/`deny` and `limit_conn`, at accept, before TLS: a refused connection is
   closed without a byte.
2. Escalation blocks, at accept and per request.
3. After routing, per request: location `allow`/`deny` (403), `limit` zones, `waf` rules,
   `challenge`, then authentication (`auth_mtls`, `auth_jwt`, `auth_basic`, `auth_forward`).
4. The handler.

## Address ACLs

```conf
server {
    listen 80;
    root /srv/www;
    location /internal/ {
        allow 10.0.0.0/8;
        allow 192.168.0.0/16;
        acl_default deny;
    }
}
```

- `allow` and `deny` take addresses, CIDRs or `all`. Rules are checked in order and the first that
  matches decides; an address no rule matches gets `acl_default` (default `allow`).
- A scope that writes rules replaces the inherited ones.
- Server-level rules apply at accept: the connection is closed before TLS. Location rules apply
  per request and answer 403.
- `allow_file` and `deny_file` read one address or CIDR per line (`#` comments) into a prefix tree
  at load; a million entries load in about a second. A reload re-reads them.

```conf
server {
    listen 80;
    root /srv/www;
    deny_file /etc/bastion/blocklist.txt;
}
```

Refusals are counted in `bastion_acl_denied_total`.

## Connection limits

```conf
limit_conn per_ip=50 subnet4=24:400 subnet6=48:400;
server { listen 80; root /srv/www; }
```

`limit_conn` caps open connections per client across all workers: `per_ip=` per address,
`subnet4=<prefix>:<n>` per IPv4 prefix and `subnet6=<prefix>:<n>` per IPv6 prefix. It is read on a
listener's default server, applies at accept, and closes a connection over the limit before TLS.
Peers in `real_ip_from` are not limited, because their connections carry many clients. Refusals
are counted in `bastion_conn_limit_refused_total`.

## Rate limits

```conf
limit_zone per_ip {
    rate 20/s burst=40;
}
limit_zone login {
    rate 5/m burst=5;
    status 429;
}
server {
    listen 80;
    root /srv/www;
    limit per_ip;
    location /login {
        limit login per_ip;
    }
}
```

A `limit_zone` is a named request rate limit shared by every worker: a lock-free GCRA table in
shared memory. `limit` applies zones to a scope's requests in order; the first that refuses
answers. A scope that names its own list replaces the inherited one, and `limit off` clears it.

| Zone directive | Default | Meaning |
|---|---|---|
| `rate` | required | `<n>/s` or `<n>/m`, with `burst=` (1 when unset): a new key gets `burst` requests at once, then one per 1/rate |
| `key` | `$remote_addr` | what a bucket counts: the client address or any template (`$http_x_api_key`, `$cookie_session`) |
| `ipv6_prefix` | `64` | IPv6 clients are keyed by this prefix, so addresses rotated inside one /64 are one client |
| `mode` | `reject` | `reject`: past the burst, refuse with `status` and `Retry-After`; `delay`: hold up to another burst until each request conforms, refuse past that |
| `status` | `429` | the status of a refused request |
| `size` | `1m` | shared memory of the zone, 16 bytes per key; a full table replaces its least recently due key |
| `dry_run` | `off` | `on`: log and count what would be refused (`bastion_limit_dry_run_total`) but refuse nothing |
| `escalate` | none | turn repeated refusals into a block (see [escalation](#escalation-to-blocks)) |

Keys are hashed with a random SipHash key, so clients cannot aim at one slot. `limit_headers on`
adds the `RateLimit` and `RateLimit-Policy` fields of the first zone to responses.

Start a new limit with `dry_run on`, watch `bastion_limit_dry_run_total` and the log, then turn it
off. Refusals are counted in `bastion_limit_rejected_total`, delays in
`bastion_limit_delayed_total`.

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
waf_rule admin_from_office {
    match path prefix /admin/;
    match ip in_cidr 10.1.0.0/16;
    action allow;
}
waf_rule admin_others {
    match path prefix /admin/;
    action deny;
}
server {
    listen 80;
    root /srv/www;
    waf no_dotfiles scanners admin_from_office admin_others;
}
```

A `waf_rule` has one or more `match` lines, which must all hold, and one `action`. `waf` lists the
rules checked for a scope's requests, in order, after routing and before the handler. A scope that
names its own list replaces the inherited one, and `waf off` clears it. The first rule that matches
with an action other than `log` decides.

`match <subject> <operator> [value]`:

| Subjects | |
|---|---|
| `path` (normalized), `uri`, `query`, `method`, `host`, `protocol`, `tls_version` | the request line and connection |
| `arg:NAME`, `header:NAME`, `cookie:NAME` | one parameter, header or cookie; with repeated values, any matching value decides (any value not matching, for `!=` and `!~`) |
| `content_type`, `content_length`, `user_agent` | common headers |
| `ip` | the client address |
| `ja4` | the TLS fingerprint (needs `tls_ja4 on`) |

| Operators | |
|---|---|
| `=`, `!=` | equal, not equal |
| `~`, `!~` | regex match, no match |
| `prefix`, `suffix`, `contains` | substring tests |
| `in_cidr`, `in_file` | address in a CIDR, value in a file |
| `>`, `<` | numeric comparison |
| `missing`, `exists` | presence, with no value |

| Action | Effect |
|---|---|
| `allow` | skip the remaining rules |
| `deny [status]` | refuse (403 by default) |
| `log` | log the match and go on |
| `challenge` | send the proof-of-work page |
| `limit <zone>` | apply a rate limit zone |

`rule_mode log` in a scope makes its rules only log what they would do (`waf: rule NAME would
...`); `enforce` (the default) acts. Matches are counted in `bastion_waf_matches_total`, denials
in `bastion_waf_denied_total`. [Tuning](../tuning.md#waf-lite-waf_rule-waf) covers costs and the
behaviour when a regex hits its limit. WAF rules are a filter for known-bad requests, not a full
WAF.

## Escalation to blocks

```conf
escalation_allow 192.0.2.10;
limit_zone per_ip {
    rate 20/s burst=40;
    escalate after=50 window=10s block=10m;
}
server {
    listen 80;
    root /srv/www;
    limit per_ip;
}
```

`escalate after=N window=W block=B`, in a `limit_zone`, a `waf_rule` or `http2_abuse`, turns
repeated refusals into a block: when one client (an IPv4 address or an IPv6 prefix) collects `N`
strikes of that rule within `W` across all workers, master blocks it for `B` (window 10s and
block 10m when unset). Blocked clients are closed at accept and refused per request; with
`xdp {}` the block is also written into the XDP block map and enforced in the driver.

Safeguards:

- Only peers that completed a TCP handshake or a validated QUIC path can be escalated, so spoofed
  packets cannot get a victim blocked (`bastion_escalate_ignored_total` counts the rest).
- Addresses in `escalation_allow` and `real_ip_from` are never blocked.
- An address from a PROXY header or `real_ip_header` is not the packet source, so it is blocked
  at L7 only, never in XDP.
- `escalation_ceiling` (default 10000) caps active blocks; past it new blocks are refused and
  counted in `bastion_escalate_refused_total{reason="ceiling"}`.

`bastionctl blocks`, `bastionctl block <addr> --ttl s` and `bastionctl unblock <addr>` list, add
and remove blocks by hand ([admin API](../admin-api.md)). Blocks survive a reload and end with a
restart.

## Authentication

Four mechanisms, valid in `global`, `server` and `location` (`auth_mtls` in `server` and
`location`). `auth_require any` (the default) lets in the first that passes, `all` needs every one
configured in the scope. They are checked in the order `auth_mtls`, `auth_jwt`, `auth_basic`,
`auth_forward`. `$auth_user` holds the user that was let in.

### HTTP Basic authentication

```conf
server {
    listen 80;
    root /srv/www;
    location /admin/ {
        auth_basic "Admin";
        auth_basic_file /etc/bastion/htpasswd;
    }
}
```

The file holds one `user:$argon2id$...` line per user, as [`bastion passwd`](../cli.md#passwd-basic-auth-entries)
prints them:

```
bastion passwd alice | sudo tee -a /etc/bastion/htpasswd
```

Master reads the file at load (a file that cannot be read or parsed fails the load) and keeps it
out of core dumps; a reload re-reads it. Entries weaker than `m=19456` KiB, `t=2` draw a warning.
Password hashes run on the disk thread pool, never on the event loop: `auth_max_concurrent`
(default 16) caps them per worker, and past it a request gets 503 with `Retry-After: 1`.
`auth_cache_ttl` (default 60s) remembers a verified credential per worker, keyed by an HMAC with
a random per-worker key, never the plaintext. A missing or wrong password gets 401 with
`WWW-Authenticate`.

### JWT bearer tokens

```conf
server {
    listen 80;
    location /api/ {
        auth_jwt keys=/etc/bastion/jwt-public.pem alg=ES256 iss=https://login.example.com aud=api;
        auth_jwt_claim_header sub X-User;
        proxy http://127.0.0.1:3000;
    }
}
```

```nginx
auth_jwt keys=<JWKS or PEM file> [alg=ES256,RS256,..] [iss=..] [aud=a,b] [leeway=30s] [header=Authorization | cookie=name];
auth_jwt secret=<file> ...;      # HS256, the only way HS256 is accepted
auth_jwt off;
```

- Allowed algorithms: ES256, ES384, RS256, PS256, EdDSA, and HS256 only with `secret=`. `none` is
  never accepted.
- Keys are picked by `kid`; an unknown `kid` is refused.
- `exp`, `nbf` and `iat` are checked with `leeway`.
- `auth_jwt_required_claim` lists claims a token must carry.
- `auth_jwt_claim_header <claim> <header>` sends a claim upstream in a request header. The
  client's own copies of that header are always removed.
- `$auth_user` is the `sub` claim and `$jwt_claim_NAME` any claim.

### Forward authentication

```conf
upstream auth_service {
    server 127.0.0.1:9091;
}
server {
    listen 80;
    location / {
        auth_forward auth_service path=/verify timeout=2s response_headers=X-User,X-Groups;
        proxy http://127.0.0.1:3000;
    }
}
```

Before the handler, Bastion sends a GET to the auth service with the headers listed in
`pass_headers=` (default `Authorization,Cookie`) and `X-Original-Method`, `X-Original-URI`,
`X-Original-Host` and `X-Original-Proto` (client copies of those are removed). The request body
is not sent.

- 2xx lets the request in, with the `response_headers=` copied onto it (client copies removed).
- 401, 403 and redirects go back to the client with their body.
- A timeout, a refused connection or any other answer is 503. There is no fail-open.

### Client certificates

```conf
server {
    listen 443 tls http2;
    tls_cert /etc/bastion/tls/example.com.crt /etc/bastion/tls/example.com.key;
    tls_client_ca /etc/bastion/tls/ca.crt;
    tls_client_auth optional;
    root /srv/www;
    location /admin/ {
        auth_mtls on;
    }
}
```

`auth_mtls on` requires a verified client certificate (403 without one). Instead of `on`, a list
of subject DNs (in the `$ssl_client_s_dn` form) or DNS SAN names accepts only those. With
`tls_client_auth optional`, the handshake succeeds without a certificate and each location
decides. See [TLS](tls.md#client-certificates-mtls).

### Combining mechanisms

```conf
server {
    listen 443 tls http2;
    tls_cert /etc/bastion/tls/example.com.crt /etc/bastion/tls/example.com.key;
    tls_client_ca /etc/bastion/tls/ca.crt;
    tls_client_auth optional;
    location /api/ {
        auth_mtls on;
        auth_jwt keys=/etc/bastion/jwt-public.pem alg=ES256;
        auth_require any;
        proxy http://127.0.0.1:3000;
    }
}
```

Here a client gets in with either a valid client certificate or a valid token.

## Maintenance mode

```conf
server {
    listen 80;
    root /srv/www;
    maintenance on;
    maintenance_allow 10.0.0.0/8;
    maintenance_retry_after 600s;
}
```

`maintenance on` answers every request with 503 and `Retry-After` (`maintenance_retry_after`,
default 300s), except for peers in `maintenance_allow`. A file path in place of `on` makes that
file (read at load, up to 1 MiB) the HTML page sent. `bastionctl maintenance on|off
[--server name]` switches it at run time, until the next reload.
