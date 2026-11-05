# Bastion Config Language

Two goals pull against each other: every behaviour must be tunable, and a simple site must take a few lines. The rule that resolves this is **every directive has a safe default, and a few high-level directives imply sensible settings**.

## Simple configs

Static site:

```nginx
server {
    listen 80;
    root /var/www/html;
}
```

HTTPS site with automatic certificates. `tls auto` implies listening on 443 with HTTP/1.1, 2 and 3, listening on 80 for redirects and ACME, and a `Strict-Transport-Security` preset. An explicit `listen` turns that implication off.

```nginx
acme { email admin@example.com; }

server {
    name example.com www.example.com;
    tls auto;
    root /var/www/example;
}
```

Reverse proxy:

```nginx
acme { email admin@example.com; }

server {
    name app.example.com;
    tls auto;
    proxy http://127.0.0.1:3000;
}
```

No config at all, for quick local use:

```sh
bastion serve ./public --port 8080
bastion proxy http://127.0.0.1:3000 --port 8080
```

## Full example

This shows the shape of a detailed config, and is not the complete list. The complete reference is generated from the schema into `docs/config-reference.md`.

```nginx
user bastion;
workers auto;
worker_cpu_affinity auto;
pid /run/bastion.pid;
error_log /var/log/bastion/error.log warn;

io {
    backend auto;                       # auto | uring | epoll
    uring_entries 4096;
    uring_sqpoll off;
    uring_napi off;
    aio_threads 4;
    huge_pages auto;
    numa auto;
}

sandbox {
    seccomp on;                         # on | log | off
    landlock on;
    namespaces on;
    drop_capabilities on;
}

limits {
    max_connections 200000;
    worker_memory 2g;
    escalation_ceiling 1000000;
    overload_status 503;
    overload_retry_after 5s;
}

xdp {
    interface eth0;
    mode auto;                          # auto | native | generic | hw
    allow 10.0.0.0/8;
    deny_file /etc/bastion/deny.txt;
    syn_rate 200/s burst=400;
    udp_rate 2000/s burst=4000;
    drop_reflection on;
    syn_cookies off;                    # off | on | auto
    ipv6_prefix 64;
}

tcp_profile edge {
    fastopen 4096;
    defer_accept 5s;
    busy_poll 50us;
    prefer_busy_poll on;
    congestion bbr;
    notsent_lowat 128k;
    user_timeout 30s;
    keepalive idle=60s interval=10s count=4;
    steering incoming_cpu;              # none | incoming_cpu | ebpf
    backlog 65535;
}

tls_profile modern {
    versions 1.2 1.3;
    groups X25519MLKEM768 X25519 P-256;
    ciphers_tls12 ECDHE-ECDSA-AES128-GCM-SHA256 ECDHE-RSA-AES128-GCM-SHA256;
    ktls tx;                            # off | tx | tx+rx
    tickets rotate=12h keep=3;
    ocsp_stapling on;
    early_data off;
    handshake_timeout 10s;
}

log_format main json {
    time $time_iso8601;
    client $remote_addr;
    request $request_line;
    status $status;
    bytes $bytes_sent;
    duration $request_time;
    ja4 $ja4;
    trace $trace_id;
}

upstream api {
    balance peak_ewma;                  # round_robin | least_conn | hash $key | peak_ewma
    server 10.0.0.1:8080 weight=2;
    server 10.0.0.2:8080;
    server backend.internal:8080 resolve;
    keepalive 256;
    connect_timeout 2s;
    health_check path=/healthz interval=5s fails=3 passes=2;
    passive_eject fails=5 window=30s for=30s;
    retry attempts=2 budget=10% on=connect_error,502,503,504;
    circuit_breaker max_pending=1024 max_active=4096;
    tls verify on;
    protocol http1;                     # http1 | http2
}

cache_store main {
    disk /var/cache/bastion size=50g;
    ram 2g;
    max_object 1g;
    lock_timeout 5s;
}

limit_zone per_ip {
    key $remote_addr;
    rate 100/s burst=200;
    escalate after=20 window=60s block=10m;
}

limit_zone strict_login {
    key $remote_addr;
    rate 5/m burst=10;
}

waf_rule wp_probe {
    match path ~ "^/(wp-admin|wp-login|xmlrpc\.php)";
    action deny 404;
}

server {
    name example.com;
    listen 443 tls http2 http3 tcp_profile=edge;
    listen 80 redirect_https;
    tls_profile modern;
    tls_cert /etc/bastion/example.crt /etc/bastion/example.key;

    access_log /var/log/bastion/access.log main sample=1.0;
    security_headers strict;
    limit per_ip;
    waf wp_probe;
    compress zstd br gzip;

    client_max_body_size 10m;
    client_header_timeout 10s;
    client_body_min_rate 1k/s;

    location / {
        root /var/www/example;
        try_files $uri $uri/ /index.html;
        expires 1h;
    }

    location ^~ /assets/ {
        root /var/www/example;
        expires 1y immutable;
        precompressed on;
    }

    location /api/ {
        proxy api;
        cache main;
        cache_valid 200 10s;
        stale_while_revalidate 30s;
        stale_if_error 1h;
        auth_jwt keys=/etc/bastion/jwks.json alg=ES256 aud=api;
    }

    location = /login {
        challenge auto;
        limit strict_login;
        proxy api;
    }

    location ~ "^/old/(.+)$" {
        redirect 301 /new/$1;
    }
}

metrics { listen 127.0.0.1:9100; }
admin   { socket /run/bastion/admin.sock mode=0600; }
include /etc/bastion/sites/*.conf;
```

## Lexical rules

- Statements are a name followed by arguments and either `;` or a `{ ... }` block.
- Comments run from `#` to end of line, outside of quotes.
- Strings: bare words, `"double"` with `\"`, `\\`, `\n`, `\t` escapes and `$var` expansion, or `'single'` with no processing.
- Sizes: `512`, `16k`, `1m`, `2g`. Durations: `50us`, `10ms`, `30s`, `5m`, `1h`, `1d`. Rates: `100/s`, `1k/s`, `6000/m`.
- `include <glob>` inserts files in sorted order. Relative paths resolve against the including file. Depth limit is 16 and cycles are errors.
- `${ENV_NAME}` and `${ENV_NAME:-default}` expand at parse time. An unset variable with no default is an error.
- UTF-8 BOM and CRLF line endings are accepted.

## Semantic rules

- **Inheritance:** global, then `server`, then `location`. Child scalars replace; lists replace unless a directive says it appends.
- **Location precedence** matches nginx: `=` exact, then longest prefix, where `^~` stops regex search, then regexes in file order (`~` and `~*`), then the longest prefix.
- **Variables:** `$host`, `$uri`, `$request_uri`, `$args`, `$arg_NAME`, `$http_NAME`, `$cookie_NAME`, `$remote_addr`, `$remote_port`, `$scheme`, `$request_method`, `$status`, `$ja4`, `$request_id`, `$trace_id`, regex captures `$1`..`$9`, and others listed in the reference. Templates compile at load. Unknown variables are load-time errors.
- **Errors** carry `file:line:col` and a suggestion: `sites/a.conf:12:5: unknown directive "proxi", did you mean "proxy"?`
- **Strictness:** unknown directives, wrong contexts, and duplicates of a single-value directive are errors. Config that loads but is probably dangerous, such as `tls verify off` on an upstream or `metrics` listening on a public address, yields a warning, visible through `bastion -t`.
- **No silent no-ops:** a directive the running kernel cannot honour either falls back with a logged warning or, when marked `require`, fails the load. Example: `ktls tx require`.

## Schema as single source of truth

Each subsystem registers its directives in a static table:

```c
typedef struct bst_directive {
    const char   *name;
    uint32_t      contexts;      /* bitmask of BST_CTX_* */
    bst_argspec   args;
    const char   *default_value; /* NULL means unset is valid */
    const char   *doc;           /* required, non-empty */
    bst_dir_apply apply;
} bst_directive;
```

The parser, `bastion -T` (print effective config with defaults) and `docs/config-reference.md` all derive from that table. A unit test fails when a directive has no documentation or its default does not parse.
