# Migrating from nginx

Bastion's configuration language looks like nginx's on purpose: blocks in braces, directives ending
in `;`, `server` and `location` with the same matching rules, and many directives with the same
name. It is not a drop-in replacement: there is no `http {}` or `events {}` wrapper, several
directives are named differently, and some nginx features have no counterpart. `bastion -t`
reports the file, line and column of anything it does not accept.

## Structure

nginx:

```
events { worker_connections 1024; }
http {
    include mime.types;
    server {
        listen 443 ssl;
        http2 on;
        server_name example.com;
        ssl_certificate     /etc/ssl/example.com.crt;
        ssl_certificate_key /etc/ssl/example.com.key;
        root /srv/www;
    }
}
```

Bastion:

```conf
server {
    listen 443 tls http2;
    name example.com;
    tls_cert /etc/bastion/tls/example.com.crt /etc/bastion/tls/example.com.key;
    root /srv/www;
}
```

- `http {}` and `events {}` do not exist: what nginx puts in `http {}` goes at the top level.
- MIME types are built in (`types` adds or overrides them), so there is no `mime.types` include.
- HTTP/2 is a flag of `listen` (with `tls`, or `h2c` for cleartext), and so is HTTP/3 (`http3`).
- The certificate and key are one directive.

## Directive table

| nginx | Bastion | Notes |
|---|---|---|
| `worker_processes auto` | `workers auto` | |
| `user www-data` | `user bastion` | master stays root; workers and the helper drop to it |
| `pid /run/nginx.pid` | `pid /run/bastion/bastion.pid` | |
| `worker_rlimit_nofile` | `worker_rlimit_nofile` | |
| `worker_cpu_affinity` | `worker_cpu_affinity` | `auto` pins workers to CPUs |
| `worker_connections` | `max_connections` | in the `limits {}` block, per worker |
| `error_log file level` | `error_log` | same form; levels debug to error |
| `access_log file format` | `access_log` | also `sample=`, `errors_only=`, `if=` |
| `log_format name '...'` | `log_format` | `log_format name text "..."` or `json { ... }`; values are always escaped |
| `include` | `include` | globs work |
| `server_name` | `name` | exact, `*.example.com`, and `~` regular expressions |
| `listen 80 default_server` | `listen` | `listen 80 default_server` |
| `listen 443 ssl` + `http2 on` | `listen` | `listen 443 tls http2` |
| `listen 443 quic` | `listen` | `listen 443 http3` |
| `listen ... proxy_protocol` | `listen` | plus `proxy_protocol_from`, which is required |
| `ssl_certificate` + `ssl_certificate_key` | `tls_cert` | one directive, certificate then key; give it twice for RSA and ECDSA |
| `ssl_protocols` | `versions` | in a `tls_profile` block; only 1.2 and 1.3 exist |
| `ssl_ciphers` | `ciphers_tls12` | in a `tls_profile`; `ciphersuites_tls13` for TLS 1.3 |
| `ssl_ecdh_curve` | `groups` | in a `tls_profile` |
| `ssl_session_tickets` | `tickets` | in a `tls_profile`; keys rotate by themselves |
| `ssl_stapling on` | `ocsp_stapling` | in a `tls_profile`; the helper fetches responses |
| `ssl_early_data on` | `early_data` | in a `tls_profile`; replay-limited to `early_data_methods` |
| `ssl_client_certificate` | `tls_client_ca` | |
| `ssl_verify_client` | `tls_client_auth` | `optional` or `required`; `auth_mtls` per location |
| certbot or acme.sh | `tls auto` | with an `acme {}` block; issuance and renewal are built in |
| `root` | `root` | |
| `alias` | `alias` | |
| `index` | `index` | |
| `try_files` | `try_files` | same arguments, `=404` included |
| `autoindex on` | `autoindex` | `autoindex_format` for JSON |
| `error_page` | `error_page` | |
| `internal` | `internal` | |
| `return 301 url` | `return` | |
| `rewrite regex repl last` | `rewrite` | `last` and `break`; PCRE2 |
| `return 301 https://$host$request_uri` | `redirect_https` | |
| `expires` | `expires` | `expires 1y immutable` |
| `etag` | `etag` | |
| `default_type` | `default_type` | |
| `types {}` | `types` | |
| `client_max_body_size` | `client_max_body_size` | |
| `client_header_timeout` | `client_header_timeout` | |
| `client_body_timeout` | `client_body_timeout` | plus `client_body_min_rate` against slow uploads |
| `keepalive_timeout` | `keepalive_timeout` | |
| `keepalive_requests` | `keepalive_requests` | |
| `send_timeout` | `send_timeout` | |
| `server_tokens off` | `server_tokens` | |
| `add_header` | `header_add` | `header_set` replaces; `always` for error responses too |
| `more_clear_headers` / `proxy_hide_header` | `header_remove` | `proxy_hide_header` exists as well |
| `gzip on` | `compress` | `compress zstd br gzip`; types and minimum size as `compress_types`, `compress_min_size` |
| `gzip_static on` | `precompressed` | also `.br` and `.zst` siblings |
| `open_file_cache` | `open_file_cache` | global only |
| `sendfile` | `sendfile` | on by default |
| `proxy_pass http://u` | `proxy` | `proxy http://host:port` or `proxy <upstream name>` |
| `upstream {}` | `upstream` | `server host:port weight= max_conns= backup` |
| `least_conn` | `balance` | `balance least_conn`; also `hash`, `peak_ewma` |
| `hash $key consistent` | `balance` | `balance hash $key consistent` |
| `keepalive` (in upstream) | `keepalive` | idle connections per worker |
| `max_fails` / `fail_timeout` | `passive_eject` | `passive_eject fails=5 window=10s for=30s` |
| nginx Plus `health_check` | `health_check` | active checks from the helper process |
| `proxy_next_upstream` | `retry` | with a retry budget |
| `proxy_connect_timeout` | `connect_timeout` | in the `upstream` block |
| `proxy_read_timeout` | `read_timeout` | in the `upstream` block |
| `proxy_set_header Host` | `proxy_host` | |
| `proxy_set_header X-...` | `request_header_set` | the `X-Forwarded-*` set is `forwarded_headers` |
| `proxy_buffering` | `response_buffering` | off by default: responses stream |
| `proxy_request_buffering` | `request_buffering` | off by default |
| `proxy_ssl_verify` | `tls` | `tls verify on` in the upstream, with `tls ca` and `tls sni` |
| `set_real_ip_from` | `real_ip_from` | |
| `real_ip_header` | `real_ip_header` | |
| `proxy_cache_path` | `cache_store` | `cache_store name { disk /path size=10g; }` |
| `proxy_cache` | `cache` | |
| `proxy_cache_valid` | `cache_valid` | |
| `proxy_cache_key` | `cache_key` | |
| `proxy_cache_bypass` | `cache_bypass` | |
| `proxy_cache_lock` | `lock` | in the `cache_store`; on by default |
| `proxy_cache_use_stale` | `stale_if_error` | and `stale_while_revalidate` |
| `limit_req_zone` | `limit_zone` | a block: `rate 10/s burst=20;` |
| `limit_req zone=z` | `limit` | `limit z` |
| `limit_conn_zone` + `limit_conn` | `limit_conn` | `limit_conn per_ip=20` |
| `allow` / `deny` | `allow` | and `deny`; `acl_default deny` to refuse the rest |
| `auth_basic` | `auth_basic` | |
| `auth_basic_user_file` | `auth_basic_file` | argon2id lines from `bastion passwd`, not crypt or apr1 |
| `auth_request` | `auth_forward` | |
| `stub_status` | `metrics` | a `metrics {}` block: Prometheus text on its own listener |

## What is different

- No `if` and no `map`. Conditions are expressed with locations, `try_files`, templates that
  count as true when non-empty and not `0` (`cache_bypass`, `access_log if=`) and `waf_rule`
  matches.
- No `set`, no embedded scripting (Lua, njs) and no dynamic modules.
- No `stream {}`: Bastion is an HTTP server. TCP and UDP proxying are out of scope.
- No `mail {}`.
- Regular expressions are PCRE2 with match and depth limits, so a hostile input cannot make a
  location match run away.
- Workers are sandboxed (seccomp, Landlock, optional namespaces): they cannot read outside the
  roots the configuration names, open certificate keys or start programs. A setup that relied on
  workers reading arbitrary files needs `extra_read`.
- Symbolic links below a root are not followed by default (`symlinks off`), and dotfiles are
  refused (`dotfiles deny`).
- Reload is a re-execution of master in the same PID: `kill -HUP` or `systemctl reload` as
  before, see [operations](operations.md#reload).

## Checking a translated configuration

```sh
bastion -t -c bastion.conf
bastion -T -c bastion.conf   # the effective configuration, environment variables expanded
```

`-T` can show secrets taken from the environment: review its output before sharing it. The
[configuration reference](../config-reference.md) lists every directive with its default.
