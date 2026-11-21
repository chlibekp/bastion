# Configuration

How the configuration file is written, read and checked: syntax, value types, contexts and
inheritance, includes, environment variables, variables in templates, and validation with `-t`
and `-T`. Each directive is described in the generated
[configuration reference](config-reference.md); the [guides](README.md#guides) show how they work
together.

## Where the file is

`bastion` reads `/etc/bastion/bastion.conf` unless `-c <file>` names another. The package installs
a default file there that serves `/usr/share/bastion/html` on port 80 and is kept on upgrade.
`bastion serve <dir>` and `bastion proxy <url>` run without any file ([CLI](cli.md)).

## Syntax

The language looks like nginx's. A file is a list of statements; a statement is a directive name,
zero or more arguments, and either `;` or a block in braces:

```conf
# A comment runs to the end of the line.
workers auto;
user bastion;

server {
    listen 80;
    name example.com www.example.com;
    root /srv/www;

    location /assets/ {
        expires 7d;
    }
}
```

The rules, from `src/config/lexer.h` and `src/config/parser.h`:

- **Words** end at whitespace, `;`, `{`, `}` or a quote. `#` starts a comment only at the start of a
  token, so `a#b` is one word.
- **Double-quoted strings** may contain spaces and newlines. `\"`, `\\`, `\n`, `\t` and `\r` are
  decoded; any other backslash is kept with the next byte, so a regex such as `"\.php$"` works.
  Variables (`$host`) and environment references (`${NAME}`) are expanded inside them.
- **Single-quoted strings** are taken literally: no escapes, no variables, no environment
  expansion.
- A directive name is always a bare word. An empty statement (`;` alone) is an error, and a block
  must close in the file that opened it.
- Lines end with LF or CRLF; a lone CR, a NUL byte or a token over 1 MiB is an error. A UTF-8 BOM
  at the start of a file is skipped.
- Blocks nest at most 64 deep.

## Value types

| Type | Syntax | Examples |
|---|---|---|
| bool | `on` or `off` | `etag on;` |
| size | digits with an optional binary suffix `k` (KiB), `m` (MiB), `g` (GiB) | `512`, `16k`, `1m`, `2g` |
| duration | digits and a unit: `us`, `ms`, `s`, `m` (minutes), `h`, `d`, `y` (365 days) | `100ms`, `30s`, `5m`, `1d` |
| rate | `<count>/s` or `<count>/m`; the count takes `k` (1024) | `20/s`, `6000/m` |
| percent | digits and `%` | `20%` |
| CIDR | an address or a prefix | `10.0.0.0/8`, `2001:db8::/32`, `192.0.2.7` |
| mode | octal file mode | `0600` |

Values are strict: no signs, no fractions, no spaces, and units are case-sensitive. A leading zero
in a multi-digit number is an error (so `0600` is never read as decimal 600), except in a file
mode. A duration always needs its unit: `30` is an error, `30s` is not. Each directive's range is
printed in the reference, for example `<duration 1000..60000000 us>`.

## Contexts

A directive may appear only in certain places, its contexts. `global` is the top level of the
file. The reference lists each directive's contexts.

| Context | Opened by | Holds |
|---|---|---|
| `global` | the file itself | process settings, logging, shared definitions |
| `server` | `server { }` | a virtual server: `listen`, `name`, TLS, locations |
| `location` | `location [= \| ^~ \| ~ \| ~*] pattern { }` in a server or location | per-path settings |
| `upstream` | `upstream <name> { }` | a group of upstream servers and their policies |
| `cache_store` | `cache_store <name> { }` | a disk (and RAM) cache |
| `limit_zone` | `limit_zone <name> { }` | a named rate limit |
| `waf_rule` | `waf_rule <name> { }` | a request rule |
| `log_format` | `log_format <name> json { }` | the fields of a JSON access log format |
| `tls_profile` | `tls_profile <name> { }` | TLS versions, groups, ciphers, tickets, 0-RTT, OCSP, kTLS |
| `tcp_profile` | `tcp_profile <name> { }` | socket options for listeners that name it |
| `http2_abuse` | `http2_abuse { }` in a server | HTTP/2 and HTTP/3 abuse budgets |
| `acme` | `acme { }` | automatic certificates |
| `metrics` | `metrics { }` | the Prometheus endpoint |
| `admin` | `admin { }` | the admin API socket |
| `io` | `io { }` | the I/O backend and its tuning |
| `sandbox` | `sandbox { }` | seccomp, Landlock, capabilities, namespaces |
| `limits` | `limits { }` | per-worker overload protection |
| `xdp` | `xdp { }` | the XDP packet filter |

`io`, `sandbox`, `limits` and `xdp` may appear once. When `io`, `sandbox` or `limits` is absent,
all its defaults apply, and `-T` prints it with them. Named blocks (`upstream`, `tcp_profile`,
`limit_zone`, ...) are repeatable and are referred to by name elsewhere: `proxy app`,
`listen 443 tls tcp_profile=edge`, `limit per_ip`.

## Inheritance

Directives valid in `global`, `server` and `location` inherit downward: a value set at the top
level applies to every server, and a server's value applies to its locations, unless a narrower
scope sets its own. Nested locations inherit from the enclosing location.

Lists follow one rule: **a scope that writes its own list replaces the inherited one**. That
covers `allow`/`deny` rules, `access_log` statements, `limit`, `waf`, `rewrite` rules and similar.
A few directives are documented as adding to the parent's list instead (for example
`proxy_hide_header`, `proxy_pass_header` and the statuses of `error_page`); the reference says so
in each case. Words such as `off` clear an inherited setting where the directive accepts them
(`access_log off`, `limit off`, `waf off`).

```conf
access_log /var/log/bastion/access.log;
server {
    listen 80;
    root /srv/www;
    # This location writes no access log: its own statement replaces the inherited one.
    location /health { access_log off; return 200 "ok\n"; }
}
```

## Servers and locations

**Listeners.** A server needs at least one `listen` (port, `addr:port` or `[v6]:port`), unless it
has `tls auto`, which implies 443 and 80. Flags after the address select the protocol: `tls`,
`http2`, `h2c`, `http3`, `proxy_protocol`, `default_server`, `tcp_profile=<name>`. All servers on
one address must agree on `tls`, `http2` and `h2c`. See [`listen`](config-reference.md#listen).

**Choosing a server.** Servers sharing an address are chosen by the request's `Host`: an exact
`name`, then the longest leading wildcard (`*.example.com`), then the longest trailing wildcard
(`example.*`), then regexes (`~...`) in file order, then the default. The default is the server
with `listen ... default_server`, else the one with no name, else the first. With TLS, the SNI
name picks the certificate (see [TLS](guide/tls.md#certificates-from-files)).

**Choosing a location**, as in nginx (`src/route/location.h`):

1. `=` exact: the whole path equals the pattern. It wins at once.
2. The longest prefix among plain and `^~` patterns. If it is `^~`, it wins at once.
3. Regexes (`~` case-sensitive, `~*` case-insensitive) in file order: the first match wins.
4. Otherwise the longest prefix of step 2.

Once a location is chosen, its nested locations are searched the same way. Matching runs on the
normalized path: percent-decoded, with `.` and `..` segments resolved and (with
`merge_slashes on`, the default) repeated slashes merged.

**Handlers.** A location answers with files (`root`, `alias`, `try_files`, `index`, `autoindex`),
`proxy`, `return`, `redirect` or `redirect_https`. `rewrite` changes the path first; `error_page`
and `try_files` can re-route internally to locations marked `internal`.

## Includes

```nginx
include /etc/bastion/conf.d/*.conf;
include sites/example.conf;
```

`include` splices other files in place, at the top level or inside any block. A relative path is relative to the
directory of the file that includes it. A pattern with `*`, `?` or `[` is a glob: matches are read
in bytewise order (independent of locale), and a glob that matches nothing is not an error (as in
nginx). A file named without a glob must exist. Includes nest at most 16 deep. Errors in an
included file name that file and line.

```conf
server { listen 80; root /srv/www; }
include /etc/bastion/conf.d/*.conf;
```

## Environment variables

`${NAME}` and `${NAME:-default}` expand inside a word or a double-quoted string, never in a
single-quoted one:

```nginx
upstream app { server ${APP_HOST:-127.0.0.1}:${APP_PORT:-3000}; }
```

- An unset variable without a default is an error that names it. An empty value counts as set.
- The default is literal text and is not expanded again.
- Expansion happens after the file is split into tokens, so a value can never add tokens: a `;`,
  `}`, `#`, quote or space in a value stays part of the one argument.
- A `$` that came from an environment value is never a template variable: an environment value
  cannot inject `$host` or any other variable.
- Directive names are never expanded.

`-T` prints the configuration with values expanded, so it can show secrets. Review it before you
share it.

## Variables in templates

Arguments documented as templates (log formats, `return` and `redirect` targets, headers,
`cache_key`, `key` of a `limit_zone`, `balance hash`, `if=` of `access_log`, ...) may use
variables. `$name` is the longest run of letters, digits and `_`; write `$$` or `\$` for a literal
dollar. An unknown variable is a load error, not an empty string.

| Variable | Value |
|---|---|
| `$host` | the request's host, without the port |
| `$uri` | the normalized, decoded path (after rewrites) |
| `$request_uri` | the path and query as the client sent them |
| `$args` | the query string |
| `$arg_NAME` | one query parameter |
| `$http_NAME` | one request header (`$http_user_agent`, `$http_x_forwarded_for`) |
| `$cookie_NAME` | one cookie |
| `$remote_addr`, `$remote_port` | the client address (after `real_ip_header`) and port |
| `$scheme` | `http` or `https` |
| `$request_method` | the method |
| `$status` | the response status |
| `$server_protocol` | the protocol of the request, in access logs |
| `$request_id` | the request ID (see `request_id`) |
| `$auth_user` | the user an auth mechanism let in (`sub` for JWT) |
| `$jwt_claim_NAME` | a claim of the verified JWT |
| `$ssl_protocol`, `$ssl_cipher`, `$ssl_session_reused`, `$ssl_early_data` | TLS details |
| `$ssl_client_verify`, `$ssl_client_s_dn`, `$ssl_client_san_dns`, `$ssl_client_fingerprint` | client certificate details |
| `$ja4` | the JA4 fingerprint of the TLS ClientHello (with `tls_ja4 on`) |
| `$1` to `$9` | groups of the location's or rewrite's regex |
| `$time_iso8601`, `$time_local` | the time, in access logs |
| `$request_time` | how long the request took, in access logs |
| `$body_bytes_sent` | response body bytes, in access logs |
| `$upstream_addr`, `$upstream_status`, `$upstream_response_time` | the upstream that answered |
| `$trace_id`, `$span_id` | the W3C trace context (with `trace_context`) |

The table lists the variables registered in `src/route/vars.c`, `src/ops/logger.c`,
`src/proxy/handler.c` and `src/filters/trace.c`.

## Defaults

Every directive has a default, chosen to be safe, so a short file is a complete configuration.
The [README's first example](../README.md) is a whole HTTPS site in six lines. `-T` prints every
default that applies, so it is the way to see what a short configuration really means.

## Checking a configuration

```
bastion -t -c /etc/bastion/bastion.conf
```

`-t` parses and compiles the file exactly as a start would, probes the I/O backend, prints
warnings and then `configuration ok`, and exits 0; on an error it prints the position and the
problem and exits 1:

```
/etc/bastion/bastion.conf:1:23: unknown directive "rot", did you mean "root"?
```

Warnings point at a valid but risky setting and do not change the exit status:

```
/etc/bastion/bastion.conf:6:11: warning: metrics listen 0.0.0.0:9145 is not a loopback address: metrics are exposed to the network (restrict them with allow or auth_basic)
```

`-t` also opens the files the configuration names (certificates, keys, password files, roots),
because a start would. Run it as the user that starts the server (usually root) so it can read
them. `systemctl reload` and the admin API's `POST /reload` run the same check before they change
anything, and the packaged unit runs it before every start.

`-T` checks the configuration and then prints it in full, with every default and every
environment value expanded. Error messages echo up to 40 bytes of an offending value, after
expansion, so review both before pasting them into a bug report.

`bastion --dump-schema` prints every directive as JSON: name, contexts, argument types and ranges,
default and documentation. The reference is generated from it.

## Common mistakes

| Message | Cause |
|---|---|
| `server has no "listen": add one, for example "listen 8080;"` | a server without `listen` and without `tls auto` |
| `expected a non-zero rate (for example 100/s), got "10r/s"` | nginx's `r/s` unit; Bastion writes `10/s` |
| `"disk" takes at most 1 argument` | a positional value where an option is expected: `disk /var/cache/bastion size=10g;` |
| `unknown directive "...", did you mean "..."?` | a typo, or an nginx directive with another name (see [migrating from nginx](guide/migrating-from-nginx.md)) |
| `tls auto and tls_cert cannot be combined` | one server takes its certificate from ACME or from files, not both |

[Troubleshooting](troubleshooting.md) covers problems at run time.
