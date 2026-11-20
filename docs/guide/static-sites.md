# Static sites

Bastion serves files from disk with `sendfile` (or kTLS over TLS), handles range and conditional
requests, and keeps every lookup below the site's root. This guide builds a site up from the
smallest configuration. [The quickstart](../quickstart.md) has more one-screen recipes, and
[examples/static-site.conf](../../examples/static-site.conf) puts them together.

## The smallest site

```conf
server {
    listen 80;
    root /srv/www;
}
```

A request for `/about/team.html` is answered from `/srv/www/about/team.html`; a request for a
directory (`/about/`) is answered from its `index.html`. For a quick look without a
configuration file, `bastion serve ./public --port 8080` does the same in the foreground.

Defaults that matter for a public site:

| Behaviour | Default | Directive |
|---|---|---|
| Symbolic links below the root | not followed (404) | [`symlinks`](../config-reference.md#symlinks) |
| Names starting with `.` | refused | [`dotfiles`](../config-reference.md#dotfiles) |
| Directory listings | off | [`autoindex`](../config-reference.md#autoindex) |
| Index file | `index.html` | [`index`](../config-reference.md#index) |
| `ETag` | on | [`etag`](../config-reference.md#etag) |
| Compression | off | [`compress`](../config-reference.md#compress) |
| Unknown file type | `application/octet-stream` | [`default_type`](../config-reference.md#default_type) |

A path can never leave the root: `..` is removed when the path is normalised, and files are
opened with `openat2(RESOLVE_BENEATH)`, so the kernel refuses anything that resolves above it.
Workers are sandboxed and can only read the roots the configuration names.

## Several sites on one address

```conf
server {
    listen 80;
    name example.com www.example.com;
    root /srv/www/example;
}
server {
    listen 80;
    name static.example.com;
    root /srv/www/static;
}
server {
    listen 80 default_server;
    return 404;
}
```

A request goes to the server whose `name` matches its `Host`. One that matches none goes to the
`default_server` (else the server with no name, else the first one); `unknown_host 421` or
`unknown_host close` on the default server refuses such requests instead.

## Single-page applications

```conf
server {
    listen 80;
    root /srv/www/app/dist;
    try_files $uri $uri/ /index.html;
    location /assets/ {
        expires 1y immutable;
    }
}
```

`try_files` serves the first argument that exists and re-routes to the last one otherwise, so
client-side routes such as `/settings/profile` load the application. Build tools put a content
hash in asset names, so `expires 1y immutable` is safe for `/assets/`.

## Locations, aliases and redirects

```conf
server {
    listen 80;
    root /srv/www;

    location = /favicon.ico { access_log off; }
    location /downloads/ { alias /srv/www/files/; autoindex on; }
    location ~ \.(bak|old|swp)$ { return 404; }
    location /old-blog/ { return 301 https://blog.example.com/; }

    rewrite ^/post/(\d+)$ /posts/$1.html last;
    error_page 404 /404.html;
    location = /404.html { internal; }
}
```

Locations use nginx's modifiers: `=` is exact, a plain prefix is the longest match, `^~` is a
prefix that stops the regular expression search, `~` and `~*` are regular expressions (PCRE2,
with match and depth limits). Locations nest and inherit from the enclosing one. `alias` replaces
the location's prefix with another directory. `internal` makes a location reachable only through
`try_files` and `error_page`; a client asking for it directly gets 404.

## Compression and pre-compressed files

```conf
server {
    listen 80;
    root /srv/www;
    compress zstd br gzip;
    precompressed on;
}
```

`compress` encodes responses on the fly in the best coding the client accepts, for the types in
`compress_types` (text, JavaScript, JSON, XML and SVG by default) and only above
`compress_min_size`. With `precompressed on`, a sibling `name.zst`, `name.br` or `name.gz` is sent
instead when one exists, which costs no CPU at request time. Responses to range requests are never
compressed.

## Caching headers

```conf
open_file_cache max=10000 ttl=60s;
server {
    listen 80;
    root /srv/www;
    location /assets/ { expires 1y immutable; }
    location / { header_set Cache-Control "no-cache"; }
}
```

`expires` adds `Cache-Control: max-age` and `Expires` to successful and redirect responses.
`header_set` writes any header.
`open_file_cache` keeps open file descriptors and metadata for hot files across requests; it is
global and shared by all servers, and off by default.

## Security headers

```conf
server {
    listen 80;
    root /srv/www;
    security_headers basic;
    server_tokens off;
}
```

`security_headers basic` adds `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`,
`Referrer-Policy: strict-origin-when-cross-origin` and, over TLS, `Strict-Transport-Security:
max-age=31536000`. `strict` is tighter and adds a Content-Security-Policy that most sites must
adjust (`csp`). Each header has its own directive to override it ([`hsts`](../config-reference.md#hsts),
[`csp`](../config-reference.md#csp), [`frame_options`](../config-reference.md#frame_options)).
`security_headers` is off by default. `server_tokens off` keeps the version out of the `Server`
header (it then says only `bastion`).

Next: put the site on HTTPS with [TLS](tls.md).
