# Quickstart

Serve a directory in one command:

```sh
bastion serve ./public --port 8080
curl -i http://127.0.0.1:8080/
```

`serve` builds a configuration with a single `root` and runs in the foreground. Stop it with
TERM or INT.

## A static site

Every `conf` block below is checked by `bastion -t` in `tests/integration/test_quickstart.py`.

```conf
workers auto;
server {
    listen 127.0.0.1:8080;
    root /srv/www;
    index index.html;
}
```

Check it before you start it:

```sh
bastion -c bastion.conf -t
bastion -c bastion.conf
```

## Single-page app fallback

```conf
server {
    listen 127.0.0.1:8080;
    root /srv/www;
    try_files $uri $uri/ /index.html;
}
```

## Directory listing

```conf
server {
    listen 127.0.0.1:8080;
    root /srv/www;
    location /files/ {
        autoindex on;
        autoindex_format json;
    }
}
```

Listings are streamed and not sorted. Dotfiles and symlinks are hidden unless allowed.

## Custom error pages

```conf
server {
    listen 127.0.0.1:8080;
    root /srv/www;
    error_page 404 /404.html;
    error_page 500 502 503 504 /50x.html;
    location /50x.html {
        internal;
    }
}
```

## Cache and range behaviour

```conf
open_file_cache max=1000 ttl=60s;
server {
    listen 127.0.0.1:8080;
    root /srv/www;
    etag on;
    max_ranges 10;
    expires 1h;
}
```

`open_file_cache` is global: workers share one cache across all servers.

Range requests (`Range: bytes=0-99`), conditional requests (`If-None-Match`,
`If-Modified-Since`, `If-Range`) and `HEAD` are handled by the static handler.

## Safety defaults

Files are resolved below the root with `openat2` (`RESOLVE_BENEATH`). `symlinks` defaults to
`off` and `dotfiles` to `deny`. Workers run sandboxed: they can read only the serving roots.

See `docs/config-reference.md` for every directive.
