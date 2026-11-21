# Caching

Bastion can keep the responses of `proxy` in a shared HTTP cache (RFC 9111), on disk with an
optional RAM tier, so repeated requests are answered without the application. Static files
served from `root` are not cached this way: they come from the page cache, and
`open_file_cache` keeps their metadata ([static sites](static-sites.md#caching-headers)).
[examples/caching-proxy.conf](../../examples/caching-proxy.conf) is a complete example.

## A cache in front of an application

```conf
cache_store main {
    disk /var/cache/bastion size=10g;
    ram 256m;
}
server {
    listen 80;
    proxy http://127.0.0.1:3000;
    cache main;
}
```

- `disk` is required: the directory (made at start if missing, owned by `user`) and its size
  limit. Objects are written to a temporary file and renamed into place, so a crash never leaves a
  partial object, and the helper process removes the least recently used ones to stay under size.
- `ram` adds a per-worker memory tier in front of the disk, scan resistant so a crawl does not
  push out the popular objects. It is off (`0`) by default.
- The cache is off unless a scope says `cache <store>`, and `cache off` turns it off again in a
  location.

## What is stored, and for how long

The cache follows the application's headers: `Cache-Control` (`s-maxage`, `max-age`, `private`,
`no-store`, `no-cache`), `CDN-Cache-Control`, `Expires`, `Vary`, `ETag` and `Last-Modified`. By
default:

- Only `GET` responses are stored; `HEAD` is answered from them (`cache_methods`).
- A response with `Set-Cookie` is passed through uncached (`cache_cookies_policy strip` stores it
  without the cookie instead).
- A response with no freshness information of its own is stored only with heuristic freshness (a
  `200` with `Last-Modified`), never an error. `cache_valid` gives such responses a lifetime.
- The key is `$scheme$host$request_uri` (`cache_key`).
- Only complete responses are stored; one cut short or failed never is. Objects above
  `max_object` (1g) pass through.
- Each response carries `Cache-Status` (RFC 9211), for example `bastion; hit; ttl=120` or
  `bastion; fwd=miss`.

```conf
cache_store main { disk /var/cache/bastion size=10g; }
server {
    listen 80;
    proxy http://127.0.0.1:3000;
    cache main;
    cache_valid 200 301 10m;
    cache_valid 404 1m;
    cache_bypass $cookie_session $http_authorization;
    location /api/ { cache off; }
}
```

`cache_bypass` skips the lookup when any template is non-empty and not `0` (the fresh response may
still be stored): logged-in users then always see live pages.

## Stale content and stampedes

```conf
cache_store main {
    disk /var/cache/bastion size=10g;
    lock on;
    lock_timeout 5s;
}
server {
    listen 80;
    proxy http://127.0.0.1:3000;
    cache main;
    stale_while_revalidate 30s;
    stale_if_error 1h;
}
```

- `lock` (on by default): when many requests miss on one key at once, one of them, in any worker,
  fetches it and the others wait for the stored object.
- `stale_while_revalidate`: a slightly stale response is served at once while one background
  request refreshes it.
- `stale_if_error`: a stale response is served when the application fails (5xx, refused, timed
  out), so an outage does not take the site down with it.

Both are 0 by default; a response's own `stale-while-revalidate` and `stale-if-error` count when
longer.

## When a new object becomes visible

Objects are written to disk on a pool of I/O threads, never on the event loop, so a slow disk does
not hold up other requests. A freshly fetched response is therefore served from the cache only
once its write has finished, a little after the client that caused the fill got it (as in nginx).
Until then a request for it waits for the write when it reaches the worker that is writing the object, and
may go to the application when it reaches another worker. `write_queue_max` bounds how far the disk may
fall behind; a fill further behind is dropped and logged, never buffered without limit.

A stop does not lose objects: a fast stop (TERM, INT) drops connections but lets every write
already queued finish, and a graceful stop (QUIT) does the same once its requests are done.
After a restart the startup scan finds those objects again.

## Purging

```conf
cache_store main { disk /var/cache/bastion size=10g; }
server {
    listen 80;
    proxy http://127.0.0.1:3000;
    cache main;
    purge_method_allow 127.0.0.1/32 10.0.0.0/8;
}
```

From an address in `purge_method_allow`, a `PURGE` request removes:

```sh
curl -X PURGE http://127.0.0.1/products/42             # that URL
curl -X PURGE -H 'Purge-Scope: host' http://127.0.0.1/ # everything of the request's host
curl -X PURGE -H 'Purge-Tag: product-42' http://127.0.0.1/
```

Tags come from the application's `Cache-Tag` response field (`cache_tag_header`), which is removed
before the response reaches clients. Anyone else gets 403.

The admin API purges by tag, by host or everything, but not by URL:

```sh
bastionctl purge --tag product-42
bastionctl purge --host example.com
bastionctl purge --all
```

A purge is one write that every worker sees at once, and it survives a restart.

## Watching the cache

`Cache-Status` on each response says what happened, and [metrics](operations.md#metrics) count
requests. `bastionctl config` lists the cache stores.
