# Compression

Bastion compresses responses on the fly with zstd, Brotli or gzip, and can send pre-compressed
files from disk instead. Compression is off by default. It applies to every handler (static
files, proxied responses, cached responses, `return` bodies) and every protocol.

## On-the-fly compression

```conf
server {
    listen 80;
    root /srv/www;
    compress zstd br gzip;
}
```

`compress` lists the codings the server may use. For each response Bastion picks the coding by
the client's `Accept-Encoding`: highest q-value first, then the server's order zstd, br, gzip. A
client that accepts none of them gets the response as it is.

A response is sent as it is when:

- it is already encoded (it has a `Content-Encoding`), or marked `Cache-Control: no-transform`;
- it answers a `Range` request, a `HEAD`, or is a 204 or a 304;
- its length is known and smaller than `compress_min_size` (256 bytes by default);
- its `Content-Type` is not in `compress_types`, or it has no `Content-Type`;
- the worker already runs `compress_max_concurrent` compressed streams (1024), or the compressor
  does not fit in `worker_memory`;
- it is a request with `Cookie` or `Authorization`, or a response that sets a cookie, and
  `compress_sensitive` is off (the default; see [BREACH](#breach-and-compress_sensitive)).

A compressed response loses its `Content-Length` (it is sent chunked on HTTP/1.1, or framed by
the protocol on HTTP/2 and HTTP/3), gets `Vary: Accept-Encoding`, and its `ETag` becomes weak.

## Settings

| Directive | Default | Meaning |
|---|---|---|
| `compress` | `off` | the codings to use, any of `zstd`, `br`, `gzip`, or `off` |
| `compress_types` | `text/html text/css text/plain text/javascript application/javascript application/json application/xml image/svg+xml` | media types compressed, matched without parameters; `text/*` matches every text type |
| `compress_min_size` | `256` | smaller responses of known length are not compressed |
| `compress_level_zstd` | `3` | 1 (fastest) to 19 |
| `compress_level_br` | `4` | 0 to 11; above 6 costs much CPU for little gain on the fly |
| `compress_level_gzip` | `5` | 1 to 9 |
| `compress_window` | `15` | log2 of the window in bytes (10 to 24): memory per stream against ratio; gzip uses at most 15 |
| `compress_max_concurrent` | `1024` | compressed streams per worker; past it responses go uncompressed |
| `compress_sensitive` | `off` | see below |

All of them are valid in `global`, `server` and `location` and inherit downward.

```conf
compress zstd br gzip;
compress_types text/* application/javascript application/json application/xml image/svg+xml application/wasm;
compress_level_br 5;
server {
    listen 80;
    root /srv/www;
    location /downloads/ {
        compress off;
    }
}
```

## Pre-compressed files

```conf
server {
    listen 80;
    root /srv/www;
    precompressed on;
}
```

With `precompressed on`, a request for `app.js` from a client that accepts Brotli is answered with
`app.js.br` when that file exists. Bastion looks for `name.zst`, `name.br` and `name.gz` in the
client's order of preference, then zstd, br, gzip. The response carries `Content-Encoding`,
`Vary: Accept-Encoding` and the original file's `Content-Type`, and is sent zero-copy like any file.

- A sibling older than the original is ignored, so a stale `.br` is never served after the
  original changed.
- Ranges apply to the encoded bytes.
- A request for `app.js.br` by its own name serves it as a plain file.

Produce the siblings at build time, at the highest levels, for example `zstd -19`, `brotli -q 11`
and `gzip -9`. `precompressed` and `compress` work together: a file with a sibling is sent
pre-compressed, a file without one is compressed on the fly when it qualifies.

## Compression and the cache

With `cache_compressed_variants on` (the default), a response compressed on the fly is stored
compressed, one variant per set of codings the client accepts, so a cache hit is not compressed
again. The filter order is upstream, compress, cache store. `Accept-Encoding` is never part of the
cache key as received. With `off`, compressed responses are not stored; only identity responses
are. See [caching](caching.md).

## BREACH and `compress_sensitive`

When a response body holds a secret (a CSRF token, a session value) next to text an attacker can
choose (a reflected query parameter), the compressed length reveals how much of the attacker's
text matches the secret, and the secret can be recovered byte by byte (the BREACH attack). So by
default Bastion does not compress responses to requests that carry `Cookie` or `Authorization`,
nor responses that set a cookie.

`compress_sensitive on` compresses them too. Turn it on only where responses to authenticated
requests contain no secrets that an attacker could guess at, or in locations that serve only
public assets:

```conf
server {
    listen 80;
    root /srv/www;
    compress zstd br gzip;
    location /assets/ {
        compress_sensitive on;
    }
}
```

## Checking it

```
curl -s -o /dev/null -D - -H 'Accept-Encoding: zstd, br, gzip' http://localhost/
```

Look for `Content-Encoding` and `Vary: Accept-Encoding` in the answer. The integration tests that
cover this are `tests/integration/test_compress.py` and `test_compress_variants.py`.
