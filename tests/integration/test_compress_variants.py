"""Precompressed files and cached compressed variants (Phase 11, Task 2): `precompressed` siblings
of static files, and the cache store running after compress on the filter chain, keyed by the set
of codings a client accepts rather than its raw Accept-Encoding."""
import gzip
import os
import time

import pytest

from process_util import connect
from test_h1_conn import Reader
from upstream_util import Upstream, ok, wait_until

BODY = b"var app = 'compress me please';\n" * 2000


def get(srv, target, headers="", method="GET"):
    with connect(srv.ports["http"]) as s:
        s.settimeout(30)
        s.sendall(f"{method} {target} HTTP/1.1\r\nHost: localhost\r\n{headers}"
                  f"Connection: close\r\n\r\n".encode())
        return Reader(s).response(head_only=method == "HEAD", timeout=30)


def one(h, name):
    v = h.get(name, [])
    return v[0] if v else None


# ---- precompressed static files ----

@pytest.fixture
def www(tmp_path):
    w = tmp_path / "www"
    w.mkdir()
    (w / "app.js").write_bytes(BODY)
    br = b"\x1b-brotli-stand-in-" * 10  # never decoded by the server: any bytes do
    (w / "app.js.br").write_bytes(br)
    (w / "app.js.gz").write_bytes(gzip.compress(BODY))
    old = time.time() - 3600
    os.utime(w / "app.js", (old, old))
    os.utime(w / "app.js.br", (old + 10, old + 10))
    os.utime(w / "app.js.gz", (old + 10, old + 10))
    return w


@pytest.fixture
def static(bastion, www):
    return bastion(f"workers 1;\nserver {{ listen 127.0.0.1:@HTTP_PORT@; root {www}; "
                   f"precompressed on; }}\n")


def test_precompressed_served(static, www):
    st, h, body = get(static, "/app.js", "Accept-Encoding: br, gzip\r\n")
    assert st == 200 and one(h, "content-encoding") == "br"
    assert body == (www / "app.js.br").read_bytes()
    assert one(h, "content-type").startswith(("application/javascript", "text/javascript"))
    assert "accept-encoding" in ",".join(h.get("vary", [])).lower()
    st, h, body = get(static, "/app.js", "Accept-Encoding: gzip\r\n")
    assert one(h, "content-encoding") == "gzip" and gzip.decompress(body) == BODY


def test_identity_client(static):
    st, h, body = get(static, "/app.js")
    assert st == 200 and body == BODY and "content-encoding" not in h
    assert "accept-encoding" in ",".join(h.get("vary", [])).lower()


def test_precompressed_stale(static, www):
    old = time.time() - 7200  # .br now older than the original: ignored
    os.utime(www / "app.js.br", (old, old))
    st, h, body = get(static, "/app.js", "Accept-Encoding: br\r\n")
    assert st == 200 and "content-encoding" not in h and body == BODY


def test_precompressed_direct_request(static, www):
    st, h, body = get(static, "/app.js.br", "Accept-Encoding: br\r\n")
    assert st == 200 and body == (www / "app.js.br").read_bytes()
    assert "content-encoding" not in h  # a plain file, not an encoded app.js
    assert not (one(h, "content-type") or "").startswith(("application/javascript", "text/javascript"))


def test_precompressed_range(static, www):
    raw = (www / "app.js.gz").read_bytes()
    st, h, body = get(static, "/app.js", "Accept-Encoding: gzip\r\nRange: bytes=0-9\r\n")
    assert st == 206 and body == raw[:10] and one(h, "content-encoding") == "gzip"
    assert one(h, "content-range") == f"bytes 0-9/{len(raw)}"
    # If-Range with the identity file's validator does not match the variant: the full variant
    _, hi, _ = get(static, "/app.js")
    st, h, body = get(static, "/app.js",
                      f"Accept-Encoding: gzip\r\nRange: bytes=0-9\r\nIf-Range: {one(hi, 'etag')}\r\n")
    assert st == 200 and body == raw


# ---- cached compressed variants ----

@pytest.fixture
def up():
    u = Upstream()
    yield u
    u.close()


def stored_objects(srv):
    """Committed cache objects on disk (temp files excluded)."""
    root = os.path.join(srv.workdir, "cache")
    n = 0
    for d, _, files in os.walk(root):
        if os.path.relpath(d, root).split(os.sep)[0] != "tmp":
            n += len(files)
    return n


def cache_conf(up, loc=""):
    return (f"workers 1;\ncache_store main {{ disk @WORKDIR@/cache size=100m; }}\n"
            f"server {{ listen 127.0.0.1:@HTTP_PORT@;\n"
            f"location / {{ proxy {up.url}; cache main; purge_method_allow 127.0.0.1/32; "
            f"compress zstd br gzip; compress_types text/plain; {loc} }} }}\n")


def plain(r, c):
    return ok(BODY, 200, (("Cache-Control", "max-age=60"), ("Content-Type", "text/plain")))


def test_variant_cached(bastion, up):
    up.handler = plain
    srv = bastion(cache_conf(up))
    st, h, b1 = get(srv, "/v", "Accept-Encoding: gzip\r\n")
    assert st == 200 and one(h, "content-encoding") == "gzip" and gzip.decompress(b1) == BODY
    assert "stored" in one(h, "cache-status")
    st, h, b2 = get(srv, "/v", "Accept-Encoding: gzip\r\n")
    # a hit of the stored compressed bytes: not compressed again (the very same bytes)
    assert one(h, "cache-status").startswith("bastion; hit"), h
    assert one(h, "content-encoding") == "gzip" and b2 == b1
    assert len(up.requests) == 1


def test_identity_variant(bastion, up):
    up.handler = plain
    srv = bastion(cache_conf(up))
    get(srv, "/i", "Accept-Encoding: gzip\r\n")
    st, h, body = get(srv, "/i")  # no Accept-Encoding: its own variant, identity
    assert st == 200 and body == BODY and "content-encoding" not in h


def test_variant_cardinality(bastion, up):
    up.handler = plain
    srv = bastion(cache_conf(up))
    codings = ["gzip", "br", "zstd", "deflate", "identity", "x-custom"]
    for i in range(1000):
        ae = f"{codings[i % 6]};q=0.{(i % 9) + 1}, {codings[(i // 6) % 6]}, tok{i}"
        fetched, stored = len(up.requests), stored_objects(srv)
        st, _, _ = get(srv, "/card", f"Accept-Encoding: {ae}\r\n")
        assert st == 200
        if len(up.requests) > fetched:
            # a fill is visible once its write on the I/O pool is done (eventual visibility)
            wait_until(lambda: stored_objects(srv) > stored, 5)
    # one entry per accepted subset of zstd, br, gzip at most, never one per string
    assert len(up.requests) <= 8, len(up.requests)


def test_upstream_encoded(bastion, up):
    gz = gzip.compress(BODY)
    up.handler = lambda r, c: ok(gz, 200, (("Content-Type", "text/plain"),
                                           ("Content-Encoding", "gzip"),
                                           ("Cache-Control", "max-age=60")))
    srv = bastion(cache_conf(up))
    st, h, body = get(srv, "/enc", "Accept-Encoding: zstd, gzip\r\n")
    assert one(h, "content-encoding") == "gzip" and body == gz  # passed through as received


def test_purge_all_variants(bastion, up):
    up.handler = plain
    srv = bastion(cache_conf(up))
    for ae in ("gzip", "br", ""):
        get(srv, "/p", f"Accept-Encoding: {ae}\r\n" if ae else "")
    n = len(up.requests)
    st, _, _ = get(srv, "/p", method="PURGE")
    assert st == 200
    for ae in ("gzip", "br", ""):
        _, h, _ = get(srv, "/p", f"Accept-Encoding: {ae}\r\n" if ae else "")
        assert not one(h, "cache-status").startswith("bastion; hit"), ae
    assert len(up.requests) == n + 3


def test_variants_off_stores_identity_only(bastion, up):
    up.handler = plain
    srv = bastion(cache_conf(up, "cache_compressed_variants off;"))
    get(srv, "/o", "Accept-Encoding: gzip\r\n")
    _, h, _ = get(srv, "/o", "Accept-Encoding: gzip\r\n")
    assert not one(h, "cache-status").startswith("bastion; hit")
