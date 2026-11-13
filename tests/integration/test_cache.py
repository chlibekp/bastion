"""The HTTP cache in front of the proxy (Phase 10, Task 5): hits and misses with Cache-Status
(RFC 9211), Age, what goes in the key, Vary, what is never stored, HEAD, Range and conditionals
from storage, revalidation, invalidation, and the fill never storing a partial response."""
import shutil
import socket
import subprocess
import threading
import time

import pytest

from quic_util import h3
from upstream_util import Upstream, ok, wait_until


@pytest.fixture
def up():
    u = Upstream()
    yield u
    u.close()


def conf(up, extra="", loc="", store="", glob=""):
    return (f"workers 1;\n{glob}\ncache_store main {{ disk @WORKDIR@/cache size=100m; {store} }}\n"
            f"server {{ listen 127.0.0.1:@HTTP_PORT@; {extra}\n"
            f"location / {{ proxy {up.url}; cache main; {loc} }} }}\n")


def parse(raw):
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split()[1]) if lines and lines[0] else 0
    hdrs = {}
    for ln in lines[1:]:
        k, _, v = ln.partition(":")
        hdrs.setdefault(k.strip().lower(), v.strip())
    if "content-length" in hdrs:
        body = body[:int(hdrs["content-length"])]
    return status, hdrs, body


def req(srv, path="/", host="localhost", extra="", method="GET", body=b""):
    s = socket.create_connection(("127.0.0.1", srv.ports["http"]), 10)
    cl = f"Content-Length: {len(body)}\r\n" if body or method == "POST" else ""
    s.sendall(f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n{extra}{cl}Connection: close\r\n\r\n".encode()
              + body)
    out = b""
    s.settimeout(10)
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            out += d
    except OSError:
        pass
    s.close()
    return parse(out)


def counting(body=b"hello", headers=(("Cache-Control", "max-age=60"),), status=200):
    def h(r, c):
        return ok(body if not callable(body) else body(r), status, headers)
    return h


def test_hit_miss(bastion, up):
    up.handler = counting()
    srv = bastion(conf(up))
    st, h, b = req(srv, "/a")
    assert st == 200 and b == b"hello"
    assert h["cache-status"].startswith("bastion; fwd=miss; stored"), h
    st, h, b = req(srv, "/a")
    assert st == 200 and b == b"hello"
    assert h["cache-status"].startswith("bastion; hit; ttl="), h
    assert len(up.requests) == 1, "the second request reached the upstream"


def test_age_header(bastion, up):
    up.handler = counting(headers=(("Cache-Control", "max-age=60"), ("Age", "10")))
    srv = bastion(conf(up))
    req(srv, "/age")
    time.sleep(1.1)
    _, h, _ = req(srv, "/age")
    assert 11 <= int(h["age"]) <= 13, h  # the upstream's 10, plus the time it sat here


def test_host_in_key(bastion, up):
    up.handler = lambda r, c: ok(f"host={r.get('host')}", 200, (("Cache-Control", "max-age=60"),))
    srv = bastion(conf(up))
    assert req(srv, "/p", host="a.example")[2] == b"host=a.example"
    assert req(srv, "/p", host="b.example")[2] == b"host=b.example"
    assert req(srv, "/p", host="a.example")[2] == b"host=a.example"
    assert len(up.requests) == 2


def test_unkeyed_header_poison(bastion, up):
    """The upstream reflects X-Forwarded-Host: an attacker's value must never reach the stored
    copy others get, because the proxy rewrites that field from what the connection proves."""
    up.handler = lambda r, c: ok(f"<a href=//{r.get('x-forwarded-host')}/>", 200,
                                 (("Cache-Control", "max-age=60"),))
    srv = bastion(conf(up))
    _, _, evil = req(srv, "/home", extra="X-Forwarded-Host: evil.example\r\n")
    _, _, victim = req(srv, "/home")
    assert b"evil" not in evil and b"evil" not in victim
    assert victim == b"<a href=//localhost/>"


def test_vary(bastion, up):
    up.handler = lambda r, c: ok(f"lang={r.get('accept-language')}", 200,
                                 (("Cache-Control", "max-age=60"), ("Vary", "Accept-Language")))
    srv = bastion(conf(up))
    assert req(srv, "/v", extra="Accept-Language: en\r\n")[2] == b"lang=en"
    assert req(srv, "/v", extra="Accept-Language: de\r\n")[2] == b"lang=de"
    st, h, b = req(srv, "/v", extra="Accept-Language:  en \r\n")
    assert b == b"lang=en" and h["cache-status"].startswith("bastion; hit"), h
    assert req(srv, "/v", extra="Accept-Language: de\r\n")[2] == b"lang=de"
    assert len(up.requests) == 2  # each variant stored on its own
    up.handler = counting(headers=(("Cache-Control", "max-age=60"), ("Vary", "*")))
    n = len(up.requests)
    req(srv, "/star")
    _, h, _ = req(srv, "/star")
    assert len(up.requests) == n + 2, "Vary: * was reused"
    assert "vary *" in h["cache-status"]


def test_set_cookie_not_cached(bastion, up):
    up.handler = counting(headers=(("Cache-Control", "max-age=60"), ("Set-Cookie", "sid=alice")))
    srv = bastion(conf(up))
    _, h1, _ = req(srv, "/me")
    _, h2, _ = req(srv, "/me")
    assert len(up.requests) == 2
    assert "set-cookie" in h2["cache-status"]


def test_authorization_not_shared(bastion, up):
    up.handler = lambda r, c: ok(f"secret of {r.get('authorization')}", 200,
                                 (("Cache-Control", "max-age=60"),))
    srv = bastion(conf(up))
    assert req(srv, "/acct", extra="Authorization: Bearer alice\r\n")[2] == b"secret of Bearer alice"
    _, _, b = req(srv, "/acct")
    assert b"alice" not in b and len(up.requests) == 2


def test_head_from_get(bastion, up):
    up.handler = counting(body=b"0123456789")
    srv = bastion(conf(up))
    req(srv, "/h")
    st, h, b = req(srv, "/h", method="HEAD")
    assert st == 200 and h["content-length"] == "10" and b == b""
    assert h["cache-status"].startswith("bastion; hit") and len(up.requests) == 1


def test_range_from_cache(bastion, up):
    up.handler = counting(body=b"0123456789", headers=(("Cache-Control", "max-age=60"), ("ETag", '"r1"')))
    srv = bastion(conf(up))
    req(srv, "/r")
    st, h, b = req(srv, "/r", extra="Range: bytes=2-5\r\n")
    assert st == 206 and b == b"2345" and h["content-range"] == "bytes 2-5/10", h
    st, _, _ = req(srv, "/r", extra="Range: bytes=50-60\r\n")
    assert st == 416
    st, _, b = req(srv, "/r", extra='Range: bytes=2-5\r\nIf-Range: "other"\r\n')
    assert st == 200 and b == b"0123456789"
    assert len(up.requests) == 1


def test_revalidate_304(bastion, up):
    def h(r, c):
        if r.get("if-none-match") == '"v1"':
            return b'HTTP/1.1 304 Not Modified\r\nETag: "v1"\r\nCache-Control: max-age=1\r\n\r\n'
        return ok(b"body-v1", 200, (("Cache-Control", "max-age=1"), ("ETag", '"v1"')))
    up.handler = h
    srv = bastion(conf(up))
    req(srv, "/rv")
    time.sleep(2.1)
    st, hd, b = req(srv, "/rv")
    assert st == 200 and b == b"body-v1", hd
    assert up.requests[-1].get("if-none-match") == '"v1"'
    assert "fwd=stale" in hd["cache-status"] and "fwd-status=304" in hd["cache-status"], hd
    st, hd, b = req(srv, "/rv")  # refreshed by the 304
    assert hd["cache-status"].startswith("bastion; hit") and b == b"body-v1"
    assert len(up.requests) == 2


def test_client_conditional(bastion, up):
    up.handler = counting(headers=(("Cache-Control", "max-age=60"), ("ETag", '"e7"')))
    srv = bastion(conf(up))
    req(srv, "/c")
    st, h, b = req(srv, "/c", extra='If-None-Match: "e7"\r\n')
    assert st == 304 and b == b"" and h.get("etag") == '"e7"'
    st, _, _ = req(srv, "/c", extra='If-None-Match: "zz"\r\n')
    assert st == 200
    assert len(up.requests) == 1


def test_invalidate_post(bastion, up):
    up.handler = counting()
    srv = bastion(conf(up))
    req(srv, "/item")
    req(srv, "/item")
    assert len(up.requests) == 1
    req(srv, "/item", method="POST", body=b"x")
    req(srv, "/item")
    assert len(up.requests) == 3, "POST did not invalidate the stored GET"


def slow_body(total=200000, first=100000, pause=1.0):
    def h(r, c):
        c.sendall(f"HTTP/1.1 200 OK\r\nContent-Length: {total}\r\nCache-Control: max-age=60\r\n\r\n".encode()
                  + b"a" * first)
        time.sleep(pause)
        try:
            c.sendall(b"a" * (total - first))
        except OSError:
            pass
        return None
    return h


def abort_mid_fill(srv, path):
    s = socket.create_connection(("127.0.0.1", srv.ports["http"]), 10)
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())
    s.recv(1000)
    s.close()


@pytest.mark.parametrize("bg", ["off", "on"])
def test_client_abort_fill(bastion, up, bg):
    up.handler = slow_body()
    srv = bastion(conf(up, loc=f"cache_background_fill {bg};"))
    abort_mid_fill(srv, "/big")
    time.sleep(2.5)
    st, h, b = req(srv, "/big")
    assert st == 200 and len(b) == 200000 and b == b"a" * 200000  # never a partial object
    if bg == "on":
        assert len(up.requests) == 2 and h["cache-status"].startswith("bastion; hit"), h
    else:
        assert len(up.requests) == 2 and "fwd=miss" in h["cache-status"], h


def test_upstream_truncated(bastion, up):
    def cut(r, c):
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nCache-Control: max-age=60\r\n\r\n" + b"x" * 500)
        r.close = True
        return None
    up.handler = cut
    srv = bastion(conf(up))
    req(srv, "/t")
    up.handler = counting(body=b"whole")
    st, h, b = req(srv, "/t")
    assert b == b"whole" and "fwd=miss" in h["cache-status"], "a truncated response was stored"


NEEDS = pytest.mark.skipif(shutil.which("curl") is None, reason="curl is needed")


@NEEDS
def test_across_protocols(bastion, up, certs):
    up.handler = counting(body=b"same-bytes" * 100)
    srv = bastion(f"workers 1;\ncache_store main {{ disk @WORKDIR@/cache size=100m; }}\n"
                  f"server {{ listen 127.0.0.1:@HTTP_PORT@; listen 127.0.0.1:@HTTPS_PORT@ tls http2; "
                  f"listen 127.0.0.1:@QUIC_PORT@ http3; "
                  f"tls_cert {certs}/ecdsa-chain.crt {certs}/ecdsa.key;\n"
                  f"location / {{ proxy {up.url}; cache main; cache_key $host$request_uri; }} }}\n")
    st, _, b1 = req(srv, "/x")
    assert st == 200
    p = subprocess.run(["curl", "-sS", "--http2", "-D", "-", "--cacert", str(certs / "ca.crt"),
                        "--resolve", f"localhost:{srv.ports['https']}:127.0.0.1",
                        f"https://localhost:{srv.ports['https']}/x"], capture_output=True, timeout=30)
    assert p.returncode == 0, p.stderr
    head, _, b2 = p.stdout.partition(b"\r\n\r\n")
    assert b2 == b1 and b"cache-status: bastion; hit" in head.lower(), head
    rc, lines = h3(srv, "/x", opts=("--print-body",))
    r = [ln for ln in lines if ln.get("type") == "resp"][0]
    assert rc == 0 and r["status"] == 200 and r["body"].encode() == b1, r
    assert len(up.requests) == 1


def test_cache_disabled_when_broken(bastion, up, tmp_path):
    blocker = tmp_path / "notadir"
    blocker.write_text("x")
    up.handler = counting()
    srv = bastion(f"workers 1;\ncache_store main {{ disk {blocker}/cache size=100m; }}\n"
                  f"server {{ listen 127.0.0.1:@HTTP_PORT@;\n"
                  f"location / {{ proxy {up.url}; cache main; }} }}\n")
    assert req(srv, "/b")[2] == b"hello"
    assert req(srv, "/b")[2] == b"hello"
    assert len(up.requests) == 2
    srv.wait_log(r"cache_store main: .*serving without this cache")


def test_cache_write_failure(bastion, up):
    """A disk that refuses writes (full) never breaks serving: the response reaches the client."""
    up.handler = counting(body=b"z" * 5000)
    srv = bastion(conf(up), env={"BST_TEST_CACHE_ENOSPC": "1"})
    st, h, b = req(srv, "/f")
    assert st == 200 and b == b"z" * 5000
    assert req(srv, "/f")[2] == b"z" * 5000
    assert len(up.requests) == 2
    srv.wait_log(r"cache_store main: writing an object failed")
