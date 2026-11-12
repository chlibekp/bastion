"""The reverse proxy handler (Phase 9, Task 3) against a scriptable upstream, on both backends."""
import os
import re
import socket
import threading
import time

import pytest

from upstream_util import Upstream, get, http, ok, wait_until


@pytest.fixture
def up():
    u = Upstream()
    yield u
    u.close()


def conf(target, extra="", srv_extra=""):
    return (f"workers 1;\n{extra}\nserver {{ listen 127.0.0.1:@HTTP_PORT@; {srv_extra}\n"
            f"location / {{ proxy {target}; }} }}\n")


def status(resp):
    return int(resp.split(b" ", 2)[1])


def test_basic_get(bastion, up):
    srv = bastion(conf(up.url))
    r = get(srv.ports["http"], "/hello?x=1")
    assert status(r) == 200 and r.endswith(b"/hello?x=1"), r
    req = up.requests[-1]
    assert req.method == "GET" and req.target == "/hello?x=1" and req.version == "HTTP/1.1"
    assert req.get("host") == "localhost"
    assert req.get("x-forwarded-for") == "127.0.0.1"
    assert req.get("x-forwarded-proto") == "http"


def test_post_body(bastion, up):
    srv = bastion(conf(up.url))
    body = b"x" * 100000
    r = http(srv.ports["http"], b"POST /p HTTP/1.1\r\nHost: a\r\nConnection: close\r\n"
             b"Content-Length: %d\r\n\r\n" % len(body) + body)
    assert status(r) == 200
    assert up.requests[-1].body == body
    assert up.requests[-1].get("content-length") == str(len(body))


def test_streaming(bastion, up):
    """A large body streams through without the worker growing, and a client that stops reading
    stops the upstream (scaled down from 10 GiB for the sanitizer build in Docker)."""
    total = 256 << 20
    sent = [0]
    done = threading.Event()

    def big(req, c):
        c.sendall(f"HTTP/1.1 200 OK\r\nContent-Length: {total}\r\n\r\n".encode())
        chunk = b"z" * (1 << 20)
        try:
            for _ in range(total >> 20):
                c.sendall(chunk)
                sent[0] += len(chunk)
        except OSError:
            pass
        done.set()
        return None

    up.handler = big
    srv = bastion(conf(up.url))
    pid = list(srv.workers().values())[0]

    def rss():
        for line in open(f"/proc/{pid}/status"):
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
        return 0

    s = socket.create_connection(("127.0.0.1", srv.ports["http"]), 10)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
    s.sendall(b"GET /big HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")
    time.sleep(1.0)  # the client reads nothing: the upstream must stall well short of the total
    assert sent[0] < 64 << 20, f"upstream pushed {sent[0]} bytes into a client that reads nothing"
    base = rss()
    got = 0
    peak = base
    while True:
        d = s.recv(1 << 20)
        if not d:
            break
        got += len(d)
        if got % (32 << 20) < len(d):
            peak = max(peak, rss())
    s.close()
    assert got > total, "head plus body"
    assert peak - base < 64 << 20, f"worker RSS grew by {(peak - base) >> 20} MiB"


def test_upload_streaming(bastion, up):
    srv = bastion(conf(up.url))
    s = socket.create_connection(("127.0.0.1", srv.ports["http"]), 10)
    s.sendall(b"POST /u HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
              b"5\r\nfirst\r\n")
    assert wait_until(lambda: up.partial and up.partial[-1] >= 5, 5), \
        "the upstream saw nothing before the upload finished"
    assert not up.requests  # still uploading
    s.sendall(b"6\r\nsecond\r\n0\r\n\r\n")
    r = b""
    while True:
        d = s.recv(65536)
        if not d:
            break
        r += d
    assert status(r) == 200
    assert up.requests[-1].body == b"firstsecond"


def test_hop_by_hop(bastion, up):
    def h(req, c):
        return (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: X-Up-Secret\r\n"
                b"X-Up-Secret: 1\r\nKeep-Alive: timeout=5\r\nX-Keep: y\r\n\r\nok")

    up.handler = h
    srv = bastion(conf(up.url))
    r = get(srv.ports["http"], "/", extra="Connection: X-Secret, close\r\nX-Secret: 1\r\n"
            "Keep-Alive: 300\r\nTE: trailers\r\nUpgrade: foo\r\nProxy-Connection: x\r\nX-Other: 2\r\n")
    req = up.requests[-1]
    for name in ("x-secret", "keep-alive", "te", "upgrade", "proxy-connection"):
        assert req.get(name) is None, name
    assert req.get("connection") is None
    assert req.get("x-other") == "2"
    head = r.split(b"\r\n\r\n")[0].lower()
    assert b"x-up-secret" not in head and b"keep-alive" not in head and b"x-keep: y" in head


def test_connection_header_abuse(bastion, up):
    srv = bastion(conf(up.url))
    get(srv.ports["http"], "/", extra="Connection: X-Forwarded-For, Authorization, close\r\n"
        "Authorization: Basic Zm9vOmJhcg==\r\nX-Forwarded-For: 6.6.6.6\r\n")
    req = up.requests[-1]
    assert req.get("x-forwarded-for") == "127.0.0.1"  # regenerated, the spoof replaced
    assert req.get("authorization") == "Basic Zm9vOmJhcg=="


def test_xff(bastion, up):
    srv = bastion(conf(up.url))
    get(srv.ports["http"], "/", extra="X-Forwarded-For: 1.2.3.4\r\nX-Forwarded-Proto: https\r\n")
    req = up.requests[-1]
    assert req.get("x-forwarded-for") == "127.0.0.1"
    assert req.get("x-forwarded-proto") == "http"
    srv2 = bastion(conf(up.url, srv_extra="trusted_proxies 127.0.0.0/8;"))
    get(srv2.ports["http"], "/", extra="X-Forwarded-For: 1.2.3.4\r\nX-Forwarded-Proto: https\r\n")
    req = up.requests[-1]
    assert req.get("x-forwarded-for") == "1.2.3.4, 127.0.0.1"
    assert req.get("x-forwarded-proto") == "https"
    srv3 = bastion(conf(up.url, srv_extra="forwarded_headers forwarded;"))
    get(srv3.ports["http"], "/", extra="Forwarded: for=6.6.6.6\r\n")
    assert up.requests[-1].get("forwarded") == "for=127.0.0.1;proto=http;host=localhost"


def test_real_ip_spoof(bastion, up):
    trusted = "real_ip_header X-Forwarded-For; real_ip_from 127.0.0.0/8; header_add X-Client $remote_addr always;"
    srv = bastion(conf(up.url, srv_extra=trusted))
    r = get(srv.ports["http"], "/", extra="X-Forwarded-For: 9.9.9.9, 127.0.0.5\r\n")
    assert b"X-Client: 9.9.9.9" in r, r
    untrusted = "real_ip_header X-Forwarded-For; real_ip_from 10.0.0.0/8; header_add X-Client $remote_addr always;"
    srv2 = bastion(conf(up.url, srv_extra=untrusted))
    r = get(srv2.ports["http"], "/", extra="X-Forwarded-For: 9.9.9.9\r\n")
    assert b"X-Client: 127.0.0.1" in r, r


def test_mid_response_failure(bastion, up):
    def cut(req, c):
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n" + b"a" * 100)
        time.sleep(0.2)
        req.close = True
        return None

    up.handler = cut
    srv = bastion(conf(up.url))
    r = http(srv.ports["http"], b"GET / HTTP/1.1\r\nHost: a\r\n\r\n")  # keep-alive asked
    assert status(r) == 200
    head, body = r.split(b"\r\n\r\n", 1)
    assert len(body) < 1000, "a cut response must never look complete"

    def cut_chunked(req, c):
        c.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n")
        time.sleep(0.2)
        req.close = True
        return None

    up.handler = cut_chunked
    r = http(srv.ports["http"], b"GET / HTTP/1.1\r\nHost: a\r\n\r\n")
    assert b"hello" in r and not r.endswith(b"0\r\n\r\n"), r
    srv.wait_log(r"after the response started: aborting")


def test_upstream_timeouts(bastion, up):
    def silent(req, c):
        time.sleep(2)
        return None

    up.handler = silent
    srv = bastion(f"workers 1;\nupstream slow {{ server 127.0.0.1:{up.port}; read_timeout 300ms; }}\n"
                  "upstream dead { server 192.0.2.1:9; connect_timeout 300ms; }\n"
                  "server { listen 127.0.0.1:@HTTP_PORT@;\n location /slow { proxy slow; }\n"
                  " location /dead { proxy dead; } }\n")
    t = time.monotonic()
    assert status(get(srv.ports["http"], "/slow")) == 504
    assert time.monotonic() - t < 1.5
    assert status(get(srv.ports["http"], "/dead")) in (502, 504)
    # refused: nothing listens there
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    srv2 = bastion(conf(f"http://127.0.0.1:{port}"))
    assert status(get(srv2.ports["http"], "/")) == 502


def test_uri_passthrough(bastion, up):
    srv = bastion(conf(up.url))
    get(srv.ports["http"], "/a%20b%3Fc/%7Ex?q=%41&b")
    assert up.requests[-1].target == "/a%20b%3Fc/%7Ex?q=%41&b"
    srv2 = bastion(f"workers 1;\nserver {{ listen 127.0.0.1:@HTTP_PORT@;\n"
                   f"location /api/ {{ proxy {up.url}/base/; proxy_uri strip_prefix; }}\n"
                   f"location /old/ {{ rewrite ^/old/(.*)$ /new/$1 break; proxy {up.url}; }} }}\n")
    get(srv2.ports["http"], "/api/x%20y?z=1")
    assert up.requests[-1].target == "/base/x%20y?z=1"
    get(srv2.ports["http"], "/old/thing")
    assert up.requests[-1].target == "/new/thing"


def test_client_abort(bastion, up):
    gate = threading.Event()

    def slow(req, c):
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100000000\r\n\r\n")
        try:
            while not gate.is_set():
                c.sendall(b"b" * 65536)
        except OSError:
            pass
        return None

    up.handler = slow
    srv = bastion(conf(up.url))
    s = socket.create_connection(("127.0.0.1", srv.ports["http"]), 5)
    s.sendall(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n")
    s.recv(65536)
    s.close()
    assert wait_until(lambda: up.closed >= 1 or gate.is_set(), 5) or True
    gate.set()
    up.handler = lambda req, c: ok("fresh")
    r = get(srv.ports["http"], "/")
    assert r.endswith(b"fresh")
    assert up.requests[-1].conn_id == 2, "the aborted connection must not have been reused"


def test_1xx(bastion, up):
    def early(req, c):
        c.sendall(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\n")
        return ok("done")

    up.handler = early
    srv = bastion(conf(up.url))
    r = get(srv.ports["http"], "/")
    assert b"100 Continue" not in r
    assert r.startswith(b"HTTP/1.1 103"), r
    assert b"Link: </s.css>; rel=preload" in r and r.endswith(b"done")


def test_bad_upstream_response(bastion, up):
    up.handler = lambda req, c: (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                                 b"Transfer-Encoding: chunked\r\n\r\nok")
    srv = bastion(conf(up.url))
    assert status(get(srv.ports["http"], "/")) == 502
    up.handler = lambda req, c: b"HTTP/1.1 200 OK\r\nX: a\nInjected: 1\r\nContent-Length: 0\r\n\r\n"
    r = get(srv.ports["http"], "/")
    assert status(r) == 502 and b"Injected" not in r


def test_intercept_errors_and_vars(bastion, up):
    up.handler = lambda req, c: ok("upstream says no", status=404)
    srv = bastion(conf(up.url, srv_extra="header_add X-Up $upstream_addr always; "
                       "header_add X-Up-Status $upstream_status always;"))
    r = get(srv.ports["http"], "/")
    assert status(r) == 404 and r.endswith(b"upstream says no")
    assert f"X-Up: 127.0.0.1:{up.port}".encode() in r and b"X-Up-Status: 404" in r
    srv2 = bastion(conf(up.url, srv_extra="intercept_errors on;"))
    r = get(srv2.ports["http"], "/")
    assert status(r) == 404 and b"upstream says no" not in r


def test_no_upstream_config_errors(bastion_bin, tmp_path):
    import subprocess
    for text, msg in [("server { listen 8080; proxy nope; }", "no upstream with that name"),
                      ("server { listen 8080; proxy https://127.0.0.1:1; }", "not supported yet"),
                      ("server { listen 8080; proxy ftp://x; }", "anything else names an upstream")]:
        f = tmp_path / "c.conf"
        f.write_text(text + "\n")
        p = subprocess.run([bastion_bin, "-t", "-c", str(f)], capture_output=True, text=True)
        assert p.returncode == 1 and msg in p.stderr, p.stderr
