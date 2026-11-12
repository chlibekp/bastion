"""WebSocket tunnels through the proxy (Phase 9, Task 7), HTTP/1.1 clients."""
import base64
import os
import socket
import threading
import time

import pytest

from upstream_util import Upstream, get, ok, wait_until
from ws_util import echo_handler, frame, read_frame, ws_connect


@pytest.fixture
def up():
    u = Upstream(echo_handler)
    yield u
    u.close()


def conf(up, extra=""):
    return (f"workers 1;\nserver {{ listen 127.0.0.1:@HTTP_PORT@; {extra}\n"
            f"location / {{ proxy {up.url}; }} }}\n")


def test_ws_h1(bastion, up):
    srv = bastion(conf(up))
    s, st, head, buf = ws_connect(srv.ports["http"])
    assert st == 101, head
    assert b"upgrade: websocket" in head.lower() and b"sec-websocket-accept:" in head.lower()
    s.sendall(frame(0x1, b"hello", True))
    assert read_frame(s, buf) == (0x1, b"hello")
    big = os.urandom(200000)
    s.sendall(frame(0x2, big, True))
    assert read_frame(s, buf) == (0x2, big)
    s.sendall(frame(0x9, b"p", True))
    assert read_frame(s, buf) == (0xA, b"p")
    s.sendall(frame(0x8, b"\x03\xe8", True))
    assert read_frame(s, buf) == (0x8, b"\x03\xe8")
    s.settimeout(5)
    assert s.recv(10) == b""  # the upstream closed: so does the tunnel
    s.close()
    req = up.requests[-1]
    assert req.get("upgrade") == "websocket" and "upgrade" in req.get("connection").lower()


@pytest.mark.parametrize("key,version", [(None, "8"), ("short", "13"), ("", "13")])
def test_ws_bad_upgrade(bastion, up, key, version):
    """A bad key or version: passed on as a plain request (no upgrade), so a normal answer."""
    srv = bastion(conf(up))
    s, st, head, _ = ws_connect(srv.ports["http"], key=key, version=version)
    assert st == 400, head
    assert up.requests[-1].get("upgrade") is None
    s.close()


def test_ws_upstream_refuses(bastion):
    """An upstream that answers 200 to an upgrade: relayed as a response; the connection stays
    HTTP, so what the client sends next is parsed as a request, never tunneled."""
    u = Upstream(lambda req, c: ok("no tunnel here"))
    try:
        srv = bastion(conf(u))
        s, st, head, buf = ws_connect(srv.ports["http"])
        assert st == 200, head
        # a second request on the same connection is answered as HTTP
        s.sendall(b"GET /second HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")
        data = buf[0]
        s.settimeout(5)
        while True:
            d = s.recv(65536)
            if not d:
                break
            data += d
        assert b"HTTP/1.1 200" in data and data.endswith(b"/second") or b"no tunnel here" in data
        assert [r.target for r in u.requests] == ["/", "/second"]
    finally:
        u.close()


def test_ws_smuggle_failed_upgrade(bastion):
    """The known smuggling pattern: the upstream refuses the upgrade (here with a 426) and the
    client then sends a request meant for a hidden path inside the would-be tunnel. It must be
    parsed by bastion as a request of its own (and routed by its rules), not relayed raw."""
    u = Upstream(lambda req, c: ok("", status=426) if req.get("upgrade") else ok(req.target))
    try:
        srv = bastion(f"workers 1;\nserver {{ listen 127.0.0.1:@HTTP_PORT@;\n"
                      f"location /internal {{ return 403; }}\n"
                      f"location / {{ proxy {u.url}; }} }}\n")
        s, st, head, buf = ws_connect(srv.ports["http"])
        assert st == 426, head
        s.sendall(b"GET /internal HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")
        data = buf[0]
        s.settimeout(5)
        while True:
            d = s.recv(65536)
            if not d:
                break
            data += d
        assert b"403" in data.split(b"\r\n", 1)[0], data[:200]
        assert all(r.target != "/internal" for r in u.requests)
    finally:
        u.close()


def test_ws_unrequested_101(bastion):
    """An upstream 101 to a request that asked for no upgrade: 502, no tunnel."""
    u = Upstream(lambda req, c: b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                 b"Connection: Upgrade\r\n\r\n")
    try:
        srv = bastion(conf(u))
        r = get(srv.ports["http"])
        assert r.startswith(b"HTTP/1.1 502"), r[:100]
    finally:
        u.close()


def test_ws_off(bastion, up):
    srv = bastion(conf(up, "websocket off;"))
    s, st, head, _ = ws_connect(srv.ports["http"])
    assert st == 400  # the upstream saw a plain GET
    assert up.requests[-1].get("upgrade") is None
    s.close()


def test_ws_idle_timeout(bastion, up):
    srv = bastion(conf(up, "tunnel_idle_timeout 300ms;"))
    s, st, _, buf = ws_connect(srv.ports["http"])
    assert st == 101
    s.sendall(frame(0x1, b"x", True))
    assert read_frame(s, buf) == (0x1, b"x")
    s.settimeout(5)
    t0 = time.monotonic()
    assert s.recv(10) == b""
    assert time.monotonic() - t0 < 3
    s.close()


def test_ws_half_close(bastion):
    """The client shuts its write side: the upstream sees EOF and can still answer."""
    got = {}

    def h(req, c):
        key = req.get("sec-websocket-key")
        from ws_util import accept_for
        c.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                   f"Sec-WebSocket-Accept: {accept_for(key)}\r\n\r\n").encode())
        data = b""
        while True:
            d = c.recv(65536)
            if not d:
                break
            data += d
        got["data"] = data
        c.sendall(b"after-eof")
        req.close = True
        return None

    u = Upstream(h)
    try:
        srv = bastion(conf(u))
        s, st, _, buf = ws_connect(srv.ports["http"])
        assert st == 101
        s.sendall(b"raw-bytes")
        s.shutdown(socket.SHUT_WR)
        s.settimeout(5)
        data = buf[0]
        while True:
            d = s.recv(65536)
            if not d:
                break
            data += d
        assert data == b"after-eof"
        assert got["data"] == b"raw-bytes"
    finally:
        u.close()


def test_ws_backpressure(bastion):
    """The client stops reading: the upstream is slowed (its writes block), memory bounded."""
    sent = [0]
    stop = threading.Event()

    def h(req, c):
        key = req.get("sec-websocket-key")
        from ws_util import accept_for
        c.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                   f"Sec-WebSocket-Accept: {accept_for(key)}\r\n\r\n").encode())
        chunk = b"z" * 65536
        c.settimeout(10)
        try:
            while not stop.is_set() and sent[0] < (512 << 20):
                c.sendall(chunk)
                sent[0] += len(chunk)
        except OSError:
            pass
        req.close = True
        return None

    u = Upstream(h)
    try:
        srv = bastion(conf(u))
        s, st, _, _ = ws_connect(srv.ports["http"])
        assert st == 101
        time.sleep(2)
        n1 = sent[0]
        time.sleep(1)
        n2 = sent[0]
        assert n2 == n1, "the upstream kept writing to a client that reads nothing"
        assert n1 < (64 << 20), f"{n1} bytes buffered on the way"
        stop.set()
        s.close()
    finally:
        u.close()


def test_max_tunnels(bastion, up):
    srv = bastion(conf(up, "max_tunnels 1;"))
    s1, st1, _, _ = ws_connect(srv.ports["http"])
    assert st1 == 101
    s2, st2, head, _ = ws_connect(srv.ports["http"])
    assert st2 == 503, head
    s1.close()
    s2.close()
