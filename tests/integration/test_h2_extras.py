"""Cleartext HTTP/2 with prior knowledge (`listen ... h2c`) and extended CONNECT's setting, against
the real binary, both backends, seccomp on. `make test-int-nosan` runs this file without
sanitizers too."""
import os
import shutil
import socket
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import h2_attack as h2  # noqa: E402

NEEDS = pytest.mark.skipif(shutil.which("curl") is None, reason="curl is needed")


def conf(extra="", flag="h2c"):
    return (f"workers 1;\nserver {{ listen 127.0.0.1:@HTTP_PORT@ {flag};\n"
            f"location = /v {{ return 200 \"hello\"; }}\n{extra} }}\n")


def run(args):
    return subprocess.run(args, capture_output=True, text=True, timeout=30)


@NEEDS
def test_h2c_prior_knowledge(bastion):
    srv = bastion(conf())
    url = f"http://127.0.0.1:{srv.ports['http']}/v"
    r = run(["curl", "-s", "--http2-prior-knowledge", "-i", url])
    assert r.stdout.startswith("HTTP/2 200"), r.stdout + r.stderr
    assert r.stdout.endswith("hello")
    c = h2.H2(srv.ports["http"], tls=False)  # the same through the raw client
    c.get(1, "/v")
    st = c.response(1)
    assert st.status == 200 and bytes(st.body) == b"hello"
    c.close()
    assert "killed by signal" not in srv.logs()


@NEEDS
def test_h1_on_h2c_listener(bastion):
    srv = bastion(conf())
    url = f"http://127.0.0.1:{srv.ports['http']}/v"
    r = run(["curl", "-s", "--http1.1", "-i", url])
    assert r.stdout.startswith("HTTP/1.1 200"), r.stdout + r.stderr
    assert r.stdout.endswith("hello")
    # a request whose first bytes start like the preface but are not it: still HTTP/1.1
    with socket.create_connection(("127.0.0.1", srv.ports["http"]), 5) as s:
        s.sendall(b"PRI / HTTP/1.1\r\nHost: x\r\n\r\n")
        data = s.recv(4096)
    assert data.startswith(b"HTTP/1.1 "), data
    # and one that arrives a byte at a time
    with socket.create_connection(("127.0.0.1", srv.ports["http"]), 5) as s:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        for b in b"GET /v HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n":
            s.sendall(bytes([b]))
        out = b""
        while chunk := s.recv(4096):
            out += chunk
    assert out.startswith(b"HTTP/1.1 200") and out.endswith(b"hello"), out


@NEEDS
def test_no_h1_upgrade(bastion):
    """`Upgrade: h2c` (removed by RFC 9113) is ignored: the request is answered as HTTP/1.1."""
    srv = bastion(conf())
    with socket.create_connection(("127.0.0.1", srv.ports["http"]), 5) as s:
        s.sendall(b"GET /v HTTP/1.1\r\nHost: x\r\nConnection: Upgrade, HTTP2-Settings\r\n"
                  b"Upgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n")
        data = s.recv(4096)
    assert data.startswith(b"HTTP/1.1 200"), data
    assert b"101" not in data.split(b"\r\n", 1)[0]
    assert b"upgrade" not in data.lower().split(b"\r\n\r\n")[0]


def test_preface_needs_the_h2c_flag(bastion):
    """A plain listener has no h2c: the preface is just a bad HTTP/1.1 request there."""
    srv = bastion(conf(flag=""))
    with socket.create_connection(("127.0.0.1", srv.ports["http"]), 5) as s:
        s.sendall(h2.PREFACE + h2.settings_frame())
        data = s.recv(4096)
    # HTTP/2.0 is not an HTTP/1.1 version: 505 (or 400), never an HTTP/2 answer
    assert data.startswith((b"HTTP/1.1 400", b"HTTP/1.1 505")), data


def test_silent_h2c_client_is_cut_off(bastion):
    srv = bastion(conf("client_header_timeout 1s;"))
    with socket.create_connection(("127.0.0.1", srv.ports["http"]), 5) as s:
        s.settimeout(5)
        s.sendall(h2.PREFACE[:10])  # the start of the preface, then silence
        assert s.recv(4096) == b""


def test_ext_connect_setting(bastion):
    """SETTINGS_ENABLE_CONNECT_PROTOCOL (0x8) is advertised only when http2_connect_protocol is on."""
    off = bastion(conf())
    c = h2.H2(off.ports["http"], tls=False)
    assert 8 not in c.server_settings
    c.close()
    on = bastion(conf("http2_connect_protocol on;"))
    c = h2.H2(on.ports["http"], tls=False)
    assert c.server_settings.get(8) == 1
    # a request with :protocol is understood (no handler takes it yet: it is refused, not malformed)
    c.send(h2.headers_frame(1, h2.request_headers("/v", "CONNECT", scheme="http") + [(":protocol", "websocket")],
                            end_stream=False))
    st = c.response(1)
    assert st.reset is None and st.status in (400, 404, 405, 501), (st.status, st.reset)
    c.close()
    # without the setting the same request is malformed
    c = h2.H2(off.ports["http"], tls=False)
    c.send(h2.headers_frame(1, h2.request_headers("/v", "CONNECT", scheme="http") + [(":protocol", "websocket")],
                            end_stream=False))
    assert c.response(1).reset == h2.PROTOCOL_ERROR
    c.close()
