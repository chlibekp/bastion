"""HTTP extras (Phase 11, Task 3): 103 Early Hints, request IDs, security header presets,
maintenance mode and the upstream response size limit."""
import re
import shutil
import socket
import ssl
import subprocess
import time

import pytest

from quic_util import h3
from upstream_util import Upstream, ok

HEX32 = re.compile(r"^[0-9a-f]{32}$")
NEEDS_CURL = pytest.mark.skipif(shutil.which("curl") is None, reason="curl is needed")


def raw(port, request, timeout=10, tls=False):
    s = socket.create_connection(("127.0.0.1", port), timeout)
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname="localhost")
    s.sendall(request)
    out = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            out += d
    except OSError:
        pass
    s.close()
    return out


def get(port, path="/", extra="", version="1.1", tls=False):
    return raw(port, f"GET {path} HTTP/{version}\r\nHost: localhost\r\n{extra}Connection: close\r\n\r\n"
               .encode(), tls=tls)


def final_head(r):
    """The final response's status and headers (lower-case names, every value)."""
    while r.startswith(b"HTTP/1.1 1"):
        r = r.split(b"\r\n\r\n", 1)[1]
    head = r.split(b"\r\n\r\n", 1)[0].decode("latin-1").split("\r\n")
    if not head[0]:
        return 0, {}
    hs = {}
    for ln in head[1:]:
        k, _, v = ln.partition(":")
        hs.setdefault(k.strip().lower(), []).append(v.strip())
    return int(head[0].split()[1]), hs


@pytest.fixture
def up():
    u = Upstream()
    yield u
    u.close()


# ---- Early Hints ----

HINTS = 'early_hints on; early_hint "</app.css>; rel=preload; as=style"; '


def test_103_h1(bastion):
    srv = bastion("workers 1;\nserver { listen 127.0.0.1:@HTTP_PORT@; " + HINTS +
                  "location / { return 200 \"done\"; } }\n")
    r = get(srv.ports["http"])
    assert r.startswith(b"HTTP/1.1 103"), r
    assert b"Link: </app.css>; rel=preload; as=style" in r.split(b"\r\n\r\n")[0]
    assert b"\r\n\r\nHTTP/1.1 200" in r and r.endswith(b"done")
    r10 = get(srv.ports["http"], version="1.0")  # never to HTTP/1.0
    assert not r10.startswith(b"HTTP/1.1 103") and b" 103 " not in r10


@NEEDS_CURL
def test_103_h2(bastion):
    srv = bastion("workers 1;\nserver { listen 127.0.0.1:@HTTP_PORT@ h2c; " + HINTS +
                  "location / { return 200 \"done\"; } }\n")
    p = subprocess.run(["curl", "-sv", "--http2-prior-knowledge",
                        f"http://127.0.0.1:{srv.ports['http']}/"], capture_output=True, text=True,
                       timeout=30)
    assert "< HTTP/2 103" in p.stderr and "< HTTP/2 200" in p.stderr, p.stderr
    assert p.stderr.index("HTTP/2 103") < p.stderr.index("HTTP/2 200")


def test_103_h3(bastion, certs):
    srv = bastion(f"workers 1;\nserver {{ listen 127.0.0.1:@QUIC_PORT@ http3; "
                  f"tls_cert {certs}/ecdsa-chain.crt {certs}/ecdsa.key; {HINTS}"
                  f"location / {{ return 200 \"done\"; }} }}\n")
    rc, lines = h3(srv, "/")
    resp = [ln for ln in lines if ln.get("type") == "resp"]
    assert rc == 0 and resp and resp[0]["status"] == 200
    assert resp[0]["interim"] == 103


def test_103_from_upstream(bastion, up):
    def early(req, c):
        c.sendall(b"HTTP/1.1 103 Early Hints\r\nLink: </u.css>; rel=preload\r\n\r\n")
        return ok("done")
    up.handler = early
    srv = bastion(f"workers 1;\nserver {{ listen 127.0.0.1:@HTTP_PORT@; "
                  f"location / {{ proxy {up.url}; }} }}\n")
    r = get(srv.ports["http"])
    assert r.startswith(b"HTTP/1.1 103") and b"</u.css>" in r and r.endswith(b"done")


# ---- request IDs ----

def rid_conf(up, extra="", workers=1):
    return (f"workers {workers};\nserver {{ listen 127.0.0.1:@HTTP_PORT@; request_id on; {extra}\n"
            f"location / {{ proxy {up.url}; }} }}\n")


def test_request_id_unique(bastion, up):
    up.handler = lambda r, c: ok("x")
    srv = bastion(rid_conf(up, workers=2))
    ids = set()
    for _ in range(40):
        _, h = final_head(get(srv.ports["http"]))
        v = h["x-request-id"]
        assert len(v) == 1 and HEX32.match(v[0]), v  # 128 bits, hex
        ids.add(v[0])
    assert len(ids) == 40
    sent = [r.get("x-request-id") for r in up.requests]
    assert set(sent) == ids  # each forwarded upstream with the very same value


def test_request_id_spoof(bastion, up):
    up.handler = lambda r, c: ok("x")
    srv = bastion(rid_conf(up, "request_id_trust 10.9.9.0/24;"))
    _, h = final_head(get(srv.ports["http"], extra="X-Request-ID: forged-1\r\n"))
    assert h["x-request-id"] != ["forged-1"] and HEX32.match(h["x-request-id"][0])
    assert up.requests[-1].all("x-request-id") == h["x-request-id"]
    srv2 = bastion(rid_conf(up, "request_id_trust 127.0.0.1/32;"))
    _, h = final_head(get(srv2.ports["http"], extra="X-Request-ID: lb-abc.123\r\n"))
    assert h["x-request-id"] == ["lb-abc.123"]
    # trusted, but not an ID shape: replaced
    _, h = final_head(get(srv2.ports["http"], extra="X-Request-ID: a b;c\r\n"))
    assert HEX32.match(h["x-request-id"][0])


# ---- security headers ----

BASIC = {"x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN",
         "referrer-policy": "strict-origin-when-cross-origin"}
STRICT = {"x-content-type-options": "nosniff", "x-frame-options": "DENY",
          "referrer-policy": "no-referrer",
          "content-security-policy": "default-src 'self'; frame-ancestors 'none'; base-uri 'self'",
          "permissions-policy": "camera=(), microphone=(), geolocation=()"}
SEC_NAMES = set(STRICT) | {"strict-transport-security"}


def sec_of(h):
    return {k: v[0] for k, v in h.items() if k in SEC_NAMES}


def test_security_presets(bastion, certs):
    for preset, want, hsts in (("basic", BASIC, "max-age=31536000"),
                               ("strict", STRICT, "max-age=63072000; includeSubDomains")):
        srv = bastion(f"workers 1;\nserver {{ listen 127.0.0.1:@HTTP_PORT@; "
                      f"listen 127.0.0.1:@HTTPS_PORT@ tls; "
                      f"tls_cert {certs}/ecdsa-chain.crt {certs}/ecdsa.key; "
                      f"security_headers {preset}; location / {{ return 200 \"ok\"; }} }}\n")
        _, h = final_head(get(srv.ports["http"]))
        assert sec_of(h) == want, (preset, h)  # no HSTS over cleartext
        _, h = final_head(get(srv.ports["https"], tls=True))
        assert sec_of(h) == dict(want, **{"strict-transport-security": hsts}), (preset, h)


def test_security_no_overwrite(bastion, up):
    up.handler = lambda r, c: ok("x", 200, (("Content-Security-Policy", "default-src https:"),
                                            ("X-Frame-Options", "ALLOW-FROM x")))
    srv = bastion(f"workers 1;\nserver {{ listen 127.0.0.1:@HTTP_PORT@; security_headers strict; "
                  f"frame_options DENY force; location / {{ proxy {up.url}; }} }}\n")
    _, h = final_head(get(srv.ports["http"]))
    assert h["content-security-policy"] == ["default-src https:"]  # the upstream's kept
    assert h["x-frame-options"] == ["DENY"]  # force replaces
    srv2 = bastion(f"workers 1;\nserver {{ listen 127.0.0.1:@HTTP_PORT@; security_headers basic; "
                   f"referrer_policy off; location / {{ return 200 \"x\"; }} }}\n")
    _, h = final_head(get(srv2.ports["http"]))
    assert "referrer-policy" not in h and h["x-content-type-options"] == ["nosniff"]


# ---- maintenance ----

def test_maintenance(bastion, tmp_path):
    srv = bastion("workers 1;\nserver { listen 127.0.0.1:@HTTP_PORT@; maintenance on; "
                  "maintenance_retry_after 120s; location / { return 200 \"up\"; } }\n")
    r = get(srv.ports["http"])
    st, h = final_head(r)
    assert st == 503 and h["retry-after"] == ["120"] and not r.endswith(b"up")
    srv = bastion("workers 1;\nserver { listen 127.0.0.1:@HTTP_PORT@; maintenance on; "
                  "maintenance_allow 127.0.0.0/8; location / { return 200 \"up\"; } }\n")
    assert get(srv.ports["http"]).endswith(b"up")  # an allowed peer bypasses
    page = tmp_path / "m.html"
    page.write_bytes(b"<h1>back soon</h1>")
    srv = bastion(f"workers 1;\nserver {{ listen 127.0.0.1:@HTTP_PORT@; maintenance {page}; "
                  f"location / {{ return 200 \"up\"; }} }}\n")
    r = get(srv.ports["http"])
    assert final_head(r)[0] == 503 and r.endswith(b"<h1>back soon</h1>")


def test_maintenance_file_unreadable(bastion, tmp_path):
    with pytest.raises(pytest.fail.Exception, match="maintenance: can not use"):
        bastion(f"workers 1;\nserver {{ listen 127.0.0.1:@HTTP_PORT@; "
                f"maintenance {tmp_path}/missing.html; }}\n")


# ---- upstream response size ----

def test_upstream_response_limit(bastion, up):
    up.handler = lambda r, c: ok(b"x" * 5000)
    srv = bastion(f"workers 1;\nserver {{ listen 127.0.0.1:@HTTP_PORT@; "
                  f"upstream_max_response_size 1k; location / {{ proxy {up.url}; }} }}\n")
    r = get(srv.ports["http"])
    assert final_head(r)[0] == 502, (r, srv.workdir.joinpath("error.log").read_text()[-3000:])

    def chunked(r, c):
        c.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
        time.sleep(0.3)  # the head reaches the client first: the response has started
        for _ in range(8):
            c.sendall(b"400\r\n" + b"y" * 1024 + b"\r\n")
        c.sendall(b"0\r\n\r\n")
        return None
    up.handler = chunked
    r = get(srv.ports["http"])
    st, _ = final_head(r)
    assert st == 200 and not r.endswith(b"0\r\n\r\n")  # started: aborted, never a clean end
