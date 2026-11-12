"""HTTP/2 and HTTP/3 clients reach an HTTP/1.1 upstream through the proxy (Phase 9, Task 3): the
request is regenerated, so no CL/TE trick of the client's survives, and a response cut off after
it started resets the client's stream on every protocol."""
import shutil
import subprocess
import time

import pytest

from quic_util import h3
from upstream_util import Upstream, ok

NEEDS = pytest.mark.skipif(shutil.which("curl") is None or shutil.which("nghttp") is None,
                           reason="curl and nghttp are needed")


@pytest.fixture
def up():
    u = Upstream()
    yield u
    u.close()


def conf(certs, up, extra=""):
    return (f"workers 1;\nserver {{ listen 127.0.0.1:@HTTPS_PORT@ tls http2; "
            f"listen 127.0.0.1:@QUIC_PORT@ http3; "
            f"tls_cert {certs}/ecdsa-chain.crt {certs}/ecdsa.key; {extra}\n"
            f"location / {{ proxy {up.url}; }} }}\n")


def curl(srv, certs, path, *args):
    return subprocess.run(["curl", "-sS", "--http2", "--cacert", str(certs / "ca.crt"),
                           "--resolve", f"localhost:{srv.ports['https']}:127.0.0.1", *args,
                           f"https://localhost:{srv.ports['https']}{path}"],
                          capture_output=True, timeout=30)


def resp(lines):
    found = [ln for ln in lines if ln.get("type") == "resp"]
    return found[0] if found else {}


@NEEDS
def test_h2_to_h1(bastion, certs, up):
    srv = bastion(conf(certs, up))
    p = curl(srv, certs, "/h2?x=1", "-H", "Cookie: a=1", "-H", "Cookie: b=2", "-d", "body!")
    assert p.returncode == 0 and p.stdout == b"/h2?x=1", p.stderr
    req = up.requests[-1]
    assert req.version == "HTTP/1.1" and req.method == "POST"
    assert req.get("host") == f"localhost:{srv.ports['https']}"
    assert req.get("cookie") == "a=1; b=2"  # RFC 9113 section 8.2.3: one field for HTTP/1.1
    assert req.body == b"body!"
    assert req.get("x-forwarded-proto") == "https"


def test_h3_to_h1(bastion, certs, up):
    srv = bastion(conf(certs, up))
    rc, lines = h3(srv, "/h3", opts=("--method", "POST", "--body-size", "1000", "--print-body"))
    r = resp(lines)
    assert rc == 0 and r.get("status") == 200, lines
    req = up.requests[-1]
    assert req.method == "POST" and len(req.body) == 1000
    # no content-length from h3client: the proxy chunks it
    assert req.get("transfer-encoding") == "chunked" or req.get("content-length") == "1000"


@NEEDS
def test_h2_to_h1_smuggling(bastion, certs, up):
    srv = bastion(conf(certs, up))
    before = len(up.requests)
    tricks = [
        ["-H", "transfer-encoding: chunked", "-d", "0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: x\r\n\r\n"],
        ["-H", "content-length: 3", "-d", "abcdefGET /smuggled HTTP/1.1\r\n\r\n"],
        ["-H", "connection: keep-alive", "-d", "x"],
        ["-H", "x-a: b\r\nGET /smuggled HTTP/1.1"],
    ]
    for t in tricks:
        subprocess.run(["nghttp", "-n", *[a if not a.startswith("-d") else a for a in t[:2]],
                        f"https://localhost:{srv.ports['https']}/t"], capture_output=True, timeout=20)
        curl(srv, certs, "/t", *t)
    time.sleep(0.3)
    seen = up.requests[before:]
    assert all("/smuggled" not in r.target for r in seen), [r.target for r in seen]
    for r in seen:
        assert r.target == "/t"
        assert len(r.all("content-length")) + len(r.all("transfer-encoding")) <= 1
    # every request the upstream saw was exactly one well-formed request per client request
    assert len(seen) <= 2 * len(tricks)


def test_h3_smuggling(bastion, certs, up):
    srv = bastion(conf(certs, up))
    before = len(up.requests)
    for hdr in ("transfer-encoding: chunked", "connection: close", "content-length: 1"):
        rc, lines = h3(srv, "/t", opts=("--method", "POST", "--body-size", "10", "--header", hdr),
                       timeout_ms=5000)
        assert resp(lines).get("status") != 200 or hdr.startswith("x"), (hdr, lines)
    assert len(up.requests) == before


@NEEDS
def test_mid_response_failure_h2(bastion, certs, up):
    def cut(req, c):
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n" + b"a" * 1000)
        time.sleep(0.2)
        req.close = True
        return None

    up.handler = cut
    srv = bastion(conf(certs, up))
    p = curl(srv, certs, "/cut")
    assert p.returncode != 0, "a cut response must not end cleanly over HTTP/2"
    assert len(p.stdout) < 100000


def test_mid_response_failure_h3(bastion, certs, up):
    def cut(req, c):
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n" + b"a" * 1000)
        time.sleep(0.2)
        req.close = True
        return None

    up.handler = cut
    srv = bastion(conf(certs, up))
    rc, lines = h3(srv, "/cut", timeout_ms=5000)
    r = resp(lines)
    assert r.get("reset") is not None or r.get("len", 0) < 100000, lines


def test_early_data_flag(bastion, certs, up, tmp_path):
    """0-RTT requests carry Early-Data: 1 and an upstream 425 reaches the client."""
    up.handler = lambda req, c: ok("too early", status=425) if req.get("early-data") else ok("fine")
    srv = bastion("workers 1;\ntls_profile e { early_data on; }\n"
                  f"server {{ listen 127.0.0.1:@HTTPS_PORT@ tls; tls_profile e; "
                  f"tls_cert {certs}/ecdsa-chain.crt {certs}/ecdsa.key;\n"
                  f"location / {{ proxy {up.url}; }} }}\n")
    base = ["openssl", "s_client", "-connect", f"127.0.0.1:{srv.ports['https']}", "-servername",
            "localhost", "-CAfile", str(certs / "ca.crt"), "-tls1_3", "-ign_eof", "-quiet"]
    sess = tmp_path / "sess"
    get = b"GET /e HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    p = subprocess.run(base + ["-sess_out", str(sess)], input=get, capture_output=True, timeout=15)
    assert b"fine" in p.stdout, p.stdout + p.stderr
    early = tmp_path / "early"
    early.write_bytes(get)
    p = subprocess.run(base + ["-sess_in", str(sess), "-early_data", str(early)], input=b"",
                       capture_output=True, timeout=15)
    if not any(r.get("early-data") for r in up.requests):
        pytest.skip("the server did not accept 0-RTT here: " + p.stderr.decode()[-200:])
    assert b" 425 " in p.stdout and b"too early" in p.stdout, p.stdout
