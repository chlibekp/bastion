"""HTTP semantics are the same over HTTP/2 as over HTTP/1.1: one listener serves both (ALPN picks),
and the same request must get the same status, validators, ranges and error pages. Both backends,
seccomp on. `make test-int-nosan` runs this file without sanitizers too."""
import os
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import h2_attack as h2  # noqa: E402

pytestmark = pytest.mark.skipif(shutil.which("curl") is None, reason="curl is needed")

KEEP = ("content-type", "content-length", "etag", "last-modified", "accept-ranges", "content-range",
        "cache-control", "allow", "vary")


def conf(certs, www):
    return (f"workers 1;\nserver {{ listen 127.0.0.1:@HTTPS_PORT@ tls http2; "
            f"tls_cert {certs}/ecdsa-chain.crt {certs}/ecdsa.key; root {www};\n"
            f"location = /r {{ return 200 \"hi\"; }} }}\n")


@pytest.fixture
def www(tmp_path):
    root = tmp_path / "www"
    root.mkdir()
    (root / "data.bin").write_bytes(bytes(range(256)) * 40)
    (root / "page.html").write_text("<h1>page</h1>\n")
    (root / "empty.txt").write_bytes(b"")
    return root


def fetch(srv, version, path, method="GET", headers=()):
    """(status, {kept headers}, body) through curl speaking the given HTTP version."""
    url = f"https://127.0.0.1:{srv.ports['https']}{path}"
    cmd = ["curl", "-sk", version, "-D", "-", "-o", "/dev/stdout", "-X", method] if method != "HEAD" else [
        "curl", "-sk", version, "-I", "-D", "-", "-o", "/dev/null"]
    for h in headers:
        cmd += ["-H", h]
    out = subprocess.run(cmd + [url], capture_output=True, timeout=30).stdout
    head, _, body = out.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split()[1])
    hdrs = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            if k.lower() in KEEP:
                hdrs[k.lower()] = v.strip()
    return status, hdrs, body


def same(srv, path, **kw):
    h1 = fetch(srv, "--http1.1", path, **kw)
    h2_ = fetch(srv, "--http2", path, **kw)
    assert h1 == h2_, (path, kw, h1, h2_)
    return h2_


def test_static_parity(bastion, certs, www):
    srv = bastion(conf(certs, www))
    st, hd, body = same(srv, "/data.bin")
    assert st == 200 and len(body) == 10240 and "etag" in hd and "last-modified" in hd
    st, hd, body = same(srv, "/page.html")
    assert st == 200 and hd["content-type"].startswith("text/html")
    st, _, body = same(srv, "/empty.txt")
    assert st == 200 and body == b""
    same(srv, "/r")


def test_range_parity(bastion, certs, www):
    srv = bastion(conf(certs, www))
    st, hd, body = same(srv, "/data.bin", headers=["Range: bytes=10-19"])
    assert st == 206 and body == bytes(range(10, 20)) and hd["content-range"] == "bytes 10-19/10240"
    st, hd, body = same(srv, "/data.bin", headers=["Range: bytes=-5"])
    assert st == 206 and body == bytes([251, 252, 253, 254, 255])
    st, _, _ = same(srv, "/data.bin", headers=["Range: bytes=99999-"])
    assert st == 416


def test_conditional_parity(bastion, certs, www):
    srv = bastion(conf(certs, www))
    _, hd, _ = same(srv, "/page.html")
    st, _, body = same(srv, "/page.html", headers=[f"If-None-Match: {hd['etag']}"])
    assert st == 304 and body == b""
    st, _, _ = same(srv, "/page.html", headers=["If-None-Match: \"nothing\""])
    assert st == 200
    st, _, _ = same(srv, "/page.html", headers=[f"If-Match: \"nothing\""])
    assert st == 412


def test_head_and_errors_parity(bastion, certs, www):
    srv = bastion(conf(certs, www))
    st, hd, body = same(srv, "/data.bin", method="HEAD")
    assert st == 200 and hd["content-length"] == "10240" and body == b""
    st, hd, body = same(srv, "/missing")
    assert st == 404 and b"404" in body and hd["content-type"].startswith("text/html")
    st, hd, _ = same(srv, "/page.html", method="DELETE")
    assert st in (405, 501), st


def test_request_trailers(bastion, certs, www):
    """A trailer section after the body is accepted; one that carries a pseudo-header is not."""
    srv = bastion(conf(certs, www))
    c = h2.H2(srv.ports["https"])
    c.send(h2.headers_frame(1, h2.request_headers("/r", "POST", extra=[("te", "trailers")]), end_stream=False))
    c.send(h2.pack(h2.DATA, 0, 1, b"body"))
    c.send(h2.headers_frame(1, [("x-checksum", "abc")], end_stream=True))
    st = c.response(1)
    assert st.reset is None and st.status in (200, 405), (st.status, st.reset)
    assert c.goaway is None
    c.send(h2.headers_frame(3, h2.request_headers("/r", "POST"), end_stream=False))
    c.send(h2.headers_frame(3, [(":path", "/evil")], end_stream=True))  # a pseudo-header in trailers
    st3 = c.response(3)
    assert st3.reset == h2.PROTOCOL_ERROR, (st3.status, st3.reset)
    c.close()


def test_malformed_requests_reset_the_stream(bastion, certs, www):
    srv = bastion(conf(certs, www))
    c = h2.H2(srv.ports["https"])
    bad = {
        1: [(":method", "GET"), (":scheme", "https"), (":authority", "x")],               # no :path
        3: h2.request_headers("/") + [("connection", "close")],                            # connection-specific
        5: h2.request_headers("/") + [("content-length", "4")],                            # body never comes
    }
    for sid, fields in bad.items():
        c.send(h2.headers_frame(sid, fields, end_stream=True))
    for sid in bad:
        assert c.response(sid).reset == h2.PROTOCOL_ERROR, sid
    assert c.goaway is None  # stream errors only: the connection goes on
    c.get(7, "/r")
    assert c.response(7).status == 200
    c.close()
    assert "killed by signal" not in srv.logs()
