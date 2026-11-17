"""On-the-fly compression through the real server (filters/compress.c).

The image has no Python zstd or brotli decoder: gzip bodies are decoded here, zstd and br are
checked by their framing, and their round trip is proven in tests/unit/test_compress.c."""
import gzip

import pytest

from process_util import connect
from test_h1_conn import Reader

BODY = b"compress me please, " * 2000


def get(srv, target, headers="", method="GET"):
    with connect(srv.ports["http"]) as s:
        s.settimeout(30)
        s.sendall(f"{method} {target} HTTP/1.1\r\nHost: x\r\n{headers}Connection: close\r\n\r\n".encode())
        return Reader(s).response(head_only=method == "HEAD", timeout=30)


@pytest.fixture
def srv(bastion, tmp_path):
    w = tmp_path / "www"
    w.mkdir()
    (w / "big.txt").write_bytes(BODY)
    (w / "small.txt").write_bytes(b"tiny")
    (w / "img.png").write_bytes(BODY)
    return bastion(f"workers 1;\nserver {{ listen 127.0.0.1:@HTTP_PORT@; root {w}; "
                   f"compress zstd br gzip; compress_types text/plain; }}\n")


def test_each_encoding(srv):
    st, h, body = get(srv, "/big.txt", "Accept-Encoding: gzip\r\n")
    assert st == 200 and h["content-encoding"] == ["gzip"]
    assert gzip.decompress(body) == BODY
    assert len(body) < len(BODY) // 10
    st, h, body = get(srv, "/big.txt", "Accept-Encoding: zstd\r\n")
    assert h["content-encoding"] == ["zstd"] and body[:4] == b"\x28\xb5\x2f\xfd"
    st, h, body = get(srv, "/big.txt", "Accept-Encoding: br, gzip\r\n")
    assert h["content-encoding"] == ["br"] and 0 < len(body) < len(BODY) // 10


def test_vary_and_headers(srv):
    _, h, _ = get(srv, "/big.txt", "Accept-Encoding: gzip\r\n")
    assert "accept-encoding" in ",".join(h.get("vary", [])).lower()
    assert "content-length" not in h
    assert all(e.startswith("W/") for e in h.get("etag", []))
    _, h, body = get(srv, "/big.txt")  # identity client still sees Vary
    assert body == BODY and "content-encoding" not in h
    assert "accept-encoding" in ",".join(h.get("vary", [])).lower()


def test_skip_rules(srv):
    for target, hdrs, method in [("/small.txt", "", "GET"), ("/img.png", "", "GET"),
                                 ("/big.txt", "", "HEAD"), ("/big.txt", "Range: bytes=0-9\r\n", "GET")]:
        st, h, _ = get(srv, target, "Accept-Encoding: gzip\r\n" + hdrs, method)
        assert "content-encoding" not in h, target


def test_range_identity(srv):
    st, h, body = get(srv, "/big.txt", "Accept-Encoding: gzip\r\nRange: bytes=0-9\r\n")
    assert (st, body) == (206, BODY[:10])


def test_sensitive_default_off(srv):
    for hdr in ("Cookie: s=1\r\n", "Authorization: Basic eDp5\r\n"):
        _, h, body = get(srv, "/big.txt", "Accept-Encoding: gzip\r\n" + hdr)
        assert "content-encoding" not in h and body == BODY
