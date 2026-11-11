"""index, try_files, autoindex, error_page and internal (static.c, autoindex.c, router.c)."""
import json
import os
import re
import socket
import time

import pytest

from process_util import connect
from test_h1_conn import Reader


def get(srv, target, headers="", method="GET", timeout=30):
    with connect(srv.ports["http"]) as s:
        s.settimeout(timeout)
        s.sendall(f"{method} {target} HTTP/1.1\r\nHost: x\r\n{headers}Connection: close\r\n\r\n".encode("latin-1"))
        return Reader(s).response(head_only=method == "HEAD", timeout=timeout)


def conf(www, body=""):
    return f'workers 1;\nserver {{ listen 127.0.0.1:@HTTP_PORT@; root {www}; {body} }}\n'


@pytest.fixture
def www(tmp_path):
    w = tmp_path / "www"
    (w / "docs").mkdir(parents=True)
    (w / "bare").mkdir()
    (w / "index.html").write_bytes(b"<h1>home</h1>")
    (w / "docs" / "index.html").write_bytes(b"docs index")
    (w / "docs" / "a.txt").write_bytes(b"a")
    (w / "app.js").write_bytes(b"js")
    (w / "bare" / "file.txt").write_bytes(b"x")
    (w / "404.html").write_bytes(b"custom not found")
    return w


def test_index(bastion, www):
    srv = bastion(conf(www))
    st, h, body = get(srv, "/")
    assert (st, body) == (200, b"<h1>home</h1>")
    assert h["content-type"] == ["text/html; charset=utf-8"]
    assert get(srv, "/docs/")[2] == b"docs index"
    assert get(srv, "/bare/")[0] == 403  # no index, no listing
    assert get(srv, "/docs")[0] == 301


def test_index_order(bastion, www):
    (www / "bare" / "default.htm").write_bytes(b"default")
    srv = bastion(conf(www, "index missing.html default.htm index.html;"))
    assert get(srv, "/bare/")[2] == b"default"


def test_spa_fallback(bastion, www):
    srv = bastion(conf(www, "location / { try_files $uri $uri/ /index.html; }"))
    assert get(srv, "/app.js")[2] == b"js"
    st, _, body = get(srv, "/some/client/route")
    assert (st, body) == (200, b"<h1>home</h1>")
    assert get(srv, "/docs/")[2] == b"docs index"
    assert get(srv, "/docs/a.txt")[2] == b"a"


def test_try_files_code(bastion, www):
    srv = bastion(conf(www, "location /api/ { try_files $uri =404; }"))
    st, _, _ = get(srv, "/api/nothing")
    assert st == 404
    srv2 = bastion(conf(www, "location / { try_files $uri =418; }"))
    assert get(srv2, "/nothing")[0] == 418
    assert get(srv2, "/app.js")[0] == 200


def test_try_files_loop_is_bounded(bastion, www):
    srv = bastion(conf(www, "rewrite_max_cycles 3; location / { try_files $uri /again; }"))
    assert get(srv, "/missing")[0] == 500
    assert srv.workers()


def test_autoindex_default_off(bastion, www):
    srv = bastion(conf(www))
    assert get(srv, "/bare/")[0] == 403


def test_autoindex_html(bastion, www):
    srv = bastion(conf(www, "autoindex on;"))
    st, h, body = get(srv, "/bare/")
    assert st == 200 and h["content-type"] == ["text/html; charset=utf-8"]
    assert b'<a href="file.txt">file.txt</a>' in body and b'<a href="../">' in body
    assert body.rstrip().endswith(b"</html>")
    st, _, body = get(srv, "/docs/")
    assert body == b"docs index"  # an index file wins over the listing


def test_autoindex_escaping(bastion, www):
    d = www / "weird"
    d.mkdir()
    names = [b"<script>\"'&.txt", b"bad\xff\xfe.bin", b"sp ace.txt", b"ctl\x01x", b".hidden", b"\xe2\x82\xac.txt"]
    for n in names:
        open(os.path.join(os.fsencode(d), n), "wb").write(b"1")
    (d / "sub").mkdir()
    srv = bastion(conf(www, "autoindex on;"))
    body = get(srv, "/weird/")[2]
    assert b"<script>" not in body and b"</script>" not in body
    assert b"&lt;script&gt;&quot;&#39;&amp;.txt" in body
    assert b"%3Cscript%3E%22%27%26.txt" in body  # the href is percent-encoded
    assert b"bad&#xFFFD;&#xFFFD;.bin" in body
    assert b"ctl&#xFFFD;x" in body
    assert b".hidden" not in body
    assert "€.txt".encode() in body and b"sp%20ace.txt" in body
    assert b'<a href="sub/">sub/</a>' in body
    srv_j = bastion(conf(www, "autoindex on; autoindex_format json;"))
    st, h, jb = get(srv_j, "/weird/")
    assert h["content-type"] == ["application/json; charset=utf-8"]
    data = json.loads(jb.decode("utf-8"))
    byname = {e["name"]: e for e in data}
    assert "<script>\"'&.txt" in byname and "bad��.bin" in byname
    assert ".hidden" not in byname and byname["sub"]["type"] == "directory"
    assert byname["sp ace.txt"]["size"] == 1 and byname["sub"]["size"] is None
    srv_d = bastion(conf(www, "autoindex on; dotfiles allow;"))
    assert b".hidden" in get(srv_d, "/weird/")[2]


def rss_kb(pid):
    for line in open(f"/proc/{pid}/status"):
        if line.startswith("VmRSS:"):
            return int(line.split()[1])


def test_autoindex_huge_dir(bastion, www):
    big = www / "huge"
    big.mkdir()
    for i in range(100_000):
        with open(big / f"file-{i:06d}.txt", "wb"):
            pass
    srv = bastion(conf(www, "autoindex on; autoindex_format json;"))
    pid = next(iter(srv.workers().values()))
    before = rss_kb(pid)
    with connect(srv.ports["http"]) as s:
        s.settimeout(60)
        s.sendall(b"GET /huge/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        buf = s.recv(4096)
        time.sleep(1)  # the client is slow: the listing waits for it
        grown = rss_kb(pid) - before
        # the worker is not stalled by the open listing
        t0 = time.time()
        assert get(srv, "/index.html")[0] == 200
        assert time.time() - t0 < 5
        total = len(buf)
        while True:
            d = s.recv(1 << 16)
            if not d:
                break
            buf += d
    assert grown < 32 * 1024, f"RSS grew {grown} kB"
    body = buf.partition(b"\r\n\r\n")[2]
    assert body.count(b"file-") == 100_000


def test_error_page(bastion, www):
    srv = bastion(conf(www, "error_page 404 /404.html;"))
    st, h, body = get(srv, "/nope")
    assert st == 404 and body == b"custom not found"
    assert h["content-type"] == ["text/html; charset=utf-8"]
    assert get(srv, "/index.html")[0] == 200
    st, _, body = get(srv, "/nope", method="HEAD")
    assert st == 404 and body == b""


def test_error_page_loop_gives_default(bastion, www):
    (www / "404.html").unlink()
    srv = bastion(conf(www, "error_page 404 /404.html;"))
    st, _, body = get(srv, "/nope")
    assert st == 404 and b"<center><h1>404 Not Found</h1></center>" in body  # the built-in page
    assert srv.workers()


def test_error_page_other_codes(bastion, www):
    srv = bastion(conf(www, "error_page 403 /404.html; "))
    st, _, body = get(srv, "/bare/")
    assert st == 403 and body == b"custom not found"


def test_internal_location(bastion, www):
    (www / "e" / "errors").mkdir(parents=True)
    (www / "e" / "errors" / "404.html").write_bytes(b"internal page")
    srv = bastion(conf(www, "error_page 404 /errors/404.html;\n"
                            "location /errors/ { internal; root " + str(www / "e") + "; }"))
    st, _, body = get(srv, "/errors/404.html")
    assert st == 404 and body == b"internal page"  # even this 404 is an error_page: the loop guard answers
    st, _, body = get(srv, "/nothing-here")
    assert st == 404 and body == b"internal page"  # reached internally: allowed


def test_internal_direct_is_404_default(bastion, www):
    srv = bastion(conf(www, "location /secret/ { internal; return 200 \"hidden\"; }\n"
                            "location /open/ { return 200 \"open\"; }"))
    st, _, body = get(srv, "/secret/")
    assert st == 404 and b"hidden" not in body
    assert get(srv, "/open/")[2] == b"open"


def test_try_files_internal_reroute_reaches_internal(bastion, www):
    srv = bastion(conf(www, "location / { try_files $uri /fallback; }\n"
                            "location /fallback { internal; return 200 \"via-internal\"; }"))
    assert get(srv, "/missing")[2] == b"via-internal"
    assert get(srv, "/fallback")[0] == 404
