"""Rewrites, redirects and header operations (src/route/rewrite.c, src/filters/headers.c)."""
import subprocess

from process_util import connect
from test_h1_conn import Reader


def get(srv, target, headers=""):
    with connect(srv.ports["http"]) as s:
        s.sendall(f"GET {target} HTTP/1.1\r\nHost: x\r\n{headers}Connection: close\r\n\r\n".encode())
        st, hdrs, body = Reader(s).response()
        return st, {k: v[0] for k, v in hdrs.items()}, body


def conf(body):
    return "workers 1;\nserver { listen 127.0.0.1:@HTTP_PORT@;\n" + body + "\n}\n"


def run_t(bastion_bin, tmp_path, text):
    f = tmp_path / "t.conf"
    f.write_text(text)
    return subprocess.run([bastion_bin, "-c", str(f), "-t"], capture_output=True, text=True,
                          timeout=20)


def test_rewrite_last_rematches(bastion):
    srv = bastion(conf('rewrite "^/old/(.*)$" /new/$1 last;\n'
                       'location /new/ { return 200 "new:$uri"; }\n'
                       'location /old/ { return 200 "old"; }'))
    st, _, body = get(srv, "/old/a")
    assert (st, body) == (200, b"new:/new/a")


def test_rewrite_break_keeps_location(bastion):
    srv = bastion(conf('location /old/ { rewrite "^/old/(.*)$" /new/$1 break;'
                       ' return 200 "in-old:$uri"; }\n'
                       'location /new/ { return 200 "new"; }'))
    assert get(srv, "/old/a")[2] == b"in-old:/new/a"


def test_rewrite_loop(bastion):
    srv = bastion(conf('rewrite_max_cycles 3;\n'
                       'location /a { rewrite "^/a$" /b last; return 200 "a"; }\n'
                       'location /b { rewrite "^/b$" /a last; return 200 "b"; }\n'
                       'location /z { return 200 "z"; }'))
    assert get(srv, "/a")[0] == 500
    assert srv.workers()
    assert get(srv, "/z")[0] == 200


def test_redirect_captures(bastion):
    srv = bastion(conf('location ~ "^/old/(.*)$" { redirect 301 /new/$1; }'))
    st, h, _ = get(srv, "/old/x/y?a=1&b=2")
    assert st == 301
    assert h["location"] == "/new/x/y?a=1&b=2"


def test_redirect_https(bastion):
    srv = bastion(conf("redirect_https;"))
    st, h, _ = get(srv, "/p?q=1")
    assert st == 301
    assert h["location"] == "https://x/p?q=1"


def test_header_crlf_injection(bastion):
    srv = bastion(conf('header_set X-Echo "$uri"; header_set X-Ok fine;'
                       ' return 200 "ok";'))
    st, h, body = get(srv, "/a%0d%0aSet-Cookie:%20evil=1")
    assert st == 200 and body == b"ok"
    assert "x-echo" not in h and "set-cookie" not in h  # dropped whole, no split
    assert h["x-ok"] == "fine"
    assert get(srv, "/fine")[1]["x-echo"] == "/fine"


def test_redirect_crlf_refused(bastion):
    srv = bastion(conf('location /go { redirect 302 /x/$arg_v; }'))
    st, h, _ = get(srv, "/go?v=a%0d%0ab")  # raw bytes are not decoded: harmless
    assert st == 302 and "\r" not in h["location"]
    srv2 = bastion(conf('location /go { redirect 302 $uri; }'))
    assert get(srv2, "/go%0d%0aX:1")[0] == 500


def test_open_redirect_scheme(bastion_bin, tmp_path):
    p = run_t(bastion_bin, tmp_path,
              'server { listen 127.0.0.1:18080; location / { redirect 302 $arg_next; } }\n')
    assert p.returncode == 0
    assert "open redirect" in p.stderr
    ok = run_t(bastion_bin, tmp_path,
               'server { listen 127.0.0.1:18080; location / { redirect 302 /x/$arg_next; } }\n')
    assert "open redirect" not in ok.stderr


def test_expires_immutable(bastion):
    srv = bastion(conf('location /a { expires 1h immutable; return 200 "a"; }\n'
                       'location /b { expires off; return 200 "b"; }'))
    h = get(srv, "/a")[1]
    assert h["cache-control"] == "max-age=3600, immutable"
    assert "expires" in h
    assert "cache-control" not in get(srv, "/b")[1]


def test_header_on_errors(bastion):
    srv = bastion(conf('header_set X-A 1; header_set X-B 2 always;'
                       ' location /e { return 404; }'))
    h = get(srv, "/e")[1]
    assert "x-a" not in h and h["x-b"] == "2"
    assert get(srv, "/missing-never")[1]["x-b"] == "2"


def test_header_remove_and_request_header(bastion):
    srv = bastion(conf('request_header_set X-In "got-$http_x_src"; header_remove Content-Type;'
                       ' header_set X-Seen "$http_x_in"; return 200 "ok";'))
    h = get(srv, "/", "X-Src: abc\r\n")[1]
    assert h["x-seen"] == "got-abc"
    assert "content-type" not in h


def test_reserved_header_refused(bastion_bin, tmp_path):
    p = run_t(bastion_bin, tmp_path,
              'server { listen 127.0.0.1:18080; header_set Content-Length 5; }\n')
    assert p.returncode != 0
    assert "protocol" in p.stderr
