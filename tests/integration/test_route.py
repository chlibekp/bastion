"""Routing end to end (src/route/router.c): the location a request reaches, bad paths, and a
regex that hits its limit. Each location answers with `return`, so the body names the match."""
import socket

import pytest

from process_util import connect
from test_h1_conn import Reader


def get(srv, path, host="localhost", extra=""):
    with connect(srv.ports["http"]) as s:
        s.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\n{extra}Connection: close\r\n\r\n"
                  .encode())
        try:
            return Reader(s).response()
        except EOFError:
            return None


def conf(body, top=""):
    return f"workers 1;\n{top}\nserver {{ listen 127.0.0.1:@HTTP_PORT@; {body} }}\n"


def test_location_precedence(bastion):
    srv = bastion(conf('''
        return 200 server;
        location / { return 200 root; }
        location /a/ { return 200 prefix-a; }
        location ^~ /img/ { return 200 img; }
        location ~ \\.png$ { return 200 png; }
        location = /exact { return 200 exact; }
        location /a/b/ { location ~ ^/a/b/(\\d+)$ { return 200 nested-regex; } }
    '''))
    assert get(srv, "/")[2] == b"root"
    assert get(srv, "/a/x")[2] == b"prefix-a"
    assert get(srv, "/img/x.png")[2] == b"img"
    assert get(srv, "/other/x.png")[2] == b"png"
    assert get(srv, "/exact")[2] == b"exact"
    assert get(srv, "/exact/")[2] == b"root"
    assert get(srv, "/a/b/12")[2] == b"nested-regex"
    assert get(srv, "/a/b/zz")[2] == b"server"  # /a/b/ itself has no handler of its own


def test_normalization_decides_the_location(bastion):
    srv = bastion(conf('''
        location / { return 200 root; }
        location /private/ { return 403 denied; }
    '''))
    # dot segments, encoded dots and slashes are resolved before matching
    assert get(srv, "/x/../private/a")[0] == 403
    assert get(srv, "/%70rivate/a")[0] == 403
    assert get(srv, "//private//a")[0] == 403  # merge_slashes is on by default
    assert get(srv, "/a/%2e%2e/%2e%2e/private/")[0] == 403
    assert get(srv, "/priv%61te/")[0] == 403


@pytest.mark.parametrize("path", ["/a%2fb", "/%00", "/a%zz", "/%", "/a%2"])
def test_bad_paths_are_400(bastion, path):
    srv = bastion(conf("return 200 ok;"))
    st = get(srv, path)
    assert st is not None and st[0] == 400


def test_merge_slashes_off(bastion):
    srv = bastion(conf("merge_slashes off; location /a/ { return 200 a; } location / { return 200 root; }"))
    assert get(srv, "/a/b")[2] == b"a"
    assert get(srv, "//a/b")[2] == b"root"


def test_regex_limit_is_500_and_worker_survives(bastion):
    srv = bastion(conf('''
        location ~ (a+)+$ { return 200 never; }
        location / { return 200 ok; }
    '''), )
    pid = srv.workers()[0]
    path = "/" + "a" * 3000 + "b"
    st = get(srv, path)
    assert st[0] == 500
    assert get(srv, "/fine")[2] == b"ok"
    assert srv.workers() == {0: pid}
    srv.wait_log(r"route: regex limit reached")


def test_regex_limit_configurable(bastion):
    srv = bastion(conf("location ~ ^/(a+)+$ { return 200 never; } location / { return 200 ok; }",
                       top="regex_match_limit 150;"))
    assert get(srv, "/" + "a" * 40 + "b")[0] == 500
    assert get(srv, "/aaaa")[2] == b"never"
