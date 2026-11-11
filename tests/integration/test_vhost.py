"""Virtual host selection (src/route/vhost.c) against the real binary, on both backends."""
import subprocess

import pytest

from process_util import connect
from test_h1_conn import Reader


def server(name, body, extra=""):
    names = f"name {name};" if name else ""
    return f'server {{ listen 127.0.0.1:@HTTP_PORT@ {extra}; {names} return 200 "{body}"; }}\n'


def ask(srv, host, version="1.1"):
    with connect(srv.ports["http"]) as s:
        s.sendall(f"GET / HTTP/{version}\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        r = Reader(s)
        try:
            return r.response()
        except EOFError:
            return None


def test_exact_wildcard_and_default(bastion):
    srv = bastion("workers 1;\n" + server("exact.example.com", "exact") +
                  server("*.example.com", "wild") + server("www.*", "trail") +
                  server("", "default"))
    assert ask(srv, "exact.example.com")[2] == b"exact"
    assert ask(srv, "EXACT.Example.COM:80")[2] == b"exact"
    assert ask(srv, "a.b.example.com")[2] == b"wild"
    assert ask(srv, "www.example.org")[2] == b"trail"
    assert ask(srv, "nothing.test")[2] == b"default"
    assert ask(srv, "example.com.")[2] == b"default"


def test_default_server_flag(bastion):
    srv = bastion("workers 1;\n" + server("a.test", "a") +
                  server("b.test", "b", "default_server"))
    assert ask(srv, "a.test")[2] == b"a"
    assert ask(srv, "zzz.test")[2] == b"b"


def test_unknown_host_default_answers(bastion):
    srv = bastion("workers 1;\n" + server("a.test", "a"))
    assert ask(srv, "zzz.test")[2] == b"a"


def test_unknown_host_421(bastion):
    srv = bastion("workers 1;\n" + server("a.test", "a") +
                  'server { listen 127.0.0.1:@HTTP_PORT@ default_server; name b.test; '
                  'unknown_host 421; return 200 "b"; }\n')
    st, _, _ = ask(srv, "zzz.test")
    assert st == 421
    assert ask(srv, "a.test")[2] == b"a"


def test_unknown_host_close(bastion):
    srv = bastion("workers 1;\n" + server("a.test", "a") +
                  'server { listen 127.0.0.1:@HTTP_PORT@ default_server; name b.test; '
                  'unknown_host close; return 200 "b"; }\n')
    assert ask(srv, "zzz.test") is None  # closed with no response at all
    assert ask(srv, "a.test")[2] == b"a"
    assert ask(srv, "b.test")[2] == b"b"
    assert srv.workers()  # the worker is fine


def run_t(bastion_bin, tmp_path, text):
    conf = tmp_path / "t.conf"
    conf.write_text(text)
    return subprocess.run([bastion_bin, "-c", str(conf), "-t"], capture_output=True, text=True,
                          timeout=20)


@pytest.mark.parametrize("name", ["a*.example.com", "*", "*.*", "example.*.com", "*x.com", "~"])
def test_bad_wildcard_forms_refused(bastion_bin, tmp_path, name):
    p = run_t(bastion_bin, tmp_path, f'server {{ listen 127.0.0.1:18080; name "{name}"; }}\n')
    assert p.returncode != 0
    assert "name" in p.stderr


def test_good_name_forms_accepted(bastion_bin, tmp_path):
    p = run_t(bastion_bin, tmp_path,
              'server { listen 127.0.0.1:18080; name a.test *.a.test a.* "~^b[0-9]$"; }\n')
    assert p.returncode == 0, p.stderr


def test_two_default_servers_refused(bastion_bin, tmp_path):
    p = run_t(bastion_bin, tmp_path,
              "server { listen 127.0.0.1:18080 default_server; name a; }\n"
              "server { listen 127.0.0.1:18080 default_server; name b; }\n")
    assert p.returncode != 0
    assert "default_server" in p.stderr
    assert ":2:" in p.stderr  # the second one is named


def test_unknown_host_bad_value(bastion_bin, tmp_path):
    p = run_t(bastion_bin, tmp_path, "server { listen 127.0.0.1:18080; unknown_host 404; }\n")
    assert p.returncode != 0
