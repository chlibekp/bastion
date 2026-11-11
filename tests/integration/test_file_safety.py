"""Safe file resolution (src/handlers/resolve.c, ofcache.c): nothing below `root` can leave it,
dotfiles and links are refused, special files do not hang a worker."""
import os
import socket
import stat
from pathlib import Path

import pytest

from process_util import connect
from test_h1_conn import Reader

CORPUS = Path(__file__).resolve().parents[1] / "corpus" / "traversal.txt"
CANARY = b"CANARY-OUTSIDE-THE-ROOT"


def raw_get(srv, target):
    with connect(srv.ports["http"]) as s:
        s.settimeout(5)
        s.sendall(b"GET " + target + b" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        try:
            return Reader(s).response()
        except (EOFError, ConnectionError):
            return None


@pytest.fixture
def site(tmp_path):
    base = tmp_path / "site"
    www = base / "www"
    (www / "dir").mkdir(parents=True)
    (www / ".git").mkdir()
    (base / "secret.txt").write_bytes(CANARY)
    (www / "a.txt").write_bytes(b"hello a\n")
    (www / "dir" / "b.txt").write_bytes(b"hello b\n")
    (www / ".env").write_bytes(b"SECRET=1\n")
    (www / ".git" / "config").write_bytes(b"[core]\n")
    (www / "link").symlink_to("a.txt")
    (www / "esc").symlink_to("/etc/passwd")
    (www / "up").symlink_to("../secret.txt")
    os.mkfifo(www / "fifo")
    return www


def conf(site, extra=""):
    return f'workers 1;\nserver {{ listen 127.0.0.1:@HTTP_PORT@; root {site}; {extra} }}\n'


def corpus():
    out = []
    for line in CORPUS.read_text().splitlines():
        if line.strip() and not line.startswith("#"):
            out.append(line.strip())
    return out


def test_serves_a_file(bastion, site):
    srv = bastion(conf(site))
    st, h, body = raw_get(srv, b"/a.txt")
    assert (st, body) == (200, b"hello a\n")
    assert h["content-length"] == ["8"]
    assert raw_get(srv, b"/dir/b.txt")[2] == b"hello b\n"
    assert raw_get(srv, b"/missing")[0] == 404


@pytest.mark.parametrize("target", corpus())
def test_traversal_corpus(bastion, site, target):
    srv = bastion(conf(site, "symlinks on;"))  # the most permissive link setting
    r = raw_get(srv, target.encode("latin-1"))
    if r is not None:  # a closed connection is a refusal too
        st, _, body = r
        assert st in (400, 403, 404), (target, st)
        assert CANARY not in body and b"root:" not in body
    assert srv.workers()


def test_symlink_off(bastion, site):
    srv = bastion(conf(site))
    assert raw_get(srv, b"/link")[0] == 404
    assert raw_get(srv, b"/a.txt")[0] == 200


def test_symlink_on_inside_root(bastion, site):
    srv = bastion(conf(site, "symlinks on;"))
    assert raw_get(srv, b"/link")[2] == b"hello a\n"


def test_symlink_escape(bastion, site):
    srv = bastion(conf(site, "symlinks on;"))
    for t in (b"/esc", b"/up"):
        st, _, body = raw_get(srv, t)
        assert st == 404 and CANARY not in body and b"root:" not in body


def test_symlink_owner_match(bastion, site):
    srv = bastion(conf(site, "symlinks owner_match;"))
    assert raw_get(srv, b"/link")[2] == b"hello a\n"  # same owner as the root
    assert raw_get(srv, b"/up")[0] == 404  # beneath is still enforced


def test_dotfile_denied(bastion, site):
    srv = bastion(conf(site))
    assert raw_get(srv, b"/.env")[0] == 404
    assert raw_get(srv, b"/.git/config")[0] == 404
    assert raw_get(srv, b"/dir/.hidden")[0] == 404


def test_dotfile_allowed(bastion, site):
    srv = bastion(conf(site, "dotfiles allow;"))
    assert raw_get(srv, b"/.env")[2] == b"SECRET=1\n"


def test_dir_is_not_file(bastion, site):
    srv = bastion(conf(site))
    st, h, _ = raw_get(srv, b"/dir")
    assert st == 301 and h["location"] == ["/dir/"]
    st, h, _ = raw_get(srv, b"/dir?x=1")
    assert h["location"] == ["/dir/?x=1"]
    assert raw_get(srv, b"/a.txt/")[0] == 404


def test_special_files(bastion, site):
    srv = bastion(conf(site))
    assert raw_get(srv, b"/fifo")[0] == 403  # answered at once: the worker did not block
    assert raw_get(srv, b"/a.txt")[0] == 200
    assert srv.workers()


def test_alias(bastion, site):
    srv = bastion(f'workers 1;\nserver {{ listen 127.0.0.1:@HTTP_PORT@; '
                  f'location /files/ {{ alias {site}/dir/; }} }}\n')
    assert raw_get(srv, b"/files/b.txt")[2] == b"hello b\n"
    assert raw_get(srv, b"/files/../a.txt")[0] == 404  # normalized to /a.txt: no location


def test_open_file_cache(bastion, site):
    srv = bastion(f'workers 1;\nopen_file_cache max=10 ttl=30s errors=on;\n' + conf(site).split("\n", 1)[1])
    for _ in range(3):
        assert raw_get(srv, b"/a.txt")[2] == b"hello a\n"
        assert raw_get(srv, b"/nope")[0] == 404
    (site / "a.txt").unlink()  # held by the cache for the ttl
    assert raw_get(srv, b"/a.txt")[2] == b"hello a\n"


def test_missing_root_is_a_startup_error(bastion_bin, tmp_path):
    import subprocess
    conf_file = tmp_path / "c.conf"
    conf_file.write_text(f"server {{ listen 127.0.0.1:18080; root {tmp_path}/nope; }}\n")
    p = subprocess.run([bastion_bin, "-c", str(conf_file)], capture_output=True, text=True,
                       timeout=20)
    assert p.returncode != 0
    assert "nope" in p.stderr


def test_relative_root_refused(bastion_bin, tmp_path):
    import subprocess
    conf_file = tmp_path / "c.conf"
    conf_file.write_text("server { listen 127.0.0.1:18080; root www; }\n")
    p = subprocess.run([bastion_bin, "-c", str(conf_file), "-t"], capture_output=True, text=True,
                       timeout=20)
    assert p.returncode != 0 and "absolute" in p.stderr
