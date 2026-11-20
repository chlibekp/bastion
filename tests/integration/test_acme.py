"""ACME (src/ops/acme*.c) against a local Pebble CA (tests/integration/acme_util.py). No test here
contacts a public CA: the directory is always Pebble's on loopback, or a fake in this file, and a
test build refuses public CA URLs outright."""
import http.client
import http.server
import os
import re
import socket
import ssl
import stat
import subprocess
import threading
import time

import pytest

from acme_util import Pebble, have_pebble, make_cert, served_cert, wait_issuer
from conftest import _free_port

pytestmark = pytest.mark.skipif(not have_pebble(), reason="pebble is not installed (docker/dev.Dockerfile)")

ENV = {"BST_TEST_ACME_FIRST_MS": "200", "BST_TEST_ACME_BACKOFF_S": "1",
       "BST_TEST_ACME_CHECK_MS": "1000", "BST_TEST_ACME_TIMEOUT_MS": "5000",
       "BST_TEST_ACME_VALIDATION_MS": "20000"}
NAME = "a.example.test"


def site(tmp_path):
    www = tmp_path / "www"
    www.mkdir(parents=True, exist_ok=True)
    (www / "index.html").write_text("hello acme\n")
    return www


def server_block(http, https, names=NAME, extra=""):
    return (f"server {{ listen 127.0.0.1:{http}; listen 127.0.0.1:{https} tls http2; name {names}; "
            f"tls auto; root @WORKDIR@/www; {extra} }}\n")


@pytest.fixture
def ports():
    return _free_port(socket.SOCK_STREAM), _free_port(socket.SOCK_STREAM)


@pytest.fixture
def pebble(tmp_path, ports):
    p = Pebble(tmp_path, *ports)
    yield p
    p.stop()


def https_get(port, name, path="/"):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    c = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=5)
    c.sock = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=5), server_hostname=name)
    c.request("GET", path, headers={"Host": name})
    r = c.getresponse()
    body = r.read()
    c.close()
    return r.status, body


def http_get(port, name, path):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request("GET", path, headers={"Host": name})
    r = c.getresponse()
    body = r.read()
    hdrs = dict(r.getheaders())
    c.close()
    return r.status, body, hdrs


def store_cert(tmp_path, name, days):
    """A certificate already in storage, as a previous issuance would have left it."""
    d = tmp_path / "acme" / "certs" / name
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(tmp_path / "acme", 0o700)
    crt, key = make_cert(d, "prev", [f"DNS:{name}"], days=days, cn="previous " + name)
    os.rename(crt, d / "cert.pem")
    os.rename(key, d / "key.pem")
    os.chmod(d / "key.pem", 0o600)
    return served_serial_of(d / "cert.pem")


def served_serial_of(path):
    out = subprocess.run(["openssl", "x509", "-in", str(path), "-noout", "-serial"], capture_output=True,
                         check=True).stdout.decode()
    return out.strip().split("=")[1]


def serial(text):
    return re.search(r"serial=(\w+)", text).group(1)


def test_http01_issue(bastion, tmp_path, ports, pebble):
    site(tmp_path)
    pebble.start()
    srv = bastion(pebble.acme_block() + server_block(*ports), env=ENV)
    srv.wait_log(rf"acme: {NAME}: certificate installed", timeout=40)
    text = wait_issuer(srv, ports[1], NAME, "Pebble")
    assert f"DNS:{NAME}" in text
    assert https_get(ports[1], NAME) == (200, b"hello acme\n")
    # the challenge was answered by a worker from the shared table
    assert re.search(r"GET /\.well-known/acme-challenge/", pebble.log()) or "http-01" in srv.logs()
    assert not (tmp_path / "acme" / "certs" / NAME / "temp").exists()


def test_alpn_issue(bastion, tmp_path, ports, pebble):
    site(tmp_path)
    pebble.start()
    srv = bastion(pebble.acme_block("challenge tls-alpn-01;") + server_block(*ports), env=ENV)
    srv.wait_log(rf"acme: {NAME}: certificate installed", timeout=40)
    wait_issuer(srv, ports[1], NAME, "Pebble")
    assert "(tls-alpn-01)" in srv.logs()


def test_dns_hook_issue(bastion, tmp_path, ports, pebble):
    site(tmp_path)
    pebble.start()
    calls = tmp_path / "hook-calls"
    hook = tmp_path / "dns-hook"
    hook.write_text(f"""#!/bin/sh
echo "$1 $2 $3 env=$(env | grep -cv '^PATH=\\|^LANG=\\|^PWD=\\|^SHLVL=\\|^_=')" >> {calls}
case "$1" in
set) exec curl -sf -X POST -d "{{\\"host\\":\\"_acme-challenge.$2.\\",\\"value\\":\\"$3\\"}}" \
        http://127.0.0.1:{pebble.dns_mgmt}/set-txt ;;
clear) exec curl -sf -X POST -d "{{\\"host\\":\\"_acme-challenge.$2.\\"}}" \
        http://127.0.0.1:{pebble.dns_mgmt}/clear-txt ;;
esac
exit 2
""")
    hook.chmod(0o755)
    srv = bastion(pebble.acme_block(f"challenge dns-01; dns_hook {hook};") +
                  server_block(*ports, names=f"{NAME} *.w.example.test"), env=ENV)
    srv.wait_log(rf"acme: {NAME}: certificate installed", timeout=40)
    text = wait_issuer(srv, ports[1], NAME, "Pebble")
    assert "DNS:*.w.example.test" in text
    lines = calls.read_text().splitlines()
    sets = [l for l in lines if l.startswith("set ")]
    assert {l.split()[1] for l in sets} == {NAME, "w.example.test"}
    assert all(re.fullmatch(r"set \S+ [A-Za-z0-9_-]{43} env=0", l) for l in sets), lines
    assert len([l for l in lines if l.startswith("clear ")]) == len(sets)


def test_temp_cert_before_issue(bastion, tmp_path, ports, pebble):
    site(tmp_path)
    # the CA is down: the server still serves at once, on a temporary self-signed certificate
    srv = bastion(pebble.acme_block() + server_block(*ports), env=ENV)
    text = served_cert(ports[1], NAME)
    assert f"subject=CN={NAME}" in text.replace(" ", "") and f"issuer=CN={NAME}" in text.replace(" ", "")
    assert https_get(ports[1], NAME) == (200, b"hello acme\n")
    assert (tmp_path / "acme" / "certs" / NAME / "temp").exists()
    srv.wait_log(rf"acme: {NAME}: .*retry in 1s", timeout=10)
    # and once the CA is back, the real one replaces it
    pebble.start()
    wait_issuer(srv, ports[1], NAME, "Pebble", timeout=40)


def test_renewal(bastion, tmp_path, ports, pebble):
    site(tmp_path)
    old = store_cert(tmp_path, NAME, days=2)  # inside renew_before (30d)
    srv = bastion(pebble.acme_block() + server_block(*ports), env=ENV)
    assert serial(served_cert(ports[1], NAME)).upper() == old.upper()
    failures, done = [], threading.Event()

    def load():
        while not done.is_set():
            try:
                st, body = https_get(ports[1], NAME)
                if st != 200 or body != b"hello acme\n":
                    failures.append(st)
            except OSError as e:
                failures.append(repr(e))
    t = threading.Thread(target=load)
    t.start()
    try:
        pebble.start()
        srv.wait_log(rf"acme: {NAME}: expires in \d+h: requesting one", timeout=20)
        wait_issuer(srv, ports[1], NAME, "Pebble", timeout=40)
        time.sleep(1)
    finally:
        done.set()
        t.join()
    assert failures == []


def test_ca_down_keeps_cert(bastion, tmp_path, ports, pebble):
    site(tmp_path)
    old = store_cert(tmp_path, NAME, days=10)
    srv = bastion(pebble.acme_block() + server_block(*ports), env=ENV)  # pebble never started
    srv.wait_log(rf"acme: {NAME}: .*the current certificate stays; retry in 1s \(failure 1\)", timeout=10)
    srv.wait_log(rf"retry in 2s \(failure 2\)", timeout=10)
    srv.wait_log(rf"retry in 4s \(failure 3\)", timeout=15)
    assert serial(served_cert(ports[1], NAME)).upper() == old.upper()
    assert https_get(ports[1], NAME) == (200, b"hello acme\n")


class FakeCA:
    """An HTTPS server answering every request with one canned response."""

    def __init__(self, tmp):
        self.crt, self.key = make_cert(tmp, "fakeca", ["IP:127.0.0.1"])
        self.status, self.headers, self.body = 200, {}, b""
        self.hits = []
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def handle_one(self):
                outer.hits.append((self.command, self.path, time.monotonic()))
                self.send_response(outer.status)
                for k, v in outer.headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(outer.body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(outer.body)
            do_GET = do_POST = do_HEAD = handle_one

            def log_message(self, *a):
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.crt, self.key)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def block(self):
        return (f"acme {{ ca https://127.0.0.1:{self.port}/dir; ca_root {self.crt}; "
                f"storage @WORKDIR@/acme; }}\n")

    def stop(self):
        self.httpd.shutdown()


def test_order_failure_backoff(bastion, tmp_path, ports, pebble):
    site(tmp_path)
    # validation fails: Pebble's HTTP-01 port reaches nothing
    pebble.http_port = _free_port(socket.SOCK_STREAM)
    pebble.start()
    srv = bastion(pebble.acme_block() + server_block(*ports), env=ENV)
    srv.wait_log(r"validation failed.*retry in 1s \(failure 1\)", timeout=30)
    srv.wait_log(r"retry in 2s \(failure 2\)", timeout=30)
    t0 = time.monotonic()
    time.sleep(3)
    attempts = len(re.findall(rf"acme: {NAME}: no certificate.*requesting one|"
                              rf"acme: {NAME}: only a temporary certificate: requesting one", srv.logs()))
    assert attempts <= 4, f"{attempts} attempts in {time.monotonic() - t0:.1f}s: a tight retry loop"


def test_retry_after_respected(bastion, tmp_path, ports):
    site(tmp_path)
    ca = FakeCA(tmp_path)
    try:
        ca.status, ca.headers = 503, {"Retry-After": "7", "Content-Type": "application/problem+json"}
        ca.body = b'{"type":"urn:ietf:params:acme:error:rateLimited","detail":"slow down"}'
        srv = bastion(ca.block() + server_block(*ports), env=ENV)
        srv.wait_log(r"HTTP 503 urn:ietf:params:acme:error:rateLimited: slow down: the current certificate "
                     r"stays; retry in 7s", timeout=10)
        time.sleep(2)
        assert len(ca.hits) == 1, ca.hits  # waits the 7 s the CA asked for, not the 1 s base
    finally:
        ca.stop()


def test_multi_domain(bastion, tmp_path, ports, pebble):
    site(tmp_path)
    pebble.start()
    pebble.set_a("b.example.test", "127.0.0.9")  # nothing listens there: validation fails
    srv = bastion(pebble.acme_block() + server_block(*ports, names=f"{NAME} a2.example.test") +
                  server_block(*ports, names="b.example.test"), env=ENV)
    srv.wait_log(r"acme: b\.example\.test: .*retry in", timeout=40)
    srv.wait_log(rf"acme: {NAME}: certificate installed", timeout=40)
    text = wait_issuer(srv, ports[1], NAME, "Pebble")
    assert "DNS:a2.example.test" in text
    assert "Pebble" in served_cert(ports[1], "a2.example.test")
    assert "Pebble" not in served_cert(ports[1], "b.example.test")


def test_storage_permissions(bastion, tmp_path, ports, pebble):
    site(tmp_path)
    pebble.start()
    srv = bastion(pebble.acme_block() + server_block(*ports), env=ENV)
    srv.wait_log(rf"acme: {NAME}: certificate installed", timeout=40)
    root = tmp_path / "acme"
    keys = [root / "certs" / NAME / "key.pem"] + list(root.glob("accounts/*/account.key"))
    assert len(keys) == 2
    for p in keys + [root / "certs" / NAME / "cert.pem"]:
        st = p.stat()
        assert stat.S_IMODE(st.st_mode) == 0o600, p
        assert st.st_uid == os.getuid()
    for d in [root, root / "certs", root / "certs" / NAME, root / "accounts"]:
        assert stat.S_IMODE(d.stat().st_mode) == 0o700, d
    key_text = (root / "certs" / NAME / "key.pem").read_text()
    body = key_text.split("-----")[2].strip().splitlines()[0]
    assert body not in srv.logs()


def test_restart_reuses(bastion, tmp_path, ports, pebble):
    site(tmp_path)
    pebble.start()
    storage = tmp_path / "acme"
    srv = bastion(pebble.acme_block(storage=storage) + server_block(*ports), env=ENV)
    srv.wait_log(rf"acme: {NAME}: certificate installed", timeout=40)
    first = serial(wait_issuer(srv, ports[1], NAME, "Pebble"))
    srv.proc.terminate()
    srv.proc.wait(10)
    site(tmp_path / "s1")  # the second server's scratch directory, same storage
    srv2 = bastion(pebble.acme_block(storage=storage) + server_block(*ports), env=ENV)
    srv2.wait_log(rf"acme: {NAME}: certificate valid, renewal in", timeout=10)
    assert "requesting one" not in srv2.logs()
    assert "made a new account key" not in srv2.logs()
    assert serial(served_cert(ports[1], NAME)) == first


def test_simple_config(bastion, tmp_path, pebble):
    """The four-line config of docs/implementation-plan/config-language.md (plus where the test CA
    is): implied listeners on 80 and 443, a redirect on 80, a Pebble certificate on 443."""
    site(tmp_path)
    pebble.http_port, pebble.tls_port = 80, 443
    pebble.start()
    conf = (f"acme {{ email admin@example.com; ca {pebble.url}; ca_root {pebble.crt}; storage @WORKDIR@/acme; }}\n"
            "server {\n    name example.test www.example.test;\n    tls auto;\n    root @WORKDIR@/www;\n}\n")
    srv = bastion(conf, env=ENV)
    wait_issuer(srv, 443, "example.test", "Pebble", timeout=40)
    assert https_get(443, "www.example.test") == (200, b"hello acme\n")
    st, _, hdrs = http_get(80, "www.example.test", "/x?y=1")
    assert st == 308 and hdrs["Location"] == "https://www.example.test/x?y=1"


def test_token_path_traversal(bastion, tmp_path, ports, pebble):
    site(tmp_path)
    (tmp_path / "www" / ".well-known" / "acme-challenge").mkdir(parents=True)
    (tmp_path / "www" / ".well-known" / "acme-challenge" / "file").write_text("from disk")
    srv = bastion(pebble.acme_block() + server_block(*ports), env=ENV)
    for path in ["/.well-known/acme-challenge/unknowntoken", "/.well-known/acme-challenge/file",
                 "/.well-known/acme-challenge/a%2F..%2F..%2Findex.html",
                 "/.well-known/acme-challenge/..%2Findex.html", "/.well-known/acme-challenge/x.y"]:
        st, body, _ = http_get(ports[0], NAME, path)
        assert st in (400, 404), (path, st, body)
        assert b"from disk" not in body and b"hello acme" not in body
    assert http_get(ports[0], NAME, "/")[0] == 200  # an explicit listen: no redirect
    assert srv.proc.poll() is None


def test_ca_response_malformed(bastion, tmp_path, ports):
    site(tmp_path)
    ca = FakeCA(tmp_path)
    try:
        ca.body = b'{"newNonce": "https://127.0.0.1/n", "newAccount": [1, 2'
        srv = bastion(ca.block() + server_block(*ports), env=ENV)
        srv.wait_log(r"malformed JSON response .*retry in 1s", timeout=10)
        ca.body = b"{" + b'"x":"' + b"a" * (2 << 20) + b'"}'
        srv.wait_log(r"response body larger than 1048576 bytes", timeout=15)
        ca.body = b'{"newNonce":"https://evil.example/n","newAccount":"https://evil.example/a",' \
                  b'"newOrder":"https://evil.example/o"}'
        srv.wait_log(r"URL on another host than the directory's", timeout=15)
        assert https_get(ports[1], NAME) == (200, b"hello acme\n")
        assert srv.proc.poll() is None
    finally:
        ca.stop()


def test_public_ca_refused_in_tests(bastion, tmp_path, ports):
    """A test build never contacts Let's Encrypt, whatever the config says."""
    site(tmp_path)
    srv = bastion("acme { storage @WORKDIR@/acme; }\n" + server_block(*ports), env=ENV)
    srv.wait_log(r"acme: a test build does not contact the public CA https://acme-v02\.api\.letsencrypt\.org",
                 timeout=10)
