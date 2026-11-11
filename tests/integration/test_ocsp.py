"""OCSP stapling (src/tls/ocsp.c, ocsp_fetch.c) against a real `openssl ocsp` responder."""
import shutil
import socket
import subprocess
import time

import pytest

from conftest import _free_port
from test_tls_conn import conf, www  # noqa: F401

ENV = {"BST_TEST_OCSP_RETRY_MS": "500", "BST_TEST_OCSP_REFRESH_MS": "60000"}


def sh(*args, **kw):
    return subprocess.run(args, check=True, capture_output=True, **kw)


class Pki:
    """A leaf with an OCSP URL in its AIA, its CA, an OCSP signer and a responder to start."""

    def __init__(self, certs, tmp, port):
        self.d = tmp / "ocsp-pki"
        self.d.mkdir()
        self.port = port
        for f in ("ca.crt", "ca.key", "ca2.crt", "ca2.key"):
            shutil.copy(certs / f, self.d / f)
        sh(str(certs.parents[1] / "tests/fixtures/certs/gen.sh"), str(self.d), "ocsp", "leaf",
           f"http://127.0.0.1:{port}/")
        self.crt = self.d / "leaf.crt"
        self.key = self.d / "leaf.key"
        self.chain = self.d / "leaf-chain.crt"
        self.chain.write_bytes(self.crt.read_bytes() + (self.d / "ca.crt").read_bytes())
        serial = sh("openssl", "x509", "-in", str(self.crt), "-serial", "-noout").stdout.decode()
        serial = serial.strip().split("=")[1]
        self.index = self.d / "index.txt"
        self.index.write_text(f"V\t330101000000Z\t\t{serial}\tunknown\t/CN=localhost\n")
        self.empty_index = self.d / "empty.txt"
        self.empty_index.write_text("")
        self.proc = None

    def responder(self, signer="ocsp-signer", ca="ca", index=None, minutes=None):
        self.stop()
        cmd = ["openssl", "ocsp", "-index", str(index or self.index), "-port", str(self.port),
               "-rsigner", str(self.d / f"{signer}.crt"), "-rkey", str(self.d / f"{signer}.key"),
               "-CA", str(self.d / f"{ca}.crt"), "-ndays", "1"]
        if minutes:
            cmd = cmd[:-2] + ["-nmin", str(minutes)]
        self.proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Not a connect probe: `openssl ocsp` wedges on a connection that closes without a request.
        time.sleep(0.7)
        assert self.proc.poll() is None, "responder did not start"

    def stop(self):
        if self.proc:
            self.proc.terminate()
            self.proc.wait(5)
            self.proc = None


@pytest.fixture
def pki(certs, tmp_path):
    p = Pki(certs, tmp_path, _free_port(socket.SOCK_STREAM))
    yield p
    p.stop()


def status(srv, certs):
    """What `openssl s_client -status` says about the stapled response."""
    r = subprocess.run(["openssl", "s_client", "-connect", f"127.0.0.1:{srv.ports['https']}",
                        "-servername", "localhost", "-status", "-CAfile", str(certs / "ca.crt")],
                       input=b"", capture_output=True, timeout=20)
    return (r.stdout + r.stderr).decode("latin-1")


def serve(bastion, pki, www, extra_profile="", tls_extra="", chain=True, env=ENV):  # noqa: F811
    text = (f"workers 1;\ntls_profile o {{ ocsp_stapling on; {extra_profile} }}\n"
            f"server {{ listen 127.0.0.1:@HTTPS_PORT@ tls; tls_profile o; tls_cert "
            f"{pki.chain if chain else pki.crt} {pki.key}; {tls_extra} root {www}; }}\n")
    return bastion(text, env=env)


def wait_staple(srv, certs, want="Cert Status: good", timeout=10):
    return srv.wait_for(lambda: want in status(srv, certs), timeout, f"{want!r} in the handshake")


def test_staple_served(bastion, certs, pki, www):  # noqa: F811
    pki.responder()
    srv = serve(bastion, pki, www)
    wait_staple(srv, certs)
    out = status(srv, certs)
    assert "OCSP Response Status: successful" in out
    assert "killed by signal" not in srv.logs()


def test_no_ocsp_url(bastion, certs, www):  # noqa: F811
    # the ordinary fixture certificate has no AIA: like a Let's Encrypt certificate today
    text = ("workers 1;\ntls_profile o { ocsp_stapling on; }\n"
            f"server {{ listen 127.0.0.1:@HTTPS_PORT@ tls; tls_profile o; "
            f"tls_cert {certs}/ecdsa-chain.crt {certs}/ecdsa.key; root {www}; }}\n")
    srv = bastion(text, env=ENV)
    time.sleep(2)
    assert "no OCSP response" in status(srv, certs) or "OCSP response: no response" in status(srv, certs)
    log = srv.logs()
    assert log.count("names no OCSP responder") == 1
    assert "OCSP fetch" not in log, log


def test_invalid_response_rejected(bastion, certs, pki, www):  # noqa: F811
    # signed by a CA that is not the issuer: the signature chain does not verify
    pki.responder(signer="ca2", ca="ca2")
    srv = serve(bastion, pki, www)
    srv.wait_log(r"OCSP fetch for .* failed: signature or signer chain not valid")
    assert "Cert Status" not in status(srv, certs)
    # a response saying the certificate is unknown is not stapled either
    pki.responder(index=pki.empty_index)
    srv.wait_log(r"OCSP fetch for .* failed: the certificate's status is not good")
    assert "Cert Status" not in status(srv, certs)


def test_responder_down(bastion, certs, pki, www, backend):  # noqa: F811
    if backend != "epoll":
        pytest.skip("one backend is enough for a test that waits a minute")
    pki.responder(minutes=1)
    srv = serve(bastion, pki, www, env={**ENV, "BST_TEST_OCSP_REFRESH_MS": "1000"})
    wait_staple(srv, certs)
    pki.stop()
    srv.wait_log(r"OCSP fetch for .* failed")
    time.sleep(1)
    assert "Cert Status: good" in status(srv, certs), "an old staple is kept while it is valid"
    # nextUpdate was a minute after the response: after it the staple is dropped
    deadline = time.monotonic() + 80
    while time.monotonic() < deadline and "Cert Status" in status(srv, certs):
        time.sleep(2)
    assert "Cert Status" not in status(srv, certs), "a staple is never served past nextUpdate"
    assert srv.proc.poll() is None


def test_ocsp_file(bastion, certs, pki, www, tmp_path):  # noqa: F811
    pki.responder()
    der = tmp_path / "staple.der"
    sh("openssl", "ocsp", "-issuer", str(pki.d / "ca.crt"), "-cert", str(pki.crt), "-url",
       f"http://127.0.0.1:{pki.port}/", "-CAfile", str(pki.d / "ca.crt"), "-respout", str(der), "-noverify")
    pki.stop()  # nothing to fetch from: the file alone staples
    srv = serve(bastion, pki, www, tls_extra=f"ocsp_file {der};")
    assert "Cert Status: good" in status(srv, certs)
    assert "OCSP fetch" not in srv.logs()


def test_ocsp_file_for_another_certificate(bastion, certs, pki, www, tmp_path):  # noqa: F811
    pki.responder()
    other = tmp_path / "other.der"
    # a response for a certificate that is not the server's
    sh("openssl", "ocsp", "-issuer", str(certs / "ca.crt"), "-cert", str(certs / "site-a.crt"), "-url",
       f"http://127.0.0.1:{pki.port}/", "-respout", str(other), "-noverify")
    pki.stop()
    text = (f"workers 1;\nserver {{ listen 127.0.0.1:@HTTPS_PORT@ tls; tls_cert {pki.chain} {pki.key}; "
            f"ocsp_file {other}; root {www}; }}\n")
    srv = bastion(text, wait=None)
    assert srv.proc.wait(10) != 0
    assert "matches no certificate" in srv.stdout() + srv.logs()
