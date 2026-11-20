"""A local ACME CA for the tests: Pebble (Let's Encrypt's test-only server) and pebble-challtestsrv
(its mock DNS, which also holds dns-01 TXT records), both pinned in docker/dev.Dockerfile and run
as processes on loopback. Nothing here ever talks to a public CA."""
import json
import shutil
import socket
import ssl
import subprocess
import time
import urllib.request

from conftest import _free_port


def have_pebble():
    return shutil.which("pebble") is not None and shutil.which("pebble-challtestsrv") is not None


def sh(*args, **kw):
    return subprocess.run(args, check=True, capture_output=True, **kw)


def make_cert(d, name, sans, days=30, cn=None):
    """A self-signed P-256 certificate and key (PEM files) for the given subjectAltName list."""
    key, crt = d / f"{name}.key", d / f"{name}.crt"
    sh("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
       "-keyout", str(key), "-out", str(crt), "-days", str(days), "-subj", f"/CN={cn or name}",
       "-addext", "subjectAltName=" + ",".join(sans))
    return crt, key


class Pebble:
    """Pebble validating against http_port (HTTP-01) and tls_port (TLS-ALPN-01), resolving every name
    through challtestsrv to 127.0.0.1 unless told otherwise."""

    def __init__(self, tmp, http_port, tls_port):
        self.d = tmp / "pebble"
        self.d.mkdir(exist_ok=True)
        self.port = _free_port(socket.SOCK_STREAM)
        self.mgmt = _free_port(socket.SOCK_STREAM)
        self.dns = _free_port(socket.SOCK_DGRAM)
        self.dns_mgmt = _free_port(socket.SOCK_STREAM)
        self.crt, self.key = make_cert(self.d, "pebble", ["IP:127.0.0.1", "DNS:localhost"])
        self.http_port, self.tls_port = http_port, tls_port
        self.procs = []

    @property
    def url(self):
        return f"https://127.0.0.1:{self.port}/dir"

    def acme_block(self, extra="", storage="@WORKDIR@/acme"):
        return (f"acme {{ email admin@example.com; ca {self.url}; ca_root {self.crt}; "
                f"storage {storage}; {extra} }}\n")

    def start(self):
        cfg = {"pebble": {
            "listenAddress": f"127.0.0.1:{self.port}",
            "managementListenAddress": f"127.0.0.1:{self.mgmt}",
            "certificate": str(self.crt), "privateKey": str(self.key),
            "httpPort": self.http_port, "tlsPort": self.tls_port,
            "ocspResponderURL": "", "externalAccountBindingRequired": False,
            "retryAfter": {"authz": 1, "order": 1}}}
        (self.d / "config.json").write_text(json.dumps(cfg))
        log = open(self.d / "challtestsrv.log", "w")
        self.procs.append(subprocess.Popen(
            ["pebble-challtestsrv", "-defaultIPv4", "127.0.0.1", "-defaultIPv6", "",
             "-dns01", f"127.0.0.1:{self.dns}", "-http01", "", "-https01", "", "-tlsalpn01", "",
             "-doh", "", "-management", f"127.0.0.1:{self.dns_mgmt}"],
            stdout=log, stderr=subprocess.STDOUT))
        log = open(self.d / "pebble.log", "w")
        env = {"PATH": "/usr/bin:/bin", "PEBBLE_VA_NOSLEEP": "1", "PEBBLE_AUTHZREUSE": "0"}
        self.procs.append(subprocess.Popen(
            ["pebble", "-config", str(self.d / "config.json"), "-dnsserver", f"127.0.0.1:{self.dns}"],
            stdout=log, stderr=subprocess.STDOUT, env=env))
        deadline = time.monotonic() + 15
        ctx = ssl.create_default_context(cafile=str(self.crt))
        while time.monotonic() < deadline:
            try:
                urllib.request.urlopen(self.url, context=ctx, timeout=1).read()
                urllib.request.urlopen(f"http://127.0.0.1:{self.dns_mgmt}/", timeout=1)
                return self
            except urllib.error.HTTPError:
                return self  # challtestsrv answers 404 on /: it is up
            except OSError:
                time.sleep(0.1)
        raise AssertionError("pebble did not start:\n" + (self.d / "pebble.log").read_text())

    def dns_post(self, path, body):
        req = urllib.request.Request(f"http://127.0.0.1:{self.dns_mgmt}{path}",
                                     data=json.dumps(body).encode(), method="POST")
        urllib.request.urlopen(req, timeout=5).read()

    def set_a(self, host, ip):
        self.dns_post("/add-a", {"host": host.rstrip(".") + ".", "addresses": [ip]})

    def log(self):
        return (self.d / "pebble.log").read_text()

    def stop(self):
        for p in self.procs:
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(5)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait(5)
        self.procs = []


def served_cert(port, name, host="127.0.0.1"):
    """The leaf certificate the server presents for SNI name, as `openssl x509 -text` output."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=5) as s:
        with ctx.wrap_socket(s, server_hostname=name) as t:
            der = t.getpeercert(binary_form=True)
    return subprocess.run(["openssl", "x509", "-inform", "DER", "-noout", "-issuer", "-subject",
                           "-serial", "-enddate", "-ext", "subjectAltName"],
                          input=der, capture_output=True, check=True).stdout.decode()


def wait_issuer(srv, port, name, needle, timeout=30):
    def check():
        try:
            text = served_cert(port, name)
        except OSError:
            return None
        return text if needle in text else None
    return srv.wait_for(check, timeout, f"a certificate for {name} issued by {needle!r}")
