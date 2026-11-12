"""TLS to upstreams (Phase 9, Task 6): verification by default, hostname checks, verify off with
its -t warning, upstream mTLS, session resumption and SNI."""
import ssl
import subprocess

import pytest

from upstream_util import Upstream, get, ok


def server_ctx(certs, leaf="ecdsa", client_ca=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(certs / f"{leaf}.crt"), str(certs / f"{leaf}.key"))
    if client_ca is not None:
        ctx.load_verify_locations(str(certs / client_ca))
        ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


@pytest.fixture
def tls_up(certs):
    made = []

    def make(**kw):
        u = Upstream(tls=server_ctx(certs, **kw))
        made.append(u)
        return u

    yield make
    for u in made:
        u.close()


def conf(port, tls_lines, host="127.0.0.1"):
    return (f"workers 1;\nupstream u {{ server {host}:{port}; {tls_lines} }}\n"
            "server { listen 127.0.0.1:@HTTP_PORT@; location / { proxy u; } }\n")


def status(r):
    return int(r.split(b" ", 2)[1])


def test_verify_default(bastion, tls_up):
    """An https:// upstream whose certificate no system CA signed: 502 and an error log."""
    up = tls_up()
    srv = bastion(f"workers 1;\nserver {{ listen 127.0.0.1:@HTTP_PORT@; "
                  f"location / {{ proxy https://127.0.0.1:{up.port}; }} }}\n")
    assert status(get(srv.ports["http"])) == 502
    srv.wait_log(r"certificate verification failed")
    assert not up.requests


def test_verified_ok(bastion, tls_up, certs):
    up = tls_up()
    srv = bastion(conf(up.port, f"tls ca {certs}/ca.crt;"))
    r = get(srv.ports["http"], "/x")
    assert status(r) == 200 and r.endswith(b"/x"), r


def test_hostname_mismatch(bastion, tls_up, certs):
    """A certificate from the trusted CA, but for a.example: the name check fails."""
    up = tls_up(leaf="site-a")
    srv = bastion(conf(up.port, f"tls ca {certs}/ca.crt;"))
    assert status(get(srv.ports["http"])) == 502
    srv.wait_log(r"certificate verification failed")
    # naming it right passes
    srv2 = bastion(conf(up.port, f"tls ca {certs}/ca.crt; tls sni a.example;"))
    assert status(get(srv2.ports["http"])) == 200


def test_verify_off_warns(bastion_bin, tmp_path, tls_up, bastion):
    up = tls_up()
    text = conf(up.port, "tls verify off;").replace("@HTTP_PORT@", "18080")
    f = tmp_path / "b.conf"
    f.write_text(text)
    p = subprocess.run([bastion_bin, "-c", str(f), "-t"], capture_output=True, text=True,
                       timeout=30)
    assert p.returncode == 0, p.stderr
    assert "warning" in p.stderr and "tls verify off" in p.stderr, p.stderr
    srv = bastion(conf(up.port, "tls verify off;"))
    assert status(get(srv.ports["http"])) == 200


def test_upstream_mtls(bastion, tls_up, certs):
    up = tls_up(client_ca="ca.crt")
    srv = bastion(conf(up.port, f"tls ca {certs}/ca.crt;"))
    assert status(get(srv.ports["http"])) == 502  # no client certificate: refused
    srv2 = bastion(conf(up.port, f"tls ca {certs}/ca.crt; tls cert {certs}/client.crt; "
                        f"tls key {certs}/client.key;"))
    assert status(get(srv2.ports["http"])) == 200
    assert up.peer_certs and up.peer_certs[-1] is not None


def test_session_reuse(bastion, tls_up, certs):
    up = tls_up()
    srv = bastion(conf(up.port, f"tls ca {certs}/ca.crt; keepalive 0;"))
    for _ in range(5):
        assert status(get(srv.ports["http"])) == 200
    assert len(up.resumed) == 5
    assert up.resumed.count(True) >= 3, up.resumed  # the first is full, later ones resume


def test_sni_sent(bastion, tls_up, certs):
    up = tls_up()
    srv = bastion(conf(up.port, f"tls ca {certs}/ca.crt;", host="localhost"))
    assert status(get(srv.ports["http"])) == 200
    assert up.sni[-1] == "localhost"
    up2 = tls_up(leaf="site-b")
    srv2 = bastion(conf(up2.port, f"tls ca {certs}/ca.crt; tls sni b.example;"))
    assert status(get(srv2.ports["http"])) == 200
    assert up2.sni[-1] == "b.example"


def test_tls_config_errors(bastion_bin, tmp_path, certs):
    f = tmp_path / "b.conf"
    f.write_text("upstream u { server 127.0.0.1:1; tls cert /nonexistent.crt; }\n"
                 "server { listen 127.0.0.1:18080; location / { proxy u; } }\n")
    p = subprocess.run([bastion_bin, "-c", str(f), "-t"], capture_output=True, text=True, timeout=30)
    assert p.returncode != 0 and "tls key" in p.stderr, p.stderr
    f.write_text(f"upstream u {{ server 127.0.0.1:1; tls ca {tmp_path}/none.pem; }}\n"
                 "server { listen 127.0.0.1:18080; location / { proxy u; } }\n")
    p = subprocess.run([bastion_bin, "-c", str(f), "-t"], capture_output=True, text=True, timeout=30)
    assert p.returncode != 0 and "CA bundle" in p.stderr, p.stderr
