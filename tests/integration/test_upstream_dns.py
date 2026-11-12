"""Upstream servers by name (Phase 9, Task 1): resolved once at load, or kept fresh by the helper
with `resolve`. Traffic-level checks (502 until resolved, traffic moving) live in
test_upstream_dns_traffic below and need the proxy handler (Task 3)."""
import subprocess

import pytest

from dns_util import FakeDNS


@pytest.fixture
def dns():
    d = FakeDNS({"app.test": ["127.0.0.1"]}, ttl=1)
    yield d
    d.close()


def _conf(dns_port, extra=""):
    return (f"resolver 127.0.0.1:{dns_port};\nresolver_ttl_min 1s;\nresolver_timeout 200ms;\n"
            f"upstream app {{ server app.test:9 resolve; }}\n{extra}"
            "server { listen @HTTP_PORT@; }\n")


def test_resolve_publishes(bastion, dns):
    srv = bastion(_conf(dns.port))
    srv.wait_log(r"helper INFO upstream app: app\.test resolved to 1 address")
    assert ("app.test", 1) in dns.queries and ("app.test", 28) in dns.queries


def test_resolve_changes(bastion, dns):
    srv = bastion(_conf(dns.port))
    srv.wait_log(r"resolved to 1 address$")
    dns.records["app.test"] = ["127.0.0.1", "127.0.0.2"]
    srv.wait_log(r"resolved to 2 addresses", timeout=5)


def test_resolver_down(bastion, dns):
    srv = bastion(_conf(dns.port))
    srv.wait_log(r"resolved to 1 address$")
    dns.silent = True
    srv.wait_log(r"WARN upstream app: resolving app\.test failed \(the resolver did not answer "
                 r"in time\): keeping the 1 address it had", timeout=5)


def test_resolve_moves_traffic(bastion, dns):
    """An address change on the DNS server moves traffic within the TTL, with no reload."""
    from upstream_util import Upstream, get

    import time

    a = Upstream(host="127.0.0.1")
    b = Upstream(host="127.0.0.2", port=a.port)  # same port, another loopback address
    try:
        srv = bastion(f"workers 1;\nresolver 127.0.0.1:{dns.port};\nresolver_ttl_min 1s;\n"
                      f"upstream app {{ server app.test:{a.port} resolve; keepalive 0; }}\n"
                      "server { listen 127.0.0.1:@HTTP_PORT@; location / { proxy app; } }\n")
        srv.wait_log(r"resolved to 1 address$")
        assert get(srv.ports["http"], "/one").startswith(b"HTTP/1.1 200")
        assert a.requests and not b.requests
        dns.records["app.test"] = ["127.0.0.2"]
        deadline = time.monotonic() + 5  # TTL 1 s, clamped to resolver_ttl_min 1 s
        while not b.requests and time.monotonic() < deadline:
            assert get(srv.ports["http"], "/two").startswith(b"HTTP/1.1 200")
            time.sleep(0.1)
        assert b.requests, "traffic did not move to the new address"
    finally:
        a.close()
        b.close()


def test_startup_unresolvable_502(bastion, dns):
    dns.silent = True
    from upstream_util import get

    srv = bastion(f"workers 1;\nresolver 127.0.0.1:{dns.port};\nresolver_timeout 100ms;\n"
                  "upstream app { server app.test:9 resolve; }\n"
                  "server { listen 127.0.0.1:@HTTP_PORT@; location / { proxy app; } }\n")
    r = get(srv.ports["http"], "/")
    assert r.startswith(b"HTTP/1.1 502"), r


def test_startup_unresolvable(bastion, bastion_bin, tmp_path, dns):
    dns.silent = True
    srv = bastion(_conf(dns.port))  # starts: the name is not needed to start
    srv.wait_log(r"keeping the 0 addresses it had", timeout=5)
    conf = tmp_path / "noresolve.conf"
    conf.write_text("upstream app { server no-such-host.invalid:80; }\nserver { listen 8080; }\n")
    p = subprocess.run([bastion_bin, "-t", "-c", str(conf)], capture_output=True, text=True)
    assert p.returncode == 1
    assert "does not resolve" in p.stderr and "add `resolve`" in p.stderr
