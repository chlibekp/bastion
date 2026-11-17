"""Escalation (Phase 12, Task 3): repeated limit_zone refusals become a block master applies for
every worker; PROXY protocol and real_ip clients are blocked at L7 only; IPv6 blocks cover the
/64; allowlisted addresses and the ceiling are respected."""
import re
import socket
import time


def get(port, path="/", extra="", prefix=b"", timeout=5):
    """The response, or b"" when the connection is closed without one (blocked at accept)."""
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout)
    except OSError:
        return b""
    out = b""
    try:
        s.sendall(prefix + f"GET {path} HTTP/1.1\r\nHost: x\r\n{extra}Connection: close\r\n\r\n".encode())
        while True:
            d = s.recv(65536)
            if not d:
                break
            out += d
    except OSError:
        pass
    s.close()
    return out


def status(r):
    return int(r.split(b" ", 2)[1]) if r else 0


ESC = "escalate after=5 window=10s block=60s;"


def conf(zone_extra=ESC, scope="", glob="", workers=1, listen_extra=""):
    return (f"workers {workers};\n{glob}\n"
            f"limit_zone z {{ rate 1/m; {zone_extra} }}\n"
            f"server {{ listen 127.0.0.1:@HTTP_PORT@ {listen_extra}; {scope}\n"
            "location / { limit z; return 200 \"ip=$remote_addr\"; } }\n")


def test_escalate_end_to_end(bastion):
    srv = bastion(conf(workers=4))
    srv.wait_workers(4)
    p = srv.ports["http"]
    assert status(get(p)) == 200
    codes = [status(get(p)) for _ in range(5)]  # five refusals: the fifth strike asks master
    assert codes == [429] * 5, codes
    t0 = time.monotonic()
    srv.wait_log(re.escape("escalate: blocked 127.0.0.1/32 for 60s (limit)"), timeout=5)
    # within a second every worker closes the client at accept: no response at all
    deadline = t0 + 1.0
    while time.monotonic() < deadline and get(p) != b"":
        time.sleep(0.02)
    assert time.monotonic() < deadline + 0.05, "not blocked within 1 s"
    for _ in range(12):  # new connections land on all four workers
        assert get(p) == b""
    assert "l7 only" not in srv.logs()


def test_proxy_protocol_no_network_block(bastion):
    srv = bastion(conf(scope="proxy_protocol_from 127.0.0.0/8;", listen_extra="proxy_protocol"))
    p = srv.ports["http"]
    hdr = b"PROXY TCP4 198.51.100.9 127.0.0.1 40000 80\r\n"
    assert status(get(p, prefix=hdr)) == 200
    for _ in range(5):
        assert status(get(p, prefix=hdr)) == 429
    # master marks it L7 only: the address is not the packet source (a network backend skips it)
    srv.wait_log(re.escape("escalate: blocked 198.51.100.9/32 for 60s (limit) l7 only"), timeout=5)
    time.sleep(0.2)
    r = get(p, prefix=hdr)
    assert r == b"" or status(r) == 403, r  # the user-space backend still refuses it
    other = b"PROXY TCP4 198.51.100.10 127.0.0.1 40000 80\r\n"
    assert status(get(p, prefix=other)) == 200  # the balancer itself is never blocked


def test_ipv6_prefix_block(bastion):
    trust = "real_ip_header X-Forwarded-For; real_ip_from 127.0.0.1/32;"
    srv = bastion(conf(scope=trust))
    p = srv.ports["http"]
    xff = "X-Forwarded-For: 2001:db8:7:7::1\r\n"
    assert status(get(p, extra=xff)) == 200
    for _ in range(5):
        assert status(get(p, extra=xff)) == 429
    srv.wait_log(re.escape("escalate: blocked 2001:db8:7:7::/64 for 60s (limit) l7 only"), timeout=5)
    time.sleep(0.2)
    # every address of the /64 is refused per request; the proxy peer is never blocked
    assert status(get(p, extra="X-Forwarded-For: 2001:db8:7:7:abcd::9\r\n")) == 403
    assert status(get(p, extra="X-Forwarded-For: 2001:db8:7:8::1\r\n")) == 200


def test_never_blocks_allowlisted(bastion):
    srv = bastion(conf(glob="escalation_allow 127.0.0.0/8;"))
    p = srv.ports["http"]
    for _ in range(8):
        get(p)
    srv.wait_log("escalate: 127.0.0.1 is exempt", timeout=5)
    time.sleep(0.2)
    assert status(get(p)) == 429  # still only rate limited, never closed at accept


def test_ceiling(bastion):
    trust = "real_ip_header X-Forwarded-For; real_ip_from 127.0.0.1/32;"
    srv = bastion(conf(scope=trust, glob="escalation_ceiling 1;"))
    p = srv.ports["http"]
    for a in ("192.0.2.1", "192.0.2.2"):
        for _ in range(6):
            get(p, extra=f"X-Forwarded-For: {a}\r\n")
    srv.wait_log("escalate: escalation_ceiling reached, not blocking 192.0.2.2", timeout=5)
    time.sleep(0.2)
    assert status(get(p, extra="X-Forwarded-For: 192.0.2.1\r\n")) == 403  # the first stays
    assert status(get(p, extra="X-Forwarded-For: 192.0.2.2\r\n")) == 429
