"""L7 escalation into the XDP block maps (Phase 13, Task 7), on a veth pair into a test network
namespace. A user-space block closes a connection after accepting it ("closed"); an XDP block
drops the SYN, so the client sees no answer at all ("timeout"): that difference is what these
tests read. A fake worker flooding its ring and the backend's list are covered by the unit suite
(tests/unit/test_xdp_block.c): there is no admin endpoint listing blocks before Phase 14."""
import re
import time

from xdp_util import net, pin  # noqa: F401  (fixtures)


def conf(n, pin_, block="3s", xdp_extra="", scope="", listen_extra=""):
    return (f"workers 2;\n"
            f"xdp {{ interface {n.host}; mode generic; pin_path {pin_}; {xdp_extra} }}\n"
            f"limit_zone z {{ rate 1/m; escalate after=3 window=10s block={block}; }}\n"
            f"server {{ listen {n.ip}:@HTTP_PORT@ {listen_extra}; {scope}\n"
            "location / { limit z; return 200 \"ok\"; } }\n")


def abuse(n, src, p, times=4):
    return [n.get(src, p) for _ in range(times)]


def test_l7_to_xdp(bastion, net, pin):
    n = net()
    srv = bastion(conf(n, pin, block="60s"))
    p = srv.ports["http"]
    codes = abuse(n, n.good, p)
    assert codes[0] == "200" and "429" in codes, codes
    t0 = time.monotonic()
    srv.wait_log(re.escape(f"escalate: blocked {n.good}/32 for 60s (limit)"), timeout=5)
    while time.monotonic() - t0 < 1.0 and n.get(n.good, p, timeout=0.3) != "timeout":
        pass
    assert time.monotonic() - t0 < 1.5, "not dropped in XDP within 1 s"
    assert n.get(n.good, p, timeout=0.5) == "timeout"
    assert n.get(n.bad, p) == "200"  # another source is untouched


def test_ttl_unblocks(bastion, net, pin):
    n = net()
    srv = bastion(conf(n, pin, block="2s"))
    p = srv.ports["http"]
    abuse(n, n.good, p)
    srv.wait_log(re.escape(f"escalate: blocked {n.good}/32 for 2s"), timeout=5)
    time.sleep(0.3)
    assert n.get(n.good, p, timeout=0.5) == "timeout"
    deadline = time.monotonic() + 6
    r = "timeout"
    while time.monotonic() < deadline and r == "timeout":
        r = n.get(n.good, p, timeout=0.5)
    assert r in ("200", "429"), r  # answered again (still over the 1/m limit: 429)


def test_allowlist_protected(bastion, net, pin):
    n = net()
    srv = bastion(conf(n, pin, xdp_extra=f"allow {n.good};"))
    p = srv.ports["http"]
    abuse(n, n.good, p)
    srv.wait_log(re.escape(f"escalate: blocked {n.good}/32"), timeout=5)
    time.sleep(0.3)
    # blocked at L7 (accepted, then closed), never dropped in XDP
    assert n.get(n.good, p, timeout=1.0) in ("closed", "403", "error:104")


def test_proxy_protocol_not_xdp(bastion, net, pin):
    """The balancer (the netns address) relays a client in its PROXY header: the client is
    blocked at L7, the balancer's own packets are never dropped."""
    n = net()
    srv = bastion(conf(n, pin, scope=f"proxy_protocol_from {n.good}/32;", listen_extra="proxy_protocol"))
    p = srv.ports["http"]
    client = "198.51.100.9"
    script = (
        "import socket,sys\n"
        "def g(ip):\n"
        f"  s=socket.socket(); s.settimeout(1); s.bind(('{n.good}',0)); s.connect(('{n.ip}',{p}))\n"
        f"  s.sendall(('PROXY TCP4 '+ip+' {n.ip} 40000 80\\r\\nGET / HTTP/1.1\\r\\nHost: x\\r\\nConnection: close\\r\\n\\r\\n').encode())\n"
        "  o=b''\n"
        "  try:\n"
        "    while True:\n"
        "      d=s.recv(9999)\n"
        "      if not d: break\n"
        "      o+=d\n"
        "  except socket.timeout: return 'timeout'\n"
        "  except OSError: return 'closed'\n"
        "  return o.split(b' ',2)[1].decode() if o else 'closed'\n"
        "print(' '.join(g(a) for a in sys.argv[1:]))\n")
    from xdp_util import sh
    run = lambda *a: sh("ip", "netns", "exec", n.ns, "python3", "-c", script, *a, check=False).stdout.split()
    assert "429" in run(client, client, client, client)
    srv.wait_log(re.escape(f"escalate: blocked {client}/32 for 3s (limit) l7 only"), timeout=5)
    time.sleep(0.3)
    out = run(client, "198.51.100.10")
    assert out[0] in ("403", "closed"), out  # the client: refused at L7
    assert out[1] == "200", out  # the balancer: never dropped in XDP
