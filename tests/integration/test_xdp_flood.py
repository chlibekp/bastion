"""XDP flood tests and metrics (Phase 13, Task 9). The flood tools (tools/synflood.c,
tools/udpflood.c, built as test fixtures, never packaged) run inside the test network namespace
against the veth address only; they refuse anything else, which test_tool_refuses_external checks.

Measured here in the dev container: generic-mode XDP on a veth, one flood process, a few hundred
thousand packets. Not a line-rate or NIC benchmark: those need real hardware (docs/tuning.md)."""
import os
import re
import subprocess
import threading
import time

from xdp_util import net, pin, sh  # noqa: F401  (fixtures)

SYN = os.environ.get("SYNFLOOD", "")
UDP = os.environ.get("UDPFLOOD", "")


def stats(srv):
    """The last `xdp: stats` line master logged, as {reason: count}."""
    lines = re.findall(r"xdp: stats (.*)", srv.logs())
    return dict((k, int(v)) for k, v in re.findall(r"(\w+)=(\d+)", lines[-1])) if lines else {}


def flood(n, tool, src, port, count):
    r = sh("ip", "netns", "exec", n.ns, tool, "-d", n.ip, "-p", str(port), "-n", str(count), "-s", src,
           check=False)
    assert r.returncode == 0, r.stderr
    return int(r.stdout.strip())


def cpu_ticks(pids):
    t = 0
    for p in pids:
        try:
            f = open(f"/proc/{p}/stat").read().rsplit(")", 1)[1].split()
            t += int(f[11]) + int(f[12])
        except (OSError, IndexError):
            pass
    return t


def test_tool_refuses_external(net):
    n = net()
    for tool in (SYN, UDP):
        assert tool, "make test-int passes SYNFLOOD and UDPFLOOD"
        # outside targets, from the namespace and from the container's own namespace
        for dst in ("8.8.8.8", "192.168.1.1", "10.0.0.1"):
            r = sh("ip", "netns", "exec", n.ns, tool, "-d", dst, "-p", "80", "-n", "1", "-s", n.good, check=False)
            assert r.returncode == 2 and "refusing" in r.stderr, (dst, r.stderr)
        r = sh(tool, "-d", n.ip, "-p", "80", "-n", "1", "-s", n.good, check=False)
        assert r.returncode == 2, "the test range outside a test namespace must be refused"
        r = sh("ip", "netns", "exec", n.ns, tool, "-d", n.ip, "-p", "80", "-n", "1", "-s", n.good, check=False)
        assert r.returncode == 0, r.stderr


def test_stats_accuracy(bastion, net, pin):
    n = net()
    srv = bastion(f"workers 1;\nxdp {{ interface {n.host}; mode generic; pin_path {pin}; deny {n.bad}; "
                  "drop_unprotected on; }\n"
                  f"server {{ listen {n.ip}:@HTTP_PORT@; location / {{ return 200 \"ok\"; }} }}\n")
    p = srv.ports["http"]
    sent_deny = flood(n, SYN, n.bad, p, 20000)
    sent_unprot = flood(n, UDP, n.good, 9, 10000)
    srv.wait_for(lambda: stats(srv).get("deny", 0) >= sent_deny * 0.99 and
                 stats(srv).get("unprotected", 0) >= sent_unprot * 0.99, timeout=10, what="stats line")
    s = stats(srv)
    assert abs(s["deny"] - sent_deny) <= sent_deny * 0.01, (s, sent_deny)
    assert abs(s["unprotected"] - sent_unprot) <= sent_unprot * 0.01, (s, sent_unprot)


def _run_flood(bastion, n, pin_, use_xdp):
    xdp = (f"xdp {{ interface {n.host}; mode generic; pin_path {pin_}; syn_rate 50/s burst=50; "
           "drop_unprotected on; }\n") if use_xdp else ""
    srv = bastion(f"workers 1;\n{xdp}server {{ listen {n.ip}:@HTTP_PORT@; location / {{ return 200 \"ok\"; }} }}\n")
    p = srv.ports["http"]
    workers = list(srv.workers())
    stop = threading.Event()

    def attack():
        while not stop.is_set():
            flood(n, SYN, n.bad, p, 50000)
            flood(n, UDP, n.bad, 9, 50000)

    t = threading.Thread(target=attack)
    before = cpu_ticks(workers)
    t.start()
    ok = 0
    try:
        for _ in range(100):
            ok += n.get(n.good, p, timeout=2.0) == "200"
    finally:
        stop.set()
        t.join()
    return ok, cpu_ticks(workers) - before, srv


def test_flood_keeps_service(bastion, net, pin):
    n = net()
    ok, cpu_xdp, srv = _run_flood(bastion, n, pin, True)
    assert ok >= 99, f"{ok}/100 legitimate requests succeeded under the flood"
    s = stats(srv)
    assert s.get("syn_rate", 0) > 0 and s.get("unprotected", 0) > 0, s
    srv.proc.terminate()
    srv.proc.wait(timeout=20)
    m = net()
    _, cpu_base, _ = _run_flood(bastion, m, pin, False)
    # The workers' CPU with XDP is no higher than without it (plus a scheduling tick of slack):
    # flood packets never reach a worker either way in this setup, so this guards against the
    # filter adding worker load, not a speed-up claim.
    assert cpu_xdp <= cpu_base + 5, (cpu_xdp, cpu_base)
