"""XDP loader and lifecycle (Phase 13, Task 6), on veth pairs into test network namespaces, in
generic mode (the dev container's veths). Native mode on a stock kernel: tests/vm/test_xdp_native.py.

Config reload arrives in Phase 14, so the reload test here drives bst_xdp_reconfigure through the
unit suite instead (tests/unit/test_xdp_loader.c, reconfigure_no_gap)."""
import os
import signal
import subprocess

import pytest

from xdp_util import net, pin, sh, xdp_conf  # noqa: F401  (fixtures)


def stop(srv, sig=signal.SIGTERM):
    srv.proc.send_signal(sig)
    srv.proc.wait(timeout=20)


def test_attach_generic_drops(bastion, net, pin):
    n = net()
    srv = bastion(xdp_conf(n, pin))
    assert "xdp: attached to %s (generic mode)" % n.host in srv.logs()
    p = srv.ports["http"]
    assert n.get(n.good, p) == "200"
    assert n.get(n.bad, p) == "timeout"  # dropped before the stack: no RST, no SYN-ACK
    assert n.get(n.good, p) == "200"
    assert n.xdp_attached()
    # security review L10: master's BPF map, program and link fds stay in master
    for pid in list(srv.workers().values()) + [srv.helper()]:
        held = []
        for fd in os.listdir(f"/proc/{pid}/fd"):
            try:
                held.append(os.readlink(f"/proc/{pid}/fd/{fd}"))
            except OSError:
                pass
        assert not [h for h in held if h.startswith("anon_inode:bpf")], (pid, held)
    master = [os.readlink(f"/proc/{srv.proc.pid}/fd/{fd}") for fd in os.listdir(f"/proc/{srv.proc.pid}/fd")]
    assert any(h.startswith("anon_inode:bpf") for h in master), master


def test_mode_fallback(bastion, net, pin):
    n = net()
    dummy = "bxd" + n.host[3:]
    if sh("ip", "link", "add", dummy, "type", "dummy", check=False).returncode != 0:
        pytest.skip("no dummy interfaces in this kernel (needed: a device without native XDP)")
    try:
        sh("ip", "link", "set", dummy, "up")
        conf = xdp_conf(n, pin, ifaces=[n.host, dummy]).replace("mode generic", "mode auto")
        srv = bastion(conf)
        logs = srv.logs()
        assert f"xdp: attached to {n.host} (native mode)" in logs, logs  # veth has native XDP
        assert f"xdp: attached to {dummy} (generic mode)" in logs, logs  # dummy steps down
        assert n.get(n.bad, srv.ports["http"]) == "timeout"
    finally:
        sh("ip", "link", "del", dummy, check=False)


def test_require_native_fails(bastion, net, pin):
    n = net()
    dummy = "bxd" + n.host[3:]
    if sh("ip", "link", "add", dummy, "type", "dummy", check=False).returncode != 0:
        pytest.skip("no dummy interfaces in this kernel")
    try:
        conf = xdp_conf(n, pin, ifaces=[dummy]).replace("mode generic", "mode native require")
        srv = bastion(conf, wait=None)
        assert srv.proc.wait(timeout=20) != 0
        assert "native mode refused" in srv.logs() + srv.stdout()
        assert "require" in srv.logs() + srv.stdout()
    finally:
        sh("ip", "link", "del", dummy, check=False)


def test_no_caps(bastion, net, pin):
    """Without CAP_BPF, CAP_SYS_ADMIN and CAP_NET_ADMIN (an unprivileged container): a warning, and
    the server runs with its L7 checks."""
    n = net()
    wrap = ["setpriv", "--bounding-set", "-bpf,-sys_admin,-net_admin,-perfmon", "--"]
    srv = bastion(xdp_conf(n, pin), wrap=wrap)
    assert "running without the XDP filter; L7 limits still apply" in srv.logs()
    assert not n.xdp_attached()
    assert n.get(n.good, srv.ports["http"]) == "200"
    assert n.get(n.bad, srv.ports["http"]) == "200"  # no filter: the deny list is XDP only


def test_clean_stop_detaches(bastion, net, pin):
    n = net()
    srv = bastion(xdp_conf(n, pin))
    assert n.xdp_attached() and os.path.exists(f"{pin}/link_{n.host}")
    stop(srv)
    assert not n.xdp_attached()
    assert not os.path.exists(f"{pin}/link_{n.host}") and not os.path.exists(f"{pin}/deny4")


def test_clean_stop_keep(bastion, net, pin):
    n = net()
    srv = bastion(xdp_conf(n, pin, extra="on_exit keep;"))
    stop(srv)
    assert n.xdp_attached()  # documented: the filter stays, with its lists
    srv2 = bastion(xdp_conf(n, pin))  # adopted, and this one detaches
    assert f"xdp: attached to {n.host} (adopted mode)" in srv2.logs()
    stop(srv2)
    assert not n.xdp_attached()


def test_kill9_stays_safe(bastion, net, pin):
    n = net()
    srv = bastion(xdp_conf(n, pin))
    p = srv.ports["http"]
    assert n.get(n.bad, p) == "timeout"
    kids = list(srv.children())
    stop(srv, signal.SIGKILL)
    for k in kids:  # the children follow their master (PR_SET_PDEATHSIG)
        try:
            os.waitpid(k, 0)
        except ChildProcessError:
            pass
    # documented: the pinned link keeps the filter (and the deny list) running, owned by the pin
    assert n.xdp_attached()
    assert os.path.exists(f"{pin}/link_{n.host}")
    assert n.get(n.bad, p, timeout=0.5) == "timeout"
    srv2 = bastion(xdp_conf(n, pin, extra=f"allow {n.bad};"))  # a later start adopts it
    logs = srv2.logs()
    assert "adopting 1 pinned link(s)" in logs and f"{n.host} (adopted mode)" in logs, logs
    p2 = srv2.ports["http"]
    assert n.get(n.good, p2) == "200"
    assert n.get(n.bad, p2) == "200"  # the new config's lists are in the adopted maps
    stop(srv2)
    assert not n.xdp_attached()


def test_multiple_interfaces(bastion, net, pin):
    a, b = net(), net()
    conf = (f"workers 1;\nxdp {{ interface {a.host} {b.host}; mode generic; pin_path {pin}; "
            f"deny {a.bad} {b.bad}; }}\n"
            f"server {{ listen {a.ip}:@HTTP_PORT@; listen {b.ip}:@HTTP_PORT@; "
            "location / { return 200 \"ok\"; } }\n")
    srv = bastion(conf)
    p = srv.ports["http"]
    assert a.xdp_attached() and b.xdp_attached()
    for n in (a, b):
        assert n.get(n.good, p) == "200"
        assert n.get(n.bad, p) == "timeout"


def test_no_block_no_bpf(bastion, net):
    n = net()
    srv = bastion("workers 1;\nserver { listen %s:@HTTP_PORT@; location / { return 200 \"ok\"; } }\n" % n.ip)
    assert "xdp:" not in srv.logs()
    assert not n.xdp_attached()
