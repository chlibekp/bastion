"""Listeners and TCP socket options, through `bastion --test-listeners` (a test-build flag:
there is no server runtime until Phase 3 Task 7).

The flag compiles the config, creates the listeners as master will, prints one JSON line with
every socket's options read back with getsockopt, then (with --test-accept-ms) accepts for that
long and prints a second JSON line with what each slot accepted. Warnings go to stderr as
error-log lines. Ports are free high ports picked per test; nothing reads host files."""
import json
import os
import re
import socket
import struct
import subprocess
import threading
import time

import pytest

IPPROTO_TCP = socket.IPPROTO_TCP
TCP_FASTOPEN_CONNECT = 30


def free_port(kind=socket.SOCK_STREAM, host="127.0.0.1"):
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind((host, 0))
        return s.getsockname()[1]


class Run:
    def __init__(self, binary, tmp_path, conf, slots, accept_ms=0, name="l.conf"):
        self.conf = tmp_path / name
        self.conf.write_text(conf)
        cmd = [binary, "-c", str(self.conf), "--test-listeners", str(slots)]
        if accept_ms:
            cmd += ["--test-accept-ms", str(accept_ms)]
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.err = ""
        self._t = threading.Thread(target=self._drain, daemon=True)
        self._t.start()
        self.listening = None
        self.done = None

    def _drain(self):
        self.err = self.proc.stderr.read()

    def wait_listening(self):
        line = self.proc.stdout.readline()
        if not line:
            self.finish()
            return None
        self.listening = json.loads(line)
        assert self.listening["event"] == "listening"
        return self.listening

    def finish(self):
        out = self.proc.stdout.read()
        self.proc.wait(timeout=30)
        self._t.join(timeout=10)
        for line in out.splitlines():
            if line.strip():
                self.done = json.loads(line)
        return self.proc.returncode


def start(bastion_bin, tmp_path, conf, slots=1, accept_ms=0):
    return Run(bastion_bin, tmp_path, conf, slots, accept_ms)


def listen_once(bastion_bin, tmp_path, conf, slots=1):
    r = start(bastion_bin, tmp_path, conf, slots)
    r.wait_listening()
    rc = r.finish()
    return r, rc


def server(port, profile=None, extra=""):
    opt = f" tcp_profile={profile}" if profile else ""
    return f"server {{ listen 127.0.0.1:{port}{opt}; {extra} }}\n"


def bst_listening(r):
    return r.listening["listeners"][0]["sockets"]


# ---------------------------------------------------------------- reuseport


def test_reuseport_slots(bastion_bin, tmp_path):
    port = free_port()
    r = start(bastion_bin, tmp_path, server(port), slots=4, accept_ms=2500)
    dump = r.wait_listening()
    socks = dump["listeners"][0]["sockets"]
    assert len(socks) == 4
    assert len({s["fd"] for s in socks}) == 4
    assert all(s["opts"]["reuseport"] == 1 and s["opts"]["acceptconn"] == 1 for s in socks)
    clients = []
    for _ in range(64):  # 64 source ports: the kernel hashes them over the four sockets
        c = socket.create_connection(("127.0.0.1", port))
        clients.append(c)
    assert r.finish() == 0
    accepted = r.done["accepted"][0]
    assert len(accepted) == 4
    assert sum(accepted) == 64
    assert sum(1 for n in accepted if n > 0) >= 2, accepted
    for c in clients:
        c.close()


def test_v6_any_and_v4_any_coexist(bastion_bin, tmp_path):
    if not socket.has_ipv6:
        pytest.skip("no IPv6 here")
    try:
        with socket.socket(socket.AF_INET6) as s:
            s.bind(("::1", 0))
    except OSError:
        pytest.skip("IPv6 loopback unusable here")
    port = free_port()
    conf = f"server {{ listen {port}; }}\nserver {{ listen [::]:{port}; }}\n"
    r, rc = listen_once(bastion_bin, tmp_path, conf, slots=2)
    assert rc == 0, r.err
    by_v6 = {l["addr"]: l for l in r.listening["listeners"]}
    assert set(by_v6) == {"0.0.0.0", "::"}
    assert all(s["opts"]["v6only"] == 1 for s in by_v6["::"]["sockets"])
    assert "v6only" not in by_v6["0.0.0.0"]["sockets"][0]["opts"]


def test_bind_failure_reports_address_and_errno(bastion_bin, tmp_path):
    with socket.socket() as blocker:
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        port = blocker.getsockname()[1]
        r, rc = listen_once(bastion_bin, tmp_path, server(port), slots=2)
    assert rc == 1
    assert f"127.0.0.1:{port}" in r.err
    assert os.strerror(98) in r.err


# ---------------------------------------------------------------- read back

# directive text, then dump key -> expected value (callable: predicate)
ROUNDTRIP = """
tcp_profile all {
    fastopen 1024;
    fastopen_key 000102030405060708090a0b0c0d0e0f;
    defer_accept 5s;
    busy_poll 50us;
    prefer_busy_poll on;
    nodelay on;
    congestion cubic;
    notsent_lowat 128k;
    user_timeout 30s;
    keepalive idle=61s interval=11s count=5;
    rcvbuf 128k;
    sndbuf 128k;
    pacing_rate 1m;
    mark 7;
    freebind on;
    steering incoming_cpu;
    backlog 1000;
}
"""

EXPECT = {
    "fastopen": lambda v: v == 1024,
    "fastopen_key": lambda v: v == "000102030405060708090a0b0c0d0e0f",
    # the kernel stores retransmit rounds: 5s reads back as the 7s that covers them
    "defer_accept": lambda v: 5 <= v <= 10,
    "busy_poll": lambda v: v == 50,
    "prefer_busy_poll": lambda v: v == 1,
    "nodelay": lambda v: v == 1,
    "congestion": lambda v: v == "cubic",
    "notsent_lowat": lambda v: v == 131072,
    "user_timeout": lambda v: v == 30000,
    "keepalive": lambda v: v == 1,
    "keepidle": lambda v: v == 61,
    "keepintvl": lambda v: v == 11,
    "keepcnt": lambda v: v == 5,
    "rcvbuf": lambda v: v == 2 * 131072,  # the kernel doubles it for bookkeeping
    "sndbuf": lambda v: v == 2 * 131072,
    "pacing_rate": lambda v: v == 1048576,
    "mark": lambda v: v == 7,
    "freebind": lambda v: v == 1,
}


def listen_backlog(port):
    """Send-Q of a LISTEN socket in `ss -ltn` is its maximum accept backlog."""
    out = subprocess.run(["ss", "-ltnH", f"sport = :{port}"], capture_output=True, text=True,
                         check=True).stdout
    rows = [l.split() for l in out.splitlines() if l.strip()]
    assert rows, out
    return {int(r[2]) for r in rows}


def test_getsockopt_roundtrip(bastion_bin, tmp_path):
    port = free_port()
    r = start(bastion_bin, tmp_path, ROUNDTRIP + server(port, "all"), slots=3, accept_ms=1000)
    dump = r.wait_listening()
    sockets = dump["listeners"][0]["sockets"]
    assert len(sockets) == 3
    assert listen_backlog(port) == {1000}  # all three sockets
    assert r.finish() == 0
    # An option this kernel refused was warned about by name; every other one must read back.
    refused = set(re.findall(r"option (\w+)(?: \([^)]*\))? not applied", r.err))
    verified = 0
    for s in sockets:
        for key, ok in EXPECT.items():
            if key in refused or (key.startswith("keep") and "keepalive" in refused):
                continue
            assert key in s["opts"], (key, s["opts"], r.err)
            assert ok(s["opts"][key]), (key, s["opts"][key])
            verified += 1
    assert verified >= 3 * 14, (verified, r.err)
    ncpu = os.cpu_count()
    assert [s["opts"]["incoming_cpu"] for s in sockets] == [i % ncpu for i in range(3)]


def test_defaults_are_applied_without_a_profile(bastion_bin, tmp_path):
    port = free_port()
    r, rc = listen_once(bastion_bin, tmp_path, server(port))
    assert rc == 0, r.err
    o = bst_listening(r)[0]["opts"]
    assert o["nodelay"] == 1  # the documented default profile
    assert o["fastopen"] == 0  # and nothing else is switched on
    assert o["defer_accept"] == 0
    assert o["mark"] == 0


def test_quickack_is_applied_on_accept(bastion_bin, tmp_path):
    port = free_port()
    conf = "tcp_profile q { quickack off; }\n" + server(port, "q")
    r = start(bastion_bin, tmp_path, conf, slots=1, accept_ms=800)
    r.wait_listening()
    c = socket.create_connection(("127.0.0.1", port))
    assert r.finish() == 0
    c.close()
    assert r.done["accepted_opts"][0]["quickack"] == 0
    assert r.done["accepted_opts"][0]["nodelay"] == 1  # inherited, not re-applied


# ---------------------------------------------------------------- kernel features


def read_netstat(field):
    with open("/proc/net/netstat") as f:
        lines = f.read().splitlines()
    for i, line in enumerate(lines):
        if line.startswith("TcpExt:") and i + 1 < len(lines) and lines[i + 1].startswith("TcpExt:"):
            names, vals = line.split()[1:], lines[i + 1].split()[1:]
            return int(vals[names.index(field)])
    raise AssertionError("no TcpExt line")


def _private_netns():
    """True only when the runner says this process is in a network namespace of its own.
    Nothing here can tell: /.dockerenv exists in --net=host containers too. ./dev knows it
    passes no --net=host and sets BST_TEST_PRIVATE_NETNS=1; any other runner opts in itself."""
    return os.environ.get("BST_TEST_PRIVATE_NETNS") == "1"


@pytest.fixture
def tfo_sysctl():
    # Assumption: tcp_fastopen is a per-netns sysctl, so writing it inside a container's own
    # netns (./dev, no --net=host) is private. On a runner without netns isolation it would be
    # host-global: skip rather than change the host.
    path = "/proc/sys/net/ipv4/tcp_fastopen"
    if not _private_netns() or not os.access(path, os.W_OK):
        pytest.skip("needs a writable tcp_fastopen in a private network namespace "
                    "(run through ./dev, which sets BST_TEST_PRIVATE_NETNS=1)")
    old = open(path).read().strip()
    open(path, "w").write("3")  # client and server; the server bit is off by default
    yield
    open(path, "w").write(old)


def tfo_client(port, data):
    c = socket.socket()
    c.setsockopt(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1)
    c.settimeout(3)
    c.connect(("127.0.0.1", port))  # with TFO_CONNECT the SYN goes out with the first send
    c.sendall(data)
    return c


def test_fastopen(bastion_bin, tmp_path, tfo_sysctl):
    port = free_port()
    conf = "tcp_profile t { fastopen 256; }\n" + server(port, "t")
    r = start(bastion_bin, tmp_path, conf, slots=1, accept_ms=1500)
    r.wait_listening()
    before = read_netstat("TCPFastOpenPassive")
    c1 = tfo_client(port, b"first")  # no cookie yet: a plain handshake that asks for one
    time.sleep(0.2)
    c2 = tfo_client(port, b"second")  # cookie cached: the data rides the SYN
    time.sleep(0.2)
    assert read_netstat("TCPFastOpenPassive") - before >= 1
    assert r.finish() == 0
    assert "net.ipv4.tcp_fastopen" not in r.err  # the sysctl is fine: nothing to warn about
    assert sum(r.done["accepted"][0]) == 2
    assert 6 in r.done["bytes"][0]  # the SYN's payload was readable right at accept
    c1.close()
    c2.close()


def test_fastopen_off_does_not_use_the_syn_payload(bastion_bin, tmp_path, tfo_sysctl):
    port = free_port()
    r = start(bastion_bin, tmp_path, server(port), slots=1, accept_ms=1000)
    r.wait_listening()
    before = read_netstat("TCPFastOpenPassive")
    c1 = tfo_client(port, b"first")
    time.sleep(0.2)
    c2 = tfo_client(port, b"second")
    time.sleep(0.2)
    assert read_netstat("TCPFastOpenPassive") == before
    assert r.finish() == 0
    c1.close()
    c2.close()


def test_defer_accept(bastion_bin, tmp_path):
    port = free_port()
    conf = "tcp_profile d { defer_accept 2s; }\n" + server(port, "d")
    r = start(bastion_bin, tmp_path, conf, slots=1, accept_ms=1400)
    r.wait_listening()
    silent = socket.create_connection(("127.0.0.1", port))  # handshake done, sends nothing
    talker = socket.create_connection(("127.0.0.1", port))
    talker.sendall(b"x")
    assert r.finish() == 0
    # the connection with data was accepted; the empty one is still held back by the kernel
    assert sum(r.done["accepted"][0]) == 1
    assert r.done["bytes"][0] == [1]
    silent.close()
    talker.close()


def test_defer_accept_releases_the_empty_connection_after_the_schedule(bastion_bin, tmp_path):
    # defer_accept 2s is two retransmit rounds: it reads back as 3 s, and the kernel then
    # hands the empty connection over at about 3.05 s (measured), not earlier.
    port = free_port()
    conf = "tcp_profile d { defer_accept 2s; }\n" + server(port, "d")
    r = start(bastion_bin, tmp_path, conf, slots=1, accept_ms=5500)
    dump = r.wait_listening()
    assert dump["listeners"][0]["sockets"][0]["opts"]["defer_accept"] == 3
    silent = socket.create_connection(("127.0.0.1", port))
    assert r.finish() == 0
    assert sum(r.done["accepted"][0]) == 1
    assert r.done["bytes"][0] == [0]
    assert 2800 <= r.done["first_accept_ms"][0] <= 4500, r.done
    silent.close()


def test_without_defer_accept_the_empty_connection_is_accepted(bastion_bin, tmp_path):
    port = free_port()
    r = start(bastion_bin, tmp_path, server(port), slots=1, accept_ms=600)
    r.wait_listening()
    silent = socket.create_connection(("127.0.0.1", port))
    assert r.finish() == 0
    assert sum(r.done["accepted"][0]) == 1
    silent.close()


# ---------------------------------------------------------------- refused options

AVAILABLE_CC = open("/proc/sys/net/ipv4/tcp_available_congestion_control").read().split()


def cc_params():
    return [
        pytest.param("bbr", marks=pytest.mark.skipif("bbr" in AVAILABLE_CC,
                                                     reason="this kernel has bbr")),
        "nosuchcc",
    ]


@pytest.mark.parametrize("cc", cc_params())
def test_missing_opt_warns(bastion_bin, tmp_path, cc):
    port = free_port()
    conf = f"tcp_profile e {{ congestion {cc}; }}\n" + server(port, "e")
    r, rc = listen_once(bastion_bin, tmp_path, conf, slots=2)
    assert rc == 0, r.err
    assert len(bst_listening(r)) == 2  # the server starts
    warns = [l for l in r.err.splitlines() if "WARN" in l and "congestion" in l]
    assert len(warns) == 1, r.err
    assert os.strerror(2) in warns[0]
    assert '"e"' in warns[0] or " e " in warns[0]


@pytest.mark.parametrize("cc", cc_params())
def test_missing_opt_require(bastion_bin, tmp_path, cc):
    port = free_port()
    conf = f"tcp_profile e {{ congestion {cc} require; }}\n" + server(port, "e")
    r, rc = listen_once(bastion_bin, tmp_path, conf, slots=2)
    assert rc == 1
    assert r.listening is None  # no listener was handed out
    assert "congestion" in r.err and cc in r.err and os.strerror(2) in r.err
    # nothing leaked: the port binds again
    with socket.socket() as s:
        s.bind(("127.0.0.1", port))


def test_clamped_buffer_is_named(bastion_bin, tmp_path):
    port = free_port()
    conf = "tcp_profile e { rcvbuf 1g; }\n" + server(port, "e")
    r, rc = listen_once(bastion_bin, tmp_path, conf)
    assert rc == 0, r.err
    assert any("rcvbuf" in l and "rmem_max" in l for l in r.err.splitlines()), r.err


# ---------------------------------------------------------------- config surface


def run_t(bastion_bin, tmp_path, conf, flag="-t"):
    p = tmp_path / "c.conf"
    p.write_text(conf)
    return subprocess.run([bastion_bin, "-c", str(p), flag], capture_output=True, text=True,
                          timeout=30)


def test_steering_ebpf_is_rejected_at_config_time(bastion_bin, tmp_path):
    p = run_t(bastion_bin, tmp_path, "tcp_profile e { steering ebpf; }\nserver { listen 8080; }\n")
    assert p.returncode == 1
    assert "c.conf:1:" in p.stderr and "not supported yet" in p.stderr


def test_undefined_profile_error_has_position_and_suggestion(bastion_bin, tmp_path):
    p = run_t(bastion_bin, tmp_path,
              "tcp_profile edge { }\nserver {\n  listen 8080 tcp_profile=edg;\n}\n")
    assert p.returncode == 1
    assert "c.conf:3:" in p.stderr
    assert 'undefined tcp_profile "edg"' in p.stderr and 'did you mean "edge"?' in p.stderr


def test_effective_config_prints_defaults_and_secret_key(bastion_bin, tmp_path):
    p = run_t(bastion_bin, tmp_path,
              "tcp_profile e { fastopen_key 000102030405060708090a0b0c0d0e0f; }\n"
              "server { listen 8080 tcp_profile=e; }\n", flag="-T")
    assert p.returncode == 0, p.stderr
    assert "000102030405060708090a0b0c0d0e0f" in p.stdout  # -T prints secrets: documented
    assert "nodelay on;" in p.stdout and "backlog 4096;" in p.stdout
