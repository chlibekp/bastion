"""Overload protection: limits { } and the worker's accept path (src/io/admission.c).

The protocol is the raw test mode of src/proc/test_raw.c, until Phase 4 has the `return` handler:
`echo` for connection limits, `budget` (BST_TEST_RAW_MEM bytes of touched memory held per
connection against worker_memory, the fixed line as the answer, and over budget the
overload_status response with Retry-After) for the memory budget. One worker per server, so every
connection meets the same limits."""
import os
import re
import select
import socket
import time
from pathlib import Path

from process_util import *  # noqa: F401,F403

BUDGET = {"BST_TEST_RAW_MODE": "budget"}
CLK_TCK = os.sysconf("SC_CLK_TCK")


def closed_by_server(s, timeout=0.5):
    """True when the server closed or reset s without sending anything; False when it is still
    connected and silent, which is what a held connection looks like in echo mode."""
    if not select.select([s], [], [], timeout)[0]:
        return False
    try:
        return s.recv(1) == b""
    except ConnectionResetError:
        return True


def open_clients(port, n):
    out = []
    for _ in range(n):
        s = socket.socket()
        s.settimeout(5)
        s.connect(("127.0.0.1", port))
        out.append(s)
    return out


def close_all(socks):
    for s in socks:
        s.close()


def cpu_ticks(pid):
    stat = Path(f"/proc/{pid}/stat").read_text()
    f = stat[stat.rindex(")") + 2:].split()
    return int(f[11]) + int(f[12])


def rss_bytes(pid):
    return int(field(pid, "VmRSS").split()[0]) * 1024


def nfds(pid):
    return len(os.listdir(f"/proc/{pid}/fd"))


def overload_totals(srv):
    """(closed, refused, fd_closed) from the last overload line the worker logged."""
    found = re.findall(r"overload: closed=(\d+) .* refused=(\d+) .* fd_closed=(\d+) ", srv.logs())
    return tuple(int(x) for x in found[-1]) if found else (0, 0, 0)


def read_response(s):
    data = b""
    while True:
        chunk = s.recv(4096)
        data += chunk
        if not chunk or data.endswith(b"\r\n\r\n") or data == RESPOND_LINE:
            return data


def test_max_connections(bastion):
    srv = bastion(conf(1, "limits { max_connections 5; }"), env=ECHO)
    port = srv.ports["http"]
    held = open_clients(port, 5)
    for s in held:  # all five are served
        s.sendall(b"hi")
        assert s.recv(2) == b"hi"
    over = open_clients(port, 4)
    assert all(closed_by_server(s) for s in over)  # closed at once, not left waiting
    srv.wait_for(lambda: overload_totals(srv)[0] >= 4, what="the closed connections counted")
    assert overload_totals(srv)[0] == 4
    held[0].sendall(b"ok")  # the held ones are untouched
    assert held[0].recv(2) == b"ok"
    close_all(over + held)
    srv.wait_for(lambda: echo_ok(port), what="service after the connections end")


def test_emfile(bastion):
    srv = bastion(conf(1, "worker_rlimit_nofile 64;\nlimits { accept_backoff 100ms; }"), env=ECHO)
    port = srv.ports["http"]
    pid = srv.workers()[0]
    base = nfds(pid)
    assert base < 50, f"the worker starts with {base} descriptors: raise worker_rlimit_nofile"
    clients = open_clients(port, 140)
    time.sleep(0.5)
    shed = [s for s in clients if closed_by_server(s, 0.05)]
    held = [s for s in clients if s not in shed]
    # The descriptor table holds 64 - base (less the reserve); the rest are accepted and closed.
    assert len(shed) >= 140 - (64 - base) - 5, (len(shed), base)
    assert 5 <= len(held) <= 64 - base, (len(held), base, srv.logs())
    srv.wait_log(r"accept: .*paused, retrying every 100 ms")
    srv.wait_for(lambda: overload_totals(srv)[2] >= len(shed) - 5, what="fd_closed counted")
    ticks, t0 = cpu_ticks(pid), time.monotonic()  # paused: backing off, not spinning
    time.sleep(1.5)
    cpu = (cpu_ticks(pid) - ticks) / CLK_TCK / (time.monotonic() - t0)
    assert cpu < 0.10, f"{cpu:.0%} of a CPU while out of descriptors"
    assert srv.workers() == {0: pid}
    close_all(clients)
    srv.wait_for(lambda: echo_ok(port), timeout=5, what="service once descriptors are free")
    srv.wait_log(r"accept: resumed")
    assert srv.workers() == {0: pid}


def test_memory_budget(bastion):
    mem = 2 << 20
    srv = bastion(conf(1, "limits { worker_memory 8m; overload_status 429; "
                          "overload_retry_after 7s; }"),
                  env=BUDGET | {"BST_TEST_RAW_MEM": str(mem)})
    port = srv.ports["http"]
    pid = srv.workers()[0]
    before = rss_bytes(pid)
    clients = []
    answers = []
    for _ in range(20):
        s = connect(port)
        answers.append(read_response(s))
        clients.append(s)
    served = [a for a in answers if a == RESPOND_LINE]
    refused = [a for a in answers if a.startswith(b"HTTP/1.1 429 ")]
    assert len(served) == 4 and len(refused) == 16, answers  # 4 * 2 MiB fill 8 MiB
    assert all(b"Retry-After: 7\r\n" in a for a in refused)
    # Without the budget 20 connections would take 40 MiB.
    assert rss_bytes(pid) - before < 20 << 20
    srv.wait_for(lambda: overload_totals(srv)[1] == 16, what="refusals counted")
    close_all(clients)
    assert srv.workers() == {0: pid}


def test_recovery(bastion):
    mem = 2 << 20
    srv = bastion(conf(1, "limits { worker_memory 4m; }"),
                  env=BUDGET | {"BST_TEST_RAW_MEM": str(mem)})
    port = srv.ports["http"]
    pid = srv.workers()[0]
    held = [connect(port) for _ in range(2)]
    assert [read_response(s) for s in held] == [RESPOND_LINE] * 2
    with connect(port) as s:
        assert read_response(s).startswith(b"HTTP/1.1 503 ")  # the default status
    close_all(held)  # the load ends
    deadline = time.monotonic() + 5
    while True:
        with connect(port) as s:
            answer = read_response(s)
        if answer == RESPOND_LINE:
            break
        assert time.monotonic() < deadline, "the budget never came back"
        time.sleep(0.05)
    assert srv.workers() == {0: pid}  # recovered without a restart
