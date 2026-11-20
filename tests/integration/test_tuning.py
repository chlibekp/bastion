"""CPU placement, NUMA, huge pages and steering (src/ops/numa.c, src/io/steering.c), and
`bastion doctor` (src/ops/doctor.c), which only reads. Host sysctls are never changed here."""
import ctypes
import os
import re
import resource
import socket
import subprocess
import time
from pathlib import Path

import pytest

from conftest import _free_port

ALLOWED = sorted(os.sched_getaffinity(0))
SO_INCOMING_CPU = 49


def cpus_of(pid):
    text = Path(f"/proc/{pid}/status").read_text()
    return re.search(r"^Cpus_allowed_list:\s*(\S+)$", text, re.M).group(1)


def get(port, path="/"):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(f"GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".encode())
        data = b""
        while chunk := s.recv(65536):
            data += chunk
    return int(data.split(b" ", 2)[1])


def site(tmp_path):
    (tmp_path / "www").mkdir(parents=True, exist_ok=True)
    (tmp_path / "www" / "index.html").write_text("ok\n")


SERVE = "server { listen 127.0.0.1:@HTTP_PORT@ @OPT@; root @WORKDIR@/www; }\n"


def test_cpu_pinned(bastion, tmp_path):
    site(tmp_path)
    srv = bastion("worker_cpu_affinity auto;\nworkers 3;\n" + SERVE.replace("@OPT@", ""))
    workers = srv.wait_workers(3)
    for slot, pid in workers.items():
        assert cpus_of(pid) == str(ALLOWED[slot % len(ALLOWED)])
    assert cpus_of(srv.helper()) == cpus_of(srv.proc.pid)  # only workers are pinned
    assert get(srv.ports["http"]) == 200


def test_cpu_list_pinned(bastion, tmp_path):
    if len(ALLOWED) < 2:
        pytest.skip("needs two CPUs")
    site(tmp_path)
    a, b = ALLOWED[-1], ALLOWED[0]
    srv = bastion(f"worker_cpu_affinity {a} {b};\nworkers 3;\n" + SERVE.replace("@OPT@", ""))
    workers = srv.wait_workers(3)
    assert [cpus_of(workers[s]) for s in range(3)] == [str(a), str(b), str(a)]


def _cpuset(cpus):
    return lambda: os.sched_setaffinity(0, cpus)


def test_affinity_respects_cpuset(bastion, tmp_path):
    if len(ALLOWED) < 3:
        pytest.skip("needs three CPUs")
    site(tmp_path)
    subset = set(ALLOWED[1:3])
    srv = bastion("workers auto;\nworker_cpu_affinity auto;\n" + SERVE.replace("@OPT@", ""),
                  preexec=_cpuset(subset))
    workers = srv.wait_workers(2)  # workers auto counts the allowed CPUs, not the online ones
    assert len(workers) == 2
    assert sorted(cpus_of(p) for p in workers.values()) == sorted(str(c) for c in subset)
    assert get(srv.ports["http"]) == 200
    # a CPU outside the cpuset is a config error, not a worker silently left unpinned
    conf = tmp_path / "outside.conf"
    conf.write_text(f"worker_cpu_affinity {ALLOWED[0]};\nserver {{ listen 127.0.0.1:1; }}\n")
    bad = subprocess.run([str(srv.proc.args[0]), "-t", "-c", str(conf)],
                         capture_output=True, text=True, preexec_fn=_cpuset(subset))
    assert bad.returncode != 0 and "is not available to this process" in bad.stderr


def _pidfd_getfd(pid, fd):
    libc = ctypes.CDLL(None, use_errno=True)
    pidfd = os.pidfd_open(pid)
    try:
        r = libc.syscall(438, pidfd, fd, 0)  # pidfd_getfd
        if r < 0:
            raise OSError(ctypes.get_errno(), "pidfd_getfd")
        return r
    finally:
        os.close(pidfd)


def _listening_fds(pid, port):
    inodes = set()
    for line in Path("/proc/net/tcp").read_text().splitlines()[1:]:
        f = line.split()
        if f[3] == "0A" and int(f[1].split(":")[1], 16) == port:
            inodes.add(f[9])
    out = []
    for fd in os.listdir(f"/proc/{pid}/fd"):
        try:
            link = os.readlink(f"/proc/{pid}/fd/{fd}")
        except OSError:
            continue
        m = re.fullmatch(r"socket:\[(\d+)\]", link)
        if m and m.group(1) in inodes:
            out.append(int(fd))
    return sorted(out)


def test_incoming_cpu(bastion, tmp_path):
    """SO_INCOMING_CPU reads back from master's sockets as the CPU each slot is pinned to, also
    under a cpuset whose CPUs do not start at 0."""
    if len(ALLOWED) < 3:
        pytest.skip("needs three CPUs")
    site(tmp_path)
    subset = sorted(ALLOWED[1:3])
    srv = bastion("tcp_profile edge { steering incoming_cpu; }\nworkers 4;\n" +
                  SERVE.replace("@OPT@", "tcp_profile=edge"), preexec=_cpuset(set(subset)))
    workers = srv.wait_workers(4)
    fds = _listening_fds(srv.proc.pid, srv.ports["http"])
    assert len(fds) == 4
    got = []
    for fd in fds:  # master creates slot 0 first, so fd order is slot order
        dup = _pidfd_getfd(srv.proc.pid, fd)
        with socket.socket(fileno=dup) as s:
            got.append(s.getsockopt(socket.SOL_SOCKET, SO_INCOMING_CPU))
    assert got == [subset[i % 2] for i in range(4)]
    assert [cpus_of(workers[i]) for i in range(4)] == [str(subset[i % 2]) for i in range(4)]


def _owner_slot(srv, server_port, client_port):
    inode = None
    for line in Path("/proc/net/tcp").read_text().splitlines()[1:]:
        f = line.split()
        if int(f[1].split(":")[1], 16) == server_port and int(f[2].split(":")[1], 16) == client_port:
            inode = f[9]
    for slot, pid in srv.workers().items():
        for fd in os.listdir(f"/proc/{pid}/fd"):
            try:
                if os.readlink(f"/proc/{pid}/fd/{fd}") == f"socket:[{inode}]":
                    return slot
            except OSError:
                pass
    return None


def test_ebpf_steering(bastion, tmp_path):
    """A reuseport program picks the socket of the worker pinned to the CPU the connection
    arrived on. On loopback the SYN is processed on the sending CPU, so a client pinned to CPU c
    lands on the worker pinned to c."""
    if len(ALLOWED) < 3:
        pytest.skip("needs three CPUs")
    site(tmp_path)
    srv = bastion("tcp_profile edge { steering ebpf; }\nworkers 3;\n" +
                  SERVE.replace("@OPT@", "tcp_profile=edge"), backend="epoll")
    srv.wait_log(r"steering ebpf: reuseport program attached on 127\.0\.0\.1:\d+ \(3 sockets\)")
    workers = srv.wait_workers(3)
    port = srv.ports["http"]
    before = os.sched_getaffinity(0)
    try:
        for slot in range(3):
            cpu = ALLOWED[slot]
            assert cpus_of(workers[slot]) == str(cpu)
            os.sched_setaffinity(0, {cpu})
            for _ in range(5):
                s = socket.create_connection(("127.0.0.1", port), timeout=5)
                s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
                assert s.recv(12).startswith(b"HTTP/1.1 200")
                owner = _owner_slot(srv, port, s.getsockname()[1])
                s.close()
                assert owner == slot, (cpu, owner)
    finally:
        os.sched_setaffinity(0, before)


def _fake_sysfs(tmp_path, thp, nodes=None):
    root = tmp_path / "sysfs"
    (root / "kernel/mm/transparent_hugepage").mkdir(parents=True)
    (root / "kernel/mm/transparent_hugepage/enabled").write_text(thp + "\n")
    for node, cpus in (nodes or {}).items():
        (root / f"devices/system/node/node{node}").mkdir(parents=True)
        for c in cpus:
            (root / f"devices/system/cpu/cpu{c}/node{node}").mkdir(parents=True)
    return root


def test_huge_pages_fallback(bastion, tmp_path):
    site(tmp_path)
    fake = _fake_sysfs(tmp_path, "always madvise [never]")
    srv = bastion("huge_pages on;\n" + SERVE.replace("@OPT@", ""), env={"BST_TEST_SYSFS": str(fake)})
    srv.wait_log(r"WARN huge_pages: transparent huge pages are off \(never\): using normal pages")
    assert get(srv.ports["http"]) == 200
    # where the kernel offers them, auto asks for them
    site(tmp_path / "s1")
    srv2 = bastion("huge_pages auto;\n" + SERVE.replace("@OPT@", ""))
    mode = re.search(r"\[(\w+)\]", Path("/sys/kernel/mm/transparent_hugepage/enabled").read_text())
    if mode and mode.group(1) != "never":
        srv2.wait_log(rf"huge_pages: the allocator asks for transparent huge pages \({mode.group(1)}\)")
    assert get(srv2.ports["http"]) == 200


def test_numa_single_node(bastion, tmp_path):
    site(tmp_path)
    srv = bastion("numa auto;\nworker_cpu_affinity auto;\nworkers 2;\n" + SERVE.replace("@OPT@", ""))
    workers = srv.wait_workers(2)
    assert [cpus_of(workers[s]) for s in range(2)] == [str(ALLOWED[s % len(ALLOWED)]) for s in range(2)]
    assert not re.search(r"numa: \d+ nodes", srv.logs())  # one node: nothing reordered
    assert get(srv.ports["http"]) == 200


def test_numa_two_nodes_simulated(bastion, tmp_path):
    if len(ALLOWED) < 4:
        pytest.skip("needs four CPUs")
    site(tmp_path)
    evens, odds = ALLOWED[0::2], ALLOWED[1::2]
    fake = _fake_sysfs(tmp_path, "[madvise]", {0: evens, 1: odds})
    srv = bastion("worker_cpu_affinity auto;\nworkers 3;\n" + SERVE.replace("@OPT@", ""),
                  env={"BST_TEST_SYSFS": str(fake)})
    srv.wait_log(r"numa: 2 nodes: workers fill the CPUs node by node")
    workers = srv.wait_workers(3)
    order = evens + odds
    assert [cpus_of(workers[s]) for s in range(3)] == [str(order[s]) for s in range(3)]


# ---- bastion doctor ----


def doctor(bastion_bin, *args):
    return subprocess.run([str(bastion_bin), "doctor", *args], capture_output=True, text=True, timeout=60)


def rows(out):
    r = {}
    for line in out.splitlines()[1:]:
        m = re.match(r"(.{22}) (\S+)\s+(.*)$", line)
        if m:
            r[m.group(1).strip()] = (m.group(2), m.group(3))
    return r


def read(path):
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


def test_doctor_output(bastion_bin):
    run = doctor(bastion_bin)
    assert run.returncode == 0, run.stderr
    r = rows(run.stdout)
    for name in ("kernel", "io_uring", "kTLS", "BPF (XDP)", "BBR", "busy_poll", "tcp_syncookies",
                 "somaxconn", "fd limit (nofile)", "Landlock", "seccomp"):
        assert name in r, (name, run.stdout)
    assert os.uname().release in r["kernel"][1]
    assert r["somaxconn"][1].startswith(read("/proc/sys/net/core/somaxconn"))
    assert r["tcp_syncookies"][1].startswith(read("/proc/sys/net/ipv4/tcp_syncookies"))
    assert (r["tcp_syncookies"][0] == "ok") == (read("/proc/sys/net/ipv4/tcp_syncookies") == "1")
    bbr = "bbr" in (read("/proc/sys/net/ipv4/tcp_available_congestion_control") or "").split()
    assert r["BBR"][1].startswith("available" if bbr else "not available")
    ktls = "tls" in (read("/proc/sys/net/ipv4/tcp_available_ulp") or "").split() or os.path.exists("/sys/module/tls")
    assert (r["kTLS"][0] == "ok") == ktls
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    assert f"soft {soft}, hard {hard}" in r["fd limit (nofile)"][1]
    landlock = ctypes.CDLL(None).syscall(444, None, 0, 1) > 0  # landlock_create_ruleset(VERSION)
    assert (r["Landlock"][0] == "ok") == landlock
    assert "doctor only reads" in run.stdout


def _snapshot():
    snap = {}
    for top in ("/proc/sys/net/core", "/proc/sys/net/ipv4", "/proc/sys/fs", "/proc/sys/kernel"):
        for dirpath, _, files in os.walk(top):
            for f in files:
                p = os.path.join(dirpath, f)
                if "random" in p or "ns_last_pid" in p or "/inode" in p or "dentry" in p or "file-nr" in p:
                    continue  # counters that move by themselves
                v = read(p)
                if v is not None:
                    snap[p] = v
    snap["modules"] = read("/proc/modules")
    snap["thp"] = read("/sys/kernel/mm/transparent_hugepage/enabled")
    return snap


def test_doctor_no_changes(bastion_bin, tmp_path):
    conf = tmp_path / "d.conf"
    conf.write_text("io { uring_napi on; }\nserver { listen 127.0.0.1:1; }\n")
    before = _snapshot()
    assert doctor(bastion_bin).returncode == 0
    assert doctor(bastion_bin, "-c", str(conf)).returncode == 0
    after = _snapshot()
    changed = [k for k in before if after.get(k) != before[k]]
    assert changed == [], changed


def test_doctor_require(bastion_bin, tmp_path):
    landlock = ctypes.CDLL(None).syscall(444, None, 0, 1) > 0
    conf = tmp_path / "r.conf"
    conf.write_text("sandbox { landlock on require; }\nserver { listen 127.0.0.1:1; }\n")
    run = doctor(bastion_bin, "-c", str(conf))
    assert run.returncode == (0 if landlock else 1), run.stdout
    assert ("landlock require would fail" in run.stdout) == (not landlock)
    conf.write_text("server { listen 127.0.0.1:1; }\n")
    run = doctor(bastion_bin, "-c", str(conf))
    assert run.returncode == 0 and "every require of the configuration can be met here" in run.stdout
    conf.write_text("server { listen nonsense; }\n")
    assert doctor(bastion_bin, "-c", str(conf)).returncode == 2
    assert doctor(bastion_bin, "--frobnicate").returncode == 2
