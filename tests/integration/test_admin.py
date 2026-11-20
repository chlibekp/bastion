"""The local admin API and bastionctl (src/ops/admin.c, src/ops/ctl.c; Phase 14 Task 6).

HTTP/1.1 over a Unix socket only, served by the helper; master does what needs it through the
mailbox. Also the Phase 13 carry-overs through the API: test_worker_compromise_limits (master's
block rules hold for the admin path too) and test_admin_list_matches_map (GET /blocks shows the
XDP maps' real state)."""
import ctypes
import json
import os
import platform
import shutil
import socket
import subprocess
import tempfile
import threading
import time

import pytest

from upstream_util import Upstream, get, ok, wait_until
from xdp_util import net, pin  # noqa: F401  (fixtures)


@pytest.fixture
def sockdir():
    """A short directory for the socket (sun_path is 108 bytes), traversable by everyone so the
    socket's own mode is what is tested."""
    d = tempfile.mkdtemp(prefix="bsta-")
    os.chmod(d, 0o755)
    yield d
    shutil.rmtree(d, ignore_errors=True)


def conf(sock, extra="", glob="", mode=""):
    return (f"workers 1;\n{glob}\nadmin {{ socket {sock}{' mode=' + mode if mode else ''}; }}\n"
            f"server {{ listen 127.0.0.1:@HTTP_PORT@; {extra} location / {{ return 200 \"ok\"; }} }}\n")


def call(sock, method, path, body=None, raw=None, timeout=70):
    """(status, parsed JSON body) of one request; raw sends those bytes instead."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(sock)
    if raw is None:
        b = json.dumps(body).encode() if body is not None else b""
        raw = (f"{method} {path} HTTP/1.1\r\nHost: x\r\nContent-Length: {len(b)}\r\n"
               f"Connection: close\r\n\r\n").encode() + b
    s.sendall(raw)
    out = b""
    while True:
        d = s.recv(65536)
        if not d:
            break
        out += d
    s.close()
    head, _, payload = out.partition(b"\r\n\r\n")
    status = int(head.split()[1]) if head.startswith(b"HTTP/1.1 ") else 0
    try:
        return status, json.loads(payload) if payload else None
    except ValueError:
        return status, payload


@pytest.fixture
def ctl(bastion_bin, tmp_path):
    link = tmp_path / "bastionctl"  # the same binary, chosen by argv[0]
    link.symlink_to(bastion_bin)

    def run(*args):
        return subprocess.run([str(link), *args], capture_output=True, text=True, timeout=90)
    return run


def blocked(sock):
    st, b = call(sock, "GET", "/blocks")
    assert st == 200, b
    return {f"{x['addr']}/{x['prefix']}" for x in b["blocks"]}


# ---- access ----

def _listen_inodes(proto):
    out = {}
    for f in (f"/proc/net/{proto}", f"/proc/net/{proto}6"):
        try:
            lines = open(f).read().splitlines()[1:]
        except OSError:
            continue
        for ln in lines:
            p = ln.split()
            if p[3] == "0A":  # LISTEN
                out[p[9]] = int(p[1].rsplit(":", 1)[1], 16)
    return out


def test_no_network_listener(bastion, sockdir):
    srv = bastion(conf(f"{sockdir}/a.sock"))
    listening = _listen_inodes("tcp")
    ports = set()
    for pid in [srv.proc.pid, *srv.children()]:
        for fd in os.listdir(f"/proc/{pid}/fd"):
            try:
                t = os.readlink(f"/proc/{pid}/fd/{fd}")
            except OSError:
                continue
            if t.startswith("socket:["):
                ino = t[8:-1]
                if ino in listening:
                    ports.add(listening[ino])
    assert ports == {srv.ports["http"]}, ports  # the server's own port only
    st, b = call(f"{sockdir}/a.sock", "GET", "/status")
    assert st == 200 and b["pid"] == srv.proc.pid


def test_off_by_default(bastion, sockdir):
    srv = bastion("workers 1;\nserver { listen 127.0.0.1:@HTTP_PORT@; location / { return 200 \"ok\"; } }\n")
    assert "admin: serving" not in srv.logs()
    assert not os.path.exists(f"{sockdir}/a.sock")


def test_socket_permissions(bastion, sockdir, bastion_bin, tmp_path):
    if os.geteuid() != 0:
        pytest.skip("needs root to try the socket as another user (run through ./dev)")
    sock = f"{sockdir}/a.sock"
    bastion(conf(sock))
    st = os.stat(sock)
    assert st.st_mode & 0o777 == 0o600 and st.st_uid == 0
    pid = os.fork()
    if pid == 0:  # an unprivileged user: the kernel refuses the connect
        code = 3
        try:
            os.setgid(65534)
            os.setuid(65534)
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                s.connect(sock)
                code = 1
            except PermissionError:
                code = 0
        finally:
            os._exit(code)
    _, status = os.waitpid(pid, 0)
    assert os.WEXITSTATUS(status) == 0, "another user reached the admin socket"
    # a mode that lets other users in is refused at load
    bad = tmp_path / "bad.conf"
    bad.write_text(conf(f"{sockdir}/b.sock", mode="0666"))
    r = subprocess.run([str(bastion_bin), "-t", "-c", str(bad)], capture_output=True, text=True)
    assert r.returncode != 0 and "gives other users access" in r.stdout + r.stderr


def test_peer_cred(bastion, sockdir):
    sock = f"{sockdir}/a.sock"
    srv = bastion(conf(sock))
    st, _ = call(sock, "POST", "/blocks", {"addr": "192.0.2.7", "ttl": 60})
    assert st == 200
    srv.wait_log(rf"admin: POST /blocks from pid={os.getpid()} uid={os.getuid()} gid={os.getgid()}")
    call(sock, "GET", "/status")
    assert "admin: GET /status from" not in srv.logs()  # reads are not write actions


# ---- blocks ----

def test_block_unblock(bastion, sockdir):
    sock = f"{sockdir}/a.sock"
    srv = bastion(conf(sock))
    st, b = call(sock, "POST", "/blocks", {"addr": "192.0.2.10", "ttl": 600})
    assert st == 200, b
    assert "192.0.2.10/32" in blocked(sock)
    st, b = call(sock, "POST", "/blocks", {"addr": "2001:db8::/64", "ttl": 600})
    assert st == 200, b
    assert "2001:db8::/64" in blocked(sock)
    st, _ = call(sock, "DELETE", "/blocks", {"addr": "192.0.2.10"})
    assert st == 200
    assert "192.0.2.10/32" not in blocked(sock)
    st, b = call(sock, "DELETE", "/blocks", {"addr": "192.0.2.10"})
    assert st == 404 and "not blocked" in b["error"]
    assert "unblocked 192.0.2.10/32" in srv.logs()


def test_block_allowlisted_refused(bastion, sockdir):
    sock = f"{sockdir}/a.sock"
    bastion(conf(sock, glob="escalation_allow 203.0.113.0/24;"))
    st, b = call(sock, "POST", "/blocks", {"addr": "203.0.113.5"})
    assert st == 409 and "allowlisted" in b["error"], b
    assert "203.0.113.5/32" not in blocked(sock)


def test_worker_compromise_limits(bastion, sockdir):
    """Master's block rules hold for whatever reaches it: networks, endless or out-of-range TTLs,
    allowlisted addresses and blocks past the ceiling are refused, through the API too."""
    sock = f"{sockdir}/a.sock"
    bastion(conf(sock, glob="escalation_ceiling 4;\nescalation_allow 10.0.0.0/8;"))
    assert call(sock, "POST", "/blocks", {"addr": "198.18.0.0/8"})[0] == 400  # a network
    assert call(sock, "POST", "/blocks", {"addr": "198.18.0.1", "ttl": 365 * 86400})[0] == 400
    assert call(sock, "POST", "/blocks", {"addr": "198.18.0.1", "ttl": 0})[0] == 400
    assert call(sock, "POST", "/blocks", {"addr": "10.1.2.3"})[0] == 409
    codes = [call(sock, "POST", "/blocks", {"addr": f"198.18.1.{i}"})[0] for i in range(8)]
    assert codes.count(200) == 4 and codes.count(409) == 4, codes
    assert len(blocked(sock)) == 4


# ---- reload, upgrade, status ----

def test_reload_error_reported(bastion, sockdir):
    sock = f"{sockdir}/a.sock"
    srv = bastion(conf(sock))
    path = srv.workdir / "bastion.conf"
    good = path.read_text()
    path.write_text(good + "\nthis_is_not_a_directive on;\n")
    st, b = call(sock, "POST", "/reload")
    assert st == 400 and "this_is_not_a_directive" in b["error"], b
    st, s = call(sock, "GET", "/status")
    assert s["reload"].startswith("failed") and s["generation"] == 0
    path.write_text(good)
    st, b = call(sock, "POST", "/reload")
    assert st == 202, b
    srv.wait_for(lambda: (lambda r: r[0] == 200 and r[1]["generation"] == 1 and r[1]["reload"] == "ok")(
        call(sock, "GET", "/status")), 20, "generation 1 serving")


def two_peers(sock, a, b, extra=""):
    return (f"workers 1;\nadmin {{ socket {sock}; }}\n"
            f"upstream app {{ server 127.0.0.1:{a.port}; server 127.0.0.1:{b.port}; }}\n"
            f"server {{ listen 127.0.0.1:@HTTP_PORT@; name site.test; {extra} "
            f"location / {{ proxy app; }} }}\n")


@pytest.fixture
def peers():
    gate = threading.Event()

    def slow(r, c):
        if r.target == "/slow":
            gate.wait(20)
        return ok(r.target)
    a, b = Upstream(handler=slow), Upstream(handler=slow)
    yield a, b, gate
    gate.set()
    a.close()
    b.close()


def reload_via_api(srv, sock, gen):
    assert call(sock, "POST", "/reload")[0] == 202
    srv.wait_for(lambda: (call(sock, "GET", "/status")[1] or {}).get("generation") == gen, 20, "reloaded")
    srv.wait_for(lambda: len(srv.children()) == 2, 20, "old generation gone")


def test_runtime_vs_reload(bastion, sockdir, peers):
    """Runtime changes are not written to the configuration (docs/admin-api.md). A reload resets
    the overrides (drain, maintenance, challenge) but keeps blocks, which the shared table keeps
    and the new master reads back: what /blocks lists is exactly what is enforced."""
    a, b, _ = peers
    sock = f"{sockdir}/a.sock"
    srv = bastion(two_peers(sock, a, b))
    text = (srv.workdir / "bastion.conf").read_text()
    assert call(sock, "POST", f"/upstreams/app/127.0.0.1:{a.port}/drain")[0] == 200
    assert call(sock, "POST", "/blocks", {"addr": "192.0.2.20", "ttl": 600})[0] == 200
    assert call(sock, "POST", "/maintenance", {"on": True})[0] == 200
    assert (srv.workdir / "bastion.conf").read_text() == text  # nothing written back
    reload_via_api(srv, sock, 1)
    st, up = call(sock, "GET", "/upstreams/app")
    assert st == 200 and not any(p["drained"] for p in up["peers"]), up
    n = len(a.requests)
    for _ in range(6):
        assert get(srv.ports["http"], "/x", host="site.test").startswith(b"HTTP/1.1 200")
    assert len(a.requests) > n  # the drained peer takes traffic again
    assert blocked(sock) == {"192.0.2.20/32"}  # kept, listed, and removable
    assert call(sock, "DELETE", "/blocks", {"addr": "192.0.2.20"})[0] == 200
    assert blocked(sock) == set()


def test_block_survives_reload_consistently(bastion, sockdir):
    """A block kept by the reload is enforced, listed, and gone from enforcement once removed:
    the shared table and master's list never disagree."""
    sock = f"{sockdir}/a.sock"
    srv = bastion(conf(sock, extra="real_ip_header X-Real-IP; real_ip_from 127.0.0.1/32;"))
    port = srv.ports["http"]

    def status(ip):
        return get(port, "/", extra=f"X-Real-IP: {ip}\r\n").split(b" ", 2)[1]
    assert call(sock, "POST", "/blocks", {"addr": "198.51.100.7", "ttl": 600})[0] == 200
    srv.wait_for(lambda: status("198.51.100.7") == b"403", 5, "blocked")
    reload_via_api(srv, sock, 1)
    assert status("198.51.100.7") == b"403"
    assert "198.51.100.7/32" in blocked(sock)
    assert call(sock, "DELETE", "/blocks", {"addr": "198.51.100.7"})[0] == 200
    srv.wait_for(lambda: status("198.51.100.7") == b"200", 5, "served after unblock")


def test_drain_upstream(bastion, sockdir, peers, ctl):
    """No new request goes to a drained peer, and the request in flight on it finishes."""
    a, b, gate = peers
    sock = f"{sockdir}/a.sock"
    srv = bastion(two_peers(sock, a, b))
    port = srv.ports["http"]
    out = {}
    t = threading.Thread(target=lambda: out.update(r=get(port, "/slow", host="site.test")))
    t.start()
    assert wait_until(lambda: any(r.target == "/slow" for r in a.requests + b.requests), 10)
    busy, other = (a, b) if any(r.target == "/slow" for r in a.requests) else (b, a)
    r = ctl("-s", sock, "upstream", "drain", "app", f"127.0.0.1:{busy.port}")
    assert r.returncode == 0 and "drained" in r.stdout, r.stderr
    st, up = call(sock, "GET", "/upstreams")
    peer = [p for p in up["upstreams"][0]["peers"] if p["server"] == f"127.0.0.1:{busy.port}"][0]
    assert st == 200 and peer["drained"] and peer["up"]
    n = len(busy.requests)
    for i in range(10):
        assert get(port, f"/n{i}", host="site.test").startswith(b"HTTP/1.1 200")
    assert len(busy.requests) == n and len(other.requests) >= 10
    gate.set()
    t.join(20)
    assert out["r"].startswith(b"HTTP/1.1 200") and out["r"].endswith(b"/slow")
    # enable by index: traffic comes back
    assert call(sock, "POST", f"/upstreams/app/{0 if busy is a else 1}/enable")[0] == 200
    for i in range(6):
        get(port, f"/m{i}", host="site.test")
    assert len(busy.requests) > n


def test_upstream_input_validation(bastion, sockdir, peers):
    a, b, _ = peers
    sock = f"{sockdir}/a.sock"
    bastion(two_peers(sock, a, b))
    assert call(sock, "POST", "/upstreams/nope/0/drain")[0] == 404
    assert call(sock, "POST", "/upstreams/app/7/drain")[0] == 404
    assert call(sock, "POST", "/upstreams/app/10.9.9.9:1/drain")[0] == 404
    assert call(sock, "POST", "/upstreams/app/0/explode")[0] == 404
    assert call(sock, "POST", "/upstreams/app/%zz/drain")[0] == 400
    assert call(sock, "GET", "/upstreams/app/0/drain")[0] == 405
    assert call(sock, "POST", "/upstreams")[0] == 405
    assert call(sock, "GET", "/upstreams/nope")[0] == 404


def test_config_view_has_no_secrets(bastion, sockdir, certs):
    sock = f"{sockdir}/a.sock"
    srv = bastion(f"workers 1;\nadmin {{ socket {sock}; }}\n"
                  f"server {{ listen 127.0.0.1:@HTTPS_PORT@ tls; name s.test; "
                  f"tls_cert {certs}/ecdsa-chain.crt {certs}/ecdsa.key; "
                  f"location / {{ return 200 \"ok\"; }} }}\n")
    st, c = call(sock, "GET", "/config")
    assert st == 200 and c["servers"][0]["names"] == ["s.test"]
    assert c["servers"][0]["certificates"] == [{"cert": f"{certs}/ecdsa-chain.crt",
                                                "key": f"{certs}/ecdsa.key"}]
    raw = json.dumps(c)
    assert "PRIVATE KEY" not in raw and "BEGIN" not in raw
    assert call(sock, "POST", "/config")[0] == 405
    assert srv.proc.poll() is None


def test_purge_cli(bastion, sockdir, ctl):
    """`bastionctl purge --tag x` end to end: tagged responses miss afterwards, others still hit."""
    def tagged(r, c):
        tag = "x" if r.target.startswith("/x/") else "y"
        return ok(f"body{r.target}", 200, (("Cache-Control", "max-age=600"), ("Cache-Tag", tag)))
    up = Upstream(handler=tagged)
    try:
        sock = f"{sockdir}/a.sock"
        srv = bastion(f"workers 1;\nadmin {{ socket {sock}; }}\n"
                      f"cache_store main {{ disk @WORKDIR@/cache size=50m; }}\n"
                      f"server {{ listen 127.0.0.1:@HTTP_PORT@; location / {{ proxy {up.url}; cache main; }} }}\n")
        port = srv.ports["http"]

        def hit(path):
            r = get(port, path)
            assert r.endswith(f"body{path}".encode()), r
            return b"cache-status: bastion; hit" in r.lower()
        for p in ("/x/1", "/y/1"):
            get(port, p)
            assert hit(p)
        r = ctl("-s", sock, "purge", "--tag", "x")
        assert r.returncode == 0 and "purged tags" in r.stdout, r.stderr
        time.sleep(0.01)
        assert not hit("/x/1") and hit("/y/1")
        assert ctl("-s", sock, "purge", "--all", "--store", "nope").returncode == 1
        assert ctl("-s", sock, "purge").returncode == 2
        for bad in ({}, {"tag": ""}, {"tags": []}, {"all": False}, {"tag": "x", "all": True},
                    {"tags": ["a"] * 65}, {"host": 5},
                    # security review M6: 64 hashes from "tag", then 64 more from "tags" used to
                    # run past the helper's stack array before the one-kind check
                    {"tag": ",".join(f"t{i}" for i in range(64)), "tags": [f"u{i}" for i in range(64)]},
                    {"tags": [f"u{i}" for i in range(64)], "tag": ",".join(f"t{i}" for i in range(64))}):
            assert call(sock, "POST", "/cache/purge", bad)[0] == 400, bad
        assert call(sock, "POST", "/cache/purge", {"all": True, "store": "main"})[0] == 200
        time.sleep(0.01)
        assert not hit("/y/1")
    finally:
        up.close()


def test_master_written_regions_read_only_in_workers(bastion, sockdir):
    """Security review H1, H2, M5: the block table, the metrics registry and the admin mailbox
    and overrides are mapped read-only in every worker (no writable mapping is left, and the
    read-only one comes from an O_RDONLY description, so mprotect cannot change that). The
    helper keeps write access to the two admin regions it writes, and to nothing else."""
    sock = os.path.join(sockdir, "a.sock")
    srv = bastion(conf(sock))

    def regions(pid):
        out = {}
        for line in open(f"/proc/{pid}/maps").read().splitlines():
            f = line.split()
            if len(f) >= 6 and f[5].startswith("/memfd:bastion-"):
                out.setdefault(f[5][len("/memfd:"):], set()).add(f[1])
        return out

    ro = ("bastion-blocks", "bastion-metrics-reg", "bastion-admin", "bastion-admin-overrides")
    for pid in srv.workers().values():
        got = regions(pid)
        for name in ro:
            assert got.get(name), (name, got)
            assert all("w" not in p for p in got[name]), (pid, name, got[name])
        assert any("w" in p for p in got.get("bastion-metrics", ())), got  # values: written by all
    got = regions(srv.helper())
    for name in ("bastion-blocks", "bastion-metrics-reg"):
        assert all("w" not in p for p in got[name]), (name, got[name])
    for name in ("bastion-admin", "bastion-admin-overrides"):
        assert any("w" in p for p in got[name]), (name, got[name])
    master = regions(srv.proc.pid)
    for name in ro:
        assert any("w" in p for p in master[name]), (name, master[name])
    assert call(sock, "GET", "/status")[0] == 200  # the mailbox still works end to end


def test_maintenance_toggle(bastion, sockdir, ctl):
    sock = f"{sockdir}/a.sock"
    srv = bastion(f"workers 1;\nadmin {{ socket {sock}; }}\n"
                  f"server {{ listen 127.0.0.1:@HTTP_PORT@; name a.test; maintenance_retry_after 90s; "
                  f"location / {{ return 200 \"a\"; }} }}\n"
                  f"server {{ listen 127.0.0.1:@HTTP_PORT@; name b.test; location / {{ return 200 \"b\"; }} }}\n")
    port = srv.ports["http"]

    def st(host):
        return get(port, "/", host=host).split(b"\r\n", 1)[0]
    assert b" 200 " in st("a.test")
    r = ctl("-s", sock, "maintenance", "on", "--server", "a.test")
    assert r.returncode == 0, r.stderr
    resp = get(port, "/", host="a.test")
    assert b" 503 " in resp.split(b"\r\n", 1)[0] and b"retry-after: 90" in resp.lower()
    assert b" 200 " in st("b.test")
    assert call(sock, "POST", "/maintenance", {"on": True, "server": "nope.test"})[0] == 404
    assert call(sock, "POST", "/maintenance", {"on": "yes"})[0] == 400
    assert ctl("-s", sock, "maintenance", "off").returncode == 0
    assert b" 200 " in st("a.test")
    assert ctl("-s", sock, "maintenance", "on").returncode == 0
    assert b" 503 " in st("b.test")
    reload_via_api(srv, sock, 1)
    assert b" 200 " in st("b.test")  # reset by the reload


def test_challenge_toggle(bastion, sockdir, ctl):
    sock = f"{sockdir}/a.sock"
    srv = bastion(f"workers 1;\nadmin {{ socket {sock}; }}\nchallenge_auto_rps 100000;\n"
                  f"server {{ listen 127.0.0.1:@HTTP_PORT@; challenge auto; challenge_difficulty 8; "
                  f"location / {{ return 200 \"page\"; }} }}\n")
    port = srv.ports["http"]

    def code():
        return get(port, "/").split(b" ", 2)[1]
    assert code() == b"200"
    r = ctl("-s", sock, "challenge", "on")
    assert r.returncode == 0, r.stderr
    assert code() == b"403"
    assert ctl("-s", sock, "challenge", "auto").returncode == 0
    assert code() == b"200"
    assert call(sock, "POST", "/challenge", {"mode": "maybe"})[0] == 400
    assert ctl("-s", sock, "challenge", "sideways").returncode == 2
    assert ctl("-s", sock, "challenge", "on").returncode == 0
    reload_via_api(srv, sock, 1)
    assert code() == b"200"  # reset by the reload


def test_challenge_without_auto(bastion, sockdir):
    sock = f"{sockdir}/a.sock"
    bastion(conf(sock))
    st, b = call(sock, "POST", "/challenge", {"mode": "on"})
    assert st == 409 and "challenge auto" in b["error"]


def test_upgrade_requires_post(bastion, sockdir):
    sock = f"{sockdir}/a.sock"
    bastion(conf(sock))
    assert call(sock, "GET", "/upgrade")[0] == 405
    assert call(sock, "GET", "/reload")[0] == 405


def test_malformed_requests(bastion, sockdir):
    sock = f"{sockdir}/a.sock"
    srv = bastion(conf(sock))
    helper = srv.helper()
    bodies = [b"", b"{", b"[]", b"null", b'{"addr": 5}', b'{"addr": "x"}', b'{"addr": "1.2.3.4/99"}',
              b'{"addr": "1.2.3.4", "ttl": "a"}', b'{"addr": "1.2.3.4", "ttl": 1.5}',
              b"\xff\xfe" * 100, b'{"addr":"' + b"9" * 5000 + b'"}']
    for b in bodies:
        raw = (f"POST /blocks HTTP/1.1\r\nContent-Length: {len(b)}\r\n\r\n").encode() + b
        st, _ = call(sock, None, None, raw=raw)
        assert st == 400, (b[:40], st)
    for raw in (b"garbage\r\n\r\n", b"GET\r\n\r\n", b"PUT /status HTTP/1.1\r\n\r\n",
                b"GET /nope HTTP/1.1\r\n\r\n", b"POST /blocks HTTP/1.1\r\nContent-Length: -1\r\n\r\n",
                b"POST /blocks HTTP/1.1\r\nContent-Length: 999999\r\n\r\n",
                b"GET /cache/purge HTTP/1.1\r\n\r\n"):
        st, _ = call(sock, None, None, raw=raw)
        assert st in (400, 404, 405, 413, 501), (raw, st)
    st, _ = call(sock, None, None, raw=b"A" * 65536)  # a head that never ends
    assert st == 413
    assert call(sock, "GET", "/status")[0] == 200
    assert srv.helper() == helper  # the helper survived all of it


# ---- bastionctl ----

def test_ctl_commands(bastion, sockdir, ctl):
    sock = f"{sockdir}/a.sock"
    srv = bastion(conf(sock))
    r = ctl("-s", sock, "status")
    assert r.returncode == 0 and json.loads(r.stdout)["pid"] == srv.proc.pid
    r = ctl("-c", str(srv.workdir / "bastion.conf"), "block", "192.0.2.30", "--ttl", "120")
    assert r.returncode == 0 and "blocked" in r.stdout, r.stderr
    r = ctl("-s", sock, "--json", "blocks")
    assert r.returncode == 0 and any(b["addr"] == "192.0.2.30" for b in json.loads(r.stdout)["blocks"])
    r = ctl("-s", sock, "block", "127.0.0.1")
    assert r.returncode == 1 and "allowlisted" in r.stderr
    r = ctl("-s", sock, "unblock", "192.0.2.30")
    assert r.returncode == 0
    r = ctl("-s", sock, "block", '1.2.3.4","ttl":0}')
    assert r.returncode == 2  # never sent: not an address
    assert ctl("-s", sock, "frobnicate").returncode == 2


def test_helper_down(sockdir, ctl):
    r = ctl("-s", f"{sockdir}/none.sock", "status")
    assert r.returncode == 1 and "cannot reach the admin API" in r.stderr


# ---- XDP: the list is the maps' real state ----

_BPF_NR = {"x86_64": 321, "aarch64": 280}.get(platform.machine())


def _bpf(cmd, attr):
    libc = ctypes.CDLL(None, use_errno=True)
    buf = ctypes.create_string_buffer(bytes(attr), 128)
    r = libc.syscall(_BPF_NR, cmd, buf, 128)
    return r, ctypes.get_errno()


def _map_keys4(path):
    """Every key of the pinned dyn_block4 map (u32, the address bytes), and its fd."""
    p = ctypes.create_string_buffer(path.encode())
    fd, err = _bpf(7, ctypes.c_uint64(ctypes.addressof(p)).value.to_bytes(8, "little") + bytes(8))
    assert fd >= 0, os.strerror(err)
    keys, cur, nxt = [], ctypes.create_string_buffer(4), ctypes.create_string_buffer(4)
    first = True
    while True:
        attr = (fd.to_bytes(4, "little") + bytes(4) +
                (0 if first else ctypes.addressof(cur)).to_bytes(8, "little") +
                ctypes.addressof(nxt).to_bytes(8, "little"))
        r, _ = _bpf(4, attr)
        if r != 0:
            break
        keys.append(socket.inet_ntoa(nxt.raw))
        ctypes.memmove(cur, nxt, 4)
        first = False
    return fd, keys


def _map_delete4(fd, addr):
    k = ctypes.create_string_buffer(socket.inet_aton(addr))
    r, err = _bpf(3, fd.to_bytes(4, "little") + bytes(4) + ctypes.addressof(k).to_bytes(8, "little"))
    assert r == 0, os.strerror(err)


def test_admin_list_matches_map(bastion, net, pin, sockdir):  # noqa: F811
    if _BPF_NR is None:
        pytest.skip(f"no bpf syscall number for {platform.machine()}")
    n = net()
    sock = f"{sockdir}/a.sock"
    srv = bastion(f"workers 1;\nxdp {{ interface {n.host}; mode generic; pin_path {pin}; }}\n"
                  f"admin {{ socket {sock}; }}\n"
                  f"server {{ listen {n.ip}:@HTTP_PORT@; location / {{ return 200 \"ok\"; }} }}\n")
    port = srv.ports["http"]
    assert n.get(n.bad, port) == "200"
    assert call(sock, "POST", "/blocks", {"addr": n.bad, "ttl": 600})[0] == 200
    assert call(sock, "POST", "/blocks", {"addr": "192.0.2.40", "ttl": 600})[0] == 200
    srv.wait_for(lambda: n.get(n.bad, port) == "timeout", 10, "XDP drops the blocked address")
    assert n.get(n.good, port) == "200"
    fd, keys = _map_keys4(f"{pin}/dyn_block4")
    assert set(keys) == {n.bad, "192.0.2.40"}
    assert {a.split("/")[0] for a in blocked(sock)} == set(keys)
    _map_delete4(fd, "192.0.2.40")  # behind master's back: the list follows the map
    os.close(fd)
    assert "192.0.2.40/32" not in blocked(sock)
    # unblock: out of the map and the address is served again
    assert call(sock, "DELETE", "/blocks", {"addr": n.bad})[0] == 200
    srv.wait_for(lambda: n.get(n.bad, port) == "200", 10, "served again after unblock")
    fd, keys = _map_keys4(f"{pin}/dyn_block4")
    os.close(fd)
    assert keys == []
