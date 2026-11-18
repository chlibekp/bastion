"""Hot reload on SIGHUP (src/proc/reload.c): master re-executes itself with the same PID, keeps
its listening sockets, starts a new generation and drains the old one. Load generators for
HTTP/1.1, HTTP/2 (curl) and HTTP/3 (the h3client fixture) run through the reloads and must see
no failed request.

QUIC hands over through the sk_reuseport routing maps (xdp/reuseport.h); under the hash
fallback it does not, and HTTP/3 failures are only asserted where the eBPF routing is on."""
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time

import pytest

import quic_util
from upstream_util import Upstream, ok
from ws_util import echo_handler, frame, read_frame, ws_connect
from xdp_util import net, pin, xdp_conf  # noqa: F401  (fixtures)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import h2_attack as h2  # noqa: E402

CURL = shutil.which("curl")


def conf(certs, www, extra="", workers=2, glob="", body="v1"):
    return (f"workers {workers};\n{glob}\n"
            f"server {{ listen 127.0.0.1:@HTTP_PORT@; listen 127.0.0.1:@HTTPS_PORT@ tls http2; "
            f"listen 127.0.0.1:@QUIC_PORT@ http3; "
            f"tls_cert {certs}/ecdsa-chain.crt {certs}/ecdsa.key; root {www};\n"
            f"location = /v {{ return 200 \"{body}\"; }}\n{extra} }}\n")


@pytest.fixture
def www(tmp_path):
    root = tmp_path / "www"
    root.mkdir()
    (root / "big.bin").write_bytes(os.urandom(1 << 20) * 16)  # 16 MiB
    return root


def get(port, path="/v", timeout=5):
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
        s.sendall(f"GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".encode())
        data = b""
        while True:
            b = s.recv(65536)
            if not b:
                break
            data += b
    return data


def reloads_done(srv):
    return len(re.findall(r"reload: generation \d+ ready", srv.logs()))


def reload(srv, timeout=20):
    n = reloads_done(srv)
    srv.proc.send_signal(signal.SIGHUP)
    srv.wait_for(lambda: reloads_done(srv) > n, timeout=timeout, what="reload done")


class Load:
    """Background clients; every failure is recorded with its reason."""

    def __init__(self, srv, h2=True, h3=True):
        self.srv, self.stop, self.fail, self.ok = srv, threading.Event(), [], 0
        self.h3_fail = []
        self.threads = [threading.Thread(target=self.h1, daemon=True) for _ in range(4)]
        if h2 and CURL:
            self.threads.append(threading.Thread(target=self.h2, daemon=True))
        if h3:
            try:
                quic_util.h3client_bin()
                self.threads.append(threading.Thread(target=self.h3, daemon=True))
            except pytest.skip.Exception:
                pass

    def h1(self):
        while not self.stop.is_set():
            try:
                r = get(self.srv.ports["http"])
                if not r.startswith(b"HTTP/1.1 200"):
                    self.fail.append(("h1", r[:80]))
                else:
                    self.ok += 1
            except OSError as e:
                self.fail.append(("h1", repr(e)))

    def h2(self):
        url = f"https://127.0.0.1:{self.srv.ports['https']}/v"
        while not self.stop.is_set():
            # One request per connection: curl does not retry a request a GOAWAY refused on a
            # reused connection, which HTTP/2 allows (RFC 9113 8.7) and browsers do.
            r = subprocess.run([CURL, "-sk", "--http2", "-w", "%{http_code}",
                                "-o", "/dev/null", url], capture_output=True, text=True, timeout=20)
            if r.returncode != 0 or r.stdout != "200":
                self.fail.append(("h2", r.returncode, r.stdout, r.stderr[-200:]))
            else:
                self.ok += 2

    def h3(self):
        while not self.stop.is_set():
            rc, lines = quic_util.h3(self.srv, "/v", "/v", timeout_ms=5000)
            st = [ln.get("status") for ln in lines if "status" in ln]
            if rc != 0 or st != [200, 200]:
                # Counted apart: zero where quic_routing ebpf hands over (each generation has
                # its own sockets and routing keys); the hash fallback has no QUIC handoff.
                self.h3_fail.append((rc, lines[-2:]))
            else:
                self.ok += 2

    def __enter__(self):
        for t in self.threads:
            t.start()
        time.sleep(0.3)
        return self

    def __exit__(self, *exc):
        self.stop.set()
        for t in self.threads:
            t.join(30)


def test_reload_under_load(bastion, certs, www):
    srv = bastion(conf(certs, www))
    pid = srv.proc.pid
    with Load(srv) as load:
        for _ in range(20):
            reload(srv)
    assert load.fail == [], load.fail[:5]
    assert load.ok > 100
    assert srv.proc.pid == pid and srv.proc.poll() is None
    assert "reload failed" not in srv.logs(), \
        [ln for ln in srv.logs().splitlines() if "reload failed" in ln][:3]
    if "routing by connection ID" in srv.logs():
        assert load.h3_fail == [], load.h3_fail[:5]
    rc, lines = quic_util.h3(srv, "/v")  # HTTP/3 works once the reloads are over
    assert rc == 0 and [ln.get("status") for ln in lines if "status" in ln] == [200]


def test_invalid_config_keeps_running(bastion, certs, www):
    srv = bastion(conf(certs, www))
    workers = sorted(srv.workers())
    conf_path = srv.workdir / "bastion.conf"
    good = conf_path.read_text()
    conf_path.write_text(good + "\nserver { listen nonsense; }\n")
    with Load(srv, h3=False) as load:
        srv.proc.send_signal(signal.SIGHUP)
        srv.wait_log("reload failed, still serving the old configuration")
    assert load.fail == []
    assert sorted(srv.workers()) == workers
    assert "listen" in srv.logs().split("reload failed")[-1]
    conf_path.write_text(good)  # the next reload works again
    reload(srv)
    assert get(srv.ports["http"]).startswith(b"HTTP/1.1 200")


def test_add_remove_listener(bastion, certs, www, tmp_path):
    srv = bastion(conf(certs, www))
    http, https = srv.ports["http"], srv.ports["https"]
    extra = socket.socket()
    extra.bind(("127.0.0.1", 0))
    new_port = extra.getsockname()[1]
    extra.close()
    conf_path = srv.workdir / "bastion.conf"
    text = conf_path.read_text()
    text = text.replace(f"listen 127.0.0.1:{https} tls http2;", f"listen 127.0.0.1:{new_port};")
    conf_path.write_text(text)
    stop, fail = threading.Event(), []

    def hammer():  # the unchanged port must never stop accepting
        while not stop.is_set():
            try:
                if not get(http).startswith(b"HTTP/1.1 200"):
                    fail.append("status")
            except OSError as e:
                fail.append(repr(e))

    t = threading.Thread(target=hammer, daemon=True)
    t.start()
    reload(srv)
    time.sleep(0.5)
    stop.set()
    t.join(10)
    assert fail == []
    assert get(new_port).startswith(b"HTTP/1.1 200")
    # The removed port closes once the old generation has drained.
    srv.wait_log(r"old worker/\d+ \(pid \d+\) exited")

    def refused():
        try:
            socket.create_connection(("127.0.0.1", https), timeout=1).close()
            return False
        except ConnectionRefusedError:
            return True
    srv.wait_for(refused, timeout=10, what="removed port refuses")


def test_long_download_survives(bastion, certs, www):
    srv = bastion(conf(certs, www))
    s = socket.create_connection(("127.0.0.1", srv.ports["http"]), timeout=20)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32768)
    s.sendall(b"GET /big.bin HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    got = s.recv(65536)
    reload(srv)  # the transfer is still running on the old generation
    while True:
        b = s.recv(1 << 20)
        if not b:
            break
        got += b
    s.close()
    head, _, body = got.partition(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.1 200"), head
    assert body == (www / "big.bin").read_bytes()


def test_rapid_reloads(bastion, certs, www):
    srv = bastion(conf(certs, www))
    with Load(srv, h3=False) as load:
        for _ in range(5):
            srv.proc.send_signal(signal.SIGHUP)
            time.sleep(0.15)
        time.sleep(3)
        srv.wait_for(lambda: len(srv.children()) <= 2 * 3, timeout=30,
                     what="old generations drained")
    assert load.fail == [], (load.fail[:5], srv.logs()[-6000:])
    # Coalesced: fewer generations than signals, never more than one pending.
    assert reloads_done(srv) <= 5
    assert "coalesced" in srv.logs() or reloads_done(srv) == 5
    srv.wait_for(lambda: len(srv.children()) == 3, timeout=30, what="one generation left")


def test_quic_across_reload(bastion, certs, www):
    """A QUIC download spanning the reload finishes on the old generation, whose packets keep
    reaching it (generation halves of the sk_reuseport map), while a new connection is served by
    the new generation at the same time."""
    events = 24

    def slow(req, c):  # 24 chunks 0.25 s apart: about 6 s, well across the reload
        c.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
        for i in range(events):
            ev = f"e{i};".encode()
            c.sendall(b"%x\r\n" % len(ev) + ev + b"\r\n")
            time.sleep(0.25)
        c.sendall(b"0\r\n\r\n")
    u = Upstream(slow)
    try:
        srv = bastion(conf(certs, www, extra=f"location /slow {{ proxy {u.url}; }}"))
        if "routing by connection ID" not in srv.logs():
            pytest.skip("quic_routing ebpf unavailable here: the hash fallback has no handoff")
        p = subprocess.Popen([quic_util.h3client_bin(), "--timeout", "20000", "--chunks",
                              "127.0.0.1", str(srv.ports["quic"]), "/slow"],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(0.5)
        reload(srv)
        assert p.poll() is None, "the stream should still be running on the old generation"
        for _ in range(3):  # new connections, while the old generation still holds the stream
            rc, lines = quic_util.h3(srv, "/v", timeout_ms=5000)
            assert rc == 0 and [ln.get("status") for ln in lines if "status" in ln] == [200], \
                f"{lines}\n{srv.logs()[-4000:]}"
        out, err = p.communicate(timeout=60)
        assert p.returncode == 0, err[-500:]
        lines = [json.loads(ln) for ln in out.decode().splitlines() if ln.startswith("{")]
        assert [ln.get("status") for ln in lines if "status" in ln] == [200], lines
        body = "".join(ln["data"] for ln in lines if ln.get("type") == "chunk")
        assert body == "".join(f"e{i};" for i in range(events))
    finally:
        u.close()


def session_reused(port, sess, out):
    args = ["openssl", "s_client", "-connect", f"127.0.0.1:{port}", "-tls1_3", "-ign_eof"]
    args += ["-sess_in", str(sess)] if not out else ["-sess_out", str(sess)]
    r = subprocess.run(args, input="GET /v HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
                       capture_output=True, text=True, timeout=20)
    return "Reused, TLSv1.3" in r.stdout


def test_shm_state_kept(bastion, certs, www, tmp_path):
    """Session ticket keys (resumption) and the block table survive a reload."""
    srv = bastion(conf(certs, www))
    sess = tmp_path / "sess.pem"
    session_reused(srv.ports["https"], sess, out=True)
    assert sess.exists() and sess.stat().st_size > 0
    reload(srv)
    assert session_reused(srv.ports["https"], sess, out=False)
    assert "bastion-tickets" not in srv.logs()


def test_tickets_turned_on(bastion, certs, www, tmp_path):
    """The ticket region outlives a reload whenever `http3` is on, even with tickets off; turning
    tickets on later must still give it a key, or no ticket is ever issued."""
    srv = bastion(conf(certs, www, glob="tls_profile t { tickets off; }", extra="tls_profile t;"))
    sess = tmp_path / "sess.pem"
    session_reused(srv.ports["https"], sess, out=True)
    assert not session_reused(srv.ports["https"], sess, out=False)
    conf_path = srv.workdir / "bastion.conf"
    conf_path.write_text(conf_path.read_text().replace("tickets off;", "tickets rotate=12h keep=2;"))
    reload(srv)
    session_reused(srv.ports["https"], sess, out=True)
    assert session_reused(srv.ports["https"], sess, out=False)


def test_cert_change(bastion, certs, www):
    srv = bastion(conf(certs, www))
    conf_path = srv.workdir / "bastion.conf"
    def key_bits():
        r = subprocess.run(["openssl", "s_client", "-connect", f"127.0.0.1:{srv.ports['https']}",
                            "-tls1_3"], input="", capture_output=True, text=True, timeout=20)
        return re.search(r"Server public key is (\d+) bit", r.stdout).group(1)
    assert key_bits() == "256"
    conf_path.write_text(conf_path.read_text().replace("ecdsa-chain.crt", "rsa.crt")
                         .replace("ecdsa.key", "rsa.key"))
    reload(srv)
    assert key_bits() == "2048"


def test_body_change(bastion, certs, www):
    srv = bastion(conf(certs, www))
    assert get(srv.ports["http"]).endswith(b"v1")
    conf_path = srv.workdir / "bastion.conf"
    conf_path.write_text(conf_path.read_text().replace('"v1"', '"v2"'))
    reload(srv)
    # The old generation may take a queued connection while it stops accepting: soon, all is v2.
    srv.wait_for(lambda: get(srv.ports["http"]).endswith(b"v2"), timeout=5, what="v2 served")
    assert all(get(srv.ports["http"]).endswith(b"v2") for _ in range(20))


def test_websocket_drain(bastion, certs, www):
    """A WebSocket tunnel open across a reload stays on the old generation, still relaying, and is
    closed once tunnel_drain_timeout has passed, well before shutdown_timeout."""
    u = Upstream(echo_handler)
    try:
        srv = bastion(conf(certs, www, glob="shutdown_timeout 60s;",
                           extra=f"location /ws {{ proxy {u.url}; tunnel_drain_timeout 2s; }}"))
        s, st, head, buf = ws_connect(srv.ports["http"], "/ws")
        assert st == 101, head
        s.sendall(frame(0x1, b"before", True))
        assert read_frame(s, buf) == (0x1, b"before")
        reload(srv)
        t0 = time.monotonic()
        s.sendall(frame(0x1, b"after", True))  # the old generation still relays it
        assert read_frame(s, buf) == (0x1, b"after")
        s.settimeout(20)
        try:
            while s.recv(65536):
                pass
        except OSError:
            pass
        took = time.monotonic() - t0
        s.close()
        assert 1.0 <= took <= 10, f"tunnel closed {took:.1f} s after the reload"
        assert get(srv.ports["http"]).endswith(b"v1")  # the new generation serves meanwhile
        srv.wait_for(lambda: len(srv.children()) == 3, timeout=20, what="old generation gone")
    finally:
        u.close()


def test_h2_goaway_on_drain(bastion, certs, www):
    """An HTTP/2 connection to the old generation gets the graceful two-phase GOAWAY (NO_ERROR,
    then the last stream it served) and is closed; its finished request was answered."""
    srv = bastion(conf(certs, www))
    c = h2.H2(srv.ports["https"])
    c.send(h2.headers_frame(1, h2.request_headers("/v")))
    st = c.response(1)
    assert st.status == 200 and bytes(st.body) == b"v1"
    reload(srv)
    assert c.until(lambda: c.goaway is not None and c.goaway[0] != 0x7fffffff, 10), c.goaway
    assert c.goaway == (1, 0), c.goaway  # NO_ERROR, and stream 1 was the last one served
    assert c.closed(10)
    c2 = h2.H2(srv.ports["https"])  # a new connection reaches the new generation
    c2.send(h2.headers_frame(1, h2.request_headers("/v")))
    assert c2.response(1).status == 200
    c2.close()


def test_cache_size_change(bastion, certs, www):
    """A cache_store whose size changes cannot keep its shared index (its layout follows the size):
    the documented reset is a fresh index on the same disk store. Responses stay correct
    throughout and caching works again under the new size."""
    u = Upstream(lambda r, c: ok(b"cached", 200, (("Cache-Control", "max-age=60"),)))
    try:
        store = "cache_store main { disk @WORKDIR@/cache size=100m; }"
        srv = bastion(conf(certs, www, glob=store,
                           extra=f"location /c {{ proxy {u.url}; cache main; }}"))

        def fetch():
            raw = get(srv.ports["http"], "/c")
            head, _, body = raw.partition(b"\r\n\r\n")
            assert raw.startswith(b"HTTP/1.1 200") and body.endswith(b"cached"), raw[:200]
            return head.decode("latin-1").lower()
        fetch()
        assert "bastion; hit" in fetch()
        conf_path = srv.workdir / "bastion.conf"
        conf_path.write_text(conf_path.read_text().replace("size=100m", "size=200m"))
        reload(srv)
        assert "reload failed" not in srv.logs()
        heads = [fetch() for _ in range(3)]  # a miss refills the fresh index, or a hit from disk
        assert "bastion; hit" in heads[-1], heads
    finally:
        u.close()


def test_reload_updates_lists(bastion, net, pin):  # noqa: F811
    """XDP deny lists follow a reload: the map contents change while the program stays attached
    (generic mode on the test veth, as the Phase 13 lifecycle tests)."""
    n = net()
    srv = bastion(xdp_conf(n, pin))
    p = srv.ports["http"]
    assert n.xdp_attached()
    assert n.get(n.good, p) == "200" and n.get(n.bad, p) == "timeout"
    conf_path = srv.workdir / "bastion.conf"
    conf_path.write_text(conf_path.read_text().replace(f"deny {n.bad};", f"deny {n.good};"))
    reload(srv)
    assert "reload failed" not in srv.logs()
    assert n.xdp_attached()
    assert n.get(n.bad, p) == "200" and n.get(n.good, p) == "timeout"
    # no detach: the new image adopts the pinned link instead of attaching a fresh one
    assert "xdp: adopting 1 pinned link(s)" in srv.logs(), srv.logs()[-3000:]
    assert f"xdp: attached to {n.host} (adopted mode)" in srv.logs(), srv.logs()[-3000:]
