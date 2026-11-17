"""limit_conn and IP ACLs (Phase 12, Task 2): connections over a limit closed at accept, counts
given back on every exit path and after a worker is killed, first-match rule order, per-location
lists, the real_ip address, and a million-entry deny_file."""
import os
import signal
import socket
import subprocess
import time


def get(port, path="/", extra="", timeout=10):
    s = socket.create_connection(("127.0.0.1", port), timeout)
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: x\r\n{extra}Connection: close\r\n\r\n".encode())
    out = b""
    try:
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


def closed_at_once(port):
    """A connection the server closes without reading: EOF or reset on the first read."""
    s = socket.create_connection(("127.0.0.1", port), 5)
    s.settimeout(3)
    try:
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        return s.recv(100) == b""
    except (ConnectionResetError, BrokenPipeError):
        return True
    except socket.timeout:
        return False
    finally:
        s.close()


def hold(port):
    s = socket.create_connection(("127.0.0.1", port), 5)
    s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n")  # unfinished: the connection stays open
    return s


CONN = ("workers 1;\nlimit_conn per_ip=2;\n"
        "server { listen 127.0.0.1:@HTTP_PORT@; client_header_timeout 30s;\n"
        "location / { return 200 \"ok\"; } }\n")


def test_per_ip_limit(bastion):
    srv = bastion(CONN)
    p = srv.ports["http"]
    a, b = hold(p), hold(p)
    time.sleep(0.2)
    assert closed_at_once(p)
    assert srv.wait_for(lambda: "bst:worker/0" in str(srv.children()), what="worker")
    a.close()
    b.close()
    srv.wait_for(lambda: status(get(p)) == 200, timeout=5, what="a slot back")


def test_counters_released(bastion):
    srv = bastion(CONN)
    p = srv.ports["http"]
    for _ in range(10):
        # the server learns of the last round's closes asynchronously: a leaked count would never
        # come back, so waiting for the slot still fails on a leak
        srv.wait_for(lambda: status(get(p)) == 200, timeout=5, what="a slot back")
        s = socket.create_connection(("127.0.0.1", p))
        s.close()  # client leaves before a byte
        s = socket.create_connection(("127.0.0.1", p))
        s.sendall(b"BROKEN\r\n\r\n")  # 400 path
        try:
            s.recv(100)
        except ConnectionResetError:
            pass
        s.close()
        s = socket.create_connection(("127.0.0.1", p))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n")
        s.close()  # reset mid-request
    time.sleep(0.3)
    a, b = hold(p), hold(p)  # still two to have
    time.sleep(0.2)
    assert closed_at_once(p)
    a.close()
    b.close()


def test_worker_crash_counter(bastion):
    srv = bastion(CONN)
    p = srv.ports["http"]
    held = [hold(p), hold(p)]
    time.sleep(0.2)
    assert closed_at_once(p)
    old = srv.workers()[0]
    os.kill(old, signal.SIGKILL)
    srv.wait_for(lambda: srv.workers().get(0) not in (None, old), what="respawned worker")
    for s in held:
        s.close()
    srv.wait_log(r"ready|worker", timeout=5)
    a, b = hold(p), hold(p)  # the dead worker's counts are gone
    time.sleep(0.2)
    s = socket.create_connection(("127.0.0.1", p), 5)
    a.close()
    b.close()
    s.close()
    srv.wait_for(lambda: status(get(p)) == 200, timeout=5, what="served after the crash")


def acl_conf(server_rules="", loc_rules="", extra=""):
    return ("workers 1;\n"
            f"server {{ listen 127.0.0.1:@HTTP_PORT@; {extra} {server_rules}\n"
            f"location / {{ return 200 \"ok\"; }}\n"
            f"location /admin/ {{ {loc_rules} return 200 \"admin\"; }} }}\n")


def test_allow_deny_order(bastion):
    # first match: the allow of the one address comes before the deny of its /8
    srv = bastion(acl_conf("allow 127.0.0.1; deny 127.0.0.0/8;"))
    assert status(get(srv.ports["http"])) == 200
    srv2 = bastion(acl_conf("deny 127.0.0.0/8; allow 127.0.0.1;"))
    assert closed_at_once(srv2.ports["http"])  # server scope: closed at accept


def test_location_acl(bastion):
    srv = bastion(acl_conf(loc_rules="deny all;"))
    p = srv.ports["http"]
    assert status(get(p, "/admin/")) == 403
    assert get(p, "/").endswith(b"ok")


TRUST = "real_ip_header X-Forwarded-For; real_ip_from 127.0.0.1/32;"


def test_acl_uses_real_ip(bastion):
    srv = bastion(acl_conf(loc_rules="allow 192.0.2.0/24; deny all;", extra=TRUST))
    p = srv.ports["http"]
    assert status(get(p, "/admin/", "X-Forwarded-For: 192.0.2.9\r\n")) == 200
    assert status(get(p, "/admin/", "X-Forwarded-For: 198.51.100.1\r\n")) == 403
    # untrusted header: the socket address decides
    srv2 = bastion(acl_conf(loc_rules="allow 192.0.2.0/24; deny all;"))
    assert status(get(srv2.ports["http"], "/admin/", "X-Forwarded-For: 192.0.2.9\r\n")) == 403


def test_deny_file_large(bastion, bastion_bin, tmp_path):
    f = tmp_path / "deny.txt"
    with open(f, "w") as out:
        for i in range(1000000):
            out.write(f"{10 + (i >> 16) % 200}.{(i >> 8) & 255}.{i & 255}.0/24\n")
        out.write("192.0.2.0/24  # docs\n")
    conf = acl_conf(loc_rules=f"deny_file {f};")
    c = tmp_path / "t.conf"
    c.write_text(conf.replace("@HTTP_PORT@", "1"))
    t = time.monotonic()
    r = subprocess.run([bastion_bin, "-t", "-c", str(c)], capture_output=True, text=True)
    took = time.monotonic() - t
    assert r.returncode == 0, r.stderr
    # ASan builds are slower; the 2 s budget is for an optimised build
    assert took < (20 if b"__asan_init" in open(bastion_bin, "rb").read() else 2), took
    srv = bastion(conf)
    p = srv.ports["http"]
    t = time.monotonic()
    for _ in range(20):
        assert get(p, "/admin/").endswith(b"admin")  # 127.0.0.1 is not listed
    assert time.monotonic() - t < 5
