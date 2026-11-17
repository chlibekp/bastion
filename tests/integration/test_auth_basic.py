"""Basic auth with Argon2id (Phase 11, Task 4): verdicts, the hashing bound under a flood, the
verified-credentials cache, unknown-user timing, logs never holding credentials, and a users
file that can not be read failing the load instead of opening the location."""
import base64
import socket
import subprocess
import threading
import time

import pytest

PW = "correct horse"
# cheap enough for ASan runs, still at the OWASP floor (not weak)
COST = ("-m", "19456", "-t", "2")


def passwd(bastion_bin, user, pw=PW, cost=COST):
    p = subprocess.run([bastion_bin, "passwd", *cost, user], input=pw + "\n", capture_output=True,
                       text=True, timeout=60)
    assert p.returncode == 0, p.stderr
    return p.stdout.strip()


def creds(user, pw):
    return "Authorization: Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode() + "\r\n"


def get(port, path="/p/", extra="", timeout=30):
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


def conf(users_file, extra=""):
    return (f"workers 1;\nerror_log @WORKDIR@/error.log debug;\n"
            f"server {{ listen 127.0.0.1:@HTTP_PORT@;\n"
            f"location /p/ {{ auth_basic \"Staff\"; auth_basic_file {users_file}; {extra} "
            f"return 200 \"hi $auth_user\"; }}\n"
            f"location /open/ {{ return 200 \"open\"; }} }}\n")


@pytest.fixture
def users(bastion_bin, tmp_path):
    f = tmp_path / "users"
    f.write_text("# staff\n" + passwd(bastion_bin, "alice") + "\n" +
                 passwd(bastion_bin, "bob", "other pw") + "\n")
    return f


def test_correct_wrong(bastion, users):
    srv = bastion(conf(users))
    r = get(srv.ports["http"], extra=creds("alice", PW))
    assert status(r) == 200 and r.endswith(b"hi alice")
    for extra in ("", creds("alice", "nope"), creds("mallory", PW), "Authorization: Basic !!\r\n",
                  "Authorization: Bearer abc\r\n"):
        r = get(srv.ports["http"], extra=extra)
        assert status(r) == 401, extra
        assert b'WWW-Authenticate: Basic realm="Staff", charset="UTF-8"' in r
    assert get(srv.ports["http"], "/open/").endswith(b"open")


def test_decode_limits(bastion, users):
    srv = bastion(conf(users))
    big = "Authorization: Basic " + "QUFB" * 2000 + "\r\n"
    r = get(srv.ports["http"], extra=big)
    assert status(r) in (401, 431)  # over-length: refused, the worker lives on
    assert get(srv.ports["http"], extra=creds("alice", PW)).endswith(b"hi alice")


def test_constant_time_unknown_user(bastion, users):
    srv = bastion(conf(users, "auth_cache_ttl 0s;"))

    def timed(user):
        t = time.monotonic()
        assert status(get(srv.ports["http"], extra=creds(user, "wrong"))) == 401
        return time.monotonic() - t
    known = min(timed("alice") for _ in range(3))
    unknown = min(timed("nobody-here") for _ in range(3))
    # an unknown user costs a full hash too: not answered at once
    assert unknown > known * 0.5, (known, unknown)


def test_cached_verification(bastion, bastion_bin, tmp_path):
    f = tmp_path / "users"
    f.write_text(passwd(bastion_bin, "carol", cost=("-m", "65536", "-t", "6")) + "\n")
    srv = bastion(conf(f, "auth_cache_ttl 60s;"))
    t = time.monotonic()
    assert status(get(srv.ports["http"], extra=creds("carol", PW))) == 200
    first = time.monotonic() - t
    times = []
    for _ in range(3):
        t = time.monotonic()
        assert status(get(srv.ports["http"], extra=creds("carol", PW))) == 200
        times.append(time.monotonic() - t)
    assert min(times) < first / 3, (first, times)  # no rehash
    # a wrong password is never served from the cache
    assert status(get(srv.ports["http"], extra=creds("carol", "x"))) == 401


def test_flood_bounded(bastion, users):
    srv = bastion(conf(users, "auth_max_concurrent 2; auth_cache_ttl 0s;"))
    codes, lat = [], []
    stop = threading.Event()

    def flood():
        while not stop.is_set() and len(codes) < 600:
            codes.append(status(get(srv.ports["http"], extra=creds("alice", "wrong"))))

    def probe():
        while not stop.is_set():
            t = time.monotonic()
            r = get(srv.ports["http"], "/open/")
            lat.append(time.monotonic() - t)
            assert r.endswith(b"open")
            time.sleep(0.05)
    ts = [threading.Thread(target=flood) for _ in range(32)] + [threading.Thread(target=probe)]
    for t in ts:
        t.start()
    time.sleep(8)
    stop.set()
    for t in ts:
        t.join(60)
    assert set(codes) <= {401, 503}, set(codes)
    assert codes.count(503) > 0  # the excess is refused, not queued
    assert lat and max(lat) < 1.0, max(lat)  # the loop stays responsive


def test_auth_header_not_logged(bastion, users):
    srv = bastion(conf(users))
    secret = "s3cr3t-in-the-log?"
    get(srv.ports["http"], extra=creds("alice", secret))
    get(srv.ports["http"], extra=creds("alice", PW))
    time.sleep(0.5)
    log = srv.logs()
    b64 = base64.b64encode(f"alice:{secret}".encode()).decode()
    assert secret not in log and b64 not in log and PW not in log


def test_file_unreadable_at_load(bastion, tmp_path):
    with pytest.raises(pytest.fail.Exception, match="auth_basic_file: can not load"):
        bastion(conf(tmp_path / "missing"))
    bad = tmp_path / "bad"
    bad.write_text("alice:{SHA}plain\n")
    with pytest.raises(pytest.fail.Exception, match="not an Argon2id PHC string"):
        bastion(conf(bad))


def test_passwd_cli(bastion_bin):
    line = passwd(bastion_bin, "dave")
    assert line.startswith("dave:$argon2id$v=19$m=19456,t=2,p=1$")
    p = subprocess.run([bastion_bin, "passwd", "a:b"], input="x\n", capture_output=True, text=True)
    assert p.returncode == 2
