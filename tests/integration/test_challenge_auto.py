"""challenge auto (Phase 12, Task 6): on within 2 s of traffic over the threshold on every worker,
off only after the hold (no flapping under an oscillating load), passes kept, and challenge on/off
ignoring the flag."""
import threading
import time

from test_challenge import HTML, bastion_obj, get, pass_cookie, post, solve

HOLD = 3


def conf(extra=""):
    return ("workers 4;\nchallenge_auto_rps 40;\n"
            f"challenge_auto_hold {HOLD}s;\n"
            "server { listen 127.0.0.1:@HTTP_PORT@; challenge auto; challenge_difficulty 8; " + extra + "\n"
            "location / { return 200 \"page\"; }\n"
            "location /gate/ { challenge on; return 200 \"gate\"; }\n"
            "location /open/ { challenge off; return 200 \"open\"; } }\n")


class Load:
    """About `rps` requests a second from a few threads, until stopped."""

    def __init__(self, port, rps):
        self.port, self.rps, self.stop = port, rps, threading.Event()
        self.threads = [threading.Thread(target=self.run, daemon=True) for _ in range(4)]
        for t in self.threads:
            t.start()

    def run(self):
        gap = 4.0 / self.rps
        while not self.stop.is_set():
            t = time.monotonic()
            try:
                get(self.port, "/open/x", extra="")
            except OSError:
                pass
            time.sleep(max(0.0, gap - (time.monotonic() - t)))

    def end(self):
        self.stop.set()
        for t in self.threads:
            t.join()


def challenged(port, n=8):
    """Each of n new connections (spread over the workers) is challenged."""
    return all(get(port)[0] == 403 for _ in range(n))


def test_activates(bastion):
    srv = bastion(conf())
    srv.wait_workers(4)
    p = srv.ports["http"]
    assert get(p)[0] == 200  # quiet: no challenge
    load = Load(p, 120)
    t0 = time.monotonic()
    try:
        srv.wait_for(lambda: get(p)[0] == 403, timeout=5, what="the challenge")
        took = time.monotonic() - t0
        assert took <= 2.5, took  # within 2 s of the load (1 Hz sample, plus slack)
        assert challenged(p, 12)  # every worker sees the one flag
    finally:
        load.end()
    srv.wait_log("challenge auto: under attack")


def test_deactivates(bastion):
    srv = bastion(conf())
    srv.wait_workers(4)
    p = srv.ports["http"]
    load = Load(p, 120)
    try:
        srv.wait_for(lambda: get(p)[0] == 403, timeout=5, what="the challenge")
    finally:
        load.end()
    # an oscillating load: a second above, a second below, for twice the hold: never off
    t_end = time.monotonic() + 2 * HOLD
    while time.monotonic() < t_end:
        burst = Load(p, 120)
        time.sleep(1.0)
        burst.end()
        assert challenged(p, 4)
        time.sleep(1.0)
        assert challenged(p, 4)
    # quiet: still on through the hold, then off
    quiet = time.monotonic()
    time.sleep(HOLD - 1.5)
    assert challenged(p, 4)
    off = False
    while not off and time.monotonic() - quiet < HOLD + 4:
        time.sleep(0.5)  # a slow poll: the polling itself must stay far below the threshold
        off = get(p)[0] == 200
    assert off, "still challenging after the hold"
    assert time.monotonic() - quiet >= HOLD - 1.0
    assert all(get(p)[0] == 200 for _ in range(8))
    assert "challenge off" in srv.logs()


def test_passes_retained(bastion):
    srv = bastion(conf())
    srv.wait_workers(4)
    p = srv.ports["http"]
    # a pass from the always-on location (the key and cookie are the server's)
    st, _, page = get(p, "/gate/")
    assert st == 403
    b = bastion_obj(page)
    st, h, _ = post(p, {"token": b["token"], "nonce": solve(b["token"], 8), "redirect": "/"})
    assert st == 303
    cookie = pass_cookie(h).split(";")[0]
    load = Load(p, 120)
    try:
        srv.wait_for(lambda: get(p)[0] == 403, timeout=5, what="the challenge")
        for _ in range(8):
            st, _, body = get(p, extra=HTML + f"Cookie: {cookie}\r\n")
            assert st == 200 and body == b"page"
    finally:
        load.end()


def test_challenge_on_overrides(bastion):
    srv = bastion(conf())
    srv.wait_workers(4)
    p = srv.ports["http"]
    assert get(p, "/gate/")[0] == 403  # on: challenged although nobody attacks
    assert get(p, "/")[0] == 200
    load = Load(p, 120)
    try:
        srv.wait_for(lambda: get(p)[0] == 403, timeout=5, what="the challenge")
        assert get(p, "/open/y")[0] == 200  # off: never challenged, even under attack
        assert get(p, "/gate/")[0] == 403
    finally:
        load.end()


def test_auto_needs_threshold(bastion_bin, tmp_path):
    import subprocess
    f = tmp_path / "c.conf"
    f.write_text("server { listen 127.0.0.1:1; challenge auto; }\n")
    r = subprocess.run([str(bastion_bin), "-t", "-c", str(f)], capture_output=True, text=True)
    assert r.returncode != 0 and "challenge_auto_rps" in r.stdout + r.stderr
