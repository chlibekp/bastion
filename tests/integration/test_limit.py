"""limit_zone rate limits (Phase 12, Task 1): one rate across all workers, 429 with Retry-After,
IPv6 clients keyed by /64, ::ffff: addresses as IPv4, X-Forwarded-For only from trusted peers,
dry_run, mode delay and the RateLimit fields."""
import socket
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


def conf(zone, scope="", workers=1):
    return (f"workers {workers};\n"
            f"limit_zone z {{ {zone} }}\n"
            f"server {{ listen 127.0.0.1:@HTTP_PORT@; {scope}\n"
            f"location / {{ limit z; return 200 \"ip=$remote_addr\"; }}\n"
            f"location /free/ {{ limit off; return 200 \"free\"; }} }}\n")


def test_limit_across_workers(bastion):
    srv = bastion(conf("rate 10/m burst=10;", workers=4))
    srv.wait_workers(4)
    codes = [status(get(srv.ports["http"])) for _ in range(40)]
    # each request is a new connection, spread over the workers: the rate is still global
    assert codes.count(200) == 10, codes
    assert codes.count(429) == 30


def test_429_retry_after(bastion):
    srv = bastion(conf("rate 1/m;"))
    assert status(get(srv.ports["http"])) == 200
    r = get(srv.ports["http"])
    assert status(r) == 429
    ra = [ln for ln in r.split(b"\r\n") if ln.lower().startswith(b"retry-after:")]
    assert ra and 1 <= int(ra[0].split(b":")[1]) <= 60, r
    assert get(srv.ports["http"], "/free/").endswith(b"free")  # `limit off` in a location
    assert "limit: zone z rejected 127.0.0.1" in srv.logs()


TRUST = "real_ip_header X-Forwarded-For; real_ip_from 127.0.0.1/32;"


def xff(a):
    return f"X-Forwarded-For: {a}\r\n"


def test_ipv6_prefix(bastion):
    srv = bastion(conf("rate 1/m;", TRUST))
    p = srv.ports["http"]
    assert status(get(p, extra=xff("2001:db8:1:2::1"))) == 200
    # rotating inside the /64: one client
    for a in ("2001:db8:1:2::2", "2001:db8:1:2:ffff:1:2:3", "2001:db8:1:2::abcd"):
        assert status(get(p, extra=xff(a))) == 429, a
    # the next /64 is somebody else
    assert status(get(p, extra=xff("2001:db8:1:3::1"))) == 200


def test_mapped_ipv4(bastion):
    srv = bastion(conf("rate 1/m;", TRUST))
    p = srv.ports["http"]
    assert status(get(p, extra=xff("192.0.2.7"))) == 200
    assert status(get(p, extra=xff("::ffff:192.0.2.7"))) == 429
    assert status(get(p, extra=xff("192.0.2.8"))) == 200


def test_xff_spoof(bastion):
    # no real_ip_from: the header is the client's word and changes nothing
    srv = bastion(conf("rate 1/m;", "real_ip_header X-Forwarded-For;"))
    p = srv.ports["http"]
    r = get(p, extra=xff("198.51.100.1"))
    assert status(r) == 200 and r.endswith(b"ip=127.0.0.1")
    for i in range(2, 6):
        assert status(get(p, extra=xff(f"198.51.100.{i}"))) == 429


def test_dry_run(bastion):
    srv = bastion(conf("rate 1/m; dry_run on;"))
    codes = [status(get(srv.ports["http"])) for _ in range(5)]
    assert codes == [200] * 5
    srv.wait_log(r"limit: zone z would reject \(dry_run\) 127\.0\.0\.1")


def test_delay_mode(bastion):
    srv = bastion(conf("rate 10/s burst=1; mode delay;"))
    p = srv.ports["http"]
    t = time.monotonic()
    assert status(get(p)) == 200
    assert status(get(p)) == 200  # held about 100 ms, then served
    assert time.monotonic() - t >= 0.05
    assert status(get(p)) in (200, 429)


def test_limit_headers(bastion):
    srv = bastion(conf("rate 10/s burst=5;", "limit_headers on;"))
    r = get(srv.ports["http"])
    assert b"RateLimit: limit=5, remaining=4" in r, r
    assert b"RateLimit-Policy: 5;w=1" in r


def test_unknown_zone_fails_load(bastion_bin, tmp_path):
    import subprocess
    f = tmp_path / "c.conf"
    f.write_text("server { listen 127.0.0.1:1; location / { limit nope; return 200; } }\n")
    p = subprocess.run([bastion_bin, "-t", "-c", str(f)], capture_output=True, text=True)
    assert p.returncode != 0 and "no limit_zone named 'nope'" in p.stderr
