"""WAF-lite (Phase 12, Task 4): deny rules after path normalization, rule order, a JA4 rule that
refuses curl over TLS and leaves cleartext alone, log mode, and a deny that escalates."""
import re
import socket
import subprocess

from test_tls_conn import client_ctx


def get(port, path="/", extra="", timeout=5):
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


RULES = """
waf_rule wp { match path prefix /wp-admin; action deny; }
waf_rule office { match ip in_cidr 127.0.0.0/8; match header:x-office = yes; action allow; }
waf_rule admin { match path prefix /admin; action deny 451; }
waf_rule bots { match user_agent ~ (?i)sqlmap; match method = GET; action deny; }
"""


def conf(rules=RULES, scope="waf office wp admin bots;", extra=""):
    return (f"workers 1;\n{rules}\n{extra}\n"
            f"server {{ listen 127.0.0.1:@HTTP_PORT@; {scope}\n"
            "location / { return 200 \"ok\"; }\n"
            "location /open/ { waf off; return 200 \"open\"; } }\n")


def test_deny_and_order(bastion):
    srv = bastion(conf())
    p = srv.ports["http"]
    assert status(get(p, "/")) == 200
    assert status(get(p, "/wp-admin/install.php")) == 403
    assert status(get(p, "/%77p-admin/install.php")) == 403  # rules see the normalized path
    assert status(get(p, "/x/../wp-admin/")) == 403
    assert status(get(p, "/admin/")) == 451  # the rule's status
    assert status(get(p, "/admin/", extra="X-Office: yes\r\n")) == 200  # an allow first wins
    assert status(get(p, "/", extra="User-Agent: SQLMap/1.7\r\n")) == 403
    assert status(get(p, "/open/wp-admin")) == 200  # `waf off` in a location
    assert re.search(r"waf: rule wp deny 127\.0\.0\.1", srv.logs())


def test_log_mode(bastion):
    srv = bastion(conf(scope="waf wp admin; rule_mode log;"))
    p = srv.ports["http"]
    assert status(get(p, "/wp-admin/")) == 200  # logged only
    assert status(get(p, "/admin/")) == 200
    srv.wait_log(r"waf: rule wp would deny 127\.0\.0\.1")
    srv.wait_log(r"waf: rule admin would deny 127\.0\.0\.1")


def test_waf_escalate(bastion):
    rules = "waf_rule wp { match path prefix /wp-; action deny; escalate after=3 window=10s block=60s; }"
    srv = bastion(conf(rules=rules, scope="waf wp;"))
    p = srv.ports["http"]
    for _ in range(3):
        assert status(get(p, "/wp-login.php")) == 403
    srv.wait_log(re.escape("escalate: blocked 127.0.0.1/32 for 60s (waf)"), timeout=5)


def test_bad_rule_rejected(bastion_bin, tmp_path):
    for bad, msg in (("waf_rule r { match path =~ x; action deny; }", "unknown operator"),
                     ("waf_rule r { match path = /x; }", "needs at least one `match` and an `action`"),
                     ("waf_rule r { match paht = /x; action deny; }", "unknown subject"),
                     ("server { listen 127.0.0.1:1; waf nope; }", "no waf_rule named 'nope'")):
        f = tmp_path / "bad.conf"
        f.write_text(f"{bad}\nserver {{ listen 127.0.0.1:2; }}\n" if "server" not in bad else bad + "\n")
        r = subprocess.run([str(bastion_bin), "-t", "-c", str(f)], capture_output=True, text=True)
        assert r.returncode != 0 and msg in r.stdout + r.stderr, (bad, r.stdout, r.stderr)


def curl(url, certs):
    return subprocess.run(["curl", "-s", "-o", "-", "-w", "%{http_code}", "--http1.1",
                           "--cacert", f"{certs}/ca.crt", url], capture_output=True, text=True,
                          timeout=10).stdout


def test_ja4_block(bastion, certs):
    tls = (f"listen 127.0.0.1:@HTTPS_PORT@ tls; tls_cert {certs}/ecdsa-chain.crt {certs}/ecdsa.key; "
           "tls_ja4 on;")
    # learn curl's JA4 from a server that echoes it
    srv = bastion(f"workers 1;\nserver {{ {tls} location / {{ return 200 \"$ja4\"; }} }}\n")
    out = curl(f"https://localhost:{srv.ports['https']}/", certs)
    ja4, code = out[:-3], out[-3:]
    assert code == "200" and ja4.startswith("t13"), out
    rules = f"waf_rule curl {{ match ja4 = {ja4}; action deny; }}"
    srv = bastion(f"workers 1;\n{rules}\nserver {{ {tls} listen 127.0.0.1:@HTTP_PORT@; waf curl;\n"
                  "location / { return 200 \"ok\"; } }\n")
    assert curl(f"https://localhost:{srv.ports['https']}/", certs).endswith("403")
    # another TLS client has another fingerprint
    ctx = client_ctx(certs)
    ctx.set_ciphers("ECDHE-ECDSA-AES128-GCM-SHA256")
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", srv.ports["https"]), 5), server_hostname="localhost")
    s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
    assert s.recv(100).startswith(b"HTTP/1.1 200")
    s.close()
    # cleartext HTTP/1.1 has no JA4: never matched
    assert curl(f"http://127.0.0.1:{srv.ports['http']}/", certs).endswith("200")
