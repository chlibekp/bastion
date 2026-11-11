"""HTTP/2 over TLS against the real binary (src/http/h2), on both backends, seccomp on. The
clients are the ones in the image: curl, nghttp and h2load. `make test-int-nosan` runs this file
without sanitizers too: only that run proves the worker's allowlist covers HTTP/2 serving."""
import re
import shutil
import subprocess

import pytest

NEEDS = pytest.mark.skipif(shutil.which("curl") is None or shutil.which("nghttp") is None,
                           reason="curl and nghttp are needed")


def conf(certs, www, listen="tls http2", extra=""):
    return (f"workers 1;\nserver {{ listen 127.0.0.1:@HTTPS_PORT@ {listen}; "
            f"tls_cert {certs}/ecdsa-chain.crt {certs}/ecdsa.key; root {www};\n"
            f"location = /v {{ return 200 \"hello h2\"; }}\n{extra} }}\n")


@pytest.fixture
def www(tmp_path):
    root = tmp_path / "www"
    root.mkdir()
    (root / "small.txt").write_bytes(b"0123456789abcdef" * 4)
    (root / "index.html").write_text("<h1>index</h1>\n")
    return root


def run(args, timeout=30):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def no_kills(srv):
    log = srv.logs()
    assert "killed by signal" not in log, log


@NEEDS
def test_h2_alpn_get(bastion, certs, www):
    srv = bastion(conf(certs, www))
    url = f"https://127.0.0.1:{srv.ports['https']}"
    r = run(["curl", "-sk", "--http2", "-i", f"{url}/v"])
    assert r.returncode == 0, r.stderr
    assert r.stdout.startswith("HTTP/2 200"), r.stdout
    assert r.stdout.endswith("hello h2"), r.stdout
    assert "date:" in r.stdout.lower() and "server:" in r.stdout.lower()
    r = run(["curl", "-sk", "--http2", "-o", "/dev/null", "-w", "%{http_version} %{size_download}",
             f"{url}/small.txt"])
    assert r.stdout == "2 64", r.stdout
    # nghttp speaks only HTTP/2: a request and its response through a second client
    r = run(["nghttp", "-n", "-v", f"{url}/small.txt"])
    assert r.returncode == 0, r.stderr
    assert ":status: 200" in r.stdout, r.stdout
    no_kills(srv)


@NEEDS
def test_h1_still_works_beside_h2(bastion, certs, www):
    srv = bastion(conf(certs, www))
    url = f"https://127.0.0.1:{srv.ports['https']}"
    r = run(["curl", "-sk", "--http1.1", "-o", "/dev/null", "-w", "%{http_version}", f"{url}/v"])
    assert r.stdout == "1.1", r.stdout


@NEEDS
def test_h2_needs_the_listen_flag(bastion, certs, www):
    srv = bastion(conf(certs, www, listen="tls"))
    url = f"https://127.0.0.1:{srv.ports['https']}"
    r = run(["curl", "-sk", "--http2", "-o", "/dev/null", "-w", "%{http_version}", f"{url}/v"])
    assert r.stdout == "1.1", r.stdout  # ALPN did not offer h2: the client fell back


@NEEDS
def test_missing_file_is_404_over_h2(bastion, certs, www):
    srv = bastion(conf(certs, www))
    url = f"https://127.0.0.1:{srv.ports['https']}"
    r = run(["curl", "-sk", "--http2", "-o", "/dev/null", "-w", "%{http_code} %{http_version}",
             f"{url}/nope"])
    assert r.stdout == "404 2", r.stdout


@pytest.mark.skipif(shutil.which("h2load") is None, reason="h2load is needed")
def test_multiplex_100(bastion, certs, www):
    srv = bastion(conf(certs, www))
    url = f"https://127.0.0.1:{srv.ports['https']}/small.txt"
    # one connection, 100 requests in flight at once (http2_max_concurrent_streams is 128)
    r = run(["h2load", "-n", "100", "-c", "1", "-m", "100", url])
    assert r.returncode == 0, r.stdout + r.stderr
    m = re.search(r"requests: (\d+) total, (\d+) started, (\d+) done, (\d+) succeeded, (\d+) failed", r.stdout)
    assert m and m.groups() == ("100", "100", "100", "100", "0"), r.stdout
    assert "100 2xx" in r.stdout, r.stdout
    no_kills(srv)


@NEEDS
def test_curl_parallel_shares_one_connection(bastion, certs, www):
    srv = bastion(conf(certs, www))
    url = f"https://127.0.0.1:{srv.ports['https']}"
    urls = [f"{url}/small.txt?i={i}" for i in range(20)]
    # without --parallel-immediate curl waits for the first connection and multiplexes onto it
    r = run(["curl", "-sk", "--http2", "--parallel", "-w", "%{http_version} %{num_connects}\n"]
            + sum([["-o", "/dev/null", u] for u in urls], []))
    lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
    assert len(lines) == 20 and all(ln.startswith("2 ") for ln in lines), r.stdout
    assert sum(int(ln.split()[1]) for ln in lines) == 1, r.stdout  # one TCP connection for all
