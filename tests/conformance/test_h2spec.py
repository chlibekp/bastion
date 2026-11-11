"""HTTP/2 conformance gate: h2spec (strict) against the real binary, with TLS and in cleartext (h2c),
on both backends. Zero failures required in each run.

h2spec is not part of the development image and nothing here fetches it. The test runs only when
the tool is found (in this order): the H2SPEC environment variable, `h2spec` on PATH, or
build/tools/h2spec*/h2spec. Otherwise it SKIPS with that reason: a skipped gate is not a passed
gate (see docs/conformance.md). The command line below follows h2spec's documented options
(-h host, -p port, -t TLS, -k skip verification, -S strict, -j JUnit report) and has not been run
against the real tool."""
import os
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def find_h2spec():
    cands = [os.environ.get("H2SPEC"), shutil.which("h2spec")]
    cands += sorted(str(p) for p in (ROOT / "build" / "tools").glob("h2spec*/h2spec"))
    return next((c for c in cands if c and os.access(c, os.X_OK)), None)


def conf(certs, www):
    return (f"workers 1;\n"
            f"server {{ listen 127.0.0.1:@HTTPS_PORT@ tls http2; "
            f"tls_cert {certs}/ecdsa-chain.crt {certs}/ecdsa.key; root {www}; }}\n"
            f"server {{ listen 127.0.0.1:@HTTP_PORT@ h2c; root {www}; }}\n")


def run_h2spec(tool, port, tls, out):
    args = [tool, "-h", "127.0.0.1", "-p", str(port), "-S", "-j", str(out), "--timeout", "5"]
    if tls:
        args += ["-t", "-k"]
    return subprocess.run(args, capture_output=True, text=True, timeout=900)


@pytest.mark.parametrize("tls", [True, False], ids=["tls", "h2c"])
def test_h2spec_strict(bastion, certs, tmp_path, tls):
    tool = find_h2spec()
    if tool is None:
        pytest.skip("h2spec not found (set H2SPEC, put it on PATH, or unpack it under build/tools/): "
                    "the HTTP/2 conformance gate was NOT executed")
    www = tmp_path / "www"
    www.mkdir()
    (www / "index.html").write_text("ok")
    srv = bastion(conf(certs, www))
    out = tmp_path / "h2spec.xml"
    r = run_h2spec(tool, srv.ports["https" if tls else "http"], tls, out)
    assert out.exists(), r.stdout + r.stderr
    root = ET.parse(out).getroot()
    suites = [root] if root.tag == "testsuite" else list(root)
    failures = [(c.get("classname"), c.get("name")) for s in suites for c in s.iter("testcase")
                if c.find("failure") is not None or c.find("error") is not None]
    assert not failures, failures
    assert "killed by signal" not in srv.logs()
