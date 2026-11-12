"""HTTP/3 and QUIC conformance gate: h3spec (https://github.com/kazu-yamamoto/h3spec) against the
real binary's `http3` listener, on both backends. Zero failures required.

h3spec is not part of the development image and nothing here fetches it. The test runs only when
the tool is found (in this order): the H3SPEC environment variable, `h3spec` on PATH, or
build/tools/h3spec*/h3spec. Otherwise it SKIPS with that reason: a skipped gate is not a passed
gate (see docs/conformance.md). Pin the tool by the release you put there (the plan names v0.1.12);
the command line below (`h3spec <host> <port>`, hspec's "N examples, M failures" summary and exit
status) follows h3spec's README and has not been run against the real tool."""
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def find_h3spec():
    cands = [os.environ.get("H3SPEC"), shutil.which("h3spec")]
    cands += sorted(str(p) for p in (ROOT / "build" / "tools").glob("h3spec*/h3spec"))
    return next((c for c in cands if c and os.access(c, os.X_OK)), None)


def conf(certs):
    return (f"workers 1;\n"
            f"server {{ listen 127.0.0.1:@QUIC_PORT@ http3; "
            f"tls_cert {certs}/ecdsa-chain.crt {certs}/ecdsa.key; location / {{ return 200 \"ok\"; }} }}\n")


def summary(text):
    """(examples, failures) from hspec's summary line, or None."""
    m = re.search(r"(\d+) examples?, (\d+) failures?", text)
    return (int(m.group(1)), int(m.group(2))) if m else None


def test_summary_parser():
    """The parser the gate relies on reads hspec's summary line, singular and plural."""
    assert summary("Finished in 1.2 seconds\n42 examples, 0 failures\n") == (42, 0)
    assert summary("1 example, 1 failure") == (1, 1)
    assert summary("no summary") is None


def test_h3spec(bastion, certs):
    tool = find_h3spec()
    if tool is None:
        pytest.skip("h3spec not found (set H3SPEC, put it on PATH, or unpack it under build/tools/): "
                    "the HTTP/3 conformance gate was NOT executed")
    srv = bastion(conf(certs))
    r = subprocess.run([tool, "127.0.0.1", str(srv.ports["quic"])], capture_output=True, text=True,
                       timeout=900)
    out = r.stdout + r.stderr
    s = summary(out)
    assert s is not None, out
    assert s[0] > 0 and s[1] == 0 and r.returncode == 0, out
    assert "killed by signal" not in srv.logs()
