"""QUIC interoperability gate: quic-interop-runner (https://github.com/quic-interop/quic-interop-runner)
with Bastion as the server against at least two other client implementations, for the scenarios
handshake, transfer, retry, resumption and multiplexing.

Manual: the runner drives Docker Compose with its own network simulator, which needs Docker inside
the environment running the tests (nested Docker), and Bastion as a runner image. Nothing here
builds or pulls images. The test runs only when all of these are present:
  QUIC_INTEROP_RUNNER  a checkout of the runner (its run.py), pinned by the commit you check out;
  BASTION_INTEROP_IMAGE  a Bastion server image following the runner's endpoint contract;
  `docker` on PATH;
and otherwise SKIPS with the reason: a skipped gate is not a passed gate (docs/conformance.md).
Clients default to ngtcp2 and quic-go (override with QUIC_INTEROP_CLIENTS, comma separated). The
command line (`run.py -s bastion -c <clients> -t <tests> -j <json>`) follows the runner's README
and has not been run."""
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

TESTS = ("handshake", "transfer", "retry", "resumption", "multiplexing")


def result_failures(doc):
    """(server, client, test) of every result other than succeeded, from the runner's JSON."""
    bad = []
    servers, clients = doc.get("servers", []), doc.get("clients", [])
    for i, row in enumerate(doc.get("results", [])):
        srv = servers[i // max(len(clients), 1)] if servers else "?"
        cli = clients[i % max(len(clients), 1)] if clients else "?"
        for t in row:
            if t.get("result") != "succeeded":
                bad.append((srv, cli, t.get("abbr") or t.get("name"), t.get("result")))
    return bad


def test_result_parser():
    doc = {"servers": ["bastion"], "clients": ["ngtcp2", "quic-go"],
           "results": [[{"abbr": "H", "result": "succeeded"}], [{"abbr": "H", "result": "failed"}]]}
    assert result_failures(doc) == [("bastion", "quic-go", "H", "failed")]
    assert result_failures({"servers": [], "clients": [], "results": []}) == []


def test_quic_interop(tmp_path):
    runner = os.environ.get("QUIC_INTEROP_RUNNER")
    image = os.environ.get("BASTION_INTEROP_IMAGE")
    if not runner or not (Path(runner) / "run.py").exists() or not image or shutil.which("docker") is None:
        pytest.skip("quic-interop-runner, BASTION_INTEROP_IMAGE or docker missing (manual gate, needs "
                    "nested Docker): the QUIC interop gate was NOT executed")
    clients = os.environ.get("QUIC_INTEROP_CLIENTS", "ngtcp2,quic-go").split(",")
    assert len(clients) >= 2, "the gate needs at least two other client implementations"
    out = tmp_path / "interop.json"
    impl = tmp_path / "implementations.json"
    impls = json.loads((Path(runner) / "implementations.json").read_text())
    impls["bastion"] = {"image": image, "url": "https://example.invalid/bastion", "role": "server"}
    impl.write_text(json.dumps(impls))
    r = subprocess.run(["python3", "run.py", "-i", str(impl), "-s", "bastion", "-c", ",".join(clients),
                        "-t", ",".join(TESTS), "-j", str(out)], cwd=runner, capture_output=True,
                       text=True, timeout=7200)
    assert out.exists(), r.stdout[-4000:] + r.stderr[-4000:]
    bad = result_failures(json.loads(out.read_text()))
    assert not bad, bad
