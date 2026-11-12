"""The QUIC send path (src/http/h3/txq.c): GSO batching and its EIO fallback, ECN in both
directions, and loss, reordering and a small path MTU on a real link.

The figures come from the server's `quic: closed` debug line (one per connection): the packets
it sent (tx), the batches the send queue made (batches, multi = those of more than one packet),
the datagrams and GSO sends the UDP layer handed the kernel (udp_msgs, udp_gso, gso_fallbacks),
the ECN-marked packets ngtcp2 received (ecn_rx) and the path MTU it settled on (pmtu).

The link tests build a network namespace joined by a veth pair and shape the server's side with
tc netem. They need root, `ip` and netem: the dev container has them; elsewhere they skip, and
tests/vm/test_quic_udp_vm.py runs this file in the VM guest, where they must not."""
import hashlib
import os
import re
import shutil
import subprocess
import uuid

import pytest

from quic_util import conn_line, h3, h3client_bin

BIG = 32 << 20  # sparse: zeros, nothing on disk
ZEROS_SHA = hashlib.sha256(bytes(BIG)).hexdigest()


def conf(certs, www, extra="", listen="127.0.0.1"):
    return ("workers 1;\nerror_log @WORKDIR@/error.log debug;\n"
            f"server {{ listen {listen}:@QUIC_PORT@ http3; "
            f"tls_cert {certs}/ecdsa-chain.crt {certs}/ecdsa.key; root {www}; {extra} }}\n")


@pytest.fixture
def www(tmp_path):
    root = tmp_path / "www"
    root.mkdir()
    with open(root / "big.bin", "wb") as f:
        f.truncate(BIG)
    return root


def closed(srv):
    """The fields of the first `quic: closed` line, as ints."""
    line = srv.wait_log(r"quic: closed [^\n]*", timeout=20).group(0)
    return {k: int(v) for k, v in re.findall(r"(\w+)=(\d+)", line)}


def download(srv, *opts, timeout_ms=120000):
    rc, lines = h3(srv, "/big.bin", opts=("--max-data", str(64 << 20), *opts), timeout_ms=timeout_ms)
    resp = [ln for ln in lines if ln.get("type") == "resp"]
    assert rc == 0 and resp and resp[0]["status"] == 200, lines
    assert resp[0]["len"] == BIG and resp[0]["sha256"] == ZEROS_SHA
    return conn_line(lines)


def test_gso_counter(bastion, certs, www):
    """A bulk transfer goes out in GSO sends of several packets each."""
    srv = bastion(conf(certs, www))
    download(srv)
    f = closed(srv)
    if f["udp_gso"] == 0 and f["multi"] == 0:
        pytest.skip(f"no batches of more than one packet: {f}")
    assert f["multi"] > 0 and f["udp_gso"] > 0, f
    assert f["tx"] / f["udp_msgs"] > 1.5, f  # packets per send


def test_gso_off(bastion, certs, www):
    """quic_gso off: one datagram per send, and the transfer is the same."""
    srv = bastion(conf(certs, www, "quic_gso off;"))
    download(srv)
    f = closed(srv)
    assert f["multi"] == 0 and f["udp_gso"] == 0, f


def test_gso_eio(bastion, certs, www):
    """An EIO from a GSO send turns GSO off for the socket and resends those packets one by one:
    the connection survives and the body arrives whole."""
    srv = bastion(conf(certs, www), env={"BST_TEST_UDP_GSO_EIO": "1"})
    download(srv)
    f = closed(srv)
    if f["multi"] == 0:
        pytest.skip(f"no GSO batch was made: {f}")
    assert f["gso_fallbacks"] == 1, f
    assert "quic: send:" not in srv.logs()  # nothing failed on the way


def test_ecn_echo(bastion, certs, www):
    """ECN both ways: the client receives ECT(0) packets, and the marks the client sets reach
    the server's ngtcp2."""
    srv = bastion(conf(certs, www))
    c = download(srv, "--ecn")
    f = closed(srv)
    not_ect, ect1, ect0, ce = c["ecn_rx"]
    assert ect0 > 0, c["ecn_rx"]
    assert f["ecn_rx"] > 0, f


def test_ecn_off(bastion, certs, www):
    """quic_ecn off: no marks set, none reported."""
    srv = bastion(conf(certs, www, "quic_ecn off;"))
    c = download(srv, "--ecn")
    f = closed(srv)
    assert c["ecn_rx"][1] == c["ecn_rx"][2] == 0, c["ecn_rx"]
    assert f["ecn_rx"] == 0, f


# ---- a real link: veth into a network namespace, shaped with netem ----

SRV_IP, CLI_IP = "10.77.0.1", "10.77.0.2"


def _sh(*cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


@pytest.fixture
def link():
    """(namespace, server-side device). The client runs in the namespace behind the veth."""
    if os.geteuid() != 0 or shutil.which("ip") is None or shutil.which("tc") is None:
        pytest.skip("needs root, ip and tc (tests/vm/test_quic_udp_vm.py runs this in the VM)")
    if shutil.which("modprobe"):  # the VM guest's stock kernel has them as modules
        _sh("modprobe", "-q", "veth")
        _sh("modprobe", "-q", "sch_netem")
    tag = uuid.uuid4().hex[:6]
    ns, dev, peer = f"bq{tag}", f"bqs{tag}", f"bqc{tag}"
    r = _sh("ip", "netns", "add", ns)
    if r.returncode != 0:
        pytest.skip(f"no network namespaces: {r.stderr.strip()}")
    try:
        for cmd in (["ip", "link", "add", dev, "type", "veth", "peer", "name", peer],
                    ["ip", "link", "set", peer, "netns", ns],
                    ["ip", "addr", "add", f"{SRV_IP}/24", "dev", dev],
                    ["ip", "link", "set", dev, "up"],
                    ["ip", "-n", ns, "addr", "add", f"{CLI_IP}/24", "dev", peer],
                    ["ip", "-n", ns, "link", "set", peer, "up"],
                    ["ip", "-n", ns, "link", "set", "lo", "up"]):
            r = _sh(*cmd)
            if r.returncode != 0:
                pytest.skip(f"{' '.join(cmd)}: {r.stderr.strip()}")
        yield ns, dev, peer
    finally:
        _sh("ip", "link", "del", dev)
        _sh("ip", "netns", "del", ns)


def netem(dev, *spec):
    r = _sh("tc", "qdisc", "add", "dev", dev, "root", "netem", *spec)
    if r.returncode != 0:
        pytest.skip(f"netem: {r.stderr.strip()} (tests/vm/test_quic_udp_vm.py runs this in the VM)")


def download_in(ns, srv, timeout_ms=180000):
    cmd = ["ip", "netns", "exec", ns, h3client_bin(), "--timeout", str(timeout_ms), "--max-data", str(64 << 20),
           SRV_IP, str(srv.ports["quic"]), "/big.bin"]
    p = subprocess.run(cmd, capture_output=True, timeout=timeout_ms / 1000 + 10)
    import json
    lines = [json.loads(ln) for ln in p.stdout.decode().splitlines() if ln.startswith("{")]
    resp = [ln for ln in lines if ln.get("type") == "resp"]
    assert p.returncode == 0 and resp and resp[0]["status"] == 200, (lines, p.stderr.decode()[-500:])
    assert resp[0]["len"] == BIG and resp[0]["sha256"] == ZEROS_SHA


def test_loss_recovery(bastion, certs, www, link):
    """5% of the server's packets lost: loss recovery retransmits and the transfer completes."""
    ns, dev, _ = link
    netem(dev, "loss", "5%")
    srv = bastion(conf(certs, www, listen=SRV_IP))
    download_in(ns, srv)


def test_reorder(bastion, certs, www, link):
    """25% of the server's packets overtaken by later ones: the transfer completes."""
    ns, dev, _ = link
    netem(dev, "delay", "10ms", "reorder", "25%", "50%")
    srv = bastion(conf(certs, www, listen=SRV_IP))
    download_in(ns, srv)


def test_low_mtu(bastion, certs, www, link):
    """A 1280-byte MTU on the client's side of the path: PMTUD's probes above it are lost, so
    the size it settles on stays within the path (1280 - 20 IPv4 - 8 UDP), and the transfer
    completes."""
    ns, _, peer = link
    r = _sh("ip", "-n", ns, "link", "set", peer, "mtu", "1280")
    assert r.returncode == 0, r.stderr
    srv = bastion(conf(certs, www, listen=SRV_IP))
    download_in(ns, srv)
    f = closed(srv)
    assert 1200 <= f["pmtu"] <= 1280 - 28, f
