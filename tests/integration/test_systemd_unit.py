"""packaging/bastion.service and bastion.socket.example, checked with systemd-analyze (pinned in
docker/dev.Dockerfile; systemd is not PID 1 here, so these are static checks). Running them
under systemd is tests/vm/test_systemd.py."""
import os
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
UNIT = ROOT / "packaging" / "bastion.service"
SOCKET = ROOT / "packaging" / "bastion.socket.example"
# The spec asks for 3.0 or a documented gap; the gap is documented in the unit's header.
SCORE_CEILING = 4.0


def analyze(*args):
    exe = shutil.which("systemd-analyze")
    assert exe, "systemd-analyze is missing: docker/dev.Dockerfile pins the systemd package"
    return subprocess.run([exe, *args], capture_output=True, text=True, timeout=60)


def directives(text):
    out = {}
    for line in text.splitlines():
        m = re.match(r"^([A-Za-z]+)=(.*)$", line)
        if m:
            out.setdefault(m.group(1), []).append(m.group(2))
    return out


def test_unit_verifies(tmp_path):
    exe = os.environ.get("BASTION_BIN") or str(ROOT / "build" / "asan" / "bastion")
    unit = tmp_path / "bastion.service"
    unit.write_text(UNIT.read_text().replace("/usr/bin/bastion", exe)
                    .replace("/bin/kill", shutil.which("kill") or "/usr/bin/kill"))
    r = analyze("verify", "--man=no", str(unit))
    assert r.returncode == 0 and "bastion.service" not in r.stdout + r.stderr, r.stdout + r.stderr


def test_socket_example_verifies(tmp_path):
    (tmp_path / "bastion.socket").write_text(SOCKET.read_text())
    (tmp_path / "bastion.service").write_text("[Service]\nExecStart=/bin/true\n")
    r = analyze("verify", "--man=no", str(tmp_path / "bastion.socket"))
    assert r.returncode == 0, r.stdout + r.stderr


def test_unit_security_score():
    r = analyze("security", "--offline=true", "--no-pager", str(UNIT))
    m = re.search(r"Overall exposure level for bastion\.service: ([0-9.]+)", r.stdout)
    assert m, r.stdout + r.stderr
    assert float(m.group(1)) <= SCORE_CEILING, r.stdout


def test_unit_keeps_what_bastion_needs():
    """Hardening that would break Bastion's own model stays out of the unit."""
    d = directives(UNIT.read_text())
    assert d["Type"] == ["notify"] and d["NotifyAccess"] == ["main"]
    caps = set(d["CapabilityBoundingSet"][0].split())
    for cap in ("CAP_NET_BIND_SERVICE", "CAP_SETUID", "CAP_SETGID", "CAP_SETPCAP", "CAP_BPF",
                "CAP_NET_ADMIN", "CAP_KILL"):
        assert cap in caps, cap
    assert not caps & {"CAP_SYS_ADMIN", "CAP_SYS_PTRACE", "CAP_DAC_OVERRIDE", "CAP_SYS_MODULE"}
    fams = d["RestrictAddressFamilies"][0].split()
    assert {"AF_UNIX", "AF_INET", "AF_INET6", "AF_NETLINK"} <= set(fams)  # netlink: XDP attach
    deny = d["SystemCallFilter"][0]
    assert deny.startswith("~")  # a deny list: master's own needs are open-ended
    for group in ("@mount", "@privileged", "@resources", "@system-service"):
        assert group not in deny, group
    for bad in ("SecureBits", "ProcSubset", "ProtectProc", "PrivateUsers", "PrivateNetwork"):
        assert bad not in d, bad
    for want in ("ProtectSystem", "ProtectHome", "PrivateTmp", "LimitNOFILE", "RuntimeDirectory",
                 "StateDirectory", "CacheDirectory", "LogsDirectory", "ExecReload",
                 "WatchdogSec"):
        assert want in d, want
    assert d["ProtectSystem"] == ["strict"] and d["KillSignal"] == ["SIGQUIT"]
