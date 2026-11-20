"""Release artifacts (Phase 14 Task 10): the static binary, .deb, .rpm, SBOM and SHA256SUMS.

Run with `./dev make test-packaging BUILD=release`, which builds the artifacts for this
container's architecture into dist/ (scripts/package.sh) and then runs these tests in the
release image, where dpkg-deb and rpm read the packages back.

The tests that need Docker itself (install, start, serve and remove in fresh Debian, Ubuntu and
RHEL-family containers, upgrade keeping the config, the scratch image as non-root, and the
foreign-architecture smoke test under QEMU) are in tests/host/test_packages_host.sh, run on the
host; test_host_suite runs it when a docker CLI is present.
"""
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DIST = ROOT / os.environ.get("BASTION_DIST", "dist")
VERSION = os.environ.get("BASTION_PKG_VERSION", "0.1.0")
ARCH = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine(), platform.machine())
RPM_ARCH = {"amd64": "x86_64", "arm64": "aarch64"}[ARCH]

BIN = DIST / f"bastion-{VERSION}-linux-{ARCH}"
DEB = DIST / f"bastion_{VERSION}-1_{ARCH}.deb"
RPM = DIST / f"bastion-{VERSION}-1.{RPM_ARCH}.rpm"
SBOM = DIST / f"bastion-{VERSION}-linux-{ARCH}.spdx.json"

# Everything either package installs, and nothing else.
EXPECTED_FILES = {
    "/usr/bin/bastion",
    "/usr/bin/bastionctl",
    "/usr/lib/systemd/system/bastion.service",
    "/etc/bastion/bastion.conf",
    "/etc/logrotate.d/bastion",
    "/usr/share/bastion/html/index.html",
    "/usr/share/man/man8/bastion.8",
    "/usr/share/doc/bastion/copyright",
    "/usr/share/licenses/bastion/LICENSE",
    "/usr/share/doc/bastion/third-party.md",
    "/usr/share/doc/bastion/quickstart.md",
    "/usr/share/doc/bastion/config-reference.md",
    "/usr/share/doc/bastion/admin-api.md",
    "/usr/share/doc/bastion/tuning.md",
    "/usr/share/doc/bastion/systemd.md",
    "/usr/share/doc/bastion/examples/bastion.socket",
}
CONFFILES = {"/etc/bastion/bastion.conf", "/etc/logrotate.d/bastion"}

# A PEM private key with a body, an OpenSSH key, or a well-known credential shape. The binary
# legitimately contains the bare PEM header strings OpenSSL parses, never a key body.
SECRET_RES = [
    re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----\r?\n[A-Za-z0-9+/=]{40,}"),
    re.compile(rb"-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=]{40,}"),
    re.compile(rb"-----BEGIN OPENSSH PRIVATE KEY-----"),
    re.compile(rb"AKIA[0-9A-Z]{16}"),
    re.compile(rb"\$argon2id\$v=19\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]{8,}\$[A-Za-z0-9+/]{16,}"),
]
FORBIDDEN_NAME = re.compile(r"(^|/)(tests?|fixtures?|corpus)(/|$)|\.(pem|key|crt|p12|pfx|jks|der|csr)$|"
                            r"(^|/)\.|(^|/)(id_rsa|id_ed25519|htpasswd|passwd)$", re.I)


def run(*args, **kw):
    return subprocess.run(list(args), capture_output=True, text=True, timeout=120, **kw)


@pytest.fixture(scope="module", autouse=True)
def artifacts():
    missing = [p.name for p in (BIN, DEB, RPM, SBOM, DIST / "SHA256SUMS") if not p.exists()]
    assert not missing, f"missing in {DIST}: {missing}: run ./dev make test-packaging BUILD=release"


@pytest.fixture(scope="module")
def deb_root(tmp_path_factory):
    d = tmp_path_factory.mktemp("deb")
    p = run("dpkg-deb", "-x", str(DEB), str(d))
    assert p.returncode == 0, p.stderr
    return d


@pytest.fixture(scope="module")
def rpm_root(tmp_path_factory):
    d = tmp_path_factory.mktemp("rpm")
    p = subprocess.run(f"rpm2cpio '{RPM}' | cpio -idm --quiet", shell=True, cwd=d,
                       capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, p.stderr
    return d


def tree(root):
    return {"/" + str(p.relative_to(root)) for p in root.rglob("*") if p.is_file() or p.is_symlink()}


def readelf(*args):
    p = run("readelf", "-W", *args, str(BIN))
    assert p.returncode == 0, p.stderr
    return p.stdout


# ---- the binary ----

def test_static():
    """Static PIE: no interpreter, no shared libraries, and it runs with an empty environment."""
    assert "Program Headers" in readelf("-l") and "INTERP" not in readelf("-l")
    assert "NEEDED" not in readelf("-d")
    ldd = run("ldd", str(BIN))
    assert "=>" not in ldd.stdout, ldd.stdout
    p = run(str(BIN), "--version", env={})
    assert p.returncode == 0, p.stderr


def test_hardening_pie_relro():
    assert "DYN (Position-Independent Executable file)" in readelf("-h")
    assert "GNU_RELRO" in readelf("-l")
    dyn = readelf("-d")
    assert "BIND_NOW" in dyn and re.search(r"FLAGS_1\).*\bPIE\b", dyn), dyn
    assert "GNU_STACK" in readelf("-l") and not re.search(r"GNU_STACK.*RWE", readelf("-l"))
    syms = readelf("-s")
    assert "__stack_chk_fail" in syms, "no stack protector"
    if ARCH == "arm64":
        # -mbranch-protection=standard: Bastion's own functions sign their return address (PAC).
        # The binary carries no GNU BTI property note,
        # because musl's startup files and the pinned libraries are not built with it, so the
        # linker drops it and the kernel does not enforce BTI; PAC still applies to our code.
        p = run("objdump", "-d", "--disassemble=bst_version_print", str(BIN))
        assert p.returncode == 0, p.stderr
        # (paciasp is itself a BTI landing pad, so no separate `bti c` is emitted here.)
        assert re.search(r"\b(paciasp|pacibsp)\b", p.stdout), p.stdout[:2000]


def test_version_stamp():
    p = run(str(BIN), "--version")
    assert p.returncode == 0, p.stderr
    first = p.stdout.splitlines()[0]
    assert re.match(rf"^bastion {re.escape(VERSION)} \(git [0-9a-f]{{7,40}}, OpenSSL 3\.5\.\d+", first), first
    env = dict(line.split("=", 1) for line in (ROOT / "deps/versions.env").read_text().splitlines()
               if re.match(r"^[A-Z0-9_]+_VERSION=", line))
    for lib, key in [("ngtcp2", "NGTCP2"), ("nghttp3", "NGHTTP3"), ("liburing", "LIBURING"),
                     ("pcre2", "PCRE2"), ("zstd", "ZSTD"), ("brotli", "BROTLI"),
                     ("zlib-ng", "ZLIBNG"), ("mimalloc", "MIMALLOC")]:
        assert f"{lib} {env[key + '_VERSION']}" in p.stdout, (lib, p.stdout)
    assert "libbpf v" + ".".join(env["LIBBPF_VERSION"].split(".")[:2]) in p.stdout, p.stdout


def test_no_test_seams_in_binary():
    data = BIN.read_bytes()
    for s in (b"BST_TEST_", b"--test-listeners", b"sandbox probe"):
        assert s not in data, s


# ---- the packages ----

def test_deb_contents(deb_root):
    assert tree(deb_root) == EXPECTED_FILES
    assert os.readlink(deb_root / "usr/bin/bastionctl") == "bastion"
    ctl = run("dpkg-deb", "-I", str(DEB))
    assert ctl.returncode == 0 and f"Version: {VERSION}-1" in ctl.stdout and f"Architecture: {ARCH}" in ctl.stdout
    conf = run("dpkg-deb", "--ctrl-tarfile", str(DEB))
    assert conf.returncode == 0


def test_deb_conffiles_and_scripts(tmp_path):
    p = run("dpkg-deb", "-e", str(DEB), str(tmp_path / "ctl"))
    assert p.returncode == 0, p.stderr
    conffiles = set((tmp_path / "ctl/conffiles").read_text().split())
    assert conffiles == CONFFILES
    for s in ("postinst", "prerm", "postrm"):
        assert os.access(tmp_path / "ctl" / s, os.X_OK), s


def test_rpm_contents(rpm_root):
    assert tree(rpm_root) == EXPECTED_FILES
    assert os.readlink(rpm_root / "usr/bin/bastionctl") == "bastion"
    cfg = run("rpm", "-qp", "--configfiles", str(RPM))
    assert cfg.returncode == 0 and set(cfg.stdout.split()) == CONFFILES, cfg.stdout + cfg.stderr
    flags = run("rpm", "-qp", "--qf", "[%{FILENAMES} %{FILEFLAGS:fflags}\n]", str(RPM))
    assert "/etc/bastion/bastion.conf cn" in flags.stdout, flags.stdout  # config(noreplace)
    scripts = run("rpm", "-qp", "--scripts", str(RPM))
    assert "postinstall scriptlet" in scripts.stdout and "preuninstall scriptlet" in scripts.stdout
    info = run("rpm", "-qpi", str(RPM))
    assert re.search(r"Version\s*:\s*" + re.escape(VERSION), info.stdout) and "License     : MIT" in info.stdout


@pytest.mark.parametrize("which", ["deb", "rpm"])
def test_no_secrets_or_test_files(which, deb_root, rpm_root):
    root = deb_root if which == "deb" else rpm_root
    for f in sorted(tree(root)):
        assert not FORBIDDEN_NAME.search(f), f
        p = root / f.lstrip("/")
        if p.is_symlink():
            continue
        data = p.read_bytes()
        for rx in SECRET_RES:
            assert not rx.search(data), (f, rx.pattern)
    # The packaged binary is the release one, byte for byte.
    assert (root / "usr/bin/bastion").read_bytes() == BIN.read_bytes()


def test_unit_and_man_page(deb_root):
    unit = (deb_root / "usr/lib/systemd/system/bastion.service").read_text()
    assert "ExecStart=/usr/bin/bastion -c /etc/bastion/bastion.conf" in unit
    assert "Documentation=man:bastion(8)" in unit
    man = (deb_root / "usr/share/man/man8/bastion.8").read_text()
    assert man.startswith(".TH BASTION 8")
    if shutil.which("mandoc"):
        p = run("mandoc", "-Tlint", "-Wwarning", str(deb_root / "usr/share/man/man8/bastion.8"))
        assert p.returncode == 0, p.stdout + p.stderr


def test_default_config_checks(deb_root, tmp_path):
    """The packaged config passes `bastion -t` (its paths rewritten into a scratch root)."""
    conf = (deb_root / "etc/bastion/bastion.conf").read_text()
    assert "user bastion;" in conf and "root /usr/share/bastion/html;" in conf
    conf = conf.replace("user bastion;", "").replace("/var/log/bastion", str(tmp_path)) \
        .replace("/usr/share/bastion/html", str(deb_root / "usr/share/bastion/html"))
    (tmp_path / "bastion.conf").write_text(conf)
    p = run(str(BIN), "-t", "-c", str(tmp_path / "bastion.conf"))
    assert p.returncode == 0, p.stderr


def test_default_config_rejects_broken(tmp_path):
    (tmp_path / "bad.conf").write_text("server { listen 80; root; }\n")
    p = run(str(BIN), "-t", "-c", str(tmp_path / "bad.conf"))
    assert p.returncode == 1, (p.stdout, p.stderr)


def test_logrotate_signals_reopen(deb_root):
    lr = (deb_root / "etc/logrotate.d/bastion").read_text()
    assert "/var/log/bastion/*.log" in lr and "USR1" in lr


# ---- SBOM and checksums ----

def test_sha256sums():
    lines = (DIST / "SHA256SUMS").read_text().splitlines()
    sums = {name: h for h, name in (l.split(None, 1) for l in lines)}
    for p in (BIN, DEB, RPM, SBOM):
        assert sums.get(p.name) == hashlib.sha256(p.read_bytes()).hexdigest(), p.name


def test_sbom():
    doc = json.loads(SBOM.read_text())
    assert doc["spdxVersion"] == "SPDX-2.3"
    pkgs = {p["name"]: p for p in doc["packages"]}
    assert pkgs["bastion"]["versionInfo"].startswith(VERSION + "+git.")
    assert pkgs["bastion"]["checksums"][0]["checksumValue"] == hashlib.sha256(BIN.read_bytes()).hexdigest()
    for lib in ("openssl", "ngtcp2", "nghttp3", "liburing", "libbpf", "pcre2", "zstd", "brotli", "zlibng", "mimalloc"):
        assert lib in pkgs, lib
        assert pkgs[lib].get("checksums"), lib
    assert sum(r["relationshipType"] == "STATIC_LINK" for r in doc["relationships"]) == len(pkgs) - 1


# ---- the Docker-level tests ----

def test_host_suite():
    if shutil.which("docker") is None:
        pytest.skip("docker CLI not available inside the test container; "
                    "run tests/host/test_packages_host.sh on the host")
    p = subprocess.run(["bash", str(ROOT / "tests/host/test_packages_host.sh"), VERSION],
                       capture_output=True, text=True, timeout=3600)
    assert p.returncode == 0, p.stdout + p.stderr
