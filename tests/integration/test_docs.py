"""The user guide and examples (Phase 15 Task 6): every configuration they show is checked by
`bastion -t`, the generated reference covers every directive and carries examples for the most used
ones, and no relative link or anchor in the documentation is broken.

Conventions the documentation follows so this file can check it:
- A fenced block tagged `conf` is a complete configuration and must pass `bastion -t`. Fragments
  (a directive's syntax line, part of a block) use `nginx` or no tag. The guides use `conf` only.
- Paths in examples use a few fixed prefixes (`PLACES` below). The test maps each onto a scratch
  directory holding what the examples expect there (a site, a certificate, a password file, a JWT
  key), so the check never touches the host and needs no root.

No test here opens a network connection: external links (http, https, mailto) are skipped."""
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

GUIDES = ["getting-started", "static-sites", "reverse-proxy", "tls", "caching", "ddos",
          "migrating-from-nginx", "operations"]

# The directives an operator meets first: each must have an example in the reference.
TOP_DIRECTIVES = [
    "workers", "user", "pid", "error_log", "include", "access_log", "log_format",
    "worker_rlimit_nofile", "shutdown_timeout", "open_file_cache",
    "server", "listen", "name", "location", "root", "alias", "index", "try_files", "autoindex",
    "error_page", "return", "rewrite", "redirect_https", "internal", "expires", "etag",
    "default_type", "client_max_body_size", "header_set", "header_remove",
    "tls_cert", "tls auto", "acme", "email", "staging", "tls_profile", "security_headers", "hsts",
    "proxy", "upstream", "health_check", "real_ip_from", "trusted_proxies", "websocket",
    "cache_store", "cache", "cache_valid", "cache_bypass", "compress",
    "limit_zone", "limit", "limit_conn", "allow", "deny", "auth_basic", "auth_jwt",
    "waf_rule", "waf", "challenge", "xdp", "metrics", "admin",
]

FENCE = re.compile(r"^```([A-Za-z0-9_-]*)[^\n]*\n(.*?)^```[ \t]*$", re.M | re.S)


def doc_files():
    """The user-facing Markdown: README, SECURITY, docs/ and docs/guide/. The implementation plan
    under docs/implementation-plan/ is design history, not documentation of the binary."""
    files = [ROOT / "README.md", ROOT / "SECURITY.md"]
    files += sorted((ROOT / "docs").glob("*.md")) + sorted((ROOT / "docs/guide").glob("*.md"))
    return [f for f in files if f.exists()]


def conf_blocks():
    out = []
    for f in doc_files():
        text = f.read_text()
        for m in FENCE.finditer(text):
            if m.group(1) == "conf":
                line = text.count("\n", 0, m.start()) + 1
                out.append((f"{f.relative_to(ROOT)}:{line}", m.group(2)))
    for f in sorted((ROOT / "examples").glob("*.conf")):
        out.append((str(f.relative_to(ROOT)), f.read_text()))
    return out


@pytest.fixture(scope="module")
def places(tmp_path_factory, bastion_bin):
    """A scratch tree standing in for the paths the documentation uses."""
    d = tmp_path_factory.mktemp("docs")
    m = {
        "/usr/share/bastion/html": d / "html",
        "/srv/www": d / "www",
        "/etc/bastion": d / "etc",
        "/var/lib/bastion": d / "state",
        "/var/cache/bastion": d / "cache",
        "/var/log/bastion": d / "log",
        "/run/bastion": d / "run",
    }
    for p in m.values():
        p.mkdir()
    for site in (m["/srv/www"], m["/usr/share/bastion/html"]):
        (site / "index.html").write_text("ok\n")
        for sub in ("example", "static", "assets", "files", "app/dist", "downloads"):
            (site / sub).mkdir(parents=True, exist_ok=True)
            (site / sub / "index.html").write_text("ok\n")
    etc = m["/etc/bastion"]
    (etc / "tls").mkdir()
    for name in ("example.com", "example.com-ecdsa"):
        alg = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256"] if "ecdsa" in name else \
            ["-newkey", "rsa:2048"]
        subprocess.run(["openssl", "req", "-x509", *alg, "-nodes", "-days", "30", "-subj",
                        "/CN=example.com", "-addext", "subjectAltName=DNS:example.com,DNS:www.example.com",
                        "-keyout", str(etc / "tls" / f"{name}.key"), "-out", str(etc / "tls" / f"{name}.crt")],
                       check=True, capture_output=True)
    # a CA bundle for client certificates and upstream verification
    (etc / "tls" / "ca.crt").write_bytes((etc / "tls" / "example.com.crt").read_bytes())
    p = subprocess.run([bastion_bin, "passwd", "alice"], input="secret\n",
                       capture_output=True, text=True, check=True)
    (etc / "htpasswd").write_text(p.stdout)
    subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out",
                    str(d / "jwt.key")], check=True, capture_output=True)
    subprocess.run(["openssl", "ec", "-in", str(d / "jwt.key"), "-pubout", "-out",
                    str(etc / "jwt-public.pem")], check=True, capture_output=True)
    (etc / "blocklist.txt").write_text("# one address or CIDR per line\n192.0.2.0/24\n")
    (etc / "conf.d").mkdir()
    (etc / "conf.d" / "site.conf").write_text("server { listen 127.0.0.1:8099; root /srv/www; }\n")
    return d, m


def localize(text, m):
    # `acme {}` without `storage` uses /var/lib/bastion/acme, which `-t` creates: point it at
    # the scratch tree the same way as a path written out.
    text = re.sub(r"\bacme\s*\{(?![^}]*\bstorage\b)", "acme { storage /var/lib/bastion/acme;", text)
    for k in sorted(m, key=len, reverse=True):
        text = text.replace(k, str(m[k]))
    return text


def check(bastion_bin, d, m, text):
    cfg = d / "check.conf"
    cfg.write_text(localize(text, m))
    # included files carry the same placeholders
    inc = m["/etc/bastion"] / "conf.d" / "site.conf"
    inc.write_text(localize("server { listen 127.0.0.1:8099; root /srv/www; }\n", m))
    p = subprocess.run([bastion_bin, "-c", str(cfg), "-t"], cwd=d, capture_output=True, text=True,
                       timeout=60)
    return p.returncode == 0 and "configuration ok" in p.stdout + p.stderr, p.stderr


def test_all_examples_parse(bastion_bin, places):
    for g in GUIDES:
        assert (ROOT / "docs/guide" / f"{g}.md").exists(), f"docs/guide/{g}.md is missing"
    assert len(list((ROOT / "examples").glob("*.conf"))) >= 5, "examples/*.conf are missing"
    blocks = conf_blocks()
    guide_blocks = [b for b in blocks if b[0].startswith("docs/guide/")]
    assert len(guide_blocks) >= 3 * len(GUIDES) - 2, len(guide_blocks)
    d, m = places
    failed = []
    for where, text in blocks:
        ok, err = check(bastion_bin, d, m, text)
        if not ok:
            failed.append(f"{where}:\n{text}\n-> {err.strip()}")
    assert not failed, "\n\n".join(failed)


def test_guides_have_no_unchecked_config(bastion_bin):
    """A guide that showed a whole configuration in an `nginx` block would escape the check above:
    guides use `conf` for configurations and plain blocks for shell."""
    for g in GUIDES:
        f = ROOT / "docs/guide" / f"{g}.md"
        if f.exists():
            tags = {m.group(1) for m in FENCE.finditer(f.read_text())}
            assert "nginx" not in tags, f"{f.name}: use ```conf (checked) for configurations"


def test_example_check_catches_errors(bastion_bin, places):
    """The harness itself: a broken block fails, so a passing run means something."""
    d, m = places
    assert not check(bastion_bin, d, m, "server { listen 8080; root /srv/www; nosuch on; }\n")[0]
    assert not check(bastion_bin, d, m, "workers 0;\nserver { listen 8080; root /srv/www; }\n")[0]
    assert check(bastion_bin, d, m, "server { listen 8080; root /srv/www; }\n")[0]


def reference_sections():
    text = (ROOT / "docs/config-reference.md").read_text()
    secs = {}
    for s in re.split(r"\n### ", text)[1:]:
        title = s.split("`")[1]
        secs.setdefault(title, []).append(s)
    return secs


def test_reference_complete(bastion_bin):
    import json
    p = subprocess.run([bastion_bin, "--dump-schema"], capture_output=True, text=True, timeout=30)
    assert p.returncode == 0, p.stderr
    want = {}
    for dd in json.loads(p.stdout)["directives"]:
        title = dd["name"] + (" " + dd["subname"] if dd["subname"] else "")
        want[title] = want.get(title, 0) + 1
        assert dd["doc"].strip(), f"{title} has no documentation in its directive table"
    secs = reference_sections()
    for title, n in want.items():
        assert len(secs.get(title, [])) == n, f"{title}: {n} in the schema, {len(secs.get(title, []))} in the reference"
    assert set(secs) == set(want), set(secs) ^ set(want)
    with_example = {t for t, ss in secs.items() if any("\nExample:\n\n```conf\n" in s for s in ss)}
    missing = [t for t in TOP_DIRECTIVES if t not in with_example]
    assert not missing, f"no example in docs/config-reference.md for: {missing}"
    assert len(with_example) >= 50, len(with_example)


def slug(heading):
    """GitHub's anchor for a heading."""
    h = re.sub(r"`|\[([^\]]*)\]\([^)]*\)", lambda mm: mm.group(1) or "", heading.strip().lower())
    h = re.sub(r"[^\w\- ]", "", h)
    return h.replace(" ", "-")


def anchors(path):
    out = set()
    seen = {}
    in_fence = False
    for line in path.read_text().splitlines():
        if line.startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence and re.match(r"#{1,6} ", line):
            s = slug(line.lstrip("#"))
            n = seen.get(s, 0)
            seen[s] = n + 1
            out.add(s if n == 0 else f"{s}-{n}")
    return out


LINK = re.compile(r"(?<!!)\[[^\]\n]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")


def links(path):
    text = FENCE.sub("", path.read_text())
    text = re.sub(r"`[^`\n]*`", "", text)
    return LINK.findall(text)


def test_docs_links():
    files = doc_files() + sorted((ROOT / "docs/implementation-plan").glob("*.md"))
    assert (ROOT / "docs/guide/getting-started.md") in files, "docs/guide/ is missing"
    bad = []
    count = 0
    for f in files:
        for target in links(f):
            if re.match(r"[a-z]+:", target):  # http, https, mailto: never fetched
                continue
            count += 1
            path, _, frag = target.partition("#")
            dest = (f.parent / path).resolve() if path else f
            if not dest.exists():
                bad.append(f"{f.relative_to(ROOT)}: {target} (no such file)")
                continue
            if frag and dest.suffix == ".md" and frag not in anchors(dest):
                bad.append(f"{f.relative_to(ROOT)}: {target} (no such heading)")
    assert not bad, "\n".join(bad)
    assert count >= 40, f"only {count} relative links: the guides should link each other and the reference"


def test_readme_starts_with_https_config():
    text = (ROOT / "README.md").read_text()
    m = FENCE.search(text)
    assert m and m.group(1) == "conf", "the README's first block is the HTTPS config"
    assert text.count("\n", 0, m.start()) < 15, "the HTTPS config is at the top of the README"
    body = m.group(2)
    directives = [x for x in re.split(r"[;{}]", body) if x.strip() and not x.strip().startswith("#")]
    names = [x.split()[0] for x in directives]
    assert names == ["acme", "email", "server", "name", "tls", "root"], names
    assert "tls auto;" in body


def test_nginx_table_targets_exist(bastion_bin):
    """Every Bastion directive the migration table names exists in the schema."""
    import json
    f = ROOT / "docs/guide/migrating-from-nginx.md"
    assert f.exists()
    p = subprocess.run([bastion_bin, "--dump-schema"], capture_output=True, text=True, timeout=30)
    names = {d["name"] for d in json.loads(p.stdout)["directives"]}
    rows = [r for r in f.read_text().splitlines() if r.startswith("| `")]
    assert len(rows) >= 40, len(rows)
    for r in rows:
        cells = [c.strip() for c in r.strip("|").split("|")]
        for tok in re.findall(r"`([a-z_0-9]+)[ `]", cells[1] + " "):
            assert tok in names, f"{r}: `{tok}` is not a Bastion directive"
