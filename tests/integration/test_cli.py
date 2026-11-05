"""Command line: -t, -T, usage errors, serve/proxy, --dump-schema, generated reference."""
import json
import os
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

VALID = "server { listen 8080; name example.com; }\n"

# Every core directive, nested locations, quoted args.
FULL = """\
user www;
workers 4;
pid /run/bastion.pid;
error_log /var/log/bastion.log info;
server {
    listen 127.0.0.1:8080;
    listen [::1]:8081;
    name Example.com "www.example.com";
    client_max_body_size 8m;
    location /api {
        client_max_body_size 2m;
        location = /api/exact { }
        location ~* '\\.php$' { }
    }
    location ^~ "/with space" { }
}
server { listen 9090; }
"""


def run(binary, *args, env=None, cwd=None, inp=None):
    e = dict(os.environ)
    e.pop("BST_TEST_VAR", None)
    if env:
        e.update(env)
    return subprocess.run([binary, *args], capture_output=True, text=True, timeout=20,
                          env=e, cwd=cwd, input=inp)


def conf(tmp_path, text, name="bastion.conf"):
    p = tmp_path / name
    p.write_text(text)
    return str(p)


def test_t_ok(bastion_bin, tmp_path):
    p = run(bastion_bin, "-c", conf(tmp_path, VALID), "-t")
    assert p.returncode == 0, p.stderr
    assert p.stdout.strip() == "configuration ok"


def test_t_error(bastion_bin, tmp_path):
    cases = [
        ("server {\n  listen 80;\n", "unclosed"),
        ("server {\n  listen 80;\n  lisen 81;\n}\n", "unknown directive"),
        ("server {\n  name a;\n}\n", "listen"),  # compile error: no_listen
    ]
    for text, word in cases:
        path = conf(tmp_path, text)
        p = run(bastion_bin, "-c", path, "-t")
        assert p.returncode == 1, (text, p.stdout, p.stderr)
        assert p.stdout == ""
        assert re.match(re.escape(path) + r":\d+:\d+: .*" + word, p.stderr), p.stderr
        assert p.stderr.count("\n") == 1, p.stderr
    # exact positions and the suggestion
    path = conf(tmp_path, cases[1][0])
    p = run(bastion_bin, "-c", path, "-t")
    assert p.stderr.startswith(f"{path}:3:3: "), p.stderr
    assert 'did you mean "listen"' in p.stderr
    path = conf(tmp_path, cases[2][0])
    assert run(bastion_bin, "-c", path, "-t").stderr.startswith(f"{path}:1:1: ")


def test_t_include_error(bastion_bin, tmp_path):
    inc = conf(tmp_path, "server {\n  bogus 1;\n  listen 80;\n}\n", "inc.conf")
    main = conf(tmp_path, "include inc.conf;\n")
    p = run(bastion_bin, "-c", main, "-t")
    assert p.returncode == 1
    assert p.stderr.startswith("inc.conf:2:3: ") or p.stderr.startswith(f"{inc}:2:3: "), p.stderr
    assert "bastion.conf" not in p.stderr and "main" not in p.stderr


def test_t_control_bytes_escaped(bastion_bin, tmp_path):
    path = conf(tmp_path, "server {\n  listen 80;\n  \"x\x01y\" 1;\n}\n")
    p = run(bastion_bin, "-c", path, "-t")
    assert p.returncode == 1
    assert not re.search(r"[\x00-\x09\x0b-\x1f\x7f]", p.stderr)


def test_T_effective(bastion_bin, tmp_path):
    first = run(bastion_bin, "-c", conf(tmp_path, FULL), "-T")
    assert first.returncode == 0, first.stderr
    out = first.stdout
    assert re.search(r"^workers 4;$", out, re.M)  # explicit value kept, no default added
    assert "workers auto" not in out
    again = run(bastion_bin, "-c", conf(tmp_path, out, "round1.conf"), "-T")
    assert again.returncode == 0, again.stderr
    assert again.stdout == out  # fixed point
    third = run(bastion_bin, "-c", conf(tmp_path, again.stdout, "round2.conf"), "-T")
    assert third.stdout == out
    assert "'\\.php$'" in out or '"\\\\.php$"' in out
    assert "/with space" in out


def test_T_defaults_and_inheritance(bastion_bin, tmp_path):
    p = run(bastion_bin, "-c", conf(tmp_path, "server { listen 80; location /a { } }"), "-T")
    assert p.returncode == 0, p.stderr
    # defaults appear where they first become valid, never repeated in children
    assert p.stdout.count("workers auto;") == 1
    assert p.stdout.count("client_max_body_size 1m;") == 1
    text = "server { client_max_body_size 10m; listen 80; location /a { } }"
    p = run(bastion_bin, "-c", conf(tmp_path, text), "-T")
    assert "10m" in p.stdout and "1m;" not in p.stdout.replace("10m;", "")
    # source order is kept within a scope, defaults follow
    out = run(bastion_bin, "-c", conf(tmp_path, "server { name b; listen 80; }"), "-T").stdout
    assert out.index("name b;") < out.index("listen 80;") < out.index("client_max_body_size")


def unquote(tok):
    """Independent decoder for the printer's three spellings."""
    if tok.startswith("'"):
        assert tok.endswith("'")
        return tok[1:-1]
    if tok.startswith('"'):
        assert tok.endswith('"')
        out, i, body = [], 0, tok[1:-1]
        while i < len(body):
            if body[i] == "\\":
                out.append({"n": "\n", "t": "\t", "r": "\r"}.get(body[i + 1], body[i + 1]))
                i += 2
            else:
                out.append(body[i])
                i += 1
        return "".join(out)
    return tok


QUOTE_VALUES = [
    "a b",
    "semi;colon",
    "brace{ }",
    "hash # tag",
    "#lead",
    'dq"uote',
    "back\\slash",
    "new\nline",
    "tab\tchar",
    "$dollar",
    "x;y {z} $q \"w\\",
    "${NOT}",
    "",
]


@pytest.mark.parametrize("val", QUOTE_VALUES)
def test_T_quoting_roundtrips(bastion_bin, tmp_path, val):
    c = conf(tmp_path, "user ${BST_TEST_VAR:-unset};\nserver { listen 80; }\n")
    first = run(bastion_bin, "-c", c, "-T", env={"BST_TEST_VAR": val})
    assert first.returncode == 0, first.stderr
    # The printed text re-parses to the same value: printing it again changes nothing, and
    # it needs no environment.
    c2 = conf(tmp_path, first.stdout, "r.conf")
    again = run(bastion_bin, "-c", c2, "-T")
    assert again.returncode == 0, (first.stdout, again.stderr)
    assert again.stdout == first.stdout
    # And the value is the same: decode the printed `user` argument by hand.
    line = next(l for l in first.stdout.splitlines() if l.startswith("user "))
    assert unquote(line[len("user "):-1]) == val


def test_T_single_quote_dollar_stays_literal(bastion_bin, tmp_path):
    c = conf(tmp_path, "user 'a$host';\nserver { listen 80; }\n")
    first = run(bastion_bin, "-c", c, "-T")
    assert first.returncode == 0, first.stderr
    assert "user 'a$host';" in first.stdout
    assert run(bastion_bin, "-c", conf(tmp_path, first.stdout, "r.conf"), "-T").stdout \
        == first.stdout


def test_T_env_dollar_stays_literal(bastion_bin, tmp_path):
    val = "p$host;x y"
    c = conf(tmp_path, "user ${BST_TEST_VAR};\nserver { listen 80; }\n")
    first = run(bastion_bin, "-c", c, "-T", env={"BST_TEST_VAR": val})
    assert first.returncode == 0, first.stderr
    assert "user 'p$host;x y';" in first.stdout  # single quotes keep the $ literal
    r = conf(tmp_path, first.stdout, "r.conf")
    assert run(bastion_bin, "-c", r, "-t").returncode == 0
    assert run(bastion_bin, "-c", r, "-T").stdout == first.stdout


def test_T_unrepresentable_value_errors(bastion_bin, tmp_path):
    c = conf(tmp_path, "user ${BST_TEST_VAR};\nserver { listen 80; }\n")
    p = run(bastion_bin, "-c", c, "-T", env={"BST_TEST_VAR": "it's $x"})
    assert p.returncode == 1
    assert p.stdout == ""  # nothing printed that could mean something else
    assert "cannot" in p.stderr and "round-trip" in p.stderr, p.stderr


def test_T_error_goes_through_compile(bastion_bin, tmp_path):
    path = conf(tmp_path, "server { name a; }\n")
    p = run(bastion_bin, "-c", path, "-T")
    assert p.returncode == 1 and p.stdout == ""
    assert p.stderr.startswith(f"{path}:1:1: ")


def test_help_warns_about_secrets(bastion_bin):
    p = run(bastion_bin, "--help")
    assert p.returncode == 0
    assert "-T" in p.stdout and "secret" in p.stdout.lower()


def test_version_unchanged(bastion_bin):
    p = run(bastion_bin, "--version")
    assert p.returncode == 0 and p.stdout.startswith("bastion ")


@pytest.mark.parametrize("args", [
    ["--bogus"], ["-x"], ["-c"], ["-t", "extra"], ["-c", "a", "-c"], ["serve"], ["proxy"],
    ["serve", "dir", "--port"], ["serve", "dir", "--port", "0"],
    ["serve", "dir", "--port", "70000"], ["serve", "dir", "--port", "8o"],
    ["serve", "a", "b"], ["proxy", "http://x", "--wat"], ["serve", "d", "-c", "f"],
])
def test_usage_errors(bastion_bin, args):
    p = run(bastion_bin, *args)
    assert p.returncode == 2, (p.stdout, p.stderr)
    assert p.stdout == ""
    assert p.stderr.startswith("bastion: ")
    assert "--help" in p.stderr
    assert len(p.stderr.strip().splitlines()) == 1


def test_default_config_missing(bastion_bin, tmp_path):
    if Path("/etc/bastion/bastion.conf").exists():
        pytest.skip("default config exists on this machine")
    p = run(bastion_bin, "-t", cwd=tmp_path)
    assert p.returncode == 1
    assert "/etc/bastion/bastion.conf" in p.stderr


def test_server_runtime_not_available_yet(bastion_bin, tmp_path):
    # Phase 3 replaces this behaviour with the real server.
    p = run(bastion_bin, "-c", conf(tmp_path, VALID))
    assert p.returncode == 2
    assert p.stderr.strip() == "server runtime not available yet"
    bad = conf(tmp_path, "bogus 1;\n", "bad.conf")
    assert run(bastion_bin, "-c", bad).returncode == 1


# Phase 5 registers `root`, which makes `serve` work (its end-to-end test replaces this one);
# until then compile reports the directive as unknown.
def test_serve_unknown_directive_until_phase5(bastion_bin):
    p = run(bastion_bin, "serve", "./public", "--port", "8080")
    assert p.returncode == 1
    assert 'unknown directive "root"' in p.stderr


# Phase 9 registers `proxy` and replaces this test with an end-to-end one.
def test_proxy_unknown_directive_until_phase9(bastion_bin):
    p = run(bastion_bin, "proxy", "http://127.0.0.1:3000")
    assert p.returncode == 1
    assert 'unknown directive "proxy"' in p.stderr


def test_serve_hostile_dir_cannot_inject(bastion_bin):
    # Nothing is generated as text, so the name is one argument of `root`: compile still
    # stops at the unknown `root`, not at a syntax error or a different directive.
    p = run(bastion_bin, "serve", "a;b {", "--port", "8080")
    assert p.returncode == 1
    assert 'unknown directive "root"' in p.stderr


def test_dump_schema(bastion_bin):
    p = run(bastion_bin, "--dump-schema")
    assert p.returncode == 0, p.stderr
    doc = json.loads(p.stdout)
    dirs = doc["directives"]
    names = {d["name"] for d in dirs}
    assert {"user", "workers", "pid", "error_log", "include", "server", "listen", "name",
            "location", "client_max_body_size"} <= names
    w = next(d for d in dirs if d["name"] == "workers")
    assert w["default"] == "auto" and w["contexts"] == ["global"]
    assert w["args"]["pos"][0]["type"] == "int" and w["args"]["pos"][0]["keywords"] == ["auto"]
    assert w["doc"] and w["block"] == "forbidden" and w["repeatable"] is False
    loc = next(d for d in dirs if d["name"] == "location")
    assert loc["contexts"] == ["server", "location"] and loc["block"] == "required"
    assert loc["repeatable"] is True
    el = next(d for d in dirs if d["name"] == "error_log")
    assert el["args"]["pos"][1]["enum"][0] == "debug"
    for d in dirs:
        for k in ("name", "subname", "contexts", "args", "default", "doc", "block",
                  "repeatable", "require"):
            assert k in d, (d["name"], k)
        assert {"min", "max", "pos", "options"} <= set(d["args"])


def test_reference_up_to_date(bastion_bin, tmp_path):
    out = tmp_path / "config-reference.md"
    p = subprocess.run([str(ROOT / "scripts/gen-config-reference.sh"), bastion_bin, str(out)],
                       capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr
    committed = (ROOT / "docs/config-reference.md").read_text()
    assert out.read_text() == committed, (
        "docs/config-reference.md is stale: run `./dev make gen-reference` and commit it")
    # reproducible
    out2 = tmp_path / "again.md"
    subprocess.run([str(ROOT / "scripts/gen-config-reference.sh"), bastion_bin, str(out2)],
                   check=True, capture_output=True, timeout=60)
    assert out2.read_text() == committed
    assert "secrets" in committed.split("\n## ")[0]
    assert "make gen-reference" in committed.split("\n## ")[0]
