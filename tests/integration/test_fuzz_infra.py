"""The fuzz runner must turn crashes, hangs and typos into failures."""
import os
import re
import subprocess

from conftest import ROOT


def run_fuzz(tmp_path, *targets, secs=3, **env):
    e = dict(os.environ, FUZZ_SRC_DIR="tests/fixtures", FUZZ_CRASH_DIR=str(tmp_path),
             **{k: str(v) for k, v in env.items() if k != "SEED"})
    seed = [f"SEED={env['SEED']}"] if "SEED" in env else []
    return subprocess.run(["make", "fuzz", "T=" + " ".join(targets), f"SECS={secs}", *seed], cwd=ROOT,
                          env=e, capture_output=True, text=True, timeout=300)


def test_detects_crash(tmp_path):
    r = run_fuzz(tmp_path, "fuzz_crash")
    assert r.returncode != 0, r.stdout + r.stderr
    assert list(tmp_path.glob("fuzz_crash-crash-*")), r.stdout + r.stderr


def test_timeout_is_failure(tmp_path):
    r = run_fuzz(tmp_path, "hang", secs=5, FUZZ_TIMEOUT=1)
    assert r.returncode != 0, r.stdout + r.stderr
    assert list(tmp_path.glob("fuzz_hang-timeout-*")), r.stdout + r.stderr


def test_no_harness_is_failure(tmp_path):
    r = run_fuzz(tmp_path, "doesnotexist")
    assert r.returncode != 0
    assert "no harness" in r.stderr + r.stdout


def test_clean_harness_passes(tmp_path):
    r = run_fuzz(tmp_path, "ok", secs=1)
    assert r.returncode == 0, r.stdout + r.stderr
    assert not list(tmp_path.iterdir())


def test_build_failure_does_not_stop_others(tmp_path):
    r = run_fuzz(tmp_path, "broken", "ok", secs=1)
    out = r.stdout + r.stderr
    assert r.returncode != 0, out
    assert "== fuzz_ok" in out, out
    assert "fuzz_broken (build failed)" in out, out


def test_signal_death_reports_no_reproducer(tmp_path):
    r = run_fuzz(tmp_path, "trap", SEED=7)
    out = r.stdout + r.stderr
    assert r.returncode != 0, out
    assert not list(tmp_path.iterdir())
    assert "no reproducer was written" in out, out
    assert "signal" in out and "-seed=7" in out, out


def seeds(out):
    return re.findall(r"^== \S+: seed=(\d+) ", out, re.M)


def test_seed_printed_and_varies(tmp_path):
    a = seeds(run_fuzz(tmp_path, "ok", secs=1).stdout)
    b = seeds(run_fuzz(tmp_path, "ok", secs=1).stdout)
    assert len(a) == 1 and len(b) == 1 and a != b
    c = run_fuzz(tmp_path, "ok", secs=1, SEED=7)
    assert seeds(c.stdout) == ["7"], c.stdout
    d = run_fuzz(tmp_path, "ok", secs=1, SEED="abc")
    assert d.returncode != 0 and "SEED must be numeric" in d.stdout + d.stderr


def test_seed_printed_for_failing_harness(tmp_path):
    r = run_fuzz(tmp_path, "crash", SEED=5)
    assert seeds(r.stdout) == ["5"], r.stdout


def test_existing_reproducer_is_still_reported(tmp_path):
    run_fuzz(tmp_path, "crash", SEED=5)
    r = run_fuzz(tmp_path, "crash", SEED=5)
    out = r.stdout + r.stderr
    assert r.returncode != 0 and "reproducer in" in out and "no reproducer" not in out, out
