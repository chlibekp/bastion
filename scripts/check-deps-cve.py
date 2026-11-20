#!/usr/bin/env python3
"""Dependency CVE check (Phase 15, Task 5): asks the NVD CVE API which published CVEs affect the
exact versions pinned in deps/versions.env, matched by CPE. Exit 1 when any is found (each is
printed with its id and score), 2 when the API cannot be reached, 0 otherwise.

  python3 scripts/check-deps-cve.py [--allow CVE-YYYY-NNNN ...]

--allow lists CVEs reviewed and judged not to apply to how Bastion uses the library; record the
reason in docs/security.md. NVD_API_KEY in the environment raises the rate limit. A dependency
with no CPE in NVD gives no result at all: the table below says which ones that is known for."""
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# versions.env variable prefix -> NVD CPE vendor:product
CPES = {
    "OPENSSL": "openssl:openssl",
    "NGTCP2": "ngtcp2:ngtcp2",
    "NGHTTP3": "ngtcp2:nghttp3",
    "LIBURING": "axboe:liburing",  # no NVD CPE known: checked by hand on bumps
    "LIBBPF": "libbpf_project:libbpf",
    "PCRE2": "pcre:pcre2",
    "ZSTD": "facebook:zstandard",
    "BROTLI": "google:brotli",
    "ZLIBNG": "zlib-ng:zlib-ng",
    "MIMALLOC": "microsoft:mimalloc",
}
API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def pins():
    out = {}
    with open(os.path.join(ROOT, "deps", "versions.env")) as f:
        for line in f:
            m = re.match(r"^([A-Z0-9]+)_VERSION=(\S+)\s*$", line)
            if m:
                out[m.group(1)] = m.group(2).strip('"')
    return out


def query(cpe, version):
    q = urllib.parse.urlencode({"virtualMatchString": f"cpe:2.3:a:{cpe}:{version}"})
    req = urllib.request.Request(f"{API}?{q}", headers={"User-Agent": "dependency-cve-check"})
    key = os.environ.get("NVD_API_KEY")
    if key:
        req.add_header("apiKey", key)
    for attempt in range(5):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r).get("vulnerabilities", [])
        except urllib.error.HTTPError as e:
            if e.code not in (403, 429, 503) or attempt == 4:
                raise
        except urllib.error.URLError:
            if attempt == 4:
                raise
        time.sleep(10 * (attempt + 1))
    return []


def score(cve):
    for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in cve.get("metrics", {}).get(k, []):
            return m["cvssData"].get("baseScore")
    return None


def main():
    allow = set(sys.argv[sys.argv.index("--allow") + 1:]) if "--allow" in sys.argv else set()
    versions = pins()
    missing = sorted(set(CPES) - set(versions))
    if missing:
        print(f"deps/versions.env has no version for: {', '.join(missing)}", file=sys.stderr)
        return 2
    found = 0
    for dep, cpe in CPES.items():
        try:
            vulns = query(cpe, versions[dep])
        except (urllib.error.URLError, OSError, ValueError) as e:
            print(f"cannot query NVD for {dep}: {e}", file=sys.stderr)
            return 2
        hits = [v["cve"] for v in vulns if v["cve"]["id"] not in allow]
        status = "ok" if not hits else f"{len(hits)} CVE(s)"
        print(f"{dep.lower():10} {versions[dep]:10} {status}")
        for c in hits:
            print(f"    {c['id']} score={score(c)}")
        found += len(hits)
        if not os.environ.get("NVD_API_KEY"):
            time.sleep(6)  # 5 requests per 30 s without a key
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
