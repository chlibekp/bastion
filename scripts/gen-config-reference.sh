#!/usr/bin/env bash
# Generates the directive reference from the binary's own schema.
# usage: scripts/gen-config-reference.sh [bastion-binary] [output]
# Defaults: build/debug/bastion, docs/config-reference.md. Run it as `./dev make gen-reference`
# (python3 is in both build images). Output is sorted and has no timestamps, so the same
# schema always gives the same bytes.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
bin=${1:-$root/build/debug/bastion}
out=${2:-$root/docs/config-reference.md}
tmp=$(mktemp)
trap 'rm -f "$tmp" "$out.new"' EXIT
"$bin" --dump-schema >"$tmp"
python3 -I - "$tmp" >"$out.new" <<'PY'
import json, sys

doc = json.load(open(sys.argv[1]))
dirs = sorted(doc["directives"], key=lambda d: (d["name"], d["subname"] or "", d["contexts"]))

def argtext(t):
    parts = list(t["keywords"])
    if t["type"] == "enum":
        parts += t["enum"]
    else:
        ty = t["type"]
        if t["type"] == "int" and t["min"] is not None:
            ty = "int %d..%d" % (t["min"], t["max"])
        elif t["type"] in ("size", "duration", "rate") and t["min"] is not None:
            unit = {"size": " bytes", "duration": " us", "rate": "/s"}[t["type"]]
            lo = str(t["min"]) if t["min"] else ""
            hi = str(t["max"]) if t["max"] else ""
            ty = "%s %s..%s%s" % (t["type"], lo, hi, unit)
        parts.append(ty)
    s = "|".join(parts)
    return s + (",..." if t["list"] else "")

def syntax(d):
    a = d["args"]
    out = [d["name"]]
    if d["subname"]:
        out.append(d["subname"])
    pos = a["pos"]
    shown = max(len(pos), a["min"]) if pos else 0
    for i in range(shown):
        txt = "<%s>" % argtext(pos[min(i, len(pos) - 1)])
        out.append(txt if i < a["min"] else "[%s]" % txt)
    if pos and (a["max"] is None or a["max"] > shown):
        out.append("...")
    for o in a["options"]:
        txt = "%s<%s>" % (o["key"], argtext(o))
        out.append(txt if o["required"] else "[%s]" % txt)
    if d["require"]:
        out.append("[require]")
    return " ".join(out) + {"forbidden": ";", "required": " { ... }", "optional": " [{ ... }];"}[d["block"]]

print("# Configuration reference")
print()
print("Generated file: do not edit. It is produced from the directive tables in the binary")
print("(`bastion --dump-schema`). Regenerate it with `./dev make gen-reference` (it runs")
print("`scripts/gen-config-reference.sh`) and commit the result; `test_reference_up_to_date`")
print("fails when it is stale.")
print()
print("`bastion -T` prints the effective configuration with environment variables expanded, so it")
print("can show secrets. Review its output before sharing it. Error messages echo up to 40 bytes")
print("of an offending value after expansion too, so an error about a secret-bearing argument can")
print("show part of the secret: review error output before pasting it into a bug report.")
print()
print("Contexts are the places a directive may appear. `global` is the top level of the file.")
print()
print("## Directives")
for d in dirs:
    title = d["name"] + (" " + d["subname"] if d["subname"] else "")
    print()
    print("### `%s`" % title)
    print()
    print("```nginx")
    print(syntax(d))
    print("```")
    print()
    print(d["doc"])
    print()
    print("- Contexts: " + ", ".join(d["contexts"]))
    if d["child_context"]:
        print("- Block context: " + d["child_context"])
    print("- Default: " + ("`%s`" % d["default"] if d["default"] is not None else "none"))
    print("- Repeatable: " + ("yes" if d["repeatable"] else "no"))
    if d["singleton"]:
        print("- Singleton block: at most once; when it is absent its children's defaults still apply")
    for o in d["args"]["options"]:
        print("- Option `%s`: %s%s" % (o["key"], argtext(o), ", required" if o["required"] else ""))
PY
mv "$out.new" "$out"
