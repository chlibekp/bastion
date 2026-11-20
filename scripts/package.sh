#!/usr/bin/env bash
# Builds the release artifacts for this container's architecture. Runs inside the release image
# (Alpine, musl), normally through scripts/build-release.sh:
#   ./dev scripts/package.sh <version> <git-rev> <outdir> BUILD=release
# (the trailing BUILD=release only makes ./dev pick the Alpine image).
#
# Produces in <outdir>: bastion-<v>-linux-<arch> (static PIE), bastion_<v>-1_<arch>.deb,
# bastion-<v>-1.<rpmarch>.rpm, bastion-<v>-linux-<arch>.spdx.json and SHA256SUMS.
set -euo pipefail

[ $# -ge 3 ] || { echo "usage: scripts/package.sh <version> <git-rev|auto> <outdir> [BUILD=release]" >&2; exit 2; }
version=$1 rev=$2 out=$3
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "package: version must be X.Y.Z, got '$version'" >&2; exit 2; }
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

# auto: read HEAD from .git without git (the release image has none).
if [ "$rev" = auto ]; then
	rev=unknown
	if [ -f .git/HEAD ]; then
		head=$(cat .git/HEAD)
		case $head in
			"ref: "*)
				ref=${head#ref: }
				if [ -f ".git/$ref" ]; then
					rev=$(cat ".git/$ref")
				elif [ -f .git/packed-refs ]; then
					rev=$(awk -v r="$ref" '$2 == r { print $1 }' .git/packed-refs)
				fi ;;
			*) rev=$head ;;
		esac
		rev=${rev:0:12}
	fi
fi
[[ $rev =~ ^[0-9a-f]{7,40}$|^unknown$ ]] || { echo "package: bad git revision '$rev'" >&2; exit 2; }

case $(uname -m) in
	x86_64) arch=amd64 ;;
	aarch64) arch=arm64 ;;
	*) echo "package: unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac

# check-release builds build/release/bastion and proves it has no test seams.
make check-release BUILD=release VERSION="$version" GIT_REV="$rev"
bin=build/release/bastion

mkdir -p "$out"
name=bastion-$version-linux-$arch
# Debug info goes; the symbol table stays for the crash handler's backtraces.
strip --strip-debug -o "$out/$name" "$bin"
chmod 0755 "$out/$name"

mkdir -p build/pkg
cp "$out/$name" build/pkg/bastion
for fmt in deb rpm; do
	BST_PKG_VERSION=$version BST_PKG_ARCH=$arch nfpm package --config packaging/nfpm.yaml --packager "$fmt" --target "$out/"
done

# SPDX 2.3 SBOM: the binary and every library statically linked into it, at its pinned version
# and source hash (deps/versions.env).
python3 - "$out/$name.spdx.json" "$name" "$version" "$rev" <<'PY'
import hashlib, json, sys, datetime, re
path, name, version, rev = sys.argv[1:5]
env = {}
for line in open("deps/versions.env"):
    m = re.match(r"^([A-Z0-9_]+)=(.*)$", line.strip())
    if m:
        env[m.group(1)] = m.group(2).strip('"')
libs = sorted({k[:-len("_VERSION")] for k in env if k.endswith("_VERSION")})
binsha = hashlib.sha256(open(path.replace(".spdx.json", ""), "rb").read()).hexdigest()
pkgs = [{
    "SPDXID": "SPDXRef-bastion", "name": "bastion", "versionInfo": f"{version}+git.{rev}",
    "downloadLocation": "NOASSERTION", "licenseConcluded": "MIT", "licenseDeclared": "MIT",
    "copyrightText": "NOASSERTION", "filesAnalyzed": False,
    "checksums": [{"algorithm": "SHA256", "checksumValue": binsha}],
}]
rels = [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-bastion"}]
for lib in libs:
    sid = "SPDXRef-" + lib.lower()
    p = {"SPDXID": sid, "name": lib.lower(), "versionInfo": env[f"{lib}_VERSION"],
         "downloadLocation": env.get(f"{lib}_URL", "NOASSERTION").replace("${" + lib + "_VERSION}", env[f"{lib}_VERSION"]),
         "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION",
         "copyrightText": "NOASSERTION", "filesAnalyzed": False}
    if env.get(f"{lib}_SHA256"):
        p["checksums"] = [{"algorithm": "SHA256", "checksumValue": env[f"{lib}_SHA256"]}]
    pkgs.append(p)
    rels.append({"spdxElementId": "SPDXRef-bastion", "relationshipType": "STATIC_LINK", "relatedSpdxElement": sid})
doc = {
    "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
    "name": name, "documentNamespace": f"https://example.invalid/spdx/{name}-{rev}",
    "creationInfo": {"created": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                     "creators": ["Tool: bastion scripts/package.sh"]},
    "packages": pkgs, "relationships": rels,
}
json.dump(doc, open(path, "w"), indent=1)
PY

# SHA256SUMS covers every artifact of every architecture built into this directory.
(cd "$out" && sha256sum -- bastion-*-linux-* bastion_*.deb bastion-*.rpm 2>/dev/null | grep -v SHA256SUMS >SHA256SUMS.tmp \
	&& mv SHA256SUMS.tmp SHA256SUMS)
ls -l "$out"
