#!/usr/bin/env bash
# Regenerates private/versions.bzl: the ZAP release archive and the add-ons
# the API scan needs, each pinned by SHA-256.
#
#   tools/update_versions.sh [<zap version>] [--index-commit <sha>] [--check]
#
# - ZAP: <version> defaults to the latest zaproxy/zaproxy release. The
#   archive is ZAP_<version>_Core.zip (the core cross-platform package); its
#   sha256 is the release asset's published digest (the release notes'
#   checksum table), and the downloaded file must hash to it.
# - Add-ons: the roots below plus their dependency closure, from ZAP's
#   marketplace index ZapVersions-<major>.<minor>.xml in zaproxy/zap-admin,
#   read at a pinned commit (default: the latest commit touching the file).
#   Each add-on's url and SHA-256 come from the index; every file is
#   downloaded and must hash to it. An add-on whose not-before-version is
#   newer than <version> is an error.
# - --check: regenerate into a temp file and diff against the checked-in
#   one (exit 1 on a difference), downloading everything again.
#
# Needs curl, python3 and sha256sum. Set GITHUB_TOKEN to raise the GitHub API
# rate limit.
set -euo pipefail

# The add-ons the scan uses directly. Their dependencies are added from the
# index. callhome is mandatory: ZAP 2.17 refuses to start without it (it
# stays silent under -silent).
ROOTS=(openapi automation ascanrules pscanrules reports callhome)

repo="$(cd "$(dirname "$0")/.." && pwd)"
out="$repo/private/versions.bzl"
version=""
index_commit=""
check=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --check) check=1 ;;
        --index-commit) index_commit="$2"; shift ;;
        -*) echo "unknown flag: $1" >&2; exit 2 ;;
        *) version="$1" ;;
    esac
    shift
done

auth=()
if [[ -n "${GITHUB_TOKEN:-}" ]]; then auth=(-H "Authorization: Bearer $GITHUB_TOKEN"); fi
api() { curl -sSfL "${auth[@]}" -H "Accept: application/vnd.github+json" "https://api.github.com/$1"; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir "$work/dl"

if [[ -z "$version" ]]; then
    version="$(api repos/zaproxy/zaproxy/releases/latest | python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"].lstrip("v"))')"
fi
minor="${version%.*}"
asset="ZAP_${version}_Core.zip"
url="https://github.com/zaproxy/zaproxy/releases/download/v${version}/${asset}"

api "repos/zaproxy/zaproxy/releases/tags/v${version}" > "$work/release.json"
sha="$(python3 - "$work/release.json" "$asset" <<'EOF'
import json, sys
rel = json.load(open(sys.argv[1]))
for a in rel["assets"]:
    if a["name"] == sys.argv[2]:
        d = a.get("digest") or ""
        if not d.startswith("sha256:"):
            sys.exit("no sha256 digest published for " + sys.argv[2])
        print(d[len("sha256:"):])
        break
else:
    sys.exit("release has no asset " + sys.argv[2])
EOF
)"
# The release notes carry the same table; they must agree.
if ! python3 -c 'import json,sys; sys.exit(0 if sys.argv[2] in json.load(open(sys.argv[1]))["body"] else 1)' "$work/release.json" "$sha"; then
    echo "the release notes' checksum table doesn't list $sha for $asset" >&2
    exit 1
fi
echo "ZAP $version: $asset $sha" >&2
curl -sSfL -o "$work/dl/$asset" "$url"
echo "$sha  $work/dl/$asset" | sha256sum -c --quiet - >&2
prefix="$(python3 -c 'import sys, zipfile; print(zipfile.ZipFile(sys.argv[1]).namelist()[0].split("/")[0])' "$work/dl/$asset")"

if [[ -z "$index_commit" ]]; then
    index_commit="$(api "repos/zaproxy/zap-admin/commits?path=ZapVersions-${minor}.xml&per_page=1" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["sha"])')"
fi
index_url="https://raw.githubusercontent.com/zaproxy/zap-admin/${index_commit}/ZapVersions-${minor}.xml"
curl -sSfL -o "$work/index.xml" "$index_url"
echo "index: $index_url" >&2

python3 - "$work/index.xml" "$version" "${ROOTS[@]}" > "$work/addons.tsv" <<'EOF'
import sys
import xml.etree.ElementTree as ET

index, version, roots = sys.argv[1], sys.argv[2], sys.argv[3:]
addons = {}
for el in ET.parse(index).getroot():
    if el.tag.startswith("addon_"):
        addons[el.tag[len("addon_"):]] = el

def vkey(v):
    return tuple(int(p) for p in v.split("."))

seen, todo = [], list(roots)
while todo:
    aid = todo.pop(0)
    if aid in seen:
        continue
    if aid not in addons:
        sys.exit("add-on %r is not in the index" % aid)
    seen.append(aid)
    el = addons[aid]
    for dep in el.findall("dependencies/addons/addon"):
        todo.append(dep.findtext("id").strip())
    nbv = (el.findtext("not-before-version") or "").strip()
    if nbv and vkey(nbv) > vkey(version):
        sys.exit("add-on %s needs ZAP >= %s" % (aid, nbv))
    nfv = (el.findtext("not-from-version") or "").strip()
    if nfv and vkey(nfv) <= vkey(version):
        sys.exit("add-on %s doesn't run on ZAP >= %s" % (aid, nfv))
for aid in sorted(seen):
    el = addons[aid]
    h = el.findtext("hash").strip()
    if not h.startswith("SHA-256:"):
        sys.exit("add-on %s: unexpected hash %s" % (aid, h))
    print("\t".join([aid, el.findtext("version").strip(), el.findtext("status").strip(),
                     el.findtext("url").strip(), h[len("SHA-256:"):]]))
EOF

while IFS=$'\t' read -r aid _ _ aurl asha; do
    curl -sSfL -o "$work/dl/$aid.zap" "$aurl"
    echo "$asha  $work/dl/$aid.zap" | sha256sum -c --quiet - >&2
    echo "  $aid ok" >&2
done < "$work/addons.tsv"

python3 - "$version" "$url" "$sha" "$prefix" "$index_url" "$work/addons.tsv" > "$work/versions.bzl" <<'EOF'
import sys
version, url, sha, prefix, index_url, tsv = sys.argv[1:]
rows = [l.rstrip("\n").split("\t") for l in open(tsv) if l.strip()]
o = []
o.append('"""Generated by tools/update_versions.sh — do not edit by hand.')
o.append("")
o.append("Schema:")
o.append("")
o.append("    ZAP_VERSIONS = {")
o.append('        "<version>": {')
o.append('            "url": "<ZAP_<version>_Core.zip release asset>",')
o.append('            "sha256": "<its published SHA-256>",')
o.append('            "strip_prefix": "<the archive\'s top directory>",')
o.append('            "addon_index": "<ZapVersions-<major.minor>.xml at a zap-admin commit>",')
o.append('            "addons": {')
o.append('                "<add-on id>": {"version", "status", "url", "sha256"},  # from the index')
o.append("            },")
o.append("        },")
o.append("    }")
o.append('"""')
o.append("")
o.append('DEFAULT_VERSION = "%s"' % version)
o.append("")
o.append("ZAP_VERSIONS = {")
o.append('    "%s": {' % version)
o.append('        "url": "%s",' % url)
o.append('        "sha256": "%s",' % sha)
o.append('        "strip_prefix": "%s",' % prefix)
o.append('        "addon_index": "%s",' % index_url)
o.append('        "addons": {')
for aid, ver, status, aurl, asha in rows:
    o.append('            "%s": {' % aid)
    o.append('                "version": "%s",' % ver)
    o.append('                "status": "%s",' % status)
    o.append('                "url": "%s",' % aurl)
    o.append('                "sha256": "%s",' % asha)
    o.append("            },")
o.append("        },")
o.append("    },")
o.append("}")
print("\n".join(o))
EOF

if [[ "$check" == 1 ]]; then
    if diff -u "$out" "$work/versions.bzl"; then
        echo "versions.bzl is up to date" >&2
    else
        echo "versions.bzl differs from a fresh generation (above)" >&2
        exit 1
    fi
else
    cp "$work/versions.bzl" "$out"
    echo "wrote $out" >&2
fi
