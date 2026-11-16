#!/usr/bin/env bash
# The pins are well-formed: every url is https on the expected host, every
# sha256 is 64 hex digits, and every required add-on is pinned.
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
# The pins proper: everything after the docstring's schema.
v="$TEST_TMPDIR/pins.bzl"
sed -n '/^ZAP_VERSIONS = {/,$p' "$TEST_SRCDIR/_main/private/versions.bzl" > "$v"
n=0
while read -r url; do
    [[ "$url" =~ ^https://github\.com/zaproxy/(zaproxy|zap-extensions)/releases/download/ ]] || fail "unexpected url $url"
    n=$((n + 1))
done < <(sed -n 's/^ *"url": "\(.*\)",$/\1/p' "$v")
while read -r sha; do
    [[ "$sha" =~ ^[0-9a-f]{64}$ ]] || fail "bad sha256 $sha"
done < <(sed -n 's/^ *"sha256": "\(.*\)",$/\1/p' "$v")
[[ "$(grep -c '"sha256":' "$v")" == "$n" ]] || fail "urls and sha256s don't pair up"
grep -q '"addon_index": "https://raw.githubusercontent.com/zaproxy/zap-admin/[0-9a-f]\{40\}/ZapVersions-' "$v" || fail "addon_index isn't pinned to a commit"
for id in openapi automation ascanrules pscanrules pscan reports commonlib network oast database callhome; do
    grep -q "^            \"$id\": {" "$v" || fail "add-on $id isn't pinned"
    grep -q "download/$id-v[^/]*/$id-[a-z]*-[0-9.]*\.zap\"" "$v" || fail "add-on $id's url doesn't name it"
done
echo "PASS: $n pins"
