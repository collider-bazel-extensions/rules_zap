#!/usr/bin/env bash
# DEFAULT_VERSION in private/versions.bzl = the zap.version() tag in
# MODULE.bazel (the extension falls back to the former).
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
r="$TEST_SRCDIR/_main"
default="$(sed -n 's/^DEFAULT_VERSION = "\(.*\)"$/\1/p' "$r/private/versions.bzl")"
module="$(sed -n 's/^zap.version(version = "\(.*\)")$/\1/p' "$r/MODULE.bazel")"
[[ -n "$default" ]] || fail "no DEFAULT_VERSION"
[[ "$default" == "$module" ]] || fail "DEFAULT_VERSION $default != MODULE.bazel zap.version $module"
grep -q "^    \"$default\": {" "$r/private/versions.bzl" || fail "$default isn't pinned in ZAP_VERSIONS"
echo "PASS: $default"
