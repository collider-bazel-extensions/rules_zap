#!/usr/bin/env bash
# //:zap runs the pinned ZAP (offline: this test is block-network) with a
# fresh home, loads exactly the pinned add-ons, and leaves no home behind.
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
zap="$TEST_SRCDIR/_main/$1"
export TMPDIR="$TEST_TMPDIR/tmp"
mkdir -p "$TMPDIR"
out="$("$zap" -version 2>&1)" || fail "exit status $?: $out"
echo "$out"
grep -qx '2.17.0' <<<"$out" || fail "no version line 2.17.0"
[[ -z "$(ls -A "$TMPDIR")" ]] || fail "left behind: $(ls -A "$TMPDIR")"
echo PASS
