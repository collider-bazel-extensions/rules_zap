#!/usr/bin/env bash
# Runs a (manual) zap_api_scan_test's executable as a nested test and checks
# its exit status, output and outputs directory.
#
# Argv: <scan executable (rootpath)> <expected exit status> <check>...
#   +TEXT   TEXT (fixed string, may span lines) appears in the output
#   -TEXT   TEXT doesn't appear
#   @FILE   FILE exists in the scan's outputs
#   =FILE:TEXT  FILE in the outputs contains TEXT
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }

scan="$TEST_SRCDIR/_main/$1"
want="$2"
shift 2

inner="$TEST_TMPDIR/inner"
out="${TEST_UNDECLARED_OUTPUTS_DIR:-$TEST_TMPDIR/outputs}/inner"
mkdir -p "$inner" "$out"
rc=0
log="$(TEST_TMPDIR="$inner" TEST_UNDECLARED_OUTPUTS_DIR="$out" XML_OUTPUT_FILE="$inner/junit.xml" \
    "$scan" 2>&1)" || rc=$?
echo "$log"
echo "---- checks (exit status $rc)"
[[ "$rc" == "$want" ]] || fail "exit status $rc, want $want"
for c in "$@"; do
    case "$c" in
        +*) [[ "$log" == *"${c:1}"* ]] || fail "output lacks: ${c:1}" ;;
        -*) if [[ "$log" == *"${c:1}"* ]]; then fail "output has: ${c:1}"; fi ;;
        @*) [[ -s "$out/${c:1}" ]] || fail "no ${c:1} in the outputs" ;;
        =*) f="${c:1}"; f="${f%%:*}"; t="${c#*:}"
            [[ -f "$out/$f" || "$f" == junit.xml ]] || fail "no $f in the outputs"
            src="$out/$f"; [[ "$f" == junit.xml ]] && src="$inner/junit.xml"
            grep -qF -- "$t" "$src" || fail "$f lacks: $t" ;;
        *) fail "bad check $c" ;;
    esac
    echo "ok: $c"
done

# Nothing left running: the server's port no longer accepts connections.
port="$(sed -n 's|.*server up at http://127.0.0.1:\([0-9]*\).*|\1|p' <<<"$log" | head -1)"
if [[ -n "$port" ]]; then
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
        fail "the server still listens on port $port after the scan"
    fi
    echo "ok: the server (port $port) is stopped"
fi
echo PASS
