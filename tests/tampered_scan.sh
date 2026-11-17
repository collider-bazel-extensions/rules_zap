#!/usr/bin/env bash
# Runs run_scan.sh against a copy of this test's runfiles (links only) in
# which one pinned ZAP add-on is removed or replaced by a corrupt file.
# Argv: <missing|corrupt> <add-on id> <run_scan.sh argv...>
set -euo pipefail
mode="$1"; id="$2"; shift 2
src="${RUNFILES_DIR:-$TEST_SRCDIR}"
copy="$TEST_TMPDIR/runfiles"
cp -a "$src" "$copy"
addon=$(cd "$copy" && compgen -G "*/addons/$id.zap" | head -1) \
    || { echo "FAIL: setup: no add-on $id in the runfiles" >&2; exit 1; }
rm -f "${copy:?}/$addon"
case "$mode" in
    missing) ;;
    corrupt) echo "not a zip" > "$copy/$addon" ;;
    *) echo "FAIL: bad mode $mode" >&2; exit 1 ;;
esac
echo "---- $mode: $addon"
RUNFILES_DIR="$copy" TEST_SRCDIR="$copy" exec "$copy/_main/tests/run_scan.sh" "$@"
