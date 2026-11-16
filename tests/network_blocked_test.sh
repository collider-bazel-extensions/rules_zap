#!/usr/bin/env bash
# Runs with the same tag as every scan (block-network): outbound connections
# fail. (Loopback works: every scan talks to its server over it.) If this
# fails, the scans aren't proven offline.
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
for target in 140.82.112.3/443 1.1.1.1/443 8.8.8.8/53; do
    if timeout 5 bash -c "exec 3<>/dev/tcp/$target" 2>/dev/null; then
        fail "connected to $target: the network isn't blocked"
    fi
    echo "ok: no route to $target"
done
if timeout 5 bash -c 'exec 3<>/dev/tcp/github.com/443' 2>/dev/null; then
    fail "resolved and connected to github.com"
fi
echo "ok: github.com unreachable"
echo PASS
