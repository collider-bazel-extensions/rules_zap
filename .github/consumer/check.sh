#!/usr/bin/env bash
# Consumer check against the commit's release archive (git archive honours
# .gitattributes export-ignore, as GitHub's tag tarballs do): the
# export-ignore'd directories are absent, @rules_zap//... loads for a
# consumer module, and the consumer runs the rules from outside:
#   - `bazel run @rules_zap//:zap -- -version` prints the pinned version;
#   - a zap_rules_config_test passes and a malformed rules_config fails
#     the build (validation action);
#   - a zap_api_scan_test scans a consumer-side server (python3's
#     http.server serving a static API; the host python3 is used here
#     only) with the network blocked.
# Usage: .github/consumer/check.sh <scratch dir>
set -euo pipefail
repo="$(cd "$(dirname "$0")/../.." && pwd)"
work="$1"
src="$work/rules_zap"
c="$work/consumer"
rm -rf "$work"; mkdir -p "$src" "$c/api"
git -C "$repo" archive HEAD | tar -x -C "$src"
for d in tests tools; do
    if [[ -e "$src/$d" ]]; then echo "FAIL: archive contains $d/" >&2; exit 1; fi
done
if [[ -f "$repo/.bazelversion" ]]; then cp "$repo/.bazelversion" "$c/"; fi
printf 'module(name = "consumer")\nbazel_dep(name = "rules_zap")\nlocal_path_override(module_name = "rules_zap", path = "%s")\n' "$src" > "$c/MODULE.bazel"

cat > "$c/BUILD.bazel" <<'B'
load("@rules_zap//:defs.bzl", "zap_api_scan_test", "zap_rules_config_test")

zap_api_scan_test(
    name = "api_scan_test",
    server = "server.sh",
    data = glob(["api/**"]),
    openapi = "openapi.json",
    rules_config = "zap-accepted.yaml",
    fail_on = "High",
)

zap_rules_config_test(
    name = "rules_config_test",
    src = "zap-accepted.yaml",
)

zap_api_scan_test(
    name = "malformed",
    server = "server.sh",
    openapi_path = "/openapi.json",
    rules_config = "malformed.yaml",
    tags = ["manual"],
)
B
cat > "$c/server.sh" <<'S'
#!/usr/bin/env bash
# A static JSON API: python3's http.server over api/ on 127.0.0.1:$PORT.
cd "$(dirname "$0")"
exec python3 -m http.server "$PORT" --bind 127.0.0.1 --directory api
S
chmod +x "$c/server.sh"
echo '{"message": "hello"}' > "$c/api/hello.json"
cat > "$c/openapi.json" <<'O'
{"openapi": "3.0.3", "info": {"title": "consumer", "version": "1"},
 "paths": {"/hello.json": {"get": {"responses": {"200": {"description": "hi"}}}}}}
O
cat > "$c/zap-accepted.yaml" <<'Y'
accept:
  - id: 10036
    reason: http.server's Server header names its version; this is a test fixture.
Y
printf 'accept:\n  - id: 10021\n' > "$c/malformed.yaml"

cd "$c"
bazel mod deps >/dev/null
n="$(bazel query @rules_zap//... 2>/dev/null | wc -l)"
echo "ok: @rules_zap//... loads from the archive ($n targets)"
v="$(bazel run @rules_zap//:zap -- -version 2>/dev/null | tail -1)"
[[ "$v" == "2.17.0" ]] || { echo "FAIL: bazel run @rules_zap//:zap -- -version printed '$v'" >&2; exit 1; }
echo "ok: bazel run @rules_zap//:zap -- -version: $v"
if bazel build //:malformed 2> build.log; then echo "FAIL: //:malformed built" >&2; exit 1; fi
grep -qF "malformed.yaml:2: accept[0] (id 10021): missing 'reason'" build.log || { cat build.log; echo "FAIL: no missing-reason error" >&2; exit 1; }
echo "ok: a rules_config without a reason fails the build"
bazel test //:api_scan_test //:rules_config_test --test_output=errors
grep -h "ZAP scanned" bazel-testlogs/api_scan_test/test.log

# The root module's zap.version() wins; an unpinned version needs its sha256.
cp MODULE.bazel MODULE.bazel.orig
printf 'zap = use_extension("@rules_zap//:extensions.bzl", "zap")\nzap.version(version = "9.9.9")\n' >> MODULE.bazel
if bazel build @rules_zap//:zap 2> build.log; then echo "FAIL: an unpinned zap.version() built" >&2; exit 1; fi
grep -qF 'zap.version(version = "9.9.9") is not pinned. Pinned: 2.17.0.' build.log || { cat build.log; echo "FAIL: no unpinned-version error" >&2; exit 1; }
echo "ok: an unpinned zap.version() without sha256 fails, naming the pinned versions"
mv MODULE.bazel.orig MODULE.bazel
echo "PASS: consumer of the release archive"
