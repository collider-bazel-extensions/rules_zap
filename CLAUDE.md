# rules_zap

Bazel rules for OWASP ZAP API scans:
- `zap_api_scan_test`: start a server on a free port, scan its OpenAPI API with ZAP's Automation Framework, offline, and fail on unaccepted alerts at or above `fail_on`;
- `rules_config` accepted alerts (reason required, optional expiry), checked at build time; `zap_rules_config_test`;
- `@rules_zap//:zap`: `bazel run` the pinned ZAP.

See DESIGN.md.

## Commit requirements

- All tests must pass before any commit with code changes: `bazel test //tests/...`, plus `bazel build //tests:malformed_config_scan` failing with "missing 'reason'", plus `.github/consumer/check.sh <scratch dir>`.
- All documentation (`README.md`, `DESIGN.md`, `CLAUDE.md`) must be updated to reflect any code changes before committing: new rules, changed attributes, new public API surface, behaviour changes.
- Never leave ZAP or a fixture server running. The driver stops both (by PID, through `ProcessHandle`); if you start one by hand, stop it by PID. Never use `pkill -f`.

## Repo layout

```
rules_zap/
├── MODULE.bazel              # module; rules_java remote JDK 21 repos; zap extension → @zap
├── .bazelrc                  # tests: --sandbox_default_allow_network=false
├── .gitattributes            # tests/ and tools/ export-ignore: the release archive loads for consumers
├── .github/consumer/check.sh # CI: git archive HEAD as a consumer (query, run //:zap, build failure, a scan)
├── BUILD.bazel               # //:zap (zap_cli)
├── defs.bzl                  # public API re-exports
├── extensions.bzl            # zap.version(version, url, sha256, strip_prefix, addons, addon_sha256)
├── private/
│   ├── versions.bzl          # generated: DEFAULT_VERSION, ZAP_VERSIONS (archive + add-on pins)
│   ├── repositories.bzl      # @zap: Core zip minus plugin/, + addons/<id>.zap; zap_distribution
│   ├── distribution.bzl, providers.bzl   # ZapInfo(version, jar, install, addons)
│   ├── common.bzl            # runfiles paths, shell quoting, the launcher template
│   ├── driver.bzl            # compiles ZapScan.java with the pinned JDK's javac → driver.jar
│   ├── ZapScan.java          # driver: check-config, config-test, scan, judge, cli
│   ├── test.bzl              # zap_api_scan_test (rule + macro adding block-network), zap_rules_config_test
│   ├── cli.bzl               # zap_cli
│   └── BUILD.bazel           # :jdk (select over @remotejdk21_*), :driver
├── tools/update_versions.sh  # re-pin ZAP + add-ons (dependency closure) from upstream; --check
└── tests/
    ├── BUILD.bazel, analysis_tests.bzl, run_scan.sh
    ├── fixtures.bzl          # java_source_server (fixtures on the pinned JDK), scan_check_test, zap_judge
    ├── fixtures/             # FixtureServer.java (vulnerable | clean), openapi.yaml, dies.sh
    ├── testdata/             # rules_config files (good, bad, expired), report.xml + judge*.yaml
    └── zap_cli_test.sh, version_test.sh, checksums_test.sh, network_blocked_test.sh
```

## Key concepts

- **Pins.** `@zap` = `ZAP_<v>_Core.zip` (its `plugin/` deleted) + 11 add-ons from `ZapVersions-<major.minor>.xml` at a zap-admin commit, all by SHA-256. The add-on roots are openapi, automation, ascanrules, pscanrules, reports and callhome (mandatory in 2.17), plus their dependency closure. Keep `DEFAULT_VERSION` and `zap.version()` in `MODULE.bazel` equal (`//tests:version_test`).
- **JDK.** `//private:jdk` selects `@remotejdk21_<platform>//:jdk` directly (no Java toolchain resolution, no java_tools). The driver is compiled with that JDK's `javac` and runs on it; ZAP runs on it too.
- **Scan.** Fresh `$TEST_TMPDIR/zap-home` with `plugin/` symlinks to the add-ons. Free loopback port → `PORT`/`HOST` → the server, waited for (TCP, or `ready_path`). Then a generated plan: openapi (`apiFile` or `apiUrl`, `targetUrl` = the server), passiveScan-wait, activeScan (strength low, 8 threads, 10106 off), passiveScan-wait, xml/json/html reports. Then `zap -silent -cmd -autorun` with update/add-on `-config`s off.
- **Verdict.** Per alert instance: accepted if an entry's `id` = plugin id or alert ref and its `url` regex (if any) is found. An alert fails if its risk ≥ `fail_on` and an instance is unaccepted. Confidence 0 (False Positive) is ignored. Exit codes: 0 pass, 1 alerts/expired, 2 errors (bad config, server died/not ready, plan failed, no URLs imported).
- **rules_config.** A strict YAML subset (`accept:` + flat mappings; keys id, url, reason, expires). All errors are reported at once with file:line. It is a validation action of each scan test, and is also checked at test start (where expiry is applied).
- **Offline.** `block-network` (macro) + `.bazelrc`. `//tests:network_blocked_test` proves the sandbox has no route out.

## Public API

```python
load("@rules_zap//:defs.bzl",
    "zap_api_scan_test",      # server, openapi | openapi_path, rules_config, fail_on, server_args, server_env,
                              # data, ready_path, ready_timeout, strength, threads, max_scan_minutes, jvm_flags, env
    "zap_rules_config_test",  # src, expect_error (Java regex; empty = must pass)
    "zap_cli",                # zap (default @zap//:zap); //:zap is one
    "ZapInfo",
)
```

## Development

```sh
bazel test //tests/...
bazel build //tests:malformed_config_scan        # must fail: missing 'reason'
.github/consumer/check.sh /tmp/rules_zap-consumer
bazel run //:zap -- -version
tools/update_versions.sh 2.17.0 --index-commit <sha> --check    # verify the pins against upstream
tools/update_versions.sh                          # re-pin to the latest release and index
```

### Test results (last full run: 2026-11-16)

All 34 test targets pass on Linux x86_64 (16 cores; ZAP 2.17.0, JDK 21.0.9) in 61 s wall time (`bazel test //tests/... --nocache_test_results`).
- **Scan durations.**
  - Alone, a scan test takes about 32–37 s: ZAP start-up about 10 s, the active scan 17–19 s, shutdown about 5 s.
  - With the whole suite in parallel, it takes 53–56 s (active scan 20–23 s).
  - At `strength = "medium"` alone it takes 45 s; at medium with 2 threads, 53 s.
- **Repeat runs.** Each scan test was run 3× in parallel, and the vulnerable scan 12× more. The verdicts never changed. One passive alert (10020-1) was missing once (see Known limitations), and the assertions were relaxed accordingly.
- **Build-time failure:** `bazel build //tests:malformed_config_scan` fails with `missing_reason.yaml:2: accept[0] (id 40012): missing 'reason'`.
- **Consumer:** `.github/consumer/check.sh` passes on the commit's `git archive`. It checks:
  - `tests/` and `tools/` are absent;
  - `@rules_zap//...` loads;
  - `bazel run @rules_zap//:zap -- -version` prints 2.17.0;
  - a missing reason fails the build;
  - a `zap_api_scan_test` of a consumer-side server passes with an accepted alert;
  - an unpinned `zap.version()` fails, naming the pinned versions.
- **Offline:**
  - Every scan runs under `linux-sandbox` with `block-network` (and `--sandbox_default_allow_network=false`).
  - `//tests:network_blocked_test` passes there. As a negative control, it fails with `--strategy=TestRunner=local`.
  - `zap.log` names no host but 127.0.0.1.
- **Pins:** `tools/update_versions.sh 2.17.0 --index-commit f48199b… --check` re-downloads everything and finds `versions.bzl` up to date.

| Test target | What it verifies | Result |
|---|---|---|
| `//tests:clean_scan_test` | the clean fixture (escaped JSON, security headers) has no alerts even at `fail_on = "Low"` | PASSED |
| `//tests:vulnerable_scan_fails_test` | the vulnerable fixture fails on reflected XSS (40012, High) via `openapi_path`. Lower alerts are listed, not failing; 10106 is off; reports, logs, plan and JUnit are written; the server is stopped | PASSED |
| `//tests:accepted_alert_scan_test` | the same XSS accepted by plugin id + URL with a reason: the scan passes and lists the reason | PASSED |
| `//tests:expired_scan_test` | an expired accepted alert fails before ZAP starts, naming file, line, date and reason | PASSED |
| `//tests:dead_server_scan_test` | a server that exits at once: error with its status and log, no hang | PASSED |
| `//tests:judge_*_test` (4) | the verdict on a checked-in report: plugin id vs alert ref, per-instance URL, partial acceptance, False Positive ignored, each `fail_on`, stale entries, JUnit | PASSED |
| `//tests:config_*_test` (11) | `zap_rules_config_test`: good configs pass; missing/blank reason, unknown key, bad id, bad regex, bad date, wrong top level, duplicate, flow YAML fail with their messages | PASSED |
| `//tests:zap_cli_test` | `//:zap -version` prints 2.17.0 offline and leaves no home behind | PASSED |
| `//tests:network_blocked_test` | the scans' sandbox has no route out | PASSED |
| `//tests:version_test`, `//tests:checksums_test` | pins well-formed; DEFAULT_VERSION = MODULE.bazel; every required add-on pinned | PASSED |
| `//tests:analysis_tests_*` (10) | runfiles (driver, ZAP jar, 11 add-ons, JDK), validation action, launcher arguments, attribute errors | PASSED |

## Known limitations

- **Flaky passive alerts.** Passive alerts are found by ZAP's passive scanner, and one was occasionally missing: 10020-1 in 1 of 15 runs of the vulnerable scan, with 9 ZAPs in parallel on 16 cores. Active-scan findings (the XSS) were stable in every run. A missing alert makes a test pass that should have failed (a false negative), never fail spuriously. The live-scan tests therefore assert only stable facts; `//tests:judge_*` covers the verdict exactly.
- **Expiry and caching.** `expires` is checked at test time, and a cached pass isn't re-run.
- **Platforms.** Only Linux x86_64 is tested. No authentication support; no GraphQL/SOAP.
