# rules_zap

Bazel rules for [OWASP ZAP](https://www.zaproxy.org/) API scans as ordinary Bazel tests. `zap_api_scan_test` starts your server on a free port inside the test and points ZAP's Automation Framework at its OpenAPI document. ZAP runs its passive and active scans, and the test fails on any alert at or above `fail_on` that you haven't accepted, with a reason, in a `rules_config` file.

- **Scans**
  - `zap_api_scan_test` — the API scan as a test. It runs in the sandbox with the network blocked, so it can run on every PR next to your other tests.
- **Accepted alerts**
  - `rules_config` — a YAML file listing accepted alerts. Each entry is matched by plugin id or alert reference, optionally by URL, and **must carry a reason**. An optional expiry date makes the test fail once it passes. The file is checked on every build.
  - `zap_rules_config_test` — a test that a `rules_config` passes that check, or fails it with an expected message.
- **The binary**
  - `@rules_zap//:zap` — `bazel run` the pinned ZAP with a fresh home and the pinned add-ons.

No host Java, no container. ZAP is the upstream release archive (ZAP 2.17.0, its Core cross-platform zip), and its add-ons are pinned individually from ZAP's marketplace index, all by SHA-256. It runs on rules_java's remote JDK 21. ZAP never updates or downloads anything at run time. Tested on Linux x86_64; the JDK is also selected for linux/aarch64 and macOS, untested.

## Installation

```python
bazel_dep(name = "rules_zap", version = "0.1.2")
archive_override(
    module_name = "rules_zap",
    urls = ["https://github.com/collider-bazel-extensions/rules_zap/archive/refs/tags/v0.1.2.tar.gz"],
    strip_prefix = "rules_zap-0.1.2",
    integrity = "sha256-xRPTXTFA7/klLY1CsA44t6sv884wP7OOg3mxZcRQ7Mo=",
)
```

The release archive (the tag tarball) leaves out `tests/` and `tools/`. `tests/` loads the dev-only `rules_shell`, so leaving it out lets `bazel query @rules_zap//...` work for consumers.

That's all. rules_zap creates `@zap` (ZAP and its add-ons) and fetches the JDK only for the platform a build needs. To pick another ZAP version, name it in your own `MODULE.bazel` (only the root module's tag counts):

```python
zap = use_extension("@rules_zap//:extensions.bzl", "zap")
zap.version(version = "2.17.0")
```

A version that rules_zap doesn't pin needs its own pins, taken from the release's published checksums:

```python
zap.version(
    version = "2.17.1",
    sha256 = "<sha256 of ZAP_2.17.1_Core.zip>",   # url defaults to the release asset
    # Optional: replace or add add-ons (url + sha256 from ZapVersions-2.17.xml).
    addons = {"ascanrules": "https://github.com/zaproxy/zap-extensions/releases/download/ascanrules-v85/ascanrules-release-85.zap"},
    addon_sha256 = {"ascanrules": "<sha256>"},
)
```

An unpinned version starts from the default version's add-ons; the `addons`/`addon_sha256` pairs replace or add to them by id.

## `zap_api_scan_test`

```python
load("@rules_zap//:defs.bzl", "zap_api_scan_test")

zap_api_scan_test(
    name = "api_zap_test",
    server = "//services/api:server",      # listens on 127.0.0.1:$PORT
    openapi = "//services/api:openapi.yaml",
    rules_config = "zap-accepted.yaml",    # optional
    fail_on = "Medium",                    # the default
)
```

The test does the following:
1. **Checks `rules_config`.** A malformed file or a missing reason fails the build, through a validation action. An entry past its `expires` date fails the test before ZAP starts.
2. **Starts `server`** with `PORT` set to a free port and `HOST=127.0.0.1`. `{port}` in `server_args` and `server_env` is replaced by the port. The server runs in the test's runfiles directory, so `$(rootpath ...)` arguments over `data` resolve. The test waits until the port accepts connections (or `GET <ready_path>` answers below 500), up to `ready_timeout` seconds. If the server exits first, the test says so and shows its log.
3. **Runs ZAP's Automation Framework**, with a fresh home directory under `$TEST_TMPDIR`. The plan does the following:
   - imports the OpenAPI document, with its server URL replaced by the test server's. The document comes from `openapi` (a file) or from `openapi_path` (fetched from the server, e.g. `"/openapi.json"`);
   - waits for the passive scan;
   - runs the active scan;
   - writes the reports.

   If the import adds no URLs, the test fails rather than passing on an empty scan. A failed plan also fails the test, and so does a server that dies during the scan.
   The active scan must really run: a pinned add-on missing from the runfiles or unloadable by ZAP, an activeScan warning in the plan's output, or an active scan that sent no requests fails the test (exit 2), naming the cause, instead of reading like a clean result.
4. **Judges the alerts.** An alert fails the test when its risk is at or above `fail_on` and at least one of its instances isn't accepted by `rules_config`. Alerts that ZAP itself rates "False Positive" never count.

On failure the log shows the failing alerts, their URLs (without the random port), parameters and evidence, followed by a `rules_config` entry to copy:

```
zap_api_scan_test //tests:vulnerable_scan: ZAP scanned 3 URL(s) from the OpenAPI document in 35.8s (37.3s in all); 4 alert type(s) raised; failing at High and above.
FAIL: 1 alert(s) at or above High not accepted by rules_config:
  [High] 40012 Cross Site Scripting (Reflected) (confidence Medium)
      GET /api/greet?name=%3C%2Fp%3E%3CscrIpt%3Ealert%281%29%3B%3C%2FscRipt%3E%3Cp%3E  param: name
        evidence: </p><scrIpt>alert(1);</scRipt><p>
Below High (reported, not failing):
  [Medium] 10020-1 Missing Anti-clickjacking Header (1 instance(s))
  [Medium] 10038-1 Content Security Policy (CSP) Header Not Set (1 instance(s))
  [Low] 10021 X-Content-Type-Options Header Missing (3 instance(s))
Reports: zap-report.html, zap-report.json, zap-report.xml (and zap.log, server.log) in the test's outputs (bazel-testlogs/<package>/<name>/test.outputs/)
Fix the server, or, for a reviewed false positive, accept the alert in rules_config with a reason:
  accept:
    - id: 40012
      url: '/api/greet'
      reason: <why this is safe>
```

- **Reports:** these files go to the test's undeclared outputs (`bazel-testlogs/<pkg>/<name>/test.outputs/`):
  - ZAP's `zap-report.html`, `zap-report.json` and `zap-report.xml` (traditional templates), which list every alert, accepted or not;
  - `zap.log` and `zap-stdout.log`;
  - `server.log`;
  - the generated `zap-plan.yaml`.

  JUnit goes to `$XML_OUTPUT_FILE`, one test case per alert type.
- **Offline:** the macro adds the `block-network` tag. In Bazel's Linux sandbox the test then sees loopback only, which is all it needs. ZAP runs with `-silent` (no update check, news or telemetry) and with every update and add-on download turned off. It loads exactly the pinned add-ons and never changes its install. The sandbox enforces the tag; with `--spawn_strategy=local` nothing is blocked.
- **Clean-up:** the server and ZAP are stopped (TERM, then KILL) when the scan ends, when the test fails, and on Bazel's timeout signal.
- **HTTP Only Site** (10106) is turned off in the scan policy. It probes for HTTPS on the same host, and the server under test is plain HTTP on loopback by construction.

| Argument | Default | |
|---|---|---|
| `server` | | executable target (or executable script) to scan; listens on `127.0.0.1:$PORT` (required) |
| `openapi` | | the OpenAPI document (JSON or YAML) as a file |
| `openapi_path` | | instead of `openapi`: the path the server serves it on (`"/openapi.json"`) |
| `rules_config` | none | accepted alerts (below) |
| `fail_on` | `"Medium"` | lowest failing risk: `"High"`, `"Medium"`, `"Low"` or `"Informational"` |
| `server_args` | `[]` | server arguments; `{port}`, `$(rootpath)` over `data` |
| `server_env` | `{}` | extra server environment; same expansion |
| `data` | `[]` | runfiles for the server |
| `ready_path` | TCP check | `GET` path that must answer < 500 before the scan |
| `ready_timeout` | `60` | seconds to wait for the server |
| `strength` | `"low"` | active scan attack strength: `low`, `medium` (ZAP's default), `high`, `insane` |
| `threads` | `8` | active scan threads against the server |
| `max_scan_minutes` | `10` | cap on the active scan (ZAP's `maxScanDurationInMins`) |
| `jvm_flags` | `["-Xmx1g"]` | JVM flags for ZAP |
| `env` | `{}` | test environment |
| `size` | `"medium"` | test size (300 s timeout) |

Exactly one of `openapi` and `openapi_path` is required. The defaults (`strength = "low"`, 8 threads) are tuned for test time. Against the fixture API (two operations) a whole test takes about 35 s. That breaks down as about 10 s of ZAP start-up, an 18 s active scan, and about 5 s for ZAP to shut down. The same scan at `strength = "medium"` takes 45 s, and with ZAP's default 2 threads 53 s. Both found the same alerts here; larger APIs scale with operations × parameters.

## `rules_config`: accepted alerts

```yaml
# zap-accepted.yaml
accept:
  - id: 10021                          # a plugin id: every alert of the rule
    reason: JSON-only API; browsers never render its responses.
  - id: 10020-1                        # an alert reference: one alert of a rule
    url: /internal/                    # optional: a regex searched in the instance's URL
    reason: Internal endpoints are never framed (SEC-1234).
    expires: 2027-03-31                # optional: fails the test from this date
```

- **Matching:** each alert instance (URL) is accepted by the first entry whose `id` equals the alert's plugin id or alert reference, and whose `url`, if any, is found in the instance's URL. The host and port are random per run, so match on the path. An alert fails only if an instance at or above `fail_on` is left unaccepted. Accepted alerts are listed in the log with their reasons. Entries that matched nothing get a note, so stale exceptions show up.
- **`reason` is required** and must not be blank. A false positive is then an explicit, reviewed exception rather than a silent filter.
- **`expires`** (`YYYY-MM-DD`) is optional. From that date the entry fails the test, before the scan, naming the file, line and reason, so it gets reviewed again. Bazel caches test results, so an unchanged test that passed stays passed until something it depends on changes. Run with `--nocache_test_results`, or tag the test `external`, if expiry must bite on a schedule.
- **Format:** a YAML subset. The top level is `accept:` and a list of flat mappings with plain or quoted scalar values (`accept: []` for none). The keys are `id`, `reason`, `url` and `expires`; anything else is an error. Comments are fine. Flow style (`{...}`), anchors and block scalars are refused. Quote values containing `: `; use single quotes for regexes with backslashes.
- **Checked on every build.** The check is a validation action of each `zap_api_scan_test` that uses the file, so a mistake fails `bazel build`. All errors are listed at once:

  ```
  rules_config tests/testdata/missing_reason.yaml: 1 error(s):
    tests/testdata/missing_reason.yaml:2: accept[0] (id 40012): missing 'reason': every accepted alert needs one, saying why it is safe to accept
  ```

  Other errors include unknown keys (`reasn`), bad ids (anything but `40012` or `10020-1`), invalid regexes, bad dates, duplicates, a wrong top-level key and unsupported YAML.

### `zap_rules_config_test`

```python
load("@rules_zap//:defs.bzl", "zap_rules_config_test")

zap_rules_config_test(name = "accepted_ok_test", src = "zap-accepted.yaml")   # must pass

zap_rules_config_test(
    name = "no_reason_is_caught_test",
    src = "testdata/no_reason.yaml",
    expect_error = "missing 'reason'",    # Java regex, searched in the error
)
```

## `@rules_zap//:zap`

```sh
bazel run @rules_zap//:zap -- -version
bazel run @rules_zap//:zap -- -autorun $PWD/plan.yaml
```

This runs the pinned ZAP on the pinned JDK, with the pinned add-ons and a throw-away home directory that is deleted on exit. `-silent` is always passed, and `-cmd` too unless you pass `-cmd` or `-daemon`. Relative paths resolve against your working directory.

## Limitations

- **Passive alerts can occasionally go missing.** Alerts found by ZAP's passive scanner (missing headers and the like) were occasionally absent from a run: one alert in 1 of 15 runs of rules_zap's fixture scan, under heavy parallel load. Active-scan findings were stable. A missing alert makes a scan pass that should have failed; it never fails one spuriously. See DESIGN.md.
- **No authentication:** no auth headers, users or login flows yet. The API must be scannable anonymously.
- **Expiry is checked when the test runs,** and Bazel caches passing results (see `expires` above).
- **Platforms:** only Linux x86_64 is tested.

## Pinned versions

| Component | Version | Source |
|---|---|---|
| ZAP | `2.17.0` | `ZAP_2.17.0_Core.zip`, zaproxy/zaproxy release (published SHA-256) |
| Add-ons | ascanrules 84, pscanrules 78, openapi 58, automation 0.62.0, reports 0.46.0, commonlib 1.44.0, network 0.33.0, oast 0.26.0, database 0.9.0, pscan 0.6.0, callhome 0.23.0 | `ZapVersions-2.17.xml` at a pinned zaproxy/zap-admin commit (URL + SHA-256 per add-on) |
| JDK | 21 (Zulu, rules_java 9.6.1's `remotejdk21_*`) | rules_java |

To re-pin, run `tools/update_versions.sh [<version>] [--index-commit <sha>]`. It downloads the ZAP archive and every add-on and verifies each against its published SHA-256. It resolves the add-ons' dependency closure from the index and rewrites `private/versions.bzl`; `--check` verifies the pins instead. Then bump `zap.version()` in `MODULE.bazel` (`//tests:version_test`).

## Development

```sh
bazel test //tests/...                           # unit, analysis and scan tests, network blocked
bazel build //tests:malformed_config_scan        # must fail: missing 'reason'
.github/consumer/check.sh /tmp/rules_zap-consumer   # the release archive, as a consumer
tools/update_versions.sh 2.17.0 --index-commit <sha> --check
```

See [DESIGN.md](DESIGN.md) for the design and trade-offs, and [CLAUDE.md](CLAUDE.md) for the repo layout and test inventory.

---

## Requesting a new rules package

Want Bazel rules for another tool or service?
[Request a rules package](https://github.com/collider-bazel-extensions/.github/issues/new?template=request-a-rules-package.yml).
The [organization page](https://github.com/collider-bazel-extensions) lists every package.

## License

[Apache License 2.0](LICENSE) (SPDX: `Apache-2.0`).
