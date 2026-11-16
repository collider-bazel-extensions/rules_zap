# rules_zap — design decisions

Bazel rules for [OWASP ZAP](https://www.zaproxy.org/) API scans, from the request in collider-bazel-extensions/.github#1. The rule there is a security scan as an ordinary, offline Bazel test: `zap_api_scan_test(name, server, openapi, rules_config, fail_on)`.

Its closest siblings are rules_gitleaks and rules_minio / rules_valkey:
- **from rules_gitleaks:** a pinned upstream binary, a config checked by a validation action, a `*_config_test` rule, and failure tests that run a manual target nested;
- **from rules_minio / rules_valkey:** a per-test process on a free port, stopped when the test ends;
- **from rules_argocd:** the extension's pin overrides (`version(sha256 = ...)` for unpinned versions).

## Decided

| # | Decision | Choice | Why |
|---|---|---|---|
| 1 | Bzlmod / WORKSPACE | **Bzlmod only**, module version 0.1.0. | Sibling family. |
| 2 | How ZAP runs | **The upstream release archive on rules_java's remote JDK 21.** No host Java, no container, no `zap-api-scan.py`. | The request; the container route needs a runtime and downloads add-ons at start. |
| 3 | Which archive | **`ZAP_<v>_Core.zip`** (108 MB), not `ZAP_<v>_Crossplatform.zip` (287 MB). Both are cross-platform: the jar and `lib/` are byte-identical, and they differ only in `plugin/` (about 20 vs 50 bundled add-ons). | The bundled add-ons are dropped anyway (#4), so the larger zip only adds 179 MB to download. `zap.version(url = ..., sha256 = ...)` can point at the Crossplatform zip. |
| 4 | Add-ons | **Pinned one by one from `ZapVersions-2.17.xml`** at a zap-admin commit, each by url + SHA-256. The archive's `plugin/` is deleted, so ZAP loads exactly the pinned set from its home's `plugin/`. | Deterministic: the pinned set is the whole set, and newer scan rules than the 2.17.0 bundle. Fewer add-ons also start faster. |
| 5 | The add-on set | Roots: openapi, automation, ascanrules, pscanrules, reports, callhome. Their dependency closure adds commonlib, network, oast, database and pscan, 11 in all. | callhome is mandatory: 2.17 refuses to start without it ("The mandatory add-on was not found: callhome"); `-silent` keeps it quiet. network carries ZAP's HTTP stack; oast and database are ascanrules' dependencies. |
| 6 | JDK | **21** (`@remotejdk21_<platform>//:jdk`, named directly through a `select`), not Java toolchain resolution. | ZAP 2.17 needs Java 17+ (`zap.sh` checks it) and runs on 21, the current LTS. Naming the repo directly means consumers set no `--java_runtime_version`, and rules_zap needs no java_tools. |
| 7 | The driver | **Java** (`private/ZapScan.java`), compiled by an action with the pinned JDK's own `javac`, and run on the same JDK. | Fully hermetic: no host Python (unlike rules_gitleaks), and nothing beyond what ZAP already needs. The report is XML, which the JDK parses. |
| 8 | `rules_config` format | **A strict YAML subset:** `accept:` and a list of flat `id` / `url` / `reason` / `expires` mappings. | Readable and comment-friendly, and valid YAML for editors, without a YAML library. Anything outside the subset is an error, never a silent misread. |
| 9 | Matching | `id` = plugin id (`40012`) **or** alert reference (`10020-1`); optional `url` regex, searched per instance. | ZAP's own identifiers. Per-instance matching means accepting one URL never hides the same alert on another. |
| 10 | Reasons | **Required, non-blank; checked at build time** (validation action) and again at test start. | The request: a false positive should be an explicit, reviewed exception. |
| 11 | Expiry | Optional `expires: YYYY-MM-DD`. The entry fails the test from that date, before ZAP starts. Checked at test time only. | An expiry forces a fresh review. A build action must not depend on the date (it would be cached), so expiry can't fail the build. |
| 12 | `fail_on` | ZAP's risk names: `High` / `Medium` (default) / `Low` / `Informational`. Alerts rated "False Positive" never count. | The names users see in ZAP's reports. Medium as the default matches what usually blocks a merge. |
| 13 | Scan policy | Default strength **low**, threshold medium, **8 threads**, `maxScanDurationInMins` 10, rule 10106 (HTTP Only Site) **off**. | Test time: an 18 s active scan versus 33 s at ZAP's defaults on the fixture, finding the same alerts. 10106 always fires on a plain-HTTP loopback server. |
| 14 | OpenAPI source | `openapi` (file, `apiFile`) **or** `openapi_path` (served by the server, `apiUrl`); `targetUrl` is always the test server. | Both shapes are common. The document's own `servers:` never matters. |
| 15 | Empty scans | **Fail** if the openapi job adds no URLs, if ZAP writes no report, or if the plan fails. | A security test that silently scans nothing is the worst outcome. |
| 16 | Offline | The macro adds `block-network`; the repo's `.bazelrc` adds `--sandbox_default_allow_network=false` for tests. ZAP runs with `-silent`, update/add-on `-config` switches off, `-Djava.net.useSystemProxies=false`, and `user.home` and `HOME` under `$TEST_TMPDIR`. | The request: it should run on every PR. |
| 17 | Fixture servers | **One Java file** (`com.sun.net.httpserver`) run from source (JEP 330) on the same pinned JDK, in two modes. | No extra download: rules_python or a Go SDK would each add one. |
| 18 | The vulnerability | **Reflected XSS** in an HTML response (40012, High), with `fail_on = "High"`. | ZAP's active scan finds it on every run, and it is the only High. The Medium/Low header alerts from the same fixture show the threshold working. |
| 19 | Test rule shape | A Starlark test rule wrapped in a legacy macro (which adds `block-network`), not an `sh_test` macro. | No public dependency on rules_shell. |
| 20 | Repo name | `@zap`, one ZAP per build. The root module's `zap.version()` wins, else rules_zap's own. | ZAP is platform-independent, so it needs no per-platform repos or toolchain. Same root/own rule as rules_gitleaks and rules_argocd. |

## The run, step by step

`ZapScan scan`:
1. Parses `rules_config` (the same code as the build-time check) and fails on expired entries.
2. Prepares `$TEST_TMPDIR/zap-home/`, fresh, holding only `plugin/<id>.zap` symlinks to the pinned add-ons in runfiles. Nothing is copied: the install and add-ons stay read-only in runfiles.
3. Takes a free loopback port from `ServerSocket(0)`. A small race with other processes on the host remains possible.
4. Starts the server, sending its output to `server.log`, and waits for it to be ready.
5. Writes `zap-plan.yaml` and runs `java -jar zap-<v>.jar -silent -installdir <runfiles install> -dir <home> -config ... -cmd -autorun <plan>`.
   - **Plan jobs:** `openapi`, `passiveScan-wait`, `activeScan`, `passiveScan-wait`, then three `report` jobs (`traditional-xml`, `-json`, `-html`).
   - **Exit codes:** 0 means the plan succeeded and 2 means it succeeded with warnings (`failOnWarning: false`). Anything else is a failed plan.
6. Checks that the server is still alive, then stops it.
7. Parses the XML report, judges the alerts, prints the summary and writes JUnit.

A shutdown hook stops ZAP's and the server's process trees: TERM, then KILL after 5 s. It runs on normal exit and on Bazel's SIGTERM at timeout. Processes are stopped by PID through `ProcessHandle`, never by name.

**Exit codes:**
- 0: pass;
- 1: alerts, or expired entries;
- 2: errors (bad `rules_config`, the server died or never got ready, a failed plan, an empty import).

## What "offline" means here, and how it is proven

- **Network:** in the sandbox, the scan sees loopback only, so it can't download add-ons or check for updates. Nothing it needs is fetched at run time.
- **Proof:**
  - every scan in `//tests` runs under `linux-sandbox` with `block-network`;
  - `//tests:network_blocked_test` runs with the same tag and fails if it can reach GitHub, 1.1.1.1 or 8.8.8.8 (as a negative control, it does fail under `--strategy=TestRunner=local`);
  - the consumer check runs a scan from another module with the macro's tag alone.
- **ZAP's own log:** no host other than 127.0.0.1 appears in `zap.log`. The Log4Shell/OAST rules log "no Active Scan OAST service is selected" and skip.

## Testing without flakiness

The fixture scans are real ZAP runs, so the tests assert only what ZAP produces every time:
- **the active scan's verdict:** reflected XSS, 40012, found in every one of 15+ runs, including 12 at once on 16 cores;
- **that alerts below `fail_on` are listed,** not failing;
- **the clean server's zero alerts;**
- **reports, logs and clean-up.**

Passive-scan alerts are less steady. In 1 of 15 runs of the vulnerable scan, Missing Anti-clickjacking Header (10020-1) was absent while its sibling Content Security Policy Header Not Set (10038-1), on the same response, was present. Nothing in ZAP's log explained it, and the rule's code was ruled out (rules are copied per scan task). A missing alert can only make a scan more lenient, never fail it spuriously. It still matters for users who fail on Medium, so it is listed in README and CLAUDE.md.

The verdict logic itself is tested deterministically: `ZapScan judge` runs the exact `scan` verdict on a checked-in report (`tests/testdata/report.xml`). The `//tests:judge_*` tests cover:
- plugin id vs alert reference;
- per-instance URL matching (a partly accepted alert still fails);
- False Positive confidence;
- each `fail_on`;
- stale entries;
- JUnit output.

## Not done

- **Authenticated APIs:** no auth headers, contexts or users. The plan could grow `env.contexts[].authentication`, or a `replacer` rule for a static header.
- **Custom scan policies** and passive rule tuning, beyond `strength`, `threads` and `max_scan_minutes`. Use `rules_config` to accept alerts instead.
- **GraphQL / SOAP imports:** the add-ons exist but aren't pinned.
- **Expiry and caching:** a cached passing result isn't re-run when an `expires` date passes (see README).
- **Platforms:** only Linux x86_64 is tested. The JDK `select` covers linux/aarch64 and macOS, and ZAP is pure Java, but those platforms haven't been run. On macOS `block-network` depends on the sandbox in use.
