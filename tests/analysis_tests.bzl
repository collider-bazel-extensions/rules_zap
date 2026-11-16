"""Analysis-time tests: the test's executable and runfiles, the rules_config
validation action, and the analysis errors for bad attributes."""

load("@bazel_skylib//lib:unittest.bzl", "analysistest", "asserts")
load("//:defs.bzl", "zap_api_scan_test")

def _runfiles_impl(ctx):
    env = analysistest.begin(ctx)
    target = analysistest.target_under_test(env)
    info = target[DefaultInfo]
    asserts.true(env, info.files_to_run.executable != None, "expected an executable")
    names = [f.basename for f in info.default_runfiles.files.to_list()]
    for want in ["driver.jar", "zap-2.17.0.jar", "openapi.yaml", "accept_xss.yaml"]:
        asserts.true(env, want in names, "runfiles lack " + want)
    addons = sorted([n for n in names if n.endswith(".zap")])
    asserts.equals(env, [
        "ascanrules.zap",
        "automation.zap",
        "callhome.zap",
        "commonlib.zap",
        "database.zap",
        "network.zap",
        "oast.zap",
        "openapi.zap",
        "pscan.zap",
        "pscanrules.zap",
        "reports.zap",
    ], addons)
    asserts.true(env, "java" in names, "runfiles lack the JDK's java")
    return analysistest.end(env)

_runfiles_test = analysistest.make(_runfiles_impl)

def _validation_impl(ctx):
    env = analysistest.begin(ctx)
    groups = analysistest.target_under_test(env)[OutputGroupInfo]
    asserts.equals(
        env,
        [ctx.attr.expect],
        [f.basename for f in groups._validation.to_list()],
    )
    actions = [a for a in analysistest.target_actions(env) if a.mnemonic == "ZapRulesConfig"]
    asserts.equals(env, 1, len(actions))
    asserts.true(env, "check-config" in actions[0].argv)
    return analysistest.end(env)

_validation_test = analysistest.make(_validation_impl, attrs = {"expect": attr.string()})

def _no_validation_impl(ctx):
    env = analysistest.begin(ctx)
    groups = analysistest.target_under_test(env)[OutputGroupInfo]
    asserts.equals(env, [], groups._validation.to_list())
    return analysistest.end(env)

_no_validation_test = analysistest.make(_no_validation_impl)

def _launcher_impl(ctx):
    env = analysistest.begin(ctx)
    actions = analysistest.target_actions(env)
    content = [a.content for a in actions if a.mnemonic == "FileWrite"][0].replace(" \\\n    ", " ")
    for want in ctx.attr.want:
        asserts.true(env, want in content, "launcher lacks " + want + ":\n" + content)
    return analysistest.end(env)

_launcher_test = analysistest.make(_launcher_impl, attrs = {"want": attr.string_list()})

def _fails_impl(ctx):
    env = analysistest.begin(ctx)
    asserts.expect_failure(env, ctx.attr.message)
    return analysistest.end(env)

_fails_test = analysistest.make(
    _fails_impl,
    expect_failure = True,
    attrs = {"message": attr.string()},
)

def analysis_test_suite(name):
    s = name + "_subject"
    m = ["manual"]
    srv = "//tests/fixtures:clean_server"
    api = "//tests/fixtures:openapi.yaml"
    zap_api_scan_test(name = s + "_ok", server = srv, openapi = api, rules_config = "//tests/testdata:accept_xss.yaml", tags = m)
    zap_api_scan_test(name = s + "_no_config", server = srv, openapi_path = "/openapi.yaml", tags = m)
    zap_api_scan_test(
        name = s + "_args",
        server = srv,
        openapi = api,
        fail_on = "Low",
        strength = "medium",
        server_args = ["--port={port}", "$(rootpath //tests/testdata:empty_list.yaml)"],
        server_env = {"MODE": "x"},
        data = ["//tests/testdata:empty_list.yaml"],
        jvm_flags = ["-Xmx768m"],
        tags = m,
    )
    zap_api_scan_test(name = s + "_both", server = srv, openapi = api, openapi_path = "/x", tags = m)
    zap_api_scan_test(name = s + "_neither", server = srv, tags = m)
    zap_api_scan_test(name = s + "_relative", server = srv, openapi_path = "openapi.json", tags = m)
    zap_api_scan_test(name = s + "_minutes", server = srv, openapi = api, max_scan_minutes = 0, tags = m)
    zap_api_scan_test(name = s + "_threads", server = srv, openapi = api, threads = 0, tags = m)

    tests = []

    def add(n, rule, **kw):
        rule(name = name + "_" + n, **kw)
        tests.append(":" + name + "_" + n)

    add("runfiles", _runfiles_test, target_under_test = ":" + s + "_ok")
    add("validation", _validation_test, target_under_test = ":" + s + "_ok", expect = s + "_ok.rules_config.ok")
    add("no_validation", _no_validation_test, target_under_test = ":" + s + "_no_config")
    add("launcher_defaults", _launcher_test, target_under_test = ":" + s + "_no_config", want = [
        "'--fail-on' 'Medium'",
        "'--strength' 'low'",
        "'--openapi-path' '/openapi.yaml'",
        "'--jvm-flag' '-Xmx1g'",
        "'--max-scan-minutes' '10'",
        "'--addon' '+zap+zap/addons/openapi.zap'",
        " scan --runfiles ",
    ])
    add("launcher_args", _launcher_test, target_under_test = ":" + s + "_args", want = [
        "'--fail-on' 'Low'",
        "'--strength' 'medium'",
        "'--server-arg' '--port={port}'",
        "'--server-arg' 'tests/testdata/empty_list.yaml'",
        "'--server-env' 'MODE=x'",
        "'--jvm-flag' '-Xmx768m'",
        "'--openapi' '_main/tests/fixtures/openapi.yaml'",
    ])
    add("both_openapi", _fails_test, target_under_test = ":" + s + "_both", message = "set exactly one of `openapi`")
    add("no_openapi", _fails_test, target_under_test = ":" + s + "_neither", message = "set exactly one of `openapi`")
    add("relative_path", _fails_test, target_under_test = ":" + s + "_relative", message = "openapi_path must start with \"/\"")
    add("zero_minutes", _fails_test, target_under_test = ":" + s + "_minutes", message = "max_scan_minutes must be at least 1")
    add("zero_threads", _fails_test, target_under_test = ":" + s + "_threads", message = "threads must be at least 1")

    native.test_suite(name = name, tests = tests)
