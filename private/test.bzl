"""zap_api_scan_test and zap_rules_config_test."""

load(":common.bzl", "JavaRuntimeInfo", "launcher_content", "rlocation")
load(":providers.bzl", "ZapInfo")

RISKS = ["Informational", "Low", "Medium", "High"]
STRENGTHS = ["low", "medium", "high", "insane"]

_DRIVER_ATTRS = {
    "_driver": attr.label(default = "//private:driver", allow_single_file = [".jar"]),
    "_jdk": attr.label(default = "//private:jdk", providers = [JavaRuntimeInfo]),
}

def display_label(label):
    """//pkg:name for the main repository, @repo//pkg:name otherwise."""
    if label.repo_name == "":
        return "//{}:{}".format(label.package, label.name)
    return "@{}//{}:{}".format(label.repo_name, label.package, label.name)

def _config_check(ctx, config):
    """A validation action: the driver's rules_config check, at build time."""
    jdk = ctx.attr._jdk_exec[JavaRuntimeInfo]
    marker = ctx.actions.declare_file(ctx.label.name + ".rules_config.ok")
    ctx.actions.run(
        executable = jdk.java_executable_exec_path,
        tools = jdk.files,
        inputs = [config, ctx.file._driver],
        outputs = [marker],
        arguments = [
            "-XX:+UseSerialGC",
            "-XX:TieredStopAtLevel=1",
            "-cp",
            ctx.file._driver.path,
            "rules_zap.ZapScan",
            "check-config",
            "--config",
            config.path,
            "--name",
            config.short_path,
            "--out",
            marker.path,
        ],
        mnemonic = "ZapRulesConfig",
        progress_message = "Checking rules_config %{input}",
    )
    return marker

def _scan_test_impl(ctx):
    zap = ctx.attr._zap[ZapInfo]
    jdk = ctx.attr._jdk[JavaRuntimeInfo]
    if bool(ctx.file.openapi) == bool(ctx.attr.openapi_path):
        fail("zap_api_scan_test: set exactly one of `openapi` (the OpenAPI document as a file) and `openapi_path` (the path the server serves it on, e.g. \"/openapi.json\")")
    if ctx.attr.openapi_path and not ctx.attr.openapi_path.startswith("/"):
        fail("zap_api_scan_test: openapi_path must start with \"/\", got \"{}\"".format(ctx.attr.openapi_path))
    if ctx.attr.ready_path and not ctx.attr.ready_path.startswith("/"):
        fail("zap_api_scan_test: ready_path must start with \"/\", got \"{}\"".format(ctx.attr.ready_path))
    if ctx.attr.max_scan_minutes < 1:
        fail("zap_api_scan_test: max_scan_minutes must be at least 1, got {}".format(ctx.attr.max_scan_minutes))
    if ctx.attr.threads < 1:
        fail("zap_api_scan_test: threads must be at least 1, got {}".format(ctx.attr.threads))
    if ctx.attr.ready_timeout < 1:
        fail("zap_api_scan_test: ready_timeout must be at least 1, got {}".format(ctx.attr.ready_timeout))
    for k in ctx.attr.server_env:
        if not k or "=" in k:
            fail("zap_api_scan_test: bad server_env name \"{}\"".format(k))

    server = ctx.executable.server
    install_dir = rlocation(ctx, zap.jar).rsplit("/", 1)[0]
    args = [
        "--label",
        display_label(ctx.label),
        "--workspace",
        ctx.workspace_name,
        "--zap-version",
        zap.version,
        "--jar",
        rlocation(ctx, zap.jar),
        "--install",
        install_dir,
        "--server",
        rlocation(ctx, server),
        "--fail-on",
        ctx.attr.fail_on,
        "--strength",
        ctx.attr.strength,
        "--threads",
        str(ctx.attr.threads),
        "--max-scan-minutes",
        str(ctx.attr.max_scan_minutes),
        "--ready-timeout",
        str(ctx.attr.ready_timeout),
    ]
    for a in zap.addons:
        args += ["--addon", rlocation(ctx, a)]
    for a in ctx.attr.server_args:
        args += ["--server-arg", ctx.expand_location(a, ctx.attr.data)]
    for k, v in ctx.attr.server_env.items():
        args += ["--server-env", k + "=" + ctx.expand_location(v, ctx.attr.data)]
    if ctx.file.openapi:
        args += ["--openapi", rlocation(ctx, ctx.file.openapi)]
    else:
        args += ["--openapi-path", ctx.attr.openapi_path]
    if ctx.attr.ready_path:
        args += ["--ready-path", ctx.attr.ready_path]
    validations = []
    files = [ctx.file._driver, zap.jar, server] + zap.addons
    if ctx.file.rules_config:
        args += [
            "--rules-config",
            rlocation(ctx, ctx.file.rules_config),
            "--rules-config-name",
            ctx.file.rules_config.short_path,
        ]
        files.append(ctx.file.rules_config)
        validations.append(_config_check(ctx, ctx.file.rules_config))
    if ctx.file.openapi:
        files.append(ctx.file.openapi)
    for f in ctx.attr.jvm_flags:
        args += ["--jvm-flag", f]

    ctx.actions.write(
        output = ctx.outputs.executable,
        content = launcher_content(ctx, jdk, ctx.file._driver, "scan", args),
        is_executable = True,
    )
    runfiles = ctx.runfiles(
        files = files + ctx.files.data,
        transitive_files = depset(transitive = [zap.install, jdk.files]),
    ).merge(ctx.attr.server[DefaultInfo].default_runfiles)
    for d in ctx.attr.data:
        runfiles = runfiles.merge(d[DefaultInfo].default_runfiles)
    return [
        DefaultInfo(executable = ctx.outputs.executable, runfiles = runfiles),
        OutputGroupInfo(_validation = depset(validations)),
        RunEnvironmentInfo(environment = ctx.attr.env),
    ]

_zap_api_scan_test = rule(
    implementation = _scan_test_impl,
    test = True,
    attrs = dict(_DRIVER_ATTRS, **{
        "server": attr.label(
            mandatory = True,
            executable = True,
            allow_files = True,
            cfg = "target",
            doc = "The server under test: an executable (a binary target, or an executable script) that listens on 127.0.0.1:$PORT.",
        ),
        "server_args": attr.string_list(doc = "Arguments for the server. `{port}` is replaced by the port; $(rootpath) / $(location) expand over `data`."),
        "server_env": attr.string_dict(doc = "Extra environment for the server (PORT and HOST are always set). `{port}` and $(rootpath) expand as in server_args."),
        "data": attr.label_list(allow_files = True, doc = "Runfiles for the server (config files, fixtures)."),
        "openapi": attr.label(allow_single_file = True, doc = "The OpenAPI document (JSON or YAML) as a file."),
        "openapi_path": attr.string(doc = "Instead of `openapi`: the path the server serves its OpenAPI document on, e.g. \"/openapi.json\"."),
        "rules_config": attr.label(allow_single_file = True, doc = "Accepted alerts, each with a reason (see README)."),
        "fail_on": attr.string(default = "Medium", values = RISKS, doc = "The lowest risk that fails the test."),
        "strength": attr.string(default = "low", values = STRENGTHS, doc = "The active scan policy's default attack strength."),
        "threads": attr.int(default = 8, doc = "Active scan threads against the server."),
        "max_scan_minutes": attr.int(default = 10, doc = "Cap on the active scan's duration (ZAP's maxScanDurationInMins)."),
        "ready_path": attr.string(doc = "If set, the server is ready when GET <ready_path> answers below 500; otherwise when its port accepts connections."),
        "ready_timeout": attr.int(default = 60, doc = "Seconds to wait for the server to be ready."),
        "jvm_flags": attr.string_list(default = ["-Xmx1g"], doc = "JVM flags for ZAP."),
        "env": attr.string_dict(doc = "Environment for the test (the driver and, through it, the server)."),
        "_zap": attr.label(default = "@zap//:zap", providers = [ZapInfo]),
        "_jdk_exec": attr.label(default = "//private:jdk", cfg = "exec", providers = [JavaRuntimeInfo]),
    }),
)

def zap_api_scan_test(name, tags = None, size = "medium", **kwargs):
    """An OWASP ZAP API scan of `server` as a test.

    The test starts `server` on a free 127.0.0.1 port ($PORT), imports its
    OpenAPI document into ZAP's Automation Framework, runs the passive and
    active scans, and fails on any alert at or above `fail_on` that
    `rules_config` doesn't accept. It is tagged `block-network`: ZAP and
    the server see only loopback.

    Args:
      name: target name.
      tags: tags; `block-network` is always added.
      size: test size (default "medium": a 300s timeout).
      **kwargs: the rule's attributes: server, openapi | openapi_path,
        rules_config, fail_on, server_args, server_env, data, strength,
        threads, max_scan_minutes, ready_path, ready_timeout, jvm_flags,
        env, and the common test attributes.
    """
    tags = list(tags or [])
    if "block-network" not in tags:
        tags.append("block-network")
    _zap_api_scan_test(name = name, tags = tags, size = size, **kwargs)

def _config_test_impl(ctx):
    jdk = ctx.attr._jdk[JavaRuntimeInfo]
    args = [
        "--label",
        display_label(ctx.label),
        "--name",
        ctx.file.src.short_path,
        "--config",
        rlocation(ctx, ctx.file.src),
    ]
    if ctx.attr.expect_error:
        args += ["--expect-error", ctx.attr.expect_error]
    ctx.actions.write(
        output = ctx.outputs.executable,
        content = launcher_content(ctx, jdk, ctx.file._driver, "config-test", args),
        is_executable = True,
    )
    return [DefaultInfo(
        executable = ctx.outputs.executable,
        runfiles = ctx.runfiles(
            files = [ctx.file.src, ctx.file._driver],
            transitive_files = jdk.files,
        ),
    )]

zap_rules_config_test = rule(
    implementation = _config_test_impl,
    test = True,
    doc = "A rules_config passes the check, or (with expect_error) fails it with a matching message.",
    attrs = dict(_DRIVER_ATTRS, **{
        "src": attr.label(allow_single_file = True, mandatory = True),
        "expect_error": attr.string(doc = "A Java regex the check's error must contain (find); empty: the check must pass."),
    }),
)
