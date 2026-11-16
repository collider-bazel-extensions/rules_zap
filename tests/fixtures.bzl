"""java_source_server: a one-file Java program run from source on rules_zap's
pinned JDK (JEP 330), so the fixture servers need nothing beyond what
rules_zap already downloads."""

load("@rules_shell//shell:sh_test.bzl", "sh_test")
load("//private:common.bzl", "JavaRuntimeInfo", "java_rlocation", "launcher_content", "rlocation", "shell_quote")

def _java_source_server_impl(ctx):
    jdk = ctx.attr._jdk[JavaRuntimeInfo]
    args = []
    for a in ctx.attr.args_:
        args.append(shell_quote(ctx.expand_location(a, ctx.attr.data)))
    ctx.actions.write(
        output = ctx.outputs.executable,
        content = """\
#!/usr/bin/env bash
set -euo pipefail
R="${{RUNFILES_DIR:-${{TEST_SRCDIR:-$0.runfiles}}}}"
cd "$R/{ws}"
exec "$R/"{java} -XX:+UseSerialGC -Xmx128m "$R/"{src} {args}
""".format(
            ws = ctx.workspace_name,
            java = shell_quote(java_rlocation(ctx, jdk)),
            src = shell_quote(rlocation(ctx, ctx.file.src)),
            args = " ".join(args),
        ),
        is_executable = True,
    )
    return [DefaultInfo(
        executable = ctx.outputs.executable,
        runfiles = ctx.runfiles(files = [ctx.file.src] + ctx.files.data, transitive_files = jdk.files),
    )]

java_source_server = rule(
    implementation = _java_source_server_impl,
    executable = True,
    attrs = {
        "src": attr.label(allow_single_file = [".java"], mandatory = True),
        # `args` is reserved on executable rules (bazel run only); these are
        # baked into the launcher, so they apply when a test runs it.
        "args_": attr.string_list(),
        "data": attr.label_list(allow_files = True),
        "_jdk": attr.label(default = "//private:jdk", providers = [JavaRuntimeInfo]),
    },
)

def scan_check_test(name, scan, status, checks, **kwargs):
    """Runs the (manual) zap_api_scan_test `scan` nested, via run_scan.sh,
    expecting exit `status` and every check (+TEXT, -TEXT, @FILE,
    =FILE:TEXT). Tagged block-network, like the scan itself."""
    sh_test(
        name = name,
        srcs = ["run_scan.sh"],
        # sh_test args are shell-tokenized: quote each.
        args = ["$(rootpath {})".format(scan), str(status)] + [shell_quote(c) for c in checks],
        data = [scan],
        tags = kwargs.pop("tags", []) + ["block-network"],
        **kwargs
    )

def _zap_judge_impl(ctx):
    jdk = ctx.attr._jdk[JavaRuntimeInfo]
    args = [
        "--label",
        "//{}:{}".format(ctx.label.package, ctx.label.name),
        "--report",
        rlocation(ctx, ctx.file.report),
        "--origin",
        "http://127.0.0.1:40000",
        "--fail-on",
        ctx.attr.fail_on,
    ]
    files = [ctx.file.report, ctx.file._driver]
    if ctx.file.rules_config:
        args += [
            "--rules-config",
            rlocation(ctx, ctx.file.rules_config),
            "--rules-config-name",
            ctx.file.rules_config.short_path,
        ]
        files.append(ctx.file.rules_config)
    ctx.actions.write(
        output = ctx.outputs.executable,
        content = launcher_content(ctx, jdk, ctx.file._driver, "judge", args),
        is_executable = True,
    )
    return [DefaultInfo(
        executable = ctx.outputs.executable,
        runfiles = ctx.runfiles(files = files, transitive_files = jdk.files),
    )]

# The driver's verdict on a checked-in report (no ZAP run): deterministic
# tests of rules_config matching and fail_on.
zap_judge = rule(
    implementation = _zap_judge_impl,
    executable = True,
    attrs = {
        "report": attr.label(allow_single_file = [".xml"], mandatory = True),
        "rules_config": attr.label(allow_single_file = True),
        "fail_on": attr.string(default = "Medium"),
        "_driver": attr.label(default = "//private:driver", allow_single_file = [".jar"]),
        "_jdk": attr.label(default = "//private:jdk", providers = [JavaRuntimeInfo]),
    },
)
