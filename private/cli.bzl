"""zap_cli: `bazel run` the pinned ZAP with a fresh home and the pinned
add-ons. Arguments go to ZAP; `-cmd` is added unless `-cmd` or `-daemon`
is given."""

load(":common.bzl", "JavaRuntimeInfo", "launcher_content", "rlocation")
load(":providers.bzl", "ZapInfo")

def _zap_cli_impl(ctx):
    zap = ctx.attr.zap[ZapInfo]
    jdk = ctx.attr._jdk[JavaRuntimeInfo]
    args = [
        "--jar",
        rlocation(ctx, zap.jar),
        "--install",
        rlocation(ctx, zap.jar).rsplit("/", 1)[0],
    ]
    for a in zap.addons:
        args += ["--addon", rlocation(ctx, a)]
    args.append("--")
    ctx.actions.write(
        output = ctx.outputs.executable,
        content = launcher_content(ctx, jdk, ctx.file._driver, "cli", args),
        is_executable = True,
    )
    return [DefaultInfo(
        executable = ctx.outputs.executable,
        runfiles = ctx.runfiles(
            files = [ctx.file._driver] + zap.addons,
            transitive_files = depset(transitive = [zap.install, jdk.files]),
        ),
    )]

zap_cli = rule(
    implementation = _zap_cli_impl,
    executable = True,
    attrs = {
        "zap": attr.label(default = "@zap//:zap", providers = [ZapInfo]),
        "_driver": attr.label(default = "//private:driver", allow_single_file = [".jar"]),
        "_jdk": attr.label(default = "//private:jdk", providers = [JavaRuntimeInfo]),
    },
)
