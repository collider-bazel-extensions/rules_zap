"""zap_driver: compiles the driver (ZapScan.java) with the pinned JDK's own
javac, so rules_zap needs neither rules_java's compile toolchain nor
java_tools."""

load(":common.bzl", "JavaRuntimeInfo")

def _zap_driver_impl(ctx):
    jdk = ctx.attr._jdk[JavaRuntimeInfo]
    jar = ctx.actions.declare_file(ctx.label.name + ".jar")
    ctx.actions.run_shell(
        inputs = depset(ctx.files.srcs, transitive = [jdk.files]),
        outputs = [jar],
        command = """\
set -euo pipefail
classes="$(mktemp -d)"
trap 'rm -rf "$classes"' EXIT
"$1/bin/javac" --release 17 -encoding UTF-8 -Xlint:-options -d "$classes" "${@:3}"
"$1/bin/jar" --create --file "$2" --date=2000-01-01T00:00:00Z -C "$classes" .
""",
        arguments = [jdk.java_home, jar.path] + [f.path for f in ctx.files.srcs],
        mnemonic = "ZapDriver",
        progress_message = "Compiling the rules_zap driver %{label}",
    )
    return [DefaultInfo(files = depset([jar]))]

zap_driver = rule(
    implementation = _zap_driver_impl,
    attrs = {
        "srcs": attr.label_list(allow_files = [".java"], mandatory = True),
        "_jdk": attr.label(
            default = "//private:jdk",
            cfg = "exec",
            providers = [JavaRuntimeInfo],
        ),
    },
)
