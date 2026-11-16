"""The @zap repo: ZAP's release archive (without its bundled add-ons) plus
the pinned add-ons, each downloaded by SHA-256, exposed as a
zap_distribution target `@zap//:zap`.
"""

_BUILD = """\
load("@rules_zap//private:distribution.bzl", "zap_distribution")

package(default_visibility = ["//visibility:public"])

zap_distribution(
    name = "zap",
    version = "{version}",
    jar = "install/{jar}",
    install = glob(["install/**"]),
    addons = glob(["addons/*.zap"]),
)
"""

def _zap_repository_impl(rctx):
    version = rctx.attr.version
    rctx.download_and_extract(
        url = rctx.attr.url,
        sha256 = rctx.attr.sha256,
        output = "install",
        stripPrefix = rctx.attr.strip_prefix,
        type = "zip",
    )

    # The archive's own add-ons are dropped: ZAP loads exactly the pinned
    # set below (the Crossplatform zip bundles ~50, the Core zip ~20).
    rctx.delete("install/plugin")
    jar = "zap-{}.jar".format(version)
    if not rctx.path("install/" + jar).exists:
        fail("rules_zap: {} has no {} under {} (strip_prefix = \"{}\")".format(
            rctx.attr.url,
            jar,
            rctx.attr.strip_prefix,
            rctx.attr.strip_prefix,
        ))

    for aid in sorted(rctx.attr.addon_urls.keys()):
        url = rctx.attr.addon_urls[aid]
        rctx.download(
            url = url,
            sha256 = rctx.attr.addon_sha256[aid],
            output = "addons/{}.zap".format(aid),
        )
    rctx.file("BUILD.bazel", _BUILD.format(version = version, jar = jar))

zap_repository = repository_rule(
    implementation = _zap_repository_impl,
    attrs = {
        "version": attr.string(mandatory = True),
        "url": attr.string(mandatory = True),
        "sha256": attr.string(mandatory = True),
        "strip_prefix": attr.string(mandatory = True),
        # add-on id -> url / sha256 (the same keys).
        "addon_urls": attr.string_dict(mandatory = True),
        "addon_sha256": attr.string_dict(mandatory = True),
    },
)
