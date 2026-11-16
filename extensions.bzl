"""Bzlmod extension. Single `version` tag: creates `@zap`, the ZAP release
archive plus the pinned add-ons.

The root module's tag wins; without one, rules_zap's own applies, so
consumers declare nothing unless they want another version. A version not
in private/versions.bzl needs its own pins (sha256, and add-on pins as
needed), as rules_argocd's argocd.version(sha256 = ...) does.
"""

load("//private:repositories.bzl", "zap_repository")
load("//private:versions.bzl", "DEFAULT_VERSION", "ZAP_VERSIONS")

_URL = "https://github.com/zaproxy/zaproxy/releases/download/v{version}/ZAP_{version}_Core.zip"

_version_tag = tag_class(attrs = {
    "version": attr.string(mandatory = True),  # e.g. "2.17.0"
    # Pins for a version not in ZAP_VERSIONS (or to replace a known one's):
    # the archive's sha256 (the release notes' checksum table); url defaults
    # to the release's ZAP_<version>_Core.zip, strip_prefix to ZAP_<version>.
    "url": attr.string(),
    "sha256": attr.string(),
    "strip_prefix": attr.string(),
    # Add-on pins by id, replacing or adding to the known version's (an
    # unknown version starts from DEFAULT_VERSION's add-ons): the url and
    # SHA-256 from ZAP's marketplace index, ZapVersions-<major.minor>.xml.
    "addons": attr.string_dict(),
    "addon_sha256": attr.string_dict(),
})

def _pins(tag):
    return struct(
        version = tag.version,
        url = tag.url,
        sha256 = tag.sha256,
        strip_prefix = tag.strip_prefix,
        addons = dict(tag.addons),
        addon_sha256 = dict(tag.addon_sha256),
    )

def _one(mod):
    pins = [_pins(t) for t in mod.tags.version]
    for p in pins[1:]:
        if p != pins[0]:
            fail("rules_zap: {} sets zap.version() more than once, differently ({} and {}); set one.".format(
                "the root module" if mod.is_root else mod.name,
                pins[0].version,
                p.version,
            ))
    return pins[0] if pins else None

def resolve_pins(pins):
    """The repository attributes for one zap.version() tag (or fail)."""
    known = ZAP_VERSIONS.get(pins.version)
    if known == None and not pins.sha256:
        fail(("rules_zap: zap.version(version = \"{}\") is not pinned. Pinned: {}. " +
              "For another version, pin it yourself: zap.version(version = ..., " +
              "sha256 = <ZAP_<version>_Core.zip sha256>), plus addons/addon_sha256 " +
              "for add-ons that need a newer pin.").format(
            pins.version,
            ", ".join(sorted(ZAP_VERSIONS.keys())),
        ))
    base = known or ZAP_VERSIONS[DEFAULT_VERSION]
    for aid in pins.addons:
        if aid not in pins.addon_sha256:
            fail("rules_zap: zap.version(addons = {{\"{}\": ...}}) needs addon_sha256 = {{\"{}\": <sha256>}}.".format(aid, aid))
    for aid in pins.addon_sha256:
        if aid not in pins.addons:
            fail("rules_zap: zap.version(addon_sha256 = {{\"{}\": ...}}) needs addons = {{\"{}\": <url>}}.".format(aid, aid))
    urls = {aid: a["url"] for aid, a in base["addons"].items()}
    shas = {aid: a["sha256"] for aid, a in base["addons"].items()}
    urls.update(pins.addons)
    shas.update(pins.addon_sha256)
    if pins.sha256:
        url = pins.url or _URL.format(version = pins.version)
        sha256 = pins.sha256
    else:
        url = pins.url or known["url"]
        sha256 = known["sha256"]
    return struct(
        version = pins.version,
        url = url,
        sha256 = sha256,
        strip_prefix = pins.strip_prefix or (known["strip_prefix"] if known else "ZAP_" + pins.version),
        addon_urls = urls,
        addon_sha256 = shas,
    )

def _impl(mctx):
    root = None
    own = None
    for mod in mctx.modules:
        if mod.is_root:
            root = _one(mod)
        elif mod.name == "rules_zap":
            own = _one(mod)

    # Only one module's tag applies: the root's, else rules_zap's own
    # (other modules' tags are ignored). The repo has no version in its
    # name, so there's one ZAP per build.
    pins = root or own or _pins(struct(
        version = DEFAULT_VERSION,
        url = "",
        sha256 = "",
        strip_prefix = "",
        addons = {},
        addon_sha256 = {},
    ))
    r = resolve_pins(pins)
    zap_repository(
        name = "zap",
        version = r.version,
        url = r.url,
        sha256 = r.sha256,
        strip_prefix = r.strip_prefix,
        addon_urls = r.addon_urls,
        addon_sha256 = r.addon_sha256,
    )
    return mctx.extension_metadata(reproducible = True)

zap = module_extension(
    implementation = _impl,
    tag_classes = {"version": _version_tag},
)
