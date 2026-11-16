"""Providers for rules_zap."""

ZapInfo = provider(
    doc = "A ZAP install (the release archive minus its bundled add-ons) and the add-ons to load.",
    fields = {
        "version": "ZAP version string, e.g. \"2.17.0\".",
        "jar": "File: zap-<version>.jar at the install's root.",
        "install": "depset of File: every file of the install.",
        "addons": "list of File: the .zap add-ons to load.",
    },
)
