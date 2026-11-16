"""Public API of rules_zap."""

load("//private:cli.bzl", _zap_cli = "zap_cli")
load("//private:providers.bzl", _ZapInfo = "ZapInfo")
load("//private:test.bzl", _zap_api_scan_test = "zap_api_scan_test", _zap_rules_config_test = "zap_rules_config_test")

zap_api_scan_test = _zap_api_scan_test
zap_rules_config_test = _zap_rules_config_test
zap_cli = _zap_cli
ZapInfo = _ZapInfo
