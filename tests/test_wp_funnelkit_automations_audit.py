from plugins.wordpress.wp_funnelkit_automations.wp_funnelkit_automations_cve_2026_131767_audit import (
    WPFunnelKitAutomationsAuditPlugin,
    is_funnelkit_automations_version_vulnerable,
    parse_funnelkit_automations_version,
)


def test_parse_funnelkit_automations_version():
    assert parse_funnelkit_automations_version("Stable tag: 3.9.0.1") == (3, 9, 0, 1)
    assert parse_funnelkit_automations_version("3.9.0.2") == (3, 9, 0, 2)
    assert parse_funnelkit_automations_version("") is None


def test_is_funnelkit_automations_version_vulnerable():
    assert is_funnelkit_automations_version_vulnerable((3, 9, 0, 1))[0] is True
    assert is_funnelkit_automations_version_vulnerable((3, 9, 0, 2))[0] is False


def test_wp_funnelkit_automations_run_audit():
    res_v = WPFunnelKitAutomationsAuditPlugin("wp.local", {"plugin_version": "3.9.0.1"}).run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-131767" in res_v["cve"]

    res_ok = WPFunnelKitAutomationsAuditPlugin("wp.local", {"plugin_version": "3.9.0.2"}).run_audit()
    assert res_ok["status"] == "OK"
