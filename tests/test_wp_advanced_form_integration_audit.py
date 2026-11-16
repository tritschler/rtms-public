"""
test_wp_advanced_form_integration_audit.py - Unit tests for WordPress Advanced Form Integration
Privilege Escalation Audit (CVE-2026-125769).
"""

from plugins.wordpress.wp_advanced_form_integration.wp_advanced_form_integration_cve_2026_125769_audit import (
    WPAdvancedFormIntegrationAuditPlugin,
    parse_advanced_form_integration_version,
    is_advanced_form_integration_version_vulnerable,
)


def test_plugin_metadata():
    plugin = WPAdvancedFormIntegrationAuditPlugin()
    assert "CVE-2026-125769" in plugin.info["cve"]
    assert plugin.info["severity"] == "CRITICAL"
    assert "Advanced Form Integration" in plugin.info["name"]


def test_version_parsing():
    html = '<script src="/wp-content/plugins/advanced-form-integration/assets/js/script.js?ver=2.11.3"></script>'
    assert parse_advanced_form_integration_version(html) == (2, 11, 3, "2.11.3")
    assert parse_advanced_form_integration_version("Stable tag: 2.11.4\n") == (2, 11, 4, "2.11.4")
    assert parse_advanced_form_integration_version("<html>No plugin</html>") is None


def test_version_vulnerability_logic():
    vuln, reason = is_advanced_form_integration_version_vulnerable(2, 11, 3)
    assert vuln is True
    assert "CVE-2026-125769" in reason

    safe, _ = is_advanced_form_integration_version_vulnerable(2, 11, 4)
    assert safe is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = WPAdvancedFormIntegrationAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "2.11.3",
            "source": "Advanced Form Integration readme.txt",
            "is_vulnerable": True,
            "reason": "Affected <= 2.11.3 (< 2.11.4)",
        },
    )
    res = plugin.run_audit("10.0.0.51", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-125769" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "2.11.4",
            "source": "Advanced Form Integration readme.txt",
            "is_vulnerable": False,
            "reason": "Patched >= 2.11.4",
        },
    )
    res_safe = plugin.run_audit("10.0.0.51", [443])
    assert res_safe["status"] == "OK"
