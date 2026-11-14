"""
test_wp_chatterbug_forms_audit.py - Unit tests for WordPress Chatterbug Forms File Upload Validation Audit (CVE-2026-125055).
"""

from plugins.wordpress.wp_chatterbug_forms.wp_chatterbug_forms_cve_2026_125055_audit import (
    WPChatterbugFormsAuditPlugin,
    parse_chatterbug_forms_version,
    is_chatterbug_forms_version_vulnerable,
)


def test_plugin_metadata():
    plugin = WPChatterbugFormsAuditPlugin()
    assert "CVE-2026-125055" in plugin.info["cve"]
    assert plugin.info["severity"] == "CRITICAL"
    assert "Chatterbug" in plugin.info["name"]


def test_version_parsing():
    html = '<link href="/wp-content/plugins/chatterbug-forms/assets/css/style.css?ver=1.0.2" />'
    assert parse_chatterbug_forms_version(html) == (1, 0, 2, "1.0.2")
    assert parse_chatterbug_forms_version("Stable tag: 1.0.3\n") == (1, 0, 3, "1.0.3")
    assert parse_chatterbug_forms_version("<html>No plugin</html>") is None


def test_version_vulnerability_logic():
    vuln, reason = is_chatterbug_forms_version_vulnerable(1, 0, 2)
    assert vuln is True
    assert "CVE-2026-125055" in reason

    safe, _ = is_chatterbug_forms_version_vulnerable(1, 0, 3)
    assert safe is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = WPChatterbugFormsAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "1.0.2",
            "source": "Chatterbug Forms readme.txt",
            "is_vulnerable": True,
            "reason": "Affected <= 1.0.2 (< 1.0.3)",
        },
    )
    res = plugin.run_audit("10.0.0.50", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-125055" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "1.0.3",
            "source": "Chatterbug Forms readme.txt",
            "is_vulnerable": False,
            "reason": "Patched >= 1.0.3",
        },
    )
    res_safe = plugin.run_audit("10.0.0.50", [443])
    assert res_safe["status"] == "OK"
