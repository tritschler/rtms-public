"""
test_wp_automatorwp_pro_audit.py - Unit tests for WordPress AutomatorWP Pro Webhook Auth Bypass Audit (CVE-2026-126173).
"""

from plugins.wordpress.wp_automatorwp_pro.wp_automatorwp_pro_cve_2026_126173_audit import (
    WPAutomatorWPProAuditPlugin,
    parse_automatorwp_version,
    is_automatorwp_version_vulnerable,
)


def test_plugin_metadata():
    plugin = WPAutomatorWPProAuditPlugin()
    assert "CVE-2026-126173" in plugin.info["cve"]
    assert plugin.info["severity"] == "CRITICAL"
    assert "AutomatorWP" in plugin.info["name"]


def test_version_parsing():
    html = '<link href="/wp-content/plugins/automatorwp-pro/assets/css/style.css?ver=1.4.4" />'
    assert parse_automatorwp_version(html) == (1, 4, 4, "1.4.4")
    assert parse_automatorwp_version("Stable tag: 1.4.5\n") == (1, 4, 5, "1.4.5")
    assert parse_automatorwp_version("<html>No plugin</html>") is None


def test_version_vulnerability_logic():
    vuln, reason = is_automatorwp_version_vulnerable(1, 4, 4)
    assert vuln is True
    assert "CVE-2026-126173" in reason

    safe, _ = is_automatorwp_version_vulnerable(1, 4, 5)
    assert safe is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = WPAutomatorWPProAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "1.4.4",
            "source": "AutomatorWP Pro Webhooks Addon readme.txt",
            "is_vulnerable": True,
            "reason": "Affected <= 1.4.4 (< 1.4.5)",
        },
    )
    res = plugin.run_audit("10.0.0.50", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-126173" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "1.4.5",
            "source": "AutomatorWP Pro Webhooks Addon readme.txt",
            "is_vulnerable": False,
            "reason": "Patched >= 1.4.5",
        },
    )
    res_safe = plugin.run_audit("10.0.0.50", [443])
    assert res_safe["status"] == "OK"
