"""
test_wp_auth_armor_audit.py - Unit tests for WordPress Auth Armor
Missing Authentication Audit (CVE-2026-110960).
"""

from plugins.wordpress.wp_auth_armor.wp_auth_armor_cve_2026_110960_audit import (
    WPAuthArmorAuditPlugin,
    parse_auth_armor_version,
    is_auth_armor_version_vulnerable,
)


def test_plugin_metadata():
    plugin = WPAuthArmorAuditPlugin()
    assert "CVE-2026-110960" in plugin.info["cve"]
    assert plugin.info["severity"] == "CRITICAL"
    assert "Auth Armor" in plugin.info["name"]


def test_version_parsing():
    html = '<script src="/wp-content/plugins/auth-armor/public/js/auth-armor.js?ver=1.0.3"></script>'
    assert parse_auth_armor_version(html) == (1, 0, 3, "1.0.3")
    assert parse_auth_armor_version("Stable tag: 1.0.4\n") == (1, 0, 4, "1.0.4")
    assert parse_auth_armor_version("<html>No plugin</html>") is None


def test_version_vulnerability_logic():
    vuln, reason = is_auth_armor_version_vulnerable(1, 0, 3)
    assert vuln is True
    assert "CVE-2026-110960" in reason

    safe, _ = is_auth_armor_version_vulnerable(1, 0, 4)
    assert safe is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = WPAuthArmorAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "1.0.3",
            "source": "Auth Armor readme.txt",
            "is_vulnerable": True,
            "reason": "Affected <= 1.0.3 (< 1.0.4)",
        },
    )
    res = plugin.run_audit("10.0.0.92", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-110960" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "1.0.4",
            "source": "Auth Armor readme.txt",
            "is_vulnerable": False,
            "reason": "Patched >= 1.0.4",
        },
    )
    res_safe = plugin.run_audit("10.0.0.92", [443])
    assert res_safe["status"] == "OK"
