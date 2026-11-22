"""
test_wp_nexter_blocks_pro_audit.py - Unit tests for WordPress Nexter Blocks Pro
Privilege Escalation Audit (CVE-2026-125294).
"""

from plugins.wordpress.wp_nexter_blocks_pro.wp_nexter_blocks_pro_cve_2026_125294_audit import (
    WPNexterBlocksProAuditPlugin,
    parse_wp_nexter_blocks_pro_version,
    is_wp_nexter_blocks_pro_version_vulnerable,
)


def test_plugin_metadata():
    plugin = WPNexterBlocksProAuditPlugin()
    assert "CVE-2026-125294" in plugin.info["cve"]
    assert plugin.info["severity"] == "CRITICAL"
    assert "Nexter Blocks Pro" in plugin.info["name"]


def test_version_parsing():
    html = '<script src="/wp-content/plugins/the-plus-addons-for-block-editor-pro/assets/js/main.min.js?ver=5.0.10"></script>'
    assert parse_wp_nexter_blocks_pro_version(html) == (5, 0, 10, "5.0.10")
    assert parse_wp_nexter_blocks_pro_version("Stable tag: 5.0.11\n") == (5, 0, 11, "5.0.11")
    assert parse_wp_nexter_blocks_pro_version("<html>No plugin</html>") is None


def test_version_vulnerability_logic():
    vuln, reason = is_wp_nexter_blocks_pro_version_vulnerable(5, 0, 10)
    assert vuln is True
    assert "CVE-2026-125294" in reason

    safe, _ = is_wp_nexter_blocks_pro_version_vulnerable(5, 0, 11)
    assert safe is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = WPNexterBlocksProAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "5.0.10",
            "source": "Nexter Blocks Pro readme.txt (/wp-content/plugins/the-plus-addons-for-block-editor-pro/readme.txt)",
            "is_vulnerable": True,
            "reason": "Affected <= 5.0.10 (< 5.0.11)",
        },
    )
    res = plugin.run_audit("10.0.0.55", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-125294" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "5.0.11",
            "source": "Nexter Blocks Pro readme.txt (/wp-content/plugins/the-plus-addons-for-block-editor-pro/readme.txt)",
            "is_vulnerable": False,
            "reason": "Patched >= 5.0.11",
        },
    )
    res_safe = plugin.run_audit("10.0.0.55", [443])
    assert res_safe["status"] == "OK"
