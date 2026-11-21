"""
test_wp_newsletters_lite_audit.py - Unit tests for WordPress Tribulant Newsletters
Object Injection & SQLi Audit (CVE-2026-129039, CVE-2026-129043).
"""

from plugins.wordpress.wp_newsletters_lite.wp_newsletters_lite_cve_2026_129039_audit import (
    WPNewslettersLiteAuditPlugin,
    parse_wp_newsletters_lite_version,
    is_wp_newsletters_lite_version_vulnerable,
)


def test_plugin_metadata():
    plugin = WPNewslettersLiteAuditPlugin()
    assert "CVE-2026-129039" in plugin.info["cve"]
    assert plugin.info["severity"] == "CRITICAL"
    assert "Tribulant Newsletters" in plugin.info["name"]


def test_version_parsing():
    html = '<script src="/wp-content/plugins/newsletters-lite/js/wp-mailinglist.js?ver=4.18.2"></script>'
    assert parse_wp_newsletters_lite_version(html) == (4, 18, 2, "4.18.2")
    assert parse_wp_newsletters_lite_version("Stable tag: 4.18.3\n") == (4, 18, 3, "4.18.3")
    assert parse_wp_newsletters_lite_version("<html>No plugin</html>") is None


def test_version_vulnerability_logic():
    vuln, reason = is_wp_newsletters_lite_version_vulnerable(4, 18, 2)
    assert vuln is True
    assert "CVE-2026-129039" in reason

    safe, _ = is_wp_newsletters_lite_version_vulnerable(4, 18, 3)
    assert safe is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = WPNewslettersLiteAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "4.18.2",
            "source": "Tribulant Newsletters readme.txt (/wp-content/plugins/newsletters-lite/readme.txt)",
            "is_vulnerable": True,
            "reason": "Affected <= 4.18.2 (< 4.18.3)",
        },
    )
    res = plugin.run_audit("10.0.0.53", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-129039" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "4.18.3",
            "source": "Tribulant Newsletters readme.txt (/wp-content/plugins/newsletters-lite/readme.txt)",
            "is_vulnerable": False,
            "reason": "Patched >= 4.18.3",
        },
    )
    res_safe = plugin.run_audit("10.0.0.53", [443])
    assert res_safe["status"] == "OK"
