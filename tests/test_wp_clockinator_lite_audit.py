"""
test_wp_clockinator_lite_audit.py - Unit tests for WordPress Clockinator Lite Compliance Audit (CVE-2026-124815).
"""

from plugins.wordpress.wp_clockinator_lite.wp_clockinator_lite_cve_2026_124815_audit import (
    WPClockinatorLiteAuditPlugin,
    parse_clockinator_version,
    is_clockinator_version_vulnerable,
)


def test_plugin_metadata():
    plugin = WPClockinatorLiteAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-124815"
    assert plugin.info["severity"] == "CRITICAL"
    assert "Clockinator Lite" in plugin.info["name"]


def test_version_parsing():
    html = '<link href="/wp-content/plugins/clockinator-lite/assets/css/style.css?ver=1.0.9" />'
    assert parse_clockinator_version(html) == (1, 0, 9, "1.0.9")
    assert parse_clockinator_version("Stable tag: 1.1.0\n") == (1, 1, 0, "1.1.0")
    assert parse_clockinator_version("<html>No plugin</html>") is None


def test_version_vulnerability_logic():
    vuln, reason = is_clockinator_version_vulnerable(1, 0, 9)
    assert vuln is True
    assert "CVE-2026-124815" in reason

    safe, _ = is_clockinator_version_vulnerable(1, 1, 0)
    assert safe is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = WPClockinatorLiteAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "1.0.9",
            "source": "Clockinator Lite readme.txt",
            "is_vulnerable": True,
            "reason": "Affected < 1.1.0",
        },
    )
    res = plugin.run_audit("10.0.0.50", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-124815" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "1.1.0",
            "source": "Clockinator Lite readme.txt",
            "is_vulnerable": False,
            "reason": "Patched >= 1.1.0",
        },
    )
    res_safe = plugin.run_audit("10.0.0.50", [443])
    assert res_safe["status"] == "OK"
