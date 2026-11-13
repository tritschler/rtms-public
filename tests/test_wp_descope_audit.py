"""
test_wp_descope_audit.py - Unit tests for WordPress Descope Authentication Bypass Compliance Audit (CVE-2026-110959).
"""

from plugins.wordpress.wp_descope.wp_descope_cve_2026_110959_audit import (
    WPDescopeAuditPlugin,
    parse_descope_version,
    is_descope_version_vulnerable,
)


def test_plugin_metadata():
    plugin = WPDescopeAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-110959"
    assert plugin.info["severity"] == "CRITICAL"
    assert "Descope" in plugin.info["name"]


def test_version_parsing():
    html = '<script src="/wp-content/plugins/descope/public/js/descope-public.js?ver=1.1.4"></script>'
    assert parse_descope_version(html) == (1, 1, 4, "1.1.4")
    assert parse_descope_version("Stable tag: 1.2.0\n") == (1, 2, 0, "1.2.0")
    assert parse_descope_version("<html>No plugin</html>") is None


def test_version_vulnerability_logic():
    vuln, reason = is_descope_version_vulnerable(1, 1, 4)
    assert vuln is True
    assert "CVE-2026-110959" in reason

    safe, _ = is_descope_version_vulnerable(1, 2, 0)
    assert safe is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = WPDescopeAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "1.1.4",
            "source": "Descope plugin readme.txt",
            "is_vulnerable": True,
            "reason": "Affected < 1.2.0",
        },
    )
    res = plugin.run_audit("10.0.0.52", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-110959" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "1.2.0",
            "source": "Descope plugin readme.txt",
            "is_vulnerable": False,
            "reason": "Patched >= 1.2.0",
        },
    )
    res_safe = plugin.run_audit("10.0.0.52", [443])
    assert res_safe["status"] == "OK"
