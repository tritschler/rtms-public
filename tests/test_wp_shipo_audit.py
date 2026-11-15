"""
test_wp_shipo_audit.py - Unit tests for WordPress Shipo Authentication Bypass Audit (CVE-2026-19907).
"""

from plugins.wordpress.wp_shipo.wp_shipo_cve_2026_19907_audit import (
    WPShipoAuditPlugin,
    parse_shipo_version,
    is_shipo_version_vulnerable,
)


def test_plugin_metadata():
    plugin = WPShipoAuditPlugin()
    assert "CVE-2026-19907" in plugin.info["cve"]
    assert plugin.info["severity"] == "CRITICAL"
    assert "Shipo" in plugin.info["name"]


def test_version_parsing():
    html = '<link href="/wp-content/plugins/shipo/assets/css/style.css?ver=1.8.0" />'
    assert parse_shipo_version(html) == (1, 8, 0, "1.8.0")
    assert parse_shipo_version("Stable tag: 1.8.1\n") == (1, 8, 1, "1.8.1")
    assert parse_shipo_version("<html>No plugin</html>") is None


def test_version_vulnerability_logic():
    vuln, reason = is_shipo_version_vulnerable(1, 8, 0)
    assert vuln is True
    assert "CVE-2026-19907" in reason

    vuln_16, _ = is_shipo_version_vulnerable(1, 6, 0)
    assert vuln_16 is True

    safe, _ = is_shipo_version_vulnerable(1, 8, 1)
    assert safe is False

    safe_old, _ = is_shipo_version_vulnerable(1, 5, 9)
    assert safe_old is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = WPShipoAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "1.8.0",
            "source": "Shipo readme.txt",
            "is_vulnerable": True,
            "reason": "Affected 1.6 through 1.8.0 (< 1.8.1)",
        },
    )
    res = plugin.run_audit("10.0.0.50", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-19907" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "1.8.1",
            "source": "Shipo readme.txt",
            "is_vulnerable": False,
            "reason": "Patched >= 1.8.1",
        },
    )
    res_safe = plugin.run_audit("10.0.0.50", [443])
    assert res_safe["status"] == "OK"
