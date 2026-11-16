"""
test_wp_estatik_audit.py - Unit tests for WordPress Estatik Local File Inclusion Audit
(CVE-2026-125795).
"""

from plugins.wordpress.wp_estatik.wp_estatik_cve_2026_125795_audit import (
    WPEstatikAuditPlugin,
    parse_estatik_version,
    is_estatik_version_vulnerable,
)


def test_plugin_metadata():
    plugin = WPEstatikAuditPlugin()
    assert "CVE-2026-125795" in plugin.info["cve"]
    assert plugin.info["severity"] == "CRITICAL"
    assert "Estatik" in plugin.info["name"]


def test_version_parsing():
    html = '<link href="/wp-content/plugins/estatik/build/public/css/estatik.min.css?ver=4.3.6" />'
    assert parse_estatik_version(html) == (4, 3, 6, "4.3.6")
    assert parse_estatik_version("Stable tag: 4.3.7\n") == (4, 3, 7, "4.3.7")
    assert parse_estatik_version("<html>No plugin</html>") is None


def test_version_vulnerability_logic():
    vuln, reason = is_estatik_version_vulnerable(4, 3, 6)
    assert vuln is True
    assert "CVE-2026-125795" in reason

    safe, _ = is_estatik_version_vulnerable(4, 3, 7)
    assert safe is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = WPEstatikAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "4.3.6",
            "source": "Estatik readme.txt",
            "is_vulnerable": True,
            "reason": "Affected <= 4.3.6 (< 4.3.7)",
        },
    )
    res = plugin.run_audit("10.0.0.53", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-125795" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "4.3.7",
            "source": "Estatik readme.txt",
            "is_vulnerable": False,
            "reason": "Patched >= 4.3.7",
        },
    )
    res_safe = plugin.run_audit("10.0.0.53", [443])
    assert res_safe["status"] == "OK"
