"""
test_wp_duplicate_audit.py - Unit tests for WordPress WP Duplicate Migration Plugin RCE Audit (CVE-2026-14492).
"""

from plugins.wordpress.wp_duplicate.wp_duplicate_cve_2026_14492_audit import (
    WPDuplicateAuditPlugin,
    parse_wp_duplicate_version,
    is_wp_duplicate_version_vulnerable,
)


def test_plugin_metadata():
    plugin = WPDuplicateAuditPlugin()
    assert "CVE-2026-14492" in plugin.info["cve"]
    assert plugin.info["severity"] == "CRITICAL"
    assert "WP Duplicate" in plugin.info["name"]


def test_version_parsing():
    html = '<script src="/wp-content/plugins/local-sync/admin/js/local-sync.js?ver=1.1.11"></script>'
    assert parse_wp_duplicate_version(html) == (1, 1, 11, "1.1.11")
    assert parse_wp_duplicate_version("Stable tag: 1.1.12\n") == (1, 1, 12, "1.1.12")
    assert parse_wp_duplicate_version("<html>No plugin</html>") is None


def test_version_vulnerability_logic():
    vuln, reason = is_wp_duplicate_version_vulnerable(1, 1, 11)
    assert vuln is True
    assert "CVE-2026-14492" in reason

    safe, _ = is_wp_duplicate_version_vulnerable(1, 1, 12)
    assert safe is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = WPDuplicateAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "1.1.11",
            "source": "WP Duplicate readme.txt (/wp-content/plugins/local-sync/readme.txt)",
            "is_vulnerable": True,
            "reason": "Affected <= 1.1.11 (< 1.1.12)",
        },
    )
    res = plugin.run_audit("10.0.0.51", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-14492" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "1.1.12",
            "source": "WP Duplicate readme.txt (/wp-content/plugins/local-sync/readme.txt)",
            "is_vulnerable": False,
            "reason": "Patched >= 1.1.12",
        },
    )
    res_safe = plugin.run_audit("10.0.0.51", [443])
    assert res_safe["status"] == "OK"
