"""
test_wp_advance_guest_post_audit.py - Unit tests for WordPress Advance Guest Post File Upload Validation Audit (CVE-2026-118063, CVE-2026-118064).
"""

from plugins.wordpress.wp_advance_guest_post.wp_advance_guest_post_cve_2026_118063_audit import (
    WPAdvanceGuestPostAuditPlugin,
    parse_advance_guest_post_version,
    is_advance_guest_post_version_vulnerable,
)


def test_plugin_metadata():
    plugin = WPAdvanceGuestPostAuditPlugin()
    assert "CVE-2026-118063" in plugin.info["cve"]
    assert plugin.info["severity"] == "CRITICAL"
    assert "Advance" in plugin.info["name"]


def test_version_parsing():
    html = '<link href="/wp-content/plugins/advance-guest-post/assets/css/style.css?ver=1.9.0" />'
    assert parse_advance_guest_post_version(html) == (1, 9, 0, "1.9.0")
    assert parse_advance_guest_post_version("Stable tag: 1.9.1\n") == (1, 9, 1, "1.9.1")
    assert parse_advance_guest_post_version("<html>No plugin</html>") is None


def test_version_vulnerability_logic():
    vuln, reason = is_advance_guest_post_version_vulnerable(1, 9, 0)
    assert vuln is True
    assert "CVE-2026-118063" in reason

    safe, _ = is_advance_guest_post_version_vulnerable(1, 9, 1)
    assert safe is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = WPAdvanceGuestPostAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "1.9.0",
            "source": "Advance Guest Post readme.txt",
            "is_vulnerable": True,
            "reason": "Affected <= 1.9 (< 1.9.1)",
        },
    )
    res = plugin.run_audit("10.0.0.50", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-118063" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "1.9.1",
            "source": "Advance Guest Post readme.txt",
            "is_vulnerable": False,
            "reason": "Patched >= 1.9.1",
        },
    )
    res_safe = plugin.run_audit("10.0.0.50", [443])
    assert res_safe["status"] == "OK"
