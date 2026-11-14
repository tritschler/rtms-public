"""
test_wp_streamit_audit.py - Unit tests for WordPress Streamit Unauthenticated AJAX Authorization Audit (CVE-2026-126119).
"""

from plugins.wordpress.wp_streamit.wp_streamit_cve_2026_126119_audit import (
    WPStreamitAuditPlugin,
    parse_streamit_version,
    is_streamit_version_vulnerable,
)


def test_plugin_metadata():
    plugin = WPStreamitAuditPlugin()
    assert "CVE-2026-126119" in plugin.info["cve"]
    assert plugin.info["severity"] == "CRITICAL"
    assert "Streamit" in plugin.info["name"]


def test_version_parsing():
    html = '<link href="/wp-content/plugins/streamit/assets/css/style.css?ver=1.3.9" />'
    assert parse_streamit_version(html) == (1, 3, 9, "1.3.9")
    assert parse_streamit_version("Stable tag: 1.3.10\n") == (1, 3, 10, "1.3.10")
    assert parse_streamit_version("<html>No plugin</html>") is None


def test_version_vulnerability_logic():
    vuln, reason = is_streamit_version_vulnerable(1, 3, 9)
    assert vuln is True
    assert "CVE-2026-126119" in reason

    safe, _ = is_streamit_version_vulnerable(1, 3, 10)
    assert safe is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = WPStreamitAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "1.3.9",
            "source": "Streamit readme.txt",
            "is_vulnerable": True,
            "reason": "Affected < 1.3.10 (<= 1.3.9)",
        },
    )
    res = plugin.run_audit("10.0.0.50", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-126119" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "1.3.10",
            "source": "Streamit readme.txt",
            "is_vulnerable": False,
            "reason": "Patched >= 1.3.10",
        },
    )
    res_safe = plugin.run_audit("10.0.0.50", [443])
    assert res_safe["status"] == "OK"
