"""
test_wp_latepoint_audit.py - Unit tests for WordPress LatePoint Authentication Bypass Audit Tool (CVE-2026-118066).
"""

import pytest

from plugins.wordpress.wp_latepoint.wp_latepoint_cve_2026_118066_audit import (
    WPLatePointAuditPlugin,
    parse_latepoint_version,
    is_latepoint_version_vulnerable,
)


def test_plugin_metadata():
    plugin = WPLatePointAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-118066"
    assert plugin.info["severity"] == "CRITICAL"
    assert "LatePoint" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    html_snippet = (
        '<link rel="stylesheet" href="https://example.com/wp-content/plugins/'
        'latepoint/public/stylesheets/front.css?ver=5.7.6" />'
    )
    assert parse_latepoint_version(html_snippet) == (5, 7, 6, "5.7.6")
    assert parse_latepoint_version("Stable tag: 5.7.5\n") == (5, 7, 5, "5.7.5")
    assert parse_latepoint_version("= 5.7.7 =\n* Security fix") == (5, 7, 7, "5.7.7")
    assert parse_latepoint_version("<html>WordPress</html>") is None


def test_version_vulnerability_logic():
    vuln, reason = is_latepoint_version_vulnerable(5, 7, 6)
    assert vuln is True
    assert "CVE-2026-118066" in reason

    vuln, _ = is_latepoint_version_vulnerable(5, 2, 0)
    assert vuln is True

    vuln, reason = is_latepoint_version_vulnerable(5, 7, 7)
    assert vuln is False
    assert "patched" in reason


def test_inspect_target_port_vulnerable_html_asset(mocker):
    plugin = WPLatePointAuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 443,
        "path": "/",
        "status_code": 200,
        "headers": {},
        "body_snippet": (
            '<html><head><link href="/wp-content/plugins/latepoint/public/stylesheets/front.css?ver=5.7.6">'
            '</head><body>Booking</body></html>'
        )
    })

    hit = plugin.inspect_target_port("192.168.1.22", 443)
    assert hit is not None
    assert hit["plugin_detected"] is True
    assert hit["is_vulnerable"] is True
    assert hit["version"] == "5.7.6"


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = WPLatePointAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(plugin, "inspect_target_port", return_value={
        "port": 443,
        "plugin_detected": True,
        "version": "5.7.6",
        "source": "LatePoint readme.txt",
        "is_vulnerable": True,
        "reason": "Vulnerable <= 5.7.6",
    })
    res = plugin.run_audit("10.0.0.82", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-118066" in res["proof"]

    mocker.patch.object(plugin, "inspect_target_port", return_value={
        "port": 443,
        "plugin_detected": True,
        "version": "5.7.7",
        "source": "LatePoint readme.txt",
        "is_vulnerable": False,
        "reason": "Patched >= 5.7.7",
    })
    res_safe = plugin.run_audit("10.0.0.82", [443])
    assert res_safe["status"] == "OK"
