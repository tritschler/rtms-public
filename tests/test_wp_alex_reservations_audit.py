"""
test_wp_alex_reservations_audit.py - Unit tests for WordPress Alex Reservations SQL Injection Compliance Audit (CVE-2026-124415).
"""

from plugins.wordpress.wp_alex_reservations.wp_alex_reservations_cve_2026_124415_audit import (
    WPAlexReservationsAuditPlugin,
    parse_alex_reservations_version,
    is_alex_reservations_version_vulnerable,
)


def test_plugin_metadata():
    plugin = WPAlexReservationsAuditPlugin()
    assert "CVE-2026-124415" in plugin.info["cve"]
    assert plugin.info["severity"] == "CRITICAL"
    assert "Alex" in plugin.info["name"]


def test_version_parsing():
    html = '<link href="/wp-content/plugins/alex-reservations/assets/css/style.css?ver=2.4.8" />'
    assert parse_alex_reservations_version(html) == (2, 4, 8, "2.4.8")
    assert parse_alex_reservations_version("Stable tag: 2.4.9\n") == (2, 4, 9, "2.4.9")
    assert parse_alex_reservations_version("<html>No plugin</html>") is None


def test_version_vulnerability_logic():
    vuln, reason = is_alex_reservations_version_vulnerable(2, 4, 8)
    assert vuln is True
    assert "CVE-2026-124415" in reason

    safe, _ = is_alex_reservations_version_vulnerable(2, 4, 9)
    assert safe is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = WPAlexReservationsAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "2.4.8",
            "source": "Alex Reservations readme.txt",
            "is_vulnerable": True,
            "reason": "Affected <= 2.4.8 (< 2.4.9)",
        },
    )
    res = plugin.run_audit("10.0.0.50", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-124415" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "2.4.9",
            "source": "Alex Reservations readme.txt",
            "is_vulnerable": False,
            "reason": "Patched >= 2.4.9",
        },
    )
    res_safe = plugin.run_audit("10.0.0.50", [443])
    assert res_safe["status"] == "OK"
