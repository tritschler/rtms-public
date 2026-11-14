"""
test_wp_base_booking_audit.py - Unit tests for WordPress WP BASE Booking SQL Injection Compliance Audit (CVE-2026-124970).
"""

from plugins.wordpress.wp_base_booking.wp_base_booking_cve_2026_124970_audit import (
    WPBaseBookingAuditPlugin,
    parse_wp_base_booking_version,
    is_wp_base_booking_version_vulnerable,
)


def test_plugin_metadata():
    plugin = WPBaseBookingAuditPlugin()
    assert "CVE-2026-124970" in plugin.info["cve"]
    assert plugin.info["severity"] == "CRITICAL"
    assert "WP" in plugin.info["name"]


def test_version_parsing():
    html = '<link href="/wp-content/plugins/wp-base-booking-of-appointments-services-and-events/assets/css/style.css?ver=6.5.2" />'
    assert parse_wp_base_booking_version(html) == (6, 5, 2, "6.5.2")
    assert parse_wp_base_booking_version("Stable tag: 6.5.3\n") == (6, 5, 3, "6.5.3")
    assert parse_wp_base_booking_version("<html>No plugin</html>") is None


def test_version_vulnerability_logic():
    vuln, reason = is_wp_base_booking_version_vulnerable(6, 5, 2)
    assert vuln is True
    assert "CVE-2026-124970" in reason

    safe, _ = is_wp_base_booking_version_vulnerable(6, 5, 3)
    assert safe is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = WPBaseBookingAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "6.5.2",
            "source": "WP BASE Booking readme.txt",
            "is_vulnerable": True,
            "reason": "Affected <= 6.5.2 (< 6.5.3)",
        },
    )
    res = plugin.run_audit("10.0.0.50", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-124970" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "6.5.3",
            "source": "WP BASE Booking readme.txt",
            "is_vulnerable": False,
            "reason": "Patched >= 6.5.3",
        },
    )
    res_safe = plugin.run_audit("10.0.0.50", [443])
    assert res_safe["status"] == "OK"
