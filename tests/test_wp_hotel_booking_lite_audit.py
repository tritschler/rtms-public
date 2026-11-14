"""
test_wp_hotel_booking_lite_audit.py - Unit tests for WordPress Hotel Booking Lite Unrestricted File Upload Audit (CVE-2026-125851).
"""

from plugins.wordpress.wp_hotel_booking_lite.wp_hotel_booking_lite_cve_2026_125851_audit import (
    WPHotelBookingLiteAuditPlugin,
    parse_hotel_booking_lite_version,
    is_hotel_booking_lite_version_vulnerable,
)


def test_plugin_metadata():
    plugin = WPHotelBookingLiteAuditPlugin()
    assert "CVE-2026-125851" in plugin.info["cve"]
    assert plugin.info["severity"] == "CRITICAL"
    assert "Hotel" in plugin.info["name"]


def test_version_parsing():
    html = '<link href="/wp-content/plugins/hotel-booking-lite/assets/css/style.css?ver=2.5.1" />'
    assert parse_hotel_booking_lite_version(html) == (2, 5, 1, "2.5.1")
    assert parse_hotel_booking_lite_version("Stable tag: 2.5.2\n") == (2, 5, 2, "2.5.2")
    assert parse_hotel_booking_lite_version("<html>No plugin</html>") is None


def test_version_vulnerability_logic():
    vuln, reason = is_hotel_booking_lite_version_vulnerable(2, 5, 1)
    assert vuln is True
    assert "CVE-2026-125851" in reason

    safe, _ = is_hotel_booking_lite_version_vulnerable(2, 5, 2)
    assert safe is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = WPHotelBookingLiteAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "2.5.1",
            "source": "Hotel Booking Lite readme.txt",
            "is_vulnerable": True,
            "reason": "Affected <= 2.5.1 (< 2.5.2)",
        },
    )
    res = plugin.run_audit("10.0.0.50", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-125851" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "2.5.2",
            "source": "Hotel Booking Lite readme.txt",
            "is_vulnerable": False,
            "reason": "Patched >= 2.5.2",
        },
    )
    res_safe = plugin.run_audit("10.0.0.50", [443])
    assert res_safe["status"] == "OK"
