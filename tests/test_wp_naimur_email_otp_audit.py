"""
test_wp_naimur_email_otp_audit.py - Unit tests for WordPress Naimur Email OTP Verification Audit Tool (CVE-2026-104014).
"""

import pytest

from plugins.wordpress.wp_naimur_email_otp.wp_naimur_email_otp_cve_2026_104014_audit import (
    WPNaimurEmailOTPAuditPlugin,
    parse_naimur_email_otp_version,
    is_naimur_email_otp_version_vulnerable,
)


def test_plugin_metadata():
    plugin = WPNaimurEmailOTPAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-104014"
    assert plugin.info["severity"] == "CRITICAL"
    assert "Naimur Email OTP" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    html_snippet = (
        '<script src="https://example.com/wp-content/plugins/'
        'naimur-email-otp-verification-for-woocommerce/assets/js/frontend.js?ver=2.1.0"></script>'
    )
    assert parse_naimur_email_otp_version(html_snippet) == (2, 1, 0, "2.1.0")
    assert parse_naimur_email_otp_version("Stable tag: 2.0.5\nLicense: GPLv2") == (2, 0, 5, "2.0.5")
    assert parse_naimur_email_otp_version("= 2.1.1 =\n* Fixed security issue") == (2, 1, 1, "2.1.1")
    assert parse_naimur_email_otp_version("<html>WordPress</html>") is None
    assert parse_naimur_email_otp_version("") is None


def test_version_vulnerability_logic():
    vuln, reason = is_naimur_email_otp_version_vulnerable(2, 1, 0)
    assert vuln is True
    assert "CVE-2026-104014" in reason

    vuln, _ = is_naimur_email_otp_version_vulnerable(1, 9, 4)
    assert vuln is True

    vuln, reason = is_naimur_email_otp_version_vulnerable(2, 1, 1)
    assert vuln is False
    assert "patched" in reason


def test_check_requirements():
    plugin = WPNaimurEmailOTPAuditPlugin()
    assert plugin.check_requirements("10.0.0.10", [80, 443]) is True
    assert plugin.check_requirements("10.0.0.10", [22, 3306]) is False


def test_inspect_target_port_vulnerable_readme(mocker):
    plugin = WPNaimurEmailOTPAuditPlugin()

    def side_effect(target_ip, port, path="/", timeout=4.0):
        if path == "/":
            return {
                "port": port,
                "path": "/",
                "status_code": 200,
                "headers": {},
                "body_snippet": "<html><head><link href='/wp-content/themes/storefront/style.css'></head></html>",
            }
        if path == "/wp-content/plugins/naimur-email-otp-verification-for-woocommerce/readme.txt":
            return {
                "port": port,
                "path": path,
                "status_code": 200,
                "headers": {},
                "body_snippet": "=== Naimur Email OTP Verification for WooCommerce ===\nStable tag: 2.1.0\n",
            }
        return None

    mocker.patch.object(plugin, "probe_http_endpoint", side_effect=side_effect)
    hit = plugin.inspect_target_port("192.168.1.20", 443)
    assert hit is not None
    assert hit["plugin_detected"] is True
    assert hit["is_vulnerable"] is True
    assert hit["version"] == "2.1.0"


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = WPNaimurEmailOTPAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(plugin, "inspect_target_port", return_value={
        "port": 443,
        "plugin_detected": True,
        "version": "2.1.0",
        "source": "Plugin readme.txt",
        "is_vulnerable": True,
        "reason": "Vulnerable <= 2.1.0",
    })
    res = plugin.run_audit("10.0.0.80", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-104014" in res["proof"]

    mocker.patch.object(plugin, "inspect_target_port", return_value={
        "port": 443,
        "plugin_detected": True,
        "version": "2.1.1",
        "source": "Plugin readme.txt",
        "is_vulnerable": False,
        "reason": "Patched >= 2.1.1",
    })
    res_safe = plugin.run_audit("10.0.0.80", [443])
    assert res_safe["status"] == "OK"
