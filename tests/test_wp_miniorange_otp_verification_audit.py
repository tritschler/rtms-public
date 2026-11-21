"""
test_wp_miniorange_otp_verification_audit.py - Unit tests for WordPress miniOrange OTP
Verification Auth Bypass Audit (CVE-2026-129073).
"""

from plugins.wordpress.wp_miniorange_otp_verification.wp_miniorange_otp_verification_cve_2026_129073_audit import (
    WPMiniorangeOtpVerificationAuditPlugin,
    parse_wp_miniorange_otp_version,
    is_wp_miniorange_otp_version_vulnerable,
)


def test_plugin_metadata():
    plugin = WPMiniorangeOtpVerificationAuditPlugin()
    assert "CVE-2026-129073" in plugin.info["cve"]
    assert plugin.info["severity"] == "CRITICAL"
    assert "miniOrange OTP Verification" in plugin.info["name"]


def test_version_parsing():
    html = '<script src="/wp-content/plugins/miniorange-otp-verification/includes/js/settings.min.js?ver=5.6.1"></script>'
    assert parse_wp_miniorange_otp_version(html) == (5, 6, 1, "5.6.1")
    assert parse_wp_miniorange_otp_version("Stable tag: 5.6.2\n") == (5, 6, 2, "5.6.2")
    assert parse_wp_miniorange_otp_version("<html>No plugin</html>") is None


def test_version_vulnerability_logic():
    vuln, reason = is_wp_miniorange_otp_version_vulnerable(5, 6, 1)
    assert vuln is True
    assert "CVE-2026-129073" in reason

    safe, _ = is_wp_miniorange_otp_version_vulnerable(5, 6, 2)
    assert safe is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = WPMiniorangeOtpVerificationAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "5.6.1",
            "source": "miniOrange OTP Verification readme.txt (/wp-content/plugins/miniorange-otp-verification/readme.txt)",
            "is_vulnerable": True,
            "reason": "Affected <= 5.6.1 (< 5.6.2)",
        },
    )
    res = plugin.run_audit("10.0.0.52", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-129073" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "5.6.2",
            "source": "miniOrange OTP Verification readme.txt (/wp-content/plugins/miniorange-otp-verification/readme.txt)",
            "is_vulnerable": False,
            "reason": "Patched >= 5.6.2",
        },
    )
    res_safe = plugin.run_audit("10.0.0.52", [443])
    assert res_safe["status"] == "OK"
