"""
test_php_fpm_audit.py - Unit tests for PHP & PHP-FPM Multi-CVE Version Compliance Audit
(CVE-2026-129289, CVE-2026-129496, CVE-2026-129481, CVE-2026-129474,
CVE-2026-129182, CVE-2026-126714, CVE-2026-115560).
"""

from plugins.php_fpm.php_fpm_cve_2026_129289_audit import (
    PhpFpmAuditPlugin,
    parse_php_version,
    is_php_version_vulnerable,
)


def test_plugin_metadata():
    plugin = PhpFpmAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-129289"
    assert plugin.info["severity"] == "CRITICAL"
    assert "PHP" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    assert parse_php_version("x-powered-by: PHP/8.4.27") == (8, 4, 27, "8.4.27")
    assert parse_php_version("Server: Apache/2.4.62 PHP/8.3.35-1~deb12u1") == (8, 3, 35, "8.3.35")
    assert parse_php_version("Server: nginx/1.30.7") is None


def test_version_vulnerability_logic():
    vuln_82, reason_82 = is_php_version_vulnerable(8, 2, 35, "8.2.35")
    assert vuln_82 is True
    assert "CVE-2026-129289" in reason_82

    vuln_83, _ = is_php_version_vulnerable(8, 3, 36, "8.3.36")
    assert vuln_83 is True

    vuln_84, _ = is_php_version_vulnerable(8, 4, 27, "8.4.27")
    assert vuln_84 is True

    vuln_85, reason_85 = is_php_version_vulnerable(8, 5, 12, "8.5.12")
    assert vuln_85 is True
    assert "CVE-2026-129474" in reason_85

    safe_82, _ = is_php_version_vulnerable(8, 2, 36, "8.2.36")
    assert safe_82 is False

    safe_83, _ = is_php_version_vulnerable(8, 3, 37, "8.3.37")
    assert safe_83 is False

    safe_84, _ = is_php_version_vulnerable(8, 4, 28, "8.4.28")
    assert safe_84 is False

    safe_85, _ = is_php_version_vulnerable(8, 5, 13, "8.5.13")
    assert safe_85 is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = PhpFpmAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "8.4.27",
            "source": "HTTP Response Headers (X-Powered-By / Server)",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-129289",
        },
    )
    res = plugin.run_audit("10.0.0.12", [443])
    assert res["status"] == "Vulnerable"
    assert "8.4.27" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "8.4.28",
            "source": "HTTP Response Headers (X-Powered-By / Server)",
            "is_vulnerable": False,
            "reason": "Patched >= 8.4.28",
        },
    )
    res_safe = plugin.run_audit("10.0.0.12", [443])
    assert res_safe["status"] == "OK"
