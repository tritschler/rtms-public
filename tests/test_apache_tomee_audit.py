"""
test_apache_tomee_audit.py - Unit tests for Apache TomEE & OpenEJB Version Compliance Audit
(CVE-2026-87756 and related OpenEJB CVEs).
"""

from plugins.apache_tomee.apache_tomee_cve_2026_87756_audit import (
    ApacheTomEEAuditPlugin,
    parse_apache_tomee_version,
    is_apache_tomee_version_vulnerable,
)


def test_plugin_metadata():
    plugin = ApacheTomEEAuditPlugin()
    assert "CVE-2026-87756" in plugin.info["cve"]
    assert plugin.info["severity"] == "CRITICAL"
    assert "TomEE" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    assert parse_apache_tomee_version("Apache TomEE/10.2.0") == (10, 2, 0, "", "10.2.0")
    assert parse_apache_tomee_version("Apache TomEE 11.0.0-M1") == (11, 0, 0, "M1", "11.0.0-M1")
    assert parse_apache_tomee_version("OpenEJB/4.7.5") == (4, 7, 5, "", "4.7.5")
    assert parse_apache_tomee_version("Apache/2.4.58") is None


def test_version_vulnerability_logic():
    vuln_102, reason_102 = is_apache_tomee_version_vulnerable(10, 2, 0)
    assert vuln_102 is True
    assert "CVE-2026-87756" in reason_102
    assert "CVE-2026-111264" in reason_102

    vuln_11m1, _ = is_apache_tomee_version_vulnerable(11, 0, 0, "M1", "11.0.0-M1")
    assert vuln_11m1 is True

    safe_103, _ = is_apache_tomee_version_vulnerable(10, 3, 0)
    assert safe_103 is False

    safe_11m2, _ = is_apache_tomee_version_vulnerable(11, 0, 0, "M2", "11.0.0-M2")
    assert safe_11m2 is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = ApacheTomEEAuditPlugin()
    plugin.discovered_ports = [8080]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 8080,
            "service_detected": True,
            "version": "10.2.0",
            "source": "HTTP Root Banner (/)",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-87756 (< 10.3.0)",
        },
    )
    res = plugin.run_audit("10.0.0.90", [8080])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-87756" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 8080,
            "service_detected": True,
            "version": "10.3.0",
            "source": "HTTP Root Banner (/)",
            "is_vulnerable": False,
            "reason": "Patched >= 10.3.0",
        },
    )
    res_safe = plugin.run_audit("10.0.0.90", [8080])
    assert res_safe["status"] == "OK"
