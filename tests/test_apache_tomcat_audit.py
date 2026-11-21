"""
test_apache_tomcat_audit.py - Unit tests for Apache Tomcat Multi-CVE Version Compliance Audit
(CVE-2026-133325, CVE-2026-118028, CVE-2026-116561, CVE-2026-95517).
"""

from plugins.apache_tomcat.apache_tomcat_cve_2026_133325_audit import (
    ApacheTomcatAuditPlugin,
    parse_apache_tomcat_version,
    is_apache_tomcat_version_vulnerable,
)


def test_plugin_metadata():
    plugin = ApacheTomcatAuditPlugin()
    assert "CVE-2026-133325" in plugin.info["cve"]
    assert plugin.info["severity"] == "CRITICAL"
    assert "Apache Tomcat" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    assert parse_apache_tomcat_version("<h3>Apache Tomcat/11.0.29</h3>") == (11, 0, 29, "", "11.0.29")
    assert parse_apache_tomcat_version("Apache Tomcat Version 10.1.62") == (10, 1, 62, "", "10.1.62")
    assert parse_apache_tomcat_version("Apache Tomcat/9.0.0.M1") == (9, 0, 0, "M1", "9.0.0-M1")
    assert parse_apache_tomcat_version("Server: nginx/1.30.7") is None


def test_version_vulnerability_logic():
    vuln_11_cluster, reason_11 = is_apache_tomcat_version_vulnerable(11, 0, 29, "", "11.0.29")
    assert vuln_11_cluster is True
    assert "CVE-2026-133325" in reason_11

    vuln_11_ear, reason_11_ear = is_apache_tomcat_version_vulnerable(11, 0, 27, "", "11.0.27")
    assert vuln_11_ear is True
    assert "CVE-2026-118028" in reason_11_ear

    vuln_10, reason_10 = is_apache_tomcat_version_vulnerable(10, 1, 62, "", "10.1.62")
    assert vuln_10 is True
    assert "CVE-2026-133325" in reason_10

    vuln_9, reason_9 = is_apache_tomcat_version_vulnerable(9, 0, 123, "", "9.0.123")
    assert vuln_9 is True
    assert "CVE-2026-95517" in reason_9

    vuln_eol, _ = is_apache_tomcat_version_vulnerable(8, 5, 100, "", "8.5.100")
    assert vuln_eol is True

    safe_11, _ = is_apache_tomcat_version_vulnerable(11, 0, 30, "", "11.0.30")
    assert safe_11 is False

    safe_10, _ = is_apache_tomcat_version_vulnerable(10, 1, 63, "", "10.1.63")
    assert safe_10 is False

    safe_9, _ = is_apache_tomcat_version_vulnerable(9, 0, 125, "", "9.0.125")
    assert safe_9 is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = ApacheTomcatAuditPlugin()
    plugin.discovered_ports = [8080]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 8080,
            "service_detected": True,
            "version": "11.0.29",
            "source": "HTTP Root Banner (/)",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-133325",
        },
    )
    res = plugin.run_audit("10.0.0.15", [8080])
    assert res["status"] == "Vulnerable"
    assert "11.0.29" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 8080,
            "service_detected": True,
            "version": "11.0.30",
            "source": "HTTP Root Banner (/)",
            "is_vulnerable": False,
            "reason": "Patched >= 11.0.30",
        },
    )
    res_safe = plugin.run_audit("10.0.0.15", [8080])
    assert res_safe["status"] == "OK"
