"""
test_splunk_enterprise_audit.py - Unit tests for Splunk Enterprise & SOAR Multi-CVE Version Compliance Audit
(CVE-2026-76536, CVE-2026-76535, CVE-2026-131253, CVE-2026-131287, CVE-2026-131202).
"""

from plugins.splunk_enterprise.splunk_enterprise_cve_2026_76536_audit import (
    SplunkEnterpriseAuditPlugin,
    parse_splunk_version,
    is_splunk_version_vulnerable,
)


def test_plugin_metadata():
    plugin = SplunkEnterpriseAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-76536"
    assert plugin.info["severity"] == "CRITICAL"
    assert "Splunk" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    assert parse_splunk_version("Splunk Enterprise 10.4.4") == (
        "enterprise",
        10,
        4,
        4,
        "10.4.4",
    )
    assert parse_splunk_version("Splunk SOAR 8.7.2") == (
        "soar",
        8,
        7,
        2,
        "8.7.2",
    )
    assert parse_splunk_version("Splunk Enterprise Security 8.6.1") == (
        "enterprise_security",
        8,
        6,
        1,
        "8.6.1",
    )
    assert parse_splunk_version("Apache/2.4.58") is None


def test_version_vulnerability_logic():
    vuln_94, reason = is_splunk_version_vulnerable(9, 4, 16, "9.4.16", product="enterprise")
    assert vuln_94 is True
    assert "CVE-2026-76536" in reason

    vuln_104, _ = is_splunk_version_vulnerable(10, 4, 4, "10.4.4", product="enterprise")
    assert vuln_104 is True

    vuln_106, reason_106 = is_splunk_version_vulnerable(10, 6, 0, "10.6.0", product="enterprise")
    assert vuln_106 is True
    assert "CVE-2026-76535" in reason_106

    vuln_soar, reason_soar = is_splunk_version_vulnerable(8, 7, 1, "8.7.1", product="soar")
    assert vuln_soar is True
    assert "CVE-2026-131253" in reason_soar

    vuln_es, reason_es = is_splunk_version_vulnerable(8, 6, 0, "8.6.0", product="enterprise_security")
    assert vuln_es is True
    assert "CVE-2026-131202" in reason_es

    safe_104, _ = is_splunk_version_vulnerable(10, 4, 5, "10.4.5", product="enterprise")
    assert safe_104 is False

    safe_106, _ = is_splunk_version_vulnerable(10, 6, 1, "10.6.1", product="enterprise")
    assert safe_106 is False

    safe_soar, _ = is_splunk_version_vulnerable(8, 8, 0, "8.8.0", product="soar")
    assert safe_soar is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = SplunkEnterpriseAuditPlugin()
    plugin.discovered_ports = [8000]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 8000,
            "service_detected": True,
            "product": "enterprise",
            "version": "10.4.4",
            "source": "Splunk Web Login Page",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-76536",
        },
    )
    res = plugin.run_audit("10.0.0.80", [8000])
    assert res["status"] == "Vulnerable"
    assert "10.4.4" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 8000,
            "service_detected": True,
            "product": "enterprise",
            "version": "10.4.5",
            "source": "Splunk Web Login Page",
            "is_vulnerable": False,
            "reason": "Patched >= 10.4.5",
        },
    )
    res_safe = plugin.run_audit("10.0.0.80", [8000])
    assert res_safe["status"] == "OK"
