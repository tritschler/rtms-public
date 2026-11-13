"""
test_azul_payara_audit.py - Unit tests for Azul Payara Server & Micro Version Compliance Audit
(CVE-2026-110003 & CVE-2026-90908).
"""

from plugins.azul_payara.azul_payara_cve_2026_110003_audit import (
    AzulPayaraAuditPlugin,
    parse_payara_version,
    is_payara_version_vulnerable,
)


def test_plugin_metadata():
    plugin = AzulPayaraAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-110003"
    assert plugin.info["severity"] == "CRITICAL"
    assert "Payara" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    assert parse_payara_version("Server: Payara Server  6.43.0 #badassfish") == ([6, 43, 0], "6.43.0")
    assert parse_payara_version("Payara Micro 7.2026.10") == ([7, 2026, 10], "7.2026.10")
    assert parse_payara_version('{"payaraVersion": "Payara Server 5.93.0"}') == ([5, 93, 0], "5.93.0")
    assert parse_payara_version("Apache/2.4.58") is None


def test_version_vulnerability_logic():
    vuln_6, reason_6 = is_payara_version_vulnerable([6, 43, 0], "6.43.0")
    assert vuln_6 is True
    assert "CVE-2026-110003" in reason_6

    safe_6, _ = is_payara_version_vulnerable([6, 44, 0], "6.44.0")
    assert safe_6 is False

    vuln_7_comm, _ = is_payara_version_vulnerable([7, 2026, 10], "7.2026.10")
    assert vuln_7_comm is True

    safe_7_comm, _ = is_payara_version_vulnerable([7, 2026, 11], "7.2026.11")
    assert safe_7_comm is False

    vuln_7_ent, _ = is_payara_version_vulnerable([7, 5, 0], "7.5.0")
    assert vuln_7_ent is True

    safe_7_ent, _ = is_payara_version_vulnerable([7, 6, 0], "7.6.0")
    assert safe_7_ent is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = AzulPayaraAuditPlugin()
    plugin.discovered_ports = [4848]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 4848,
            "service_detected": True,
            "version": "6.43.0",
            "source": "Payara Management REST version endpoint",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-110003 & CVE-2026-90908",
        },
    )
    res = plugin.run_audit("10.0.0.48", [4848])
    assert res["status"] == "Vulnerable"
    assert "6.43.0" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 4848,
            "service_detected": True,
            "version": "6.44.0",
            "source": "Payara Management REST version endpoint",
            "is_vulnerable": False,
            "reason": "Patched >= 6.44.0",
        },
    )
    res_safe = plugin.run_audit("10.0.0.48", [4848])
    assert res_safe["status"] == "OK"
