"""
test_f5_bigip_audit.py - Unit tests for F5 BIG-IP TMOS & APM Version Compliance Audit
(CVE-2026-123637, CVE-2026-120722, CVE-2026-121805, CVE-2026-116953,
CVE-2026-120292, CVE-2026-120285, CVE-2026-120718).
"""

from plugins.f5_bigip.f5_bigip_cve_2026_123637_audit import (
    F5BigIpAuditPlugin,
    parse_bigip_version,
    is_bigip_version_vulnerable,
)


def test_plugin_metadata():
    plugin = F5BigIpAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-123637"
    assert plugin.info["severity"] == "CRITICAL"
    assert "BIG-IP" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    assert parse_bigip_version("BIG-IP 17.5.1.4 Build 0.0.12") == (
        17,
        5,
        1,
        4,
        "17.5.1.4",
    )
    assert parse_bigip_version('"version": "21.1.0.1"') == (
        21,
        1,
        0,
        1,
        "21.1.0.1",
    )
    assert parse_bigip_version("Apache/2.4.58") is None


def test_version_vulnerability_logic():
    vuln_175, reason = is_bigip_version_vulnerable(17, 5, 1, 4, "17.5.1.4")
    assert vuln_175 is True
    assert "CVE-2026-123637" in reason
    assert "CVE-2026-120718" in reason

    vuln_171, _ = is_bigip_version_vulnerable(17, 1, 3, 2, "17.1.3.2")
    assert vuln_171 is True

    vuln_211, _ = is_bigip_version_vulnerable(21, 1, 0, 1, "21.1.0.1")
    assert vuln_211 is True

    safe_175, _ = is_bigip_version_vulnerable(17, 5, 1, 10, "17.5.1.10")
    assert safe_175 is False

    safe_171, _ = is_bigip_version_vulnerable(17, 1, 3, 6, "17.1.3.6")
    assert safe_171 is False

    safe_211, _ = is_bigip_version_vulnerable(21, 1, 0, 2, "21.1.0.2")
    assert safe_211 is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = F5BigIpAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "17.5.1.4",
            "source": "BIG-IP TMUI Configuration Utility",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-123637",
        },
    )
    res = plugin.run_audit("10.0.0.245", [443])
    assert res["status"] == "Vulnerable"
    assert "17.5.1.4" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "17.5.1.10",
            "source": "BIG-IP TMUI Configuration Utility",
            "is_vulnerable": False,
            "reason": "Patched >= 17.5.1.10",
        },
    )
    res_safe = plugin.run_audit("10.0.0.245", [443])
    assert res_safe["status"] == "OK"
