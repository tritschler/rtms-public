"""
test_citrix_netscaler_audit.py - Unit tests for Citrix NetScaler Console & ADC Gateway Version Compliance Audit
(CVE-2026-120869, CVE-2026-107412, CVE-2026-107415, CVE-2026-120868).
"""

from plugins.citrix_netscaler.citrix_netscaler_cve_2026_120869_audit import (
    CitrixNetScalerAuditPlugin,
    parse_netscaler_version,
    is_netscaler_version_vulnerable,
)


def test_plugin_metadata():
    plugin = CitrixNetScalerAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-120869"
    assert plugin.info["severity"] == "CRITICAL"
    assert "NetScaler" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    assert parse_netscaler_version("NetScaler NS14.1-34.42.nc") == (14, 1, 34, 42, "14.1-34.42")
    assert parse_netscaler_version("NetScaler Console 13.1-52.19") == (13, 1, 52, 19, "13.1-52.19")
    assert parse_netscaler_version("Apache/2.4.58") is None


def test_version_vulnerability_logic():
    vuln_141, reason_141 = is_netscaler_version_vulnerable(14, 1, 34, 42)
    assert vuln_141 is True
    assert "CVE-2026-120869" in reason_141
    assert "CVE-2026-107412" in reason_141

    vuln_adc_141, reason_adc_141 = is_netscaler_version_vulnerable(14, 1, 66, 58)
    assert vuln_adc_141 is True
    assert "CVE-2026-107412" in reason_adc_141

    safe_141, _ = is_netscaler_version_vulnerable(14, 1, 73, 57)
    assert safe_141 is False

    vuln_131, _ = is_netscaler_version_vulnerable(13, 1, 52, 19)
    assert vuln_131 is True

    safe_131, _ = is_netscaler_version_vulnerable(13, 1, 64, 39)
    assert safe_131 is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = CitrixNetScalerAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "14.1-34.42",
            "source": "Citrix NITRO v1 config/nsversion endpoint",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-120869 & CVE-2026-107412",
        },
    )
    res = plugin.run_audit("10.0.0.20", [443])
    assert res["status"] == "Vulnerable"
    assert "14.1-34.42" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "14.1-73.57",
            "source": "Citrix NITRO v1 config/nsversion endpoint",
            "is_vulnerable": False,
            "reason": "Patched >= 14.1-73.57",
        },
    )
    res_safe = plugin.run_audit("10.0.0.20", [443])
    assert res_safe["status"] == "OK"
