"""
test_sogo_groupware_audit.py - Unit tests for Alinto SOGo Groupware SAML & Sieve Version Compliance Audit (CVE-2026-127131).
"""

from plugins.sogo_groupware.sogo_cve_2026_127131_audit import (
    SogoGroupwareAuditPlugin,
    parse_sogo_version,
    is_sogo_version_vulnerable,
)


def test_plugin_metadata():
    plugin = SogoGroupwareAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-127131"
    assert plugin.info["severity"] == "CRITICAL"
    assert "SOGo" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    assert parse_sogo_version("SOGo 5.12.5") == (5, 12, 5, "5.12.5")
    assert parse_sogo_version("/SOGo.woa/WebServerResources/5.12.12/js/Main.js") == (5, 12, 12, "5.12.12")
    assert parse_sogo_version('sogoVersion = "2.4.6"') == (2, 4, 6, "2.4.6")
    assert parse_sogo_version("nginx/1.24.0") is None


def test_version_vulnerability_logic():
    vuln_5, reason_5 = is_sogo_version_vulnerable(5, 12, 12)
    assert vuln_5 is True
    assert "CVE-2026-127131" in reason_5

    safe_5, _ = is_sogo_version_vulnerable(5, 12, 13)
    assert safe_5 is False

    vuln_2, reason_2 = is_sogo_version_vulnerable(2, 4, 6)
    assert vuln_2 is True
    assert "CVE-2026-127131" in reason_2


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = SogoGroupwareAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "5.12.12",
            "source": "SOGo webmail portal (/SOGo/)",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-127131",
        },
    )
    res = plugin.run_audit("10.0.0.40", [443])
    assert res["status"] == "Vulnerable"
    assert "5.12.12" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "5.12.13",
            "source": "SOGo webmail portal (/SOGo/)",
            "is_vulnerable": False,
            "reason": "Patched >= 5.12.13",
        },
    )
    res_safe = plugin.run_audit("10.0.0.40", [443])
    assert res_safe["status"] == "OK"
