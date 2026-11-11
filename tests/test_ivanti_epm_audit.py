"""
test_ivanti_epm_audit.py - Unit tests for Ivanti Endpoint Manager Version Compliance Audit (CVE-2026-121653).
"""

from plugins.ivanti_epm.ivanti_epm_cve_2026_121653_audit import (
    IvantiEpmAuditPlugin,
    parse_ivanti_epm_version,
    is_ivanti_epm_version_vulnerable,
)


def test_plugin_metadata():
    plugin = IvantiEpmAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-121653"
    assert plugin.info["severity"] == "CRITICAL"
    assert "Ivanti Endpoint Manager" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    assert parse_ivanti_epm_version("Ivanti Endpoint Manager 2024 SU6") == (2024, 6, "2024 SU6")
    assert parse_ivanti_epm_version("Ivanti Endpoint Manager 2024 SU8") == (2024, 8, "2024 SU8")
    assert parse_ivanti_epm_version("Core Version: 11.0.6.5.120") == (2024, 5, "2024 SU5 (11.0.6.5)")
    assert parse_ivanti_epm_version("Core Version: 11.0.5.4") == (2022, 4, "2022 SU4 (11.0.5.4)")
    assert parse_ivanti_epm_version("nginx/1.25.0") is None


def test_version_vulnerability_logic():
    vuln_su7, reason_su7 = is_ivanti_epm_version_vulnerable(2024, 7)
    assert vuln_su7 is True
    assert "CVE-2026-121653" in reason_su7

    vuln_2022, _ = is_ivanti_epm_version_vulnerable(2022, 5)
    assert vuln_2022 is True

    safe_su8, reason_su8 = is_ivanti_epm_version_vulnerable(2024, 8)
    assert safe_su8 is False
    assert "2024 SU8" in reason_su8


def test_inspect_target_port_vulnerable(mocker):
    plugin = IvantiEpmAuditPlugin()
    mocker.patch.object(
        plugin,
        "probe_http_endpoint",
        return_value={
            "port": 443,
            "path": "/remote/",
            "status_code": 200,
            "headers": {"server": "Microsoft-IIS/10.0"},
            "body_snippet": "<html><title>Ivanti Endpoint Manager 2024 SU6</title></html>",
        },
    )

    hit = plugin.inspect_target_port("10.0.0.60", 443)
    assert hit is not None
    assert hit["service_detected"] is True
    assert hit["is_vulnerable"] is True
    assert hit["version"] == "2024 SU6"


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = IvantiEpmAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "2024 SU6",
            "source": "Ivanti EPM Web Console (/remote/)",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-121653",
        },
    )
    res = plugin.run_audit("10.0.0.60", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-121653" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "2024 SU8",
            "source": "Ivanti EPM Web Console (/remote/)",
            "is_vulnerable": False,
            "reason": "Patched >= 2024 SU8",
        },
    )
    res_safe = plugin.run_audit("10.0.0.60", [443])
    assert res_safe["status"] == "OK"
