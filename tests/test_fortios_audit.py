"""
test_fortios_audit.py - Unit tests for Fortinet FortiOS Version Compliance Audit (CVE-2026-126259).
"""

from plugins.fortios.fortios_cve_2026_126259_audit import (
    FortiOSAuditPlugin,
    parse_fortios_version,
    is_fortios_version_vulnerable,
)


def test_plugin_metadata():
    plugin = FortiOSAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-126259"
    assert plugin.info["severity"] == "CRITICAL"
    assert "FortiOS" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    assert parse_fortios_version("FortiOS v7.6.6-build3510") == (7, 6, 6, "7.6.6")
    assert parse_fortios_version('window.fgt_version = "7.4.12";') == (7, 4, 12, "7.4.12")
    assert parse_fortios_version("FortiGate-VM64 v8.0.1") == (8, 0, 1, "8.0.1")
    assert parse_fortios_version("nginx/1.24.0") is None


def test_version_vulnerability_logic():
    vuln_70, reason_70 = is_fortios_version_vulnerable(7, 0, 19)
    assert vuln_70 is True
    assert "CVE-2026-126259" in reason_70

    safe_70, _ = is_fortios_version_vulnerable(7, 0, 20)
    assert safe_70 is False

    vuln_72, _ = is_fortios_version_vulnerable(7, 2, 13)
    assert vuln_72 is True

    safe_72, _ = is_fortios_version_vulnerable(7, 2, 14)
    assert safe_72 is False

    vuln_74, _ = is_fortios_version_vulnerable(7, 4, 12)
    assert vuln_74 is True

    safe_74, _ = is_fortios_version_vulnerable(7, 4, 13)
    assert safe_74 is False

    vuln_76, _ = is_fortios_version_vulnerable(7, 6, 7)
    assert vuln_76 is True

    safe_76, _ = is_fortios_version_vulnerable(7, 6, 8)
    assert safe_76 is False

    vuln_80_0, _ = is_fortios_version_vulnerable(8, 0, 0)
    assert vuln_80_0 is True

    vuln_80_1, _ = is_fortios_version_vulnerable(8, 0, 1)
    assert vuln_80_1 is True

    safe_80_2, _ = is_fortios_version_vulnerable(8, 0, 2)
    assert safe_80_2 is False


def test_inspect_target_port_vulnerable(mocker):
    plugin = FortiOSAuditPlugin()
    mocker.patch.object(
        plugin,
        "probe_http_endpoint",
        return_value={
            "port": 443,
            "path": "/login",
            "status_code": 200,
            "headers": {"server": "xxxxxxxx-xxxxx"},
            "body_snippet": "<html><title>FortiGate</title><script>var fgt_version='7.6.6';</script></html>",
        },
    )

    hit = plugin.inspect_target_port("10.0.0.1", 443)
    assert hit is not None
    assert hit["service_detected"] is True
    assert hit["is_vulnerable"] is True
    assert hit["version"] == "7.6.6"


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = FortiOSAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "7.6.6",
            "source": "FortiOS administrative /login portal",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-126259",
        },
    )
    res = plugin.run_audit("10.0.0.1", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-126259" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "7.6.8",
            "source": "FortiOS administrative /login portal",
            "is_vulnerable": False,
            "reason": "Patched >= 7.6.8",
        },
    )
    res_safe = plugin.run_audit("10.0.0.1", [443])
    assert res_safe["status"] == "OK"
