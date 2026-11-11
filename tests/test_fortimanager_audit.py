"""
test_fortimanager_audit.py - Unit tests for Fortinet FortiManager Version Compliance Audit (CVE-2026-126261).
"""

from plugins.fortimanager.fortimanager_cve_2026_126261_audit import (
    FortiManagerAuditPlugin,
    parse_fortimanager_version,
    is_fortimanager_version_vulnerable,
)


def test_plugin_metadata():
    plugin = FortiManagerAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-126261"
    assert plugin.info["severity"] == "CRITICAL"
    assert "FortiManager" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    assert parse_fortimanager_version("FortiManager v7.6.5-build3412") == (7, 6, 5, "7.6.5")
    assert parse_fortimanager_version('window.fmg_version = "7.4.4";') == (7, 4, 4, "7.4.4")
    assert parse_fortimanager_version("FortiManager-VM64 v8.0.0") == (8, 0, 0, "8.0.0")
    assert parse_fortimanager_version("Apache/2.4.58") is None


def test_version_vulnerability_logic():
    vuln_76, reason_76 = is_fortimanager_version_vulnerable(7, 6, 7)
    assert vuln_76 is True
    assert "CVE-2026-126261" in reason_76

    safe_76, _ = is_fortimanager_version_vulnerable(7, 6, 8)
    assert safe_76 is False

    vuln_74, _ = is_fortimanager_version_vulnerable(7, 4, 5)
    assert vuln_74 is True

    safe_74, _ = is_fortimanager_version_vulnerable(7, 4, 6)
    assert safe_74 is False

    vuln_72, _ = is_fortimanager_version_vulnerable(7, 2, 8)
    assert vuln_72 is True

    safe_72, _ = is_fortimanager_version_vulnerable(7, 2, 9)
    assert safe_72 is False

    vuln_80, _ = is_fortimanager_version_vulnerable(8, 0, 0)
    assert vuln_80 is True

    safe_80, _ = is_fortimanager_version_vulnerable(8, 0, 1)
    assert safe_80 is False


def test_inspect_target_port_vulnerable(mocker):
    plugin = FortiManagerAuditPlugin()
    mocker.patch.object(
        plugin,
        "probe_http_endpoint",
        return_value={
            "port": 443,
            "path": "/p/login/",
            "status_code": 200,
            "headers": {"server": "HTTPS Server"},
            "body_snippet": "<html><title>FortiManager</title><script>var FMG_VERSION='7.6.6';</script></html>",
        },
    )

    hit = plugin.inspect_target_port("10.0.0.50", 443)
    assert hit is not None
    assert hit["service_detected"] is True
    assert hit["is_vulnerable"] is True
    assert hit["version"] == "7.6.6"


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = FortiManagerAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "7.6.6",
            "source": "FortiManager /p/login/ web portal",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-126261",
        },
    )
    res = plugin.run_audit("10.0.0.50", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-126261" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "7.6.8",
            "source": "FortiManager /p/login/ web portal",
            "is_vulnerable": False,
            "reason": "Patched >= 7.6.8",
        },
    )
    res_safe = plugin.run_audit("10.0.0.50", [443])
    assert res_safe["status"] == "OK"
