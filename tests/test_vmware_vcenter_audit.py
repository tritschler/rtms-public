"""
test_vmware_vcenter_audit.py - Unit tests for VMware vCenter Server Directory Service Auth Bypass Audit
(CVE-2026-123890).
"""

from plugins.vmware_vcenter.vmware_vcenter_cve_2026_123890_audit import (
    VMwareVCenterAuditPlugin,
    parse_vcenter_version,
    is_vcenter_version_vulnerable,
)


def test_plugin_metadata():
    plugin = VMwareVCenterAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-123890"
    assert plugin.info["severity"] == "CRITICAL"
    assert "vCenter" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    assert parse_vcenter_version("VMware vCenter Server 9.1.1.0100") == (
        9,
        1,
        1,
        100,
        "9.1.1.0100",
    )
    assert parse_vcenter_version("VMware vCenter Server 8.0 U3l") == (
        8,
        0,
        3,
        12,
        "8.0 U3l",
    )
    assert parse_vcenter_version("<version>9.0.2.0200</version>") == (
        9,
        0,
        2,
        200,
        "9.0.2.0200",
    )
    assert parse_vcenter_version("Apache/2.4.58") is None


def test_version_vulnerability_logic():
    vuln_91, reason = is_vcenter_version_vulnerable(9, 1, 1, 100, "9.1.1.0100")
    assert vuln_91 is True
    assert "CVE-2026-123890" in reason

    vuln_90, _ = is_vcenter_version_vulnerable(9, 0, 1, 100, "9.0.1.0100")
    assert vuln_90 is True

    vuln_80, _ = is_vcenter_version_vulnerable(8, 0, 3, 12, "8.0 U3l")
    assert vuln_80 is True

    vuln_5, _ = is_vcenter_version_vulnerable(5, 2, 4, 0, "5.2.4")
    assert vuln_5 is True

    safe_91, _ = is_vcenter_version_vulnerable(9, 1, 1, 200, "9.1.1.0200")
    assert safe_91 is False

    safe_90, _ = is_vcenter_version_vulnerable(9, 0, 2, 200, "9.0.2.0200")
    assert safe_90 is False

    safe_80, _ = is_vcenter_version_vulnerable(8, 0, 3, 13, "8.0 U3m")
    assert safe_80 is False

    safe_5, _ = is_vcenter_version_vulnerable(5, 2, 5, 0, "5.2.5")
    assert safe_5 is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = VMwareVCenterAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "9.1.1.0100",
            "source": "vCenter SDK vimServiceVersions.xml",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-123890",
        },
    )
    res = plugin.run_audit("10.0.0.99", [443])
    assert res["status"] == "Vulnerable"
    assert "9.1.1.0100" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "9.1.1.0200",
            "source": "vCenter SDK vimServiceVersions.xml",
            "is_vulnerable": False,
            "reason": "Patched >= 9.1.1.0200",
        },
    )
    res_safe = plugin.run_audit("10.0.0.99", [443])
    assert res_safe["status"] == "OK"
