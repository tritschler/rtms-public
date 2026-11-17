"""
test_opencti_audit.py - Unit tests for OpenCTI Platform Version Compliance Audit
(CVE-2026-104840).
"""

from plugins.opencti.opencti_cve_2026_104840_audit import (
    OpenCTIAuditPlugin,
    parse_opencti_version,
    is_opencti_version_vulnerable,
)


def test_plugin_metadata():
    plugin = OpenCTIAuditPlugin()
    assert "CVE-2026-104840" in plugin.info["cve"]
    assert plugin.info["severity"] == "CRITICAL"
    assert "OpenCTI" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    assert parse_opencti_version("OpenCTI/7.260420.0") == (7, 260420, 0, "7.260420.0")
    assert parse_opencti_version("OpenCTI v6.5.2") == (6, 5, 2, "6.5.2")
    assert parse_opencti_version('{"opencti_version": "7.260428.0"}') == (7, 260428, 0, "7.260428.0")
    assert parse_opencti_version("nginx/1.26.0") is None


def test_version_vulnerability_logic():
    vuln_old, reason_old = is_opencti_version_vulnerable(6, 5, 2)
    assert vuln_old is True
    assert "CVE-2026-104840" in reason_old

    vuln_7, _ = is_opencti_version_vulnerable(7, 260427, 0)
    assert vuln_7 is True

    safe_patched, reason_safe = is_opencti_version_vulnerable(7, 260428, 0)
    assert safe_patched is False
    assert "patched" in reason_safe


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = OpenCTIAuditPlugin()
    plugin.discovered_ports = [4000]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 4000,
            "service_detected": True,
            "version": "6.5.2",
            "source": "HTTP Root Banner (/)",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-104840 (< 7.260428.0)",
        },
    )
    res = plugin.run_audit("10.0.0.86", [4000])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-104840" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 4000,
            "service_detected": True,
            "version": "7.260428.0",
            "source": "HTTP Root Banner (/)",
            "is_vulnerable": False,
            "reason": "Patched >= 7.260428.0",
        },
    )
    res_safe = plugin.run_audit("10.0.0.86", [4000])
    assert res_safe["status"] == "OK"
