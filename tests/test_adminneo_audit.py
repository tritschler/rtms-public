"""
test_adminneo_audit.py - Unit tests for AdminNeo Version Compliance Audit
(CVE-2026-130366 / CVE-2026-130380).
"""

from plugins.adminneo.adminneo_cve_2026_130366_audit import (
    AdminNeoAuditPlugin,
    parse_adminneo_version,
    is_adminneo_version_vulnerable,
)


def test_plugin_metadata():
    plugin = AdminNeoAuditPlugin()
    assert "CVE-2026-130366" in plugin.info["cve"]
    assert plugin.info["severity"] == "CRITICAL"
    assert "AdminNeo" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    assert parse_adminneo_version("AdminNeo 5.9.0") == (5, 9, 0, "5.9.0")
    assert parse_adminneo_version('<span class="version">5.8.2</span>') == (5, 8, 2, "5.8.2")
    assert parse_adminneo_version("AdminNeo/5.9.1") == (5, 9, 1, "5.9.1")
    assert parse_adminneo_version("nginx/1.26.0") is None


def test_version_vulnerability_logic():
    vuln_590, reason_590 = is_adminneo_version_vulnerable(5, 9, 0)
    assert vuln_590 is True
    assert "CVE-2026-130366" in reason_590
    assert "CVE-2026-130380" in reason_590

    safe_591, reason_591 = is_adminneo_version_vulnerable(5, 9, 1)
    assert safe_591 is False
    assert "patched" in reason_591


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = AdminNeoAuditPlugin()
    plugin.discovered_ports = [8080]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 8080,
            "service_detected": True,
            "version": "5.9.0",
            "source": "HTTP Root Page (/)",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-130366 and CVE-2026-130380 (< 5.9.1)",
        },
    )
    res = plugin.run_audit("10.0.0.88", [8080])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-130366" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 8080,
            "service_detected": True,
            "version": "5.9.1",
            "source": "HTTP Root Page (/)",
            "is_vulnerable": False,
            "reason": "Patched >= 5.9.1",
        },
    )
    res_safe = plugin.run_audit("10.0.0.88", [8080])
    assert res_safe["status"] == "OK"
