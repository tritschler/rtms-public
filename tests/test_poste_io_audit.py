"""
test_poste_io_audit.py - Unit tests for Poste.io Mail Server DMARC Processing RCE
Compliance Audit (CVE-2026-127027).
"""

from plugins.poste_io.poste_io_cve_2026_127027_audit import (
    PosteIoAuditPlugin,
    parse_poste_io_version,
    is_poste_io_version_vulnerable,
)


def test_plugin_metadata():
    plugin = PosteIoAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-127027"
    assert plugin.info["severity"] == "CRITICAL"
    assert "Poste.io" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    assert parse_poste_io_version("Poste.io PRO 2.5.21") == (2, 5, 21, "2.5.21")
    assert parse_poste_io_version("x-poste-version: 2.5.22") == (2, 5, 22, "2.5.22")
    assert parse_poste_io_version("<html>Generic Mail</html>") is None


def test_version_vulnerability_logic():
    vuln, reason = is_poste_io_version_vulnerable(2, 5, 21)
    assert vuln is True
    assert "CVE-2026-127027" in reason

    safe, _ = is_poste_io_version_vulnerable(2, 5, 22)
    assert safe is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = PosteIoAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "2.5.21",
            "source": "Poste.io Admin Login (/admin/login)",
            "is_vulnerable": True,
            "reason": "Affected < 2.5.22",
        },
    )
    res = plugin.run_audit("10.0.0.35", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-127027" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "2.5.22",
            "source": "Poste.io Admin Login (/admin/login)",
            "is_vulnerable": False,
            "reason": "Patched >= 2.5.22",
        },
    )
    res_safe = plugin.run_audit("10.0.0.35", [443])
    assert res_safe["status"] == "OK"
