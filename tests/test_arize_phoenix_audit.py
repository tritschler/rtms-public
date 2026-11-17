"""
test_arize_phoenix_audit.py - Unit tests for Arize AI Phoenix Version Compliance Audit
(CVE-2026-53998).
"""

from plugins.arize_phoenix.arize_phoenix_cve_2026_53998_audit import (
    ArizePhoenixAuditPlugin,
    parse_arize_phoenix_version,
    is_arize_phoenix_version_vulnerable,
)


def test_plugin_metadata():
    plugin = ArizePhoenixAuditPlugin()
    assert "CVE-2026-53998" in plugin.info["cve"]
    assert plugin.info["severity"] == "CRITICAL"
    assert "Phoenix" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    assert parse_arize_phoenix_version("Arize-Phoenix/15.6.0") == (15, 6, 0, "15.6.0")
    assert parse_arize_phoenix_version('{"phoenixVersion": "14.2.1"}') == (14, 2, 1, "14.2.1")
    assert parse_arize_phoenix_version("nginx/1.26.0") is None


def test_version_vulnerability_logic():
    vuln_156, reason_156 = is_arize_phoenix_version_vulnerable(15, 6, 0)
    assert vuln_156 is True
    assert "CVE-2026-53998" in reason_156

    safe_157, _ = is_arize_phoenix_version_vulnerable(15, 7, 0)
    assert safe_157 is False

    safe_12, _ = is_arize_phoenix_version_vulnerable(12, 9, 0)
    assert safe_12 is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = ArizePhoenixAuditPlugin()
    plugin.discovered_ports = [6006]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 6006,
            "service_detected": True,
            "version": "15.6.0",
            "source": "HTTP Root Page (/)",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-53998 (13.0.0 - < 15.7.0)",
        },
    )
    res = plugin.run_audit("10.0.0.89", [6006])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-53998" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 6006,
            "service_detected": True,
            "version": "15.7.0",
            "source": "HTTP Root Page (/)",
            "is_vulnerable": False,
            "reason": "Patched >= 15.7.0",
        },
    )
    res_safe = plugin.run_audit("10.0.0.89", [6006])
    assert res_safe["status"] == "OK"
