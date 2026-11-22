"""
test_surrealdb_audit.py - Unit tests for SurrealDB Embedded JS Capability Bypass
Compliance Audit (CVE-2026-134292).
"""

from plugins.surrealdb.surrealdb_cve_2026_134292_audit import (
    SurrealDbAuditPlugin,
    parse_surrealdb_version,
    is_surrealdb_version_vulnerable,
)


def test_plugin_metadata():
    plugin = SurrealDbAuditPlugin()
    assert "CVE-2026-134292" in plugin.info["cve"]
    assert plugin.info["severity"] == "CRITICAL"
    assert "SurrealDB" in plugin.info["name"]


def test_version_parsing():
    assert parse_surrealdb_version("surrealdb-2.1.4+20261001") == (2, 1, 4, "2.1.4")
    assert parse_surrealdb_version("Server: SurrealDB/3.0.2") == (3, 0, 2, "3.0.2")
    assert parse_surrealdb_version("<html>Not surreal</html>") is None


def test_version_vulnerability_logic():
    vuln, reason = is_surrealdb_version_vulnerable(3, 0, 2)
    assert vuln is True
    assert "CVE-2026-134292" in reason

    safe, _ = is_surrealdb_version_vulnerable(4, 0, 0)
    assert safe is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = SurrealDbAuditPlugin()
    plugin.discovered_ports = [8000]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 8000,
            "service_detected": True,
            "version": "3.0.2",
            "source": "SurrealDB Version Endpoint (/version)",
            "is_vulnerable": True,
            "reason": "Affected >= 1.0.0, < 4.0.0",
        },
    )
    res = plugin.run_audit("10.0.0.65", [8000])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-134292" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 8000,
            "service_detected": True,
            "version": "4.0.0",
            "source": "SurrealDB Version Endpoint (/version)",
            "is_vulnerable": False,
            "reason": "Patched >= 4.0.0",
        },
    )
    res_safe = plugin.run_audit("10.0.0.65", [8000])
    assert res_safe["status"] == "OK"
