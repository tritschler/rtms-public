"""
test_postgres_enterprise_manager_audit.py - Unit tests for Postgres Enterprise Manager (PEM)
Multi-CVE Version Compliance Audit (CVE-2026-132660, CVE-2026-132659, CVE-2026-132658).
"""

from plugins.postgres_enterprise_manager.postgres_enterprise_manager_cve_2026_132660_audit import (
    PostgresEnterpriseManagerAuditPlugin,
    parse_pem_version,
    is_pem_version_vulnerable,
)


def test_plugin_metadata():
    plugin = PostgresEnterpriseManagerAuditPlugin()
    assert "CVE-2026-132660" in plugin.info["cve"]
    assert plugin.info["severity"] == "CRITICAL"
    assert "Postgres Enterprise Manager" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    assert parse_pem_version("Postgres Enterprise Manager v10.6.0") == (10, 6, 0, "10.6.0")
    assert parse_pem_version('<script src="/pem/static/js/generated/pem.js?ver=100600"></script>') == (10, 6, 0, "10.6.0")
    assert parse_pem_version('"pem_version": "10.6.1"') == (10, 6, 1, "10.6.1")
    assert parse_pem_version("<html>Generic Page</html>") is None


def test_version_vulnerability_logic():
    vuln, reason = is_pem_version_vulnerable(10, 6, 0)
    assert vuln is True
    assert "CVE-2026-132660" in reason

    safe, _ = is_pem_version_vulnerable(10, 6, 1)
    assert safe is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = PostgresEnterpriseManagerAuditPlugin()
    plugin.discovered_ports = [8443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 8443,
            "service_detected": True,
            "version": "10.6.0",
            "source": "PEM Web Login Page (/pem/login)",
            "is_vulnerable": True,
            "reason": "Affected < 10.6.1",
        },
    )
    res = plugin.run_audit("10.0.0.22", [8443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-132660" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 8443,
            "service_detected": True,
            "version": "10.6.1",
            "source": "PEM Web Login Page (/pem/login)",
            "is_vulnerable": False,
            "reason": "Patched >= 10.6.1",
        },
    )
    res_safe = plugin.run_audit("10.0.0.22", [8443])
    assert res_safe["status"] == "OK"
