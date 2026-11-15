"""
test_dokploy_audit.py - Unit tests for Dokploy PaaS Version Compliance Audit
(CVE-2026-129433).
"""

from plugins.dokploy.dokploy_cve_2026_129433_audit import (
    DokployAuditPlugin,
    parse_dokploy_version,
    is_dokploy_version_vulnerable,
)


def test_plugin_metadata():
    plugin = DokployAuditPlugin()
    assert "CVE-2026-129433" in plugin.info["cve"]
    assert plugin.info["severity"] == "CRITICAL"
    assert "Dokploy" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    assert parse_dokploy_version("Dokploy/0.30.4") == (0, 30, 4, "0.30.4")
    assert parse_dokploy_version("Dokploy v0.31.1") == (0, 31, 1, "0.31.1")
    assert parse_dokploy_version('{"dokploy_version": "0.31.0"}') == (0, 31, 0, "0.31.0")
    assert parse_dokploy_version("nginx/1.26.0") is None


def test_version_vulnerability_logic():
    vuln_0310, reason_0310 = is_dokploy_version_vulnerable(0, 31, 0)
    assert vuln_0310 is True
    assert "CVE-2026-129433" in reason_0310

    safe_0311, reason_0311 = is_dokploy_version_vulnerable(0, 31, 1)
    assert safe_0311 is False
    assert "patched" in reason_0311


def test_inspect_target_port_vulnerable(mocker):
    plugin = DokployAuditPlugin()
    mocker.patch.object(
        plugin,
        "probe_http_endpoint",
        return_value={
            "port": 3000,
            "path": "/",
            "status_code": 200,
            "headers": {"x-powered-by": "Dokploy/0.31.0"},
            "body_snippet": "<html><title>Dokploy</title></html>",
        },
    )

    hit = plugin.inspect_target_port("10.0.0.85", 3000)
    assert hit is not None
    assert hit["service_detected"] is True
    assert hit["is_vulnerable"] is True
    assert hit["version"] == "0.31.0"


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = DokployAuditPlugin()
    plugin.discovered_ports = [3000]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 3000,
            "service_detected": True,
            "version": "0.31.0",
            "source": "HTTP Root Banner (/)",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-129433 (< 0.31.1)",
        },
    )
    res = plugin.run_audit("10.0.0.85", [3000])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-129433" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 3000,
            "service_detected": True,
            "version": "0.31.1",
            "source": "HTTP Root Banner (/)",
            "is_vulnerable": False,
            "reason": "Patched >= 0.31.1",
        },
    )
    res_safe = plugin.run_audit("10.0.0.85", [3000])
    assert res_safe["status"] == "OK"
