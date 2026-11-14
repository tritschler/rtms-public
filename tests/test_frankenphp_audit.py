"""
test_frankenphp_audit.py - Unit tests for FrankenPHP Version Compliance Audit
(CVE-2026-128014, CVE-2026-128023, CVE-2026-128027).
"""

from plugins.frankenphp.frankenphp_cve_2026_128014_audit import (
    FrankenPHPAuditPlugin,
    parse_frankenphp_version,
    is_frankenphp_version_vulnerable,
)


def test_plugin_metadata():
    plugin = FrankenPHPAuditPlugin()
    assert "CVE-2026-128014" in plugin.info["cve"]
    assert "CVE-2026-128023" in plugin.info["cve"]
    assert "CVE-2026-128027" in plugin.info["cve"]
    assert plugin.info["severity"] == "CRITICAL"
    assert "FrankenPHP" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    assert parse_frankenphp_version("Server: Caddy FrankenPHP/1.12.0") == (1, 12, 0, "1.12.0")
    assert parse_frankenphp_version("FrankenPHP v1.13.2") == (1, 13, 2, "1.13.2")
    assert parse_frankenphp_version('{"frankenphp_version": "1.1.10"}') == (1, 1, 10, "1.1.10")
    assert parse_frankenphp_version("nginx/1.26.0") is None


def test_version_vulnerability_logic():
    vuln_110, reason_110 = is_frankenphp_version_vulnerable(1, 1, 10)
    assert vuln_110 is True
    assert "CVE-2026-128027" in reason_110
    assert "CVE-2026-128023" in reason_110

    vuln_112, reason_112 = is_frankenphp_version_vulnerable(1, 12, 0)
    assert vuln_112 is True
    assert "CVE-2026-128023" in reason_112
    assert "CVE-2026-128014" in reason_112

    vuln_1131, reason_1131 = is_frankenphp_version_vulnerable(1, 13, 1)
    assert vuln_1131 is True
    assert "CVE-2026-128014" in reason_1131
    assert "CVE-2026-128023" not in reason_1131

    safe_1132, reason_1132 = is_frankenphp_version_vulnerable(1, 13, 2)
    assert safe_1132 is False
    assert "patched" in reason_1132


def test_inspect_target_port_vulnerable(mocker):
    plugin = FrankenPHPAuditPlugin()
    mocker.patch.object(
        plugin,
        "probe_http_endpoint",
        return_value={
            "port": 8080,
            "path": "/",
            "status_code": 200,
            "headers": {"server": "Caddy FrankenPHP/1.12.1"},
            "body_snippet": "<html>OK</html>",
        },
    )

    hit = plugin.inspect_target_port("10.0.0.80", 8080)
    assert hit is not None
    assert hit["service_detected"] is True
    assert hit["is_vulnerable"] is True
    assert hit["version"] == "1.12.1"


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = FrankenPHPAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "1.12.1",
            "source": "HTTP Root Banner (/)",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-128023, CVE-2026-128014",
        },
    )
    res = plugin.run_audit("10.0.0.80", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-128014" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "1.13.2",
            "source": "HTTP Root Banner (/)",
            "is_vulnerable": False,
            "reason": "Patched >= 1.13.2",
        },
    )
    res_safe = plugin.run_audit("10.0.0.80", [443])
    assert res_safe["status"] == "OK"
