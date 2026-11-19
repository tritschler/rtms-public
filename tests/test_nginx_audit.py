"""
test_nginx_audit.py - Unit tests for NGINX Open Source & NGINX Plus Version Compliance Audit
(CVE-2026-121810, CVE-2026-123007, CVE-2026-113425, CVE-2026-123634, CVE-2026-123633).
"""

from plugins.nginx.nginx_cve_2026_121810_audit import (
    NginxAuditPlugin,
    parse_nginx_version,
    is_nginx_version_vulnerable,
)


def test_plugin_metadata():
    plugin = NginxAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-121810"
    assert plugin.info["severity"] == "CRITICAL"
    assert "NGINX" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    assert parse_nginx_version("Server: nginx/1.30.4") == (1, 30, 4, "1.30.4")
    assert parse_nginx_version("<hr><center>nginx/1.31.6 (Ubuntu)</center>") == (1, 31, 6, "1.31.6")
    assert parse_nginx_version("Server: Apache/2.4.58") is None


def test_version_vulnerability_logic():
    vuln_stable, reason = is_nginx_version_vulnerable(1, 30, 4, "1.30.4")
    assert vuln_stable is True
    assert "CVE-2026-121810" in reason
    assert "CVE-2026-123007" in reason

    vuln_mainline, reason_ml = is_nginx_version_vulnerable(1, 31, 6, "1.31.6")
    assert vuln_mainline is True
    assert "CVE-2026-123633" in reason_ml

    safe_stable, _ = is_nginx_version_vulnerable(1, 30, 7, "1.30.7")
    assert safe_stable is False

    safe_mainline, _ = is_nginx_version_vulnerable(1, 31, 9, "1.31.9")
    assert safe_mainline is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = NginxAuditPlugin()
    plugin.discovered_ports = [80]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 80,
            "service_detected": True,
            "version": "1.30.4",
            "source": "HTTP Server Header",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-121810",
        },
    )
    res = plugin.run_audit("10.0.0.80", [80])
    assert res["status"] == "Vulnerable"
    assert "1.30.4" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 80,
            "service_detected": True,
            "version": "1.30.7",
            "source": "HTTP Server Header",
            "is_vulnerable": False,
            "reason": "Patched >= 1.30.7",
        },
    )
    res_safe = plugin.run_audit("10.0.0.80", [80])
    assert res_safe["status"] == "OK"
