"""
test_imgproxy_audit.py - Unit tests for imgproxy Version Compliance Audit (CVE-2026-123614).
"""

from plugins.imgproxy.imgproxy_cve_2026_123614_audit import (
    ImgproxyAuditPlugin,
    parse_imgproxy_version,
    is_imgproxy_version_vulnerable,
)


def test_plugin_metadata():
    plugin = ImgproxyAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-123614"
    assert plugin.info["severity"] == "CRITICAL"
    assert "imgproxy" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    assert parse_imgproxy_version("imgproxy/4.0.12") == (4, 0, 12, "4.0.12")
    assert parse_imgproxy_version('{"status":"ok","version":"4.0.16"}') == (4, 0, 16, "4.0.16")
    assert parse_imgproxy_version("nginx/1.24.0") is None


def test_version_vulnerability_logic():
    vuln_4012, reason_4012 = is_imgproxy_version_vulnerable(4, 0, 12)
    assert vuln_4012 is True
    assert "CVE-2026-123614" in reason_4012

    vuln_4016, reason_4016 = is_imgproxy_version_vulnerable(4, 0, 16)
    assert vuln_4016 is False
    assert "4.0.16" in reason_4016

    vuln_3, _ = is_imgproxy_version_vulnerable(3, 24, 0)
    assert vuln_3 is False


def test_inspect_target_port_vulnerable(mocker):
    plugin = ImgproxyAuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 8080,
        "path": "/health",
        "status_code": 200,
        "headers": {"server": "imgproxy/4.0.14"},
        "body_snippet": "imgproxy is running",
    })

    hit = plugin.inspect_target_port("10.0.0.70", 8080)
    assert hit is not None
    assert hit["service_detected"] is True
    assert hit["is_vulnerable"] is True
    assert hit["version"] == "4.0.14"


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = ImgproxyAuditPlugin()
    plugin.discovered_ports = [8080]

    mocker.patch.object(plugin, "inspect_target_port", return_value={
        "port": 8080,
        "service_detected": True,
        "version": "4.0.14",
        "source": "imgproxy /health endpoint",
        "is_vulnerable": True,
        "reason": "Affected 4.0.0 to 4.0.15",
    })
    res = plugin.run_audit("10.0.0.70", [8080])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-123614" in res["proof"]

    mocker.patch.object(plugin, "inspect_target_port", return_value={
        "port": 8080,
        "service_detected": True,
        "version": "4.0.16",
        "source": "imgproxy /health endpoint",
        "is_vulnerable": False,
        "reason": "Patched >= 4.0.16",
    })
    res_safe = plugin.run_audit("10.0.0.70", [8080])
    assert res_safe["status"] == "OK"
