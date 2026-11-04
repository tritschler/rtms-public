"""
test_sonicwall_gms_audit.py - Unit tests for SonicWall Global Management System (GMS) Audit Tool (CVE-2026-109593).
"""

from plugins.sonicwall_gms.sonicwall_gms_cve_2026_109593_audit import (
    SonicWallGmsAuditPlugin,
    parse_sonicwall_gms_version,
    is_sonicwall_gms_vulnerable,
)


def test_plugin_metadata():
    plugin = SonicWallGmsAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-109593"
    assert plugin.info["severity"] == "CRITICAL"
    assert "SonicWall" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"
    assert 443 in plugin.target_ports
    assert 8443 in plugin.target_ports


def test_version_parsing():
    assert parse_sonicwall_gms_version(
        "<html><title>SonicWall Global Management System 9.5.2</title></html>"
    ) == (9, 5, 2, "9.5.2")
    assert parse_sonicwall_gms_version(
        '<script src="/sgms/js/app.js?v=9.4.1"></script>'
    ) == (9, 4, 1, "9.4.1")
    assert parse_sonicwall_gms_version(
        "SonicWall GMS v9.5.3"
    ) == (9, 5, 3, "9.5.3")
    assert parse_sonicwall_gms_version("<html>Apache Server</html>") is None
    assert parse_sonicwall_gms_version("") is None


def test_version_vulnerability_logic():
    vuln, reason = is_sonicwall_gms_vulnerable(9, 5, 2, "9.5.2")
    assert vuln is True
    assert "CVE-2026-109593" in reason

    vuln, _ = is_sonicwall_gms_vulnerable(9, 4, 0, "9.4.0")
    assert vuln is True

    vuln, reason = is_sonicwall_gms_vulnerable(9, 5, 3, "9.5.3")
    assert vuln is False
    assert "patched" in reason


def test_check_requirements():
    plugin = SonicWallGmsAuditPlugin()
    assert plugin.check_requirements("10.0.0.50", [443, 8443]) is True
    assert 8443 in plugin.discovered_ports
    assert plugin.check_requirements("10.0.0.50", {9443: {"name": "sonicwall-sgms"}}) is True
    assert 9443 in plugin.discovered_ports
    assert plugin.check_requirements("10.0.0.50", [22, 25]) is False


def test_inspect_target_port_vulnerable(mocker):
    plugin = SonicWallGmsAuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 8443,
        "path": "/sgms/login",
        "status_code": 200,
        "headers": {"set-cookie": "JSESSIONID=ABCD; Path=/sgms"},
        "body_snippet": "<html><title>SonicWall Global Management System 9.5.2</title></html>"
    })

    hit = plugin.inspect_target_port("10.0.0.80", 8443)
    assert hit is not None
    assert hit["gms_detected"] is True
    assert hit["is_vulnerable"] is True
    assert hit["version"] == "9.5.2"


def test_inspect_target_port_patched(mocker):
    plugin = SonicWallGmsAuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 443,
        "path": "/sgms/login",
        "status_code": 200,
        "headers": {"set-cookie": "JSESSIONID=ABCD; Path=/sgms"},
        "body_snippet": "<html><title>SonicWall Global Management System 9.5.3</title></html>"
    })

    hit = plugin.inspect_target_port("10.0.0.81", 443)
    assert hit is not None
    assert hit["gms_detected"] is True
    assert hit["is_vulnerable"] is False
    assert hit["version"] == "9.5.3"


def test_inspect_target_port_concealed(mocker):
    plugin = SonicWallGmsAuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 8443,
        "path": "/sgms/login",
        "status_code": 200,
        "headers": {"set-cookie": "JSESSIONID=ABCD; Path=/sgms"},
        "body_snippet": "<html><title>SonicWall Global Management System Login</title></html>"
    })

    hit = plugin.inspect_target_port("10.0.0.82", 8443)
    assert hit is not None
    assert hit["gms_detected"] is True
    assert hit["is_vulnerable"] is False
    assert hit.get("concealed") is True


def test_run_audit_vulnerable_target(mocker):
    plugin = SonicWallGmsAuditPlugin()
    plugin.discovered_ports = [8443]
    mocker.patch.object(plugin, "inspect_target_port", return_value={
        "port": 8443,
        "gms_detected": True,
        "version": "9.5.2",
        "source": "HTTP GET /sgms/login",
        "is_vulnerable": True,
        "reason": "SonicWall Global Management System (GMS) 9.5.2 is vulnerable to CVE-2026-109593."
    })

    res = plugin.run_audit("10.0.0.80", [8443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-109593" in res["proof"]
    assert "9.5.2" in res["details"]
