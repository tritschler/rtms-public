"""
test_glpi_audit.py - Unit tests for GLPI Two-Factor Authentication Bypass Audit Tool (CVE-2026-52848).
"""

from plugins.glpi.glpi_cve_2026_52848_audit import (
    GlpiAuditPlugin,
    parse_glpi_version,
    is_glpi_vulnerable,
)


def test_plugin_metadata():
    plugin = GlpiAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-52848"
    assert plugin.info["severity"] == "CRITICAL"
    assert "GLPI" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"
    assert 80 in plugin.target_ports
    assert 443 in plugin.target_ports


def test_version_parsing():
    assert parse_glpi_version(
        "<html><footer>GLPI 11.0.5 Copyright (C) Teclib</footer></html>"
    ) == (11, 0, 5, "11.0.5")
    assert parse_glpi_version(
        '<link rel="stylesheet" href="/css/palettes/auror.min.css?v=11.0.7">'
    ) == (11, 0, 7, "11.0.7")
    assert parse_glpi_version(
        "GLPI version 11.0.8"
    ) == (11, 0, 8, "11.0.8")
    assert parse_glpi_version("<html>Apache Server</html>") is None
    assert parse_glpi_version("") is None


def test_version_vulnerability_logic():
    vuln, reason = is_glpi_vulnerable(11, 0, 0, "11.0.0")
    assert vuln is True
    assert "CVE-2026-52848" in reason

    vuln, _ = is_glpi_vulnerable(11, 0, 7, "11.0.7")
    assert vuln is True

    vuln, reason = is_glpi_vulnerable(11, 0, 8, "11.0.8")
    assert vuln is False
    assert "not affected" in reason

    vuln, _ = is_glpi_vulnerable(10, 0, 16, "10.0.16")
    assert vuln is False


def test_check_requirements():
    plugin = GlpiAuditPlugin()
    assert plugin.check_requirements("10.0.0.10", [80, 443]) is True
    assert 443 in plugin.discovered_ports
    assert plugin.check_requirements("10.0.0.10", {8088: {"name": "glpi-http"}}) is True
    assert 8088 in plugin.discovered_ports
    assert plugin.check_requirements("10.0.0.10", [22, 25]) is False


def test_inspect_target_port_vulnerable(mocker):
    plugin = GlpiAuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 443,
        "path": "/front/login.php",
        "status_code": 200,
        "headers": {"set-cookie": "glpi_123456=abcdef; Path=/"},
        "body_snippet": "<html><title>GLPI - Authentication</title><link href='/css/app.css?v=11.0.6'></html>"
    })

    hit = plugin.inspect_target_port("10.0.0.20", 443)
    assert hit is not None
    assert hit["glpi_detected"] is True
    assert hit["is_vulnerable"] is True
    assert hit["version"] == "11.0.6"


def test_inspect_target_port_patched(mocker):
    plugin = GlpiAuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 443,
        "path": "/front/login.php",
        "status_code": 200,
        "headers": {"set-cookie": "glpi_123456=abcdef; Path=/"},
        "body_snippet": "<html><title>GLPI - Authentication</title><footer>GLPI 11.0.8 Copyright Teclib</footer></html>"
    })

    hit = plugin.inspect_target_port("10.0.0.21", 443)
    assert hit is not None
    assert hit["glpi_detected"] is True
    assert hit["is_vulnerable"] is False
    assert hit["version"] == "11.0.8"


def test_inspect_target_port_concealed(mocker):
    plugin = GlpiAuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 443,
        "path": "/front/login.php",
        "status_code": 200,
        "headers": {"set-cookie": "glpi_123456=abcdef; Path=/"},
        "body_snippet": "<html><title>GLPI - Authentication</title></html>"
    })

    hit = plugin.inspect_target_port("10.0.0.22", 443)
    assert hit is not None
    assert hit["glpi_detected"] is True
    assert hit["is_vulnerable"] is False
    assert hit.get("concealed") is True


def test_run_audit_vulnerable_target(mocker):
    plugin = GlpiAuditPlugin()
    plugin.discovered_ports = [443]
    mocker.patch.object(plugin, "inspect_target_port", return_value={
        "port": 443,
        "glpi_detected": True,
        "version": "11.0.6",
        "source": "HTTP GET /front/login.php",
        "is_vulnerable": True,
        "reason": "GLPI 11.0.6 is vulnerable to CVE-2026-52848."
    })

    res = plugin.run_audit("10.0.0.20", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-52848" in res["proof"]
    assert "11.0.6" in res["details"]
